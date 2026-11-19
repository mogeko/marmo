//! VLESS inbound (TCP and UDP over TLS).

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const Metrics = @import("../core/metrics.zig").Metrics;
const relay = @import("../core/relay.zig");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const vless = @import("../protocol/vless.zig");
const xudp = @import("../protocol/xudp.zig");
const Metadata = @import("../routing/metadata.zig").Metadata;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;

pub const Context = struct {
    uuid: vless.Uuid,
};

const UdpMode = enum { simple, xudp };

const UdpContext = struct {
    io: std.Io,
    stream: Stream,
    outbound: PacketConn,
    target: Endpoint,
    metrics: *Metrics,
    mode: UdpMode,
};

pub fn handle(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    arena: std.mem.Allocator,
    context: *const Context,
) !void {
    var domain_buffer: [vless.max_domain_len]u8 = undefined;
    const request = try vless.readRequestHeader(
        io,
        stream,
        &context.uuid,
        &domain_buffer,
    );
    const target = try ownTarget(arena, request.target);

    switch (request.command) {
        vless.command_tcp => try handleTcp(
            io,
            stream,
            inbound_tag,
            dispatch,
            target,
        ),
        vless.command_udp => try handleUdp(
            io,
            stream,
            inbound_tag,
            dispatch,
            target,
        ),
        vless.command_mux => {
            if (!xudp.isMuxTarget(request.target)) {
                return error.UnsupportedAddress;
            }
            try handleXudp(io, stream, inbound_tag, dispatch, arena);
        },
        else => return error.CommandUnsupported,
    }
}

fn handleTcp(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    target: Endpoint,
) !void {
    const metadata: Metadata = .{
        .network = .tcp,
        .source = stream.remote(),
        .destination = target,
        .domain = switch (target) {
            .domain => |domain| domain.name,
            .ip => null,
        },
        .inbound = inbound_tag,
    };

    const action = dispatch.route(&metadata);
    const tag = switch (action) {
        .route => |route_tag| route_tag,
        .direct => "direct",
        .reject, .hijack_dns => return,
    };

    const remote = try dispatch.connect(io, tag, target);
    defer remote.close(io);

    try vless.writeResponseHeader(io, stream);
    try relay.relay(io, stream, remote, dispatch.metrics());
}

fn handleUdp(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    target: Endpoint,
) !void {
    const outbound = try openUdp(io, stream, inbound_tag, dispatch, target) orelse
        return;
    defer outbound.close(io);
    try vless.writeResponseHeader(io, stream);

    var context: UdpContext = .{
        .io = io,
        .stream = stream,
        .outbound = outbound,
        .target = target,
        .metrics = dispatch.metrics(),
        .mode = .simple,
    };
    var reply_future = io.concurrent(udpReply, .{&context}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.ConcurrencyUnavailable,
    };
    defer {
        _ = reply_future.cancel(io);
    }

    var buffer: [vless.max_udp_payload]u8 = undefined;
    while (true) {
        const payload_len = vless.readUdpPacket(io, stream, &buffer) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.EndOfStream => return,
            error.MessageTooBig => return error.ProtocolViolation,
            else => return error.ProtocolViolation,
        };
        if (payload_len == 0) continue;

        outbound.send_to(io, target, buffer[0..payload_len]) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.MessageTooBig => return error.MessageTooBig,
            else => return error.ProtocolViolation,
        };
        context.metrics.addToRemote(payload_len);
    }
}

fn handleXudp(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    arena: std.mem.Allocator,
) !void {
    var meta_buffer: [xudp.max_meta_len]u8 = undefined;
    var data_buffer: [xudp.max_data_len]u8 = undefined;

    const first = try xudp.readFrame(io, stream, &meta_buffer, &data_buffer);
    if (first.status != xudp.status_new) return error.ProtocolViolation;
    const target = try ownTarget(arena, first.target orelse
        return error.ProtocolViolation);
    const outbound = try openUdp(io, stream, inbound_tag, dispatch, target) orelse
        return;
    defer outbound.close(io);

    try vless.writeResponseHeader(io, stream);

    var context: UdpContext = .{
        .io = io,
        .stream = stream,
        .outbound = outbound,
        .target = target,
        .metrics = dispatch.metrics(),
        .mode = .xudp,
    };
    var reply_future = io.concurrent(udpReply, .{&context}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.ConcurrencyUnavailable,
    };
    defer {
        _ = reply_future.cancel(io);
    }

    if (first.data.len != 0) {
        try sendXudpData(io, outbound, target, first.data, context.metrics);
    }

    while (true) {
        const frame = xudp.readFrame(
            io,
            stream,
            &meta_buffer,
            &data_buffer,
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.EndOfStream => return,
            error.MessageTooBig => return error.ProtocolViolation,
            else => return error.ProtocolViolation,
        };
        switch (frame.status) {
            xudp.status_keepalive => continue,
            xudp.status_end => return,
            xudp.status_new, xudp.status_keep => {
                if (frame.target) |frame_target| {
                    if (!Endpoint.eql(frame_target, target)) {
                        return error.ProtocolViolation;
                    }
                }
                if (frame.data.len == 0) continue;
                try sendXudpData(io, outbound, target, frame.data, context.metrics);
            },
            else => return error.ProtocolViolation,
        }
    }
}

fn openUdp(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    target: Endpoint,
) !?PacketConn {
    const metadata: Metadata = .{
        .network = .udp,
        .source = stream.remote(),
        .destination = target,
        .domain = switch (target) {
            .domain => |domain| domain.name,
            .ip => null,
        },
        .inbound = inbound_tag,
    };

    const action = dispatch.route(&metadata);
    const tag = switch (action) {
        .route => |route_tag| route_tag,
        .direct => "direct",
        .reject, .hijack_dns => return null,
    };
    return try dispatch.connect_packet(io, tag, target);
}

fn sendXudpData(
    io: std.Io,
    outbound: PacketConn,
    target: Endpoint,
    data: []const u8,
    metrics: *Metrics,
) !void {
    outbound.send_to(io, target, data) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.MessageTooBig => return error.MessageTooBig,
        else => return error.ProtocolViolation,
    };
    metrics.addToRemote(data.len);
}

fn udpReply(context: *UdpContext) void {
    var buffer: [vless.max_udp_payload]u8 = undefined;
    while (true) {
        const message = context.outbound.receive(context.io, &buffer) catch return;
        switch (context.target) {
            .ip => if (!Endpoint.eql(message.source, context.target)) continue,
            .domain => {},
        }
        if (message.data_len == 0) continue;
        switch (context.mode) {
            .simple => vless.writeUdpPacket(
                context.io,
                context.stream,
                buffer[0..message.data_len],
            ) catch return,
            .xudp => xudp.writeKeep(
                context.io,
                context.stream,
                buffer[0..message.data_len],
            ) catch return,
        }
        context.metrics.addToClient(message.data_len);
    }
}

fn ownTarget(arena: std.mem.Allocator, target: Endpoint) !Endpoint {
    return switch (target) {
        .ip => target,
        .domain => |domain| .{
            .domain = .{
                .name = try arena.dupe(u8, domain.name),
                .port = domain.port,
            },
        },
    };
}
