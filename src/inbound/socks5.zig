//! SOCKS5 inbound (CONNECT only; UDP ASSOCIATE is Phase 1 follow-up).

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const relay = @import("../core/relay.zig");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Metadata = @import("../routing/metadata.zig").Metadata;
const Dialer = @import("../transport/dialer.zig").Dialer;
const Stream = @import("../transport/stream.zig").Stream;
const PacketConn = @import("../transport/packet.zig").PacketConn;

const version = 5;
const method_no_auth = 0;
const command_connect = 1;
const command_udp_associate = 3;

const UdpContext = struct {
    io: std.Io,
    client_socket: std.Io.net.Socket,
    dispatch: Dispatch,
    tcp_client_ip: ?std.Io.net.IpAddress,
    inbound_tag: []const u8,
    client_address: ?std.Io.net.IpAddress = null,
    outbound: ?PacketConn = null,
    outbound_tag: []const u8 = "",
    reply_future: ?std.Io.Future(void) = null,
};

const UdpRequest = struct {
    target: Endpoint,
    payload: []const u8,
};

pub fn handle(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    arena: std.mem.Allocator,
) !void {
    try negotiate(io, stream);
    try handleRequest(io, stream, inbound_tag, dispatch, arena);
}

fn negotiate(io: std.Io, stream: Stream) !void {
    var header: [2]u8 = undefined;
    try readExact(io, stream, &header);
    if (header[0] != version) return error.BadVersion;

    const method_count = header[1];
    if (method_count == 0) return error.NoMethods;
    var methods: [255]u8 = undefined;
    try readExact(io, stream, methods[0..method_count]);

    var supports_no_auth = false;
    for (methods[0..method_count]) |method| {
        if (method == method_no_auth) {
            supports_no_auth = true;
            break;
        }
    }
    if (!supports_no_auth) {
        try writeAll(io, stream, &.{ version, 0xff });
        return error.AuthUnsupported;
    }
    try writeAll(io, stream, &.{ version, method_no_auth });
}

fn handleRequest(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    arena: std.mem.Allocator,
) !void {
    var header: [4]u8 = undefined;
    try readExact(io, stream, &header);
    if (header[0] != version or header[2] != 0) return error.BadRequest;

    const target = try readAddress(io, stream, header[3], arena);
    if (header[1] == command_udp_associate) {
        try handleUdpAssociate(io, stream, inbound_tag, dispatch);
        return;
    }
    if (header[1] != command_connect) {
        try replyFailure(io, stream, 0x07);
        return error.CommandUnsupported;
    }

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
        .reject => {
            try replyFailure(io, stream, 0x02);
            return;
        },
        .hijack_dns => {
            try replyFailure(io, stream, 0x07);
            return;
        },
    };

    const remote = dispatch.connect(io, tag, target) catch |err| {
        try replyFailure(io, stream, replyCode(err));
        return;
    };
    defer remote.close(io);

    try replySuccess(io, stream);
    try relay.relay(io, stream, remote, dispatch.metrics());
}

fn readAddress(
    io: std.Io,
    stream: Stream,
    address_type: u8,
    arena: std.mem.Allocator,
) !Endpoint {
    switch (address_type) {
        0x01 => {
            var bytes: [4]u8 = undefined;
            try readExact(io, stream, &bytes);
            const port = try readPort(io, stream);
            return .{ .ip = .{ .ip4 = .{ .bytes = bytes, .port = port } } };
        },
        0x03 => {
            var length: [1]u8 = undefined;
            try readExact(io, stream, &length);
            if (length[0] == 0) return error.EmptyDomain;
            const name = try arena.alloc(u8, length[0]);
            try readExact(io, stream, name);
            const port = try readPort(io, stream);
            return .{ .domain = .{ .name = name, .port = port } };
        },
        0x04 => {
            var bytes: [16]u8 = undefined;
            try readExact(io, stream, &bytes);
            const port = try readPort(io, stream);
            return .{ .ip = .{ .ip6 = .{ .bytes = bytes, .port = port } } };
        },
        else => return error.AddressTypeUnsupported,
    }
}

fn readPort(io: std.Io, stream: Stream) !u16 {
    var bytes: [2]u8 = undefined;
    try readExact(io, stream, &bytes);
    return std.mem.readInt(u16, &bytes, .big);
}

fn readExact(io: std.Io, stream: Stream, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var buffers = [_][]u8{buffer[offset..]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
}

fn writeAll(io: std.Io, stream: Stream, bytes: []const u8) !void {
    _ = try stream.write(io, &.{bytes});
}

fn replySuccess(io: std.Io, stream: Stream) !void {
    try writeAll(io, stream, &.{ 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
}

fn replyFailure(io: std.Io, stream: Stream, code: u8) !void {
    try writeAll(io, stream, &.{ 5, code, 0, 1, 0, 0, 0, 0, 0, 0 });
}

fn replySuccessEndpoint(
    io: std.Io,
    stream: Stream,
    address: std.Io.net.IpAddress,
) !void {
    var buffer: [22]u8 = undefined;
    buffer[0] = version;
    buffer[1] = 0;
    buffer[2] = 0;
    const address_len = try encodeAddress(buffer[3..], address);
    try writeAll(io, stream, buffer[0 .. 3 + address_len]);
}

fn handleUdpAssociate(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
) !void {
    const remote = stream.remote();
    const tcp_client_ip: ?std.Io.net.IpAddress = switch (remote) {
        .ip => |ip| ip,
        .domain => null,
    };
    const bind_address: std.Io.net.IpAddress = switch (remote) {
        .ip => |ip| switch (ip) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        },
        .domain => .{ .ip4 = .unspecified(0) },
    };

    const socket = std.Io.net.IpAddress.bind(
        &bind_address,
        io,
        .{ .mode = .dgram, .protocol = .udp },
    ) catch {
        try replyFailure(io, stream, 0x01);
        return;
    };
    errdefer socket.close(io);
    try replySuccessEndpoint(io, stream, socket.address);

    var context: UdpContext = .{
        .io = io,
        .client_socket = socket,
        .dispatch = dispatch,
        .tcp_client_ip = tcp_client_ip,
        .inbound_tag = inbound_tag,
    };
    var relay_future = io.concurrent(udpRelay, .{&context}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.ConcurrencyUnavailable,
    };

    var byte: [1]u8 = undefined;
    while (true) {
        var buffers = [_][]u8{&byte};
        const read_len = stream.read(io, &buffers) catch break;
        if (read_len == 0) break;
    }

    _ = relay_future.cancel(io);
    if (context.reply_future) |*future| _ = future.cancel(io);
    if (context.outbound) |outbound| outbound.close(io);
    socket.close(io);
}

fn udpRelay(context: *UdpContext) void {
    var buffer: [65535]u8 = undefined;

    while (true) {
        const message = context.client_socket.receive(context.io, &buffer) catch return;

        if (context.client_address == null) {
            if (context.tcp_client_ip) |expected| {
                if (!sameIp(message.from, expected)) continue;
            }
            context.client_address = message.from;
        } else if (!std.Io.net.IpAddress.eql(&message.from, &context.client_address.?)) {
            continue;
        }

        handleClientDatagram(context, message.from, message.data) catch continue;
    }
}

fn handleClientDatagram(
    context: *UdpContext,
    client: std.Io.net.IpAddress,
    packet: []const u8,
) !void {
    const request = try parseUdpRequest(packet);
    const metadata: Metadata = .{
        .network = .udp,
        .source = .{ .ip = client },
        .destination = request.target,
        .domain = switch (request.target) {
            .domain => |domain| domain.name,
            .ip => null,
        },
        .inbound = context.inbound_tag,
    };

    const action = context.dispatch.route(&metadata);
    const tag = switch (action) {
        .route => |route_tag| route_tag,
        .direct => "direct",
        .reject, .hijack_dns => return,
    };

    if (context.outbound == null) {
        const outbound = try context.dispatch.connect_packet(
            context.io,
            tag,
            request.target,
        );
        context.outbound = outbound;
        context.outbound_tag = tag;
        context.reply_future = io_concurrent_reply(context) catch {
            outbound.close(context.io);
            context.outbound = null;
            return error.ConcurrencyUnavailable;
        };
    } else if (!std.mem.eql(u8, tag, context.outbound_tag)) {
        return;
    }

    const outbound = context.outbound orelse return;
    try outbound.send_to(context.io, request.target, request.payload);
    context.dispatch.metrics().addToRemote(request.payload.len);
}

fn io_concurrent_reply(context: *UdpContext) !std.Io.Future(void) {
    return std.Io.concurrent(context.io, udpReply, .{context});
}

fn udpReply(context: *UdpContext) void {
    const outbound = context.outbound orelse return;
    var buffer: [65535]u8 = undefined;

    while (true) {
        const message = outbound.receive(context.io, &buffer) catch return;
        const client = context.client_address orelse return;
        const source = switch (message.source) {
            .ip => |ip| ip,
            .domain => return,
        };
        sendUdpReply(
            context.io,
            context.client_socket,
            client,
            source,
            buffer[0..message.data_len],
        ) catch return;
        context.dispatch.metrics().addToClient(message.data_len);
    }
}

fn parseUdpRequest(packet: []const u8) !UdpRequest {
    if (packet.len < 4) return error.Malformed;
    if (packet[0] != 0 or packet[1] != 0) return error.Malformed;
    if (packet[2] != 0) return error.Fragmented;

    var offset: usize = 3;
    const address_type = packet[offset];
    offset += 1;

    switch (address_type) {
        0x01 => {
            if (offset + 6 > packet.len) return error.Malformed;
            const bytes = packet[offset..][0..4];
            const port = packetPort(packet[offset + 4 ..][0..2]);
            offset += 6;
            return .{
                .target = .{ .ip = .{ .ip4 = .{
                    .bytes = bytes[0..4].*,
                    .port = port,
                } } },
                .payload = packet[offset..],
            };
        },
        0x03 => {
            if (offset + 1 > packet.len) return error.Malformed;
            const name_len = packet[offset];
            offset += 1;
            if (name_len == 0 or offset + name_len + 2 > packet.len) {
                return error.Malformed;
            }
            const name = packet[offset .. offset + name_len];
            offset += name_len;
            const port = packetPort(packet[offset..][0..2]);
            offset += 2;
            return .{
                .target = .{ .domain = .{ .name = name, .port = port } },
                .payload = packet[offset..],
            };
        },
        0x04 => {
            if (offset + 18 > packet.len) return error.Malformed;
            const bytes = packet[offset..][0..16];
            const port = packetPort(packet[offset + 16 ..][0..2]);
            offset += 18;
            return .{
                .target = .{ .ip = .{ .ip6 = .{
                    .bytes = bytes[0..16].*,
                    .port = port,
                } } },
                .payload = packet[offset..],
            };
        },
        else => return error.AddressTypeUnsupported,
    }
}

fn sendUdpReply(
    io: std.Io,
    socket: std.Io.net.Socket,
    client: std.Io.net.IpAddress,
    source: std.Io.net.IpAddress,
    payload: []const u8,
) !void {
    var buffer: [65535 + 262]u8 = undefined;
    buffer[0] = 0;
    buffer[1] = 0;
    buffer[2] = 0;
    const address_len = try encodeAddress(buffer[3..], source);
    const total_len = 3 + address_len + payload.len;
    if (total_len > buffer.len) return error.MessageTooBig;
    @memcpy(buffer[3 + address_len ..][0..payload.len], payload);
    try socket.send(io, &client, buffer[0..total_len]);
}

fn encodeAddress(buffer: []u8, address: std.Io.net.IpAddress) !usize {
    switch (address) {
        .ip4 => |ip4| {
            if (buffer.len < 7) return error.NoSpace;
            buffer[0] = 0x01;
            @memcpy(buffer[1..5], &ip4.bytes);
            buffer[5] = @intCast(ip4.port >> 8);
            buffer[6] = @intCast(ip4.port & 0xff);
            return 7;
        },
        .ip6 => |ip6| {
            if (buffer.len < 19) return error.NoSpace;
            buffer[0] = 0x04;
            @memcpy(buffer[1..17], &ip6.bytes);
            buffer[17] = @intCast(ip6.port >> 8);
            buffer[18] = @intCast(ip6.port & 0xff);
            return 19;
        },
    }
}

fn packetPort(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

fn sameIp(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a_ip4| switch (b) {
            .ip4 => |b_ip4| std.mem.eql(u8, &a_ip4.bytes, &b_ip4.bytes),
            .ip6 => false,
        },
        .ip6 => |a_ip6| switch (b) {
            .ip6 => |b_ip6| std.mem.eql(u8, &a_ip6.bytes, &b_ip6.bytes),
            .ip4 => false,
        },
    };
}

fn replyCode(err: Dialer.ConnectError) u8 {
    return switch (err) {
        error.ConnectionRefused => 0x05,
        error.HostUnreachable => 0x04,
        error.TimedOut => 0x06,
        error.Unsupported => 0x07,
        else => 0x01,
    };
}
