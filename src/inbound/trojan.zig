//! Trojan inbound (TCP CONNECT and UDP ASSOCIATE over TLS).

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const Metrics = @import("../core/metrics.zig").Metrics;
const relay = @import("../core/relay.zig");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const trojan = @import("../protocol/trojan.zig");
const Action = @import("../routing/router.zig").Action;
const Metadata = @import("../routing/metadata.zig").Metadata;
const Dialer = @import("../transport/dialer.zig").Dialer;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;

pub const Context = struct {
    password_hash: trojan.PasswordHash,
    /// Optional service that receives decrypted traffic which does not start
    /// with a valid Trojan authentication line. Routed like any other TCP
    /// connection; see ADR-0011.
    fallback: ?Endpoint = null,
};

const UdpContext = struct {
    io: std.Io,
    stream: Stream,
    outbound: PacketConn,
    metrics: *Metrics,
};

pub fn handle(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    arena: std.mem.Allocator,
    context: *const Context,
) !void {
    var prefix: [trojan.auth_prefix_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &prefix);
    const auth = trojan.readAuthPrefix(
        io,
        stream,
        &context.password_hash,
        &prefix,
    ) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.ProtocolViolation,
    };

    if (!auth.matched) {
        return handleFallback(
            io,
            stream,
            inbound_tag,
            dispatch,
            context.fallback,
            prefix[0..auth.len],
        );
    }

    var domain_buffer: [trojan.max_domain_len]u8 = undefined;
    const request = trojan.readRequestHeader(
        io,
        stream,
        &domain_buffer,
    ) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.ProtocolViolation,
    };
    const target = try ownTarget(arena, request.target);

    switch (request.command) {
        trojan.command_connect => try handleTcp(
            io,
            stream,
            inbound_tag,
            dispatch,
            target,
        ),
        trojan.command_udp_associate => try handleUdp(
            io,
            stream,
            inbound_tag,
            dispatch,
        ),
        else => return error.ProtocolViolation,
    }
}

fn handleFallback(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    fallback: ?Endpoint,
    prefix: []const u8,
) !void {
    if (prefix.len == 0) return;
    const target = fallback orelse return;

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

    const remote = dispatch.connect(io, tag, target) catch |err| {
        std.log.scoped(.marmo).debug(
            "trojan fallback connect failed: {s}",
            .{@errorName(err)},
        );
        return;
    };
    defer remote.close(io);

    try writeAll(io, remote, prefix);
    try relay.relay(io, stream, remote, dispatch.metrics());
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
    try relay.relay(io, stream, remote, dispatch.metrics());
}

const UdpSession = struct {
    outbound: ?PacketConn = null,
    tag: []const u8 = "",
    reply_future: ?std.Io.Future(void) = null,
    context: UdpContext = undefined,
};

fn handleUdp(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
) !void {
    var buffer: [trojan.max_udp_payload]u8 = undefined;
    var domain_buffer: [trojan.max_domain_len]u8 = undefined;
    var session: UdpSession = .{};
    defer {
        if (session.reply_future) |*future| _ = future.cancel(io);
        if (session.outbound) |connection| connection.close(io);
    }

    while (true) {
        const packet = trojan.readUdpPacket(
            io,
            stream,
            &buffer,
            &domain_buffer,
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.EndOfStream => return,
            error.MessageTooBig => return error.ProtocolViolation,
            else => return error.ProtocolViolation,
        };
        if (packet.data_len == 0) continue;

        const metadata: Metadata = .{
            .network = .udp,
            .source = stream.remote(),
            .destination = packet.endpoint,
            .domain = switch (packet.endpoint) {
                .domain => |domain| domain.name,
                .ip => null,
            },
            .inbound = inbound_tag,
        };
        const action = dispatch.route(&metadata);
        const tag = switch (action) {
            .route => |route_tag| route_tag,
            .direct => "direct",
            .reject, .hijack_dns => continue,
        };

        if (session.outbound == null) {
            try openUdp(io, stream, dispatch, packet.endpoint, tag, &session);
        } else if (!std.mem.eql(u8, tag, session.tag)) {
            continue;
        }

        const connection = session.outbound orelse return;
        try sendUdp(
            io,
            connection,
            packet.endpoint,
            buffer[0..packet.data_len],
            dispatch.metrics(),
        );
    }
}

fn openUdp(
    io: std.Io,
    stream: Stream,
    dispatch: Dispatch,
    target: Endpoint,
    tag: []const u8,
    session: *UdpSession,
) !void {
    const connection = dispatch.connect_packet(io, tag, target) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.ProtocolViolation,
    };
    session.outbound = connection;
    session.tag = tag;
    session.context = .{
        .io = io,
        .stream = stream,
        .outbound = connection,
        .metrics = dispatch.metrics(),
    };
    session.reply_future = io.concurrent(udpReply, .{&session.context}) catch {
        return error.ConcurrencyUnavailable;
    };
    dispatch.metrics().udpSessionOpened();
}

fn sendUdp(
    io: std.Io,
    connection: PacketConn,
    target: Endpoint,
    data: []const u8,
    metrics: *Metrics,
) !void {
    connection.send_to(io, target, data) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.MessageTooBig => return error.MessageTooBig,
        else => return error.ProtocolViolation,
    };
    metrics.addToRemote(data.len);
}

fn udpReply(context: *UdpContext) void {
    var buffer: [trojan.max_udp_payload]u8 = undefined;
    while (true) {
        const message = context.outbound.receive(context.io, &buffer) catch return;
        if (message.data_len == 0) continue;
        trojan.writeUdpPacket(
            context.io,
            context.stream,
            message.source,
            buffer[0..message.data_len],
        ) catch return;
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

fn writeAll(io: std.Io, stream: Stream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try stream.write(io, &.{bytes[offset..]});
        if (written == 0) return error.BrokenPipe;
        offset += written;
    }
}

const TestStream = struct {
    input: []const u8 = "",
    position: usize = 0,

    fn stream(self: *TestStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        _ = io;
        const self: *TestStream = @ptrCast(@alignCast(ctx));
        if (self.position == self.input.len) return 0;
        const available = self.input[self.position..];
        var total: usize = 0;
        for (buffers) |buffer| {
            if (total == available.len) break;
            const count = @min(buffer.len, available.len - total);
            @memcpy(buffer[0..count], available[total..][0..count]);
            total += count;
        }
        self.position += total;
        return total;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        _ = ctx;
        _ = io;
        _ = buffers;
        return error.BrokenPipe;
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        _ = ctx;
        _ = io;
        _ = how;
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        _ = ctx;
        _ = io;
    }

    fn local(ctx: *anyopaque) Endpoint {
        _ = ctx;
        return .{ .ip = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } } };
    }

    fn remote(ctx: *anyopaque) Endpoint {
        _ = ctx;
        return .{ .ip = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 2 } } };
    }

    const vtable: Stream.VTable = .{
        .read = read,
        .write = write,
        .shutdown = shutdown,
        .close = close,
        .local = local,
        .remote = remote,
    };
};

const FakeDispatch = struct {
    action: Action,
    connect_called: bool = false,
    metrics: Metrics = .{},

    fn dispatch(self: *FakeDispatch) Dispatch {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn route(ctx: *anyopaque, metadata: *const Metadata) Action {
        _ = metadata;
        const self: *FakeDispatch = @ptrCast(@alignCast(ctx));
        return self.action;
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        tag: []const u8,
        target: Endpoint,
    ) Dialer.ConnectError!Stream {
        _ = io;
        _ = tag;
        _ = target;
        const self: *FakeDispatch = @ptrCast(@alignCast(ctx));
        self.connect_called = true;
        return error.Unsupported;
    }

    fn connectPacket(
        ctx: *anyopaque,
        io: std.Io,
        tag: []const u8,
        target: Endpoint,
    ) Dialer.ConnectError!PacketConn {
        _ = ctx;
        _ = io;
        _ = tag;
        _ = target;
        return error.Unsupported;
    }

    fn metricsPtr(ctx: *anyopaque) *Metrics {
        const self: *FakeDispatch = @ptrCast(@alignCast(ctx));
        return &self.metrics;
    }

    const vtable: Dispatch.VTable = .{
        .route = route,
        .connect = connect,
        .connect_packet = connectPacket,
        .metrics = metricsPtr,
    };
};

test "fallback routes authentication failures through Dispatch" {
    var stream_state: TestStream = .{};
    var fake: FakeDispatch = .{ .action = .{ .route = "proxy" } };
    const fallback = try Endpoint.parse("127.0.0.1:8080");

    try handleFallback(
        std.testing.io,
        stream_state.stream(),
        "trojan-in",
        fake.dispatch(),
        fallback,
        "GET /",
    );
    try std.testing.expect(fake.connect_called);
}

test "fallback reject closes without connecting" {
    var stream_state: TestStream = .{};
    var fake: FakeDispatch = .{ .action = .{ .reject = .rule } };
    const fallback = try Endpoint.parse("127.0.0.1:8080");

    try handleFallback(
        std.testing.io,
        stream_state.stream(),
        "trojan-in",
        fake.dispatch(),
        fallback,
        "GET /",
    );
    try std.testing.expect(!fake.connect_called);
}

test "valid authentication with a malformed request does not fall back" {
    const hash = trojan.hashPassword("secret");
    var input: [trojan.auth_prefix_len + 1]u8 = undefined;
    @memcpy(input[0..trojan.password_hash_len], &hash);
    @memcpy(input[trojan.password_hash_len..trojan.auth_prefix_len], "\r\n");
    input[trojan.auth_prefix_len] = 'x';

    var stream_state: TestStream = .{ .input = &input };
    var fake: FakeDispatch = .{ .action = .{ .route = "proxy" } };
    var context: Context = .{
        .password_hash = hash,
        .fallback = try Endpoint.parse("127.0.0.1:8080"),
    };

    try std.testing.expectError(
        error.ProtocolViolation,
        handle(
            std.testing.io,
            stream_state.stream(),
            "trojan-in",
            fake.dispatch(),
            std.testing.allocator,
            &context,
        ),
    );
    try std.testing.expect(!fake.connect_called);
}
