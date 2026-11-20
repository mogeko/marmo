//! Shadowsocks 2022 inbound (TCP).

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const relay = @import("../core/relay.zig");
const Guard = @import("../core/connection_guard.zig").Guard;
const s2022 = @import("../protocol/shadowsocks2022.zig");
const Metadata = @import("../routing/metadata.zig").Metadata;
const Stream = @import("../transport/stream.zig").Stream;

pub const Context = struct {
    method: s2022.Method,
    key: s2022.Key,
    replay: s2022.ReplayCache,

    pub fn init(
        allocator: std.mem.Allocator,
        method: s2022.Method,
        key: s2022.Key,
    ) !*Context {
        const self = try allocator.create(Context);
        self.* = .{ .method = method, .key = key, .replay = .{} };
        return self;
    }

    pub fn deinit(self: *Context) void {
        self.key.deinit();
    }
};

pub fn handle(
    io: std.Io,
    gpa: std.mem.Allocator,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    context: *Context,
    guard: ?*Guard,
) !void {
    var plaintext: [s2022.max_payload]u8 = undefined;
    const request = s2022.readClientRequest(
        io,
        stream,
        context.method,
        &context.key,
        &context.replay,
        &plaintext,
    ) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return err,
    };

    const metadata: Metadata = .{
        .network = .tcp,
        .source = stream.remote(),
        .destination = request.target,
        .domain = switch (request.target) {
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

    const remote = try dispatch.connect(io, tag, request.target);
    defer remote.close(io);

    const server_stream = try s2022.ServerStream.create(
        gpa,
        stream,
        context.method,
        &context.key,
        request.salt[0..request.salt_len],
        &request.recv_key,
        request.initial_payload,
        stream.local(),
        request.target,
    );
    defer server_stream.destroy(io);

    try relay.relayWithGuard(
        io,
        server_stream.stream(),
        remote,
        dispatch.metrics(),
        guard,
    );
}
