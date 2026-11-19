//! VLESS inbound (TCP over TLS).

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const relay = @import("../core/relay.zig");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const vless = @import("../protocol/vless.zig");
const Metadata = @import("../routing/metadata.zig").Metadata;
const Stream = @import("../transport/stream.zig").Stream;

pub const Context = struct {
    uuid: vless.Uuid,
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
    if (request.command != vless.command_tcp) {
        return error.CommandUnsupported;
    }

    const target = try ownTarget(arena, request.target);
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
