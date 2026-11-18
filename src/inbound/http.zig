//! HTTP/1.1 CONNECT inbound. Forward proxying is a Phase 1 follow-up.

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const relay = @import("../core/relay.zig");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Metadata = @import("../routing/metadata.zig").Metadata;
const Stream = @import("../transport/stream.zig").Stream;

const headers_max = 8192;

pub fn handle(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    arena: std.mem.Allocator,
) !void {
    _ = arena;
    var buffer: [headers_max]u8 = undefined;
    const header_len = try readHeaders(io, stream, &buffer);

    const line_end = std.mem.findScalar(u8, buffer[0..header_len], '\r') orelse
        return error.BadRequest;
    const request_line = buffer[0..line_end];

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.BadRequest;
    const target_text = parts.next() orelse return error.BadRequest;
    _ = parts.next() orelse return error.BadRequest;

    if (!std.mem.eql(u8, method, "CONNECT")) {
        try respond(io, stream, "501 Not Implemented");
        return;
    }

    const target = Endpoint.parse(target_text) catch {
        try respond(io, stream, "400 Bad Request");
        return;
    };

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
            try respond(io, stream, "403 Forbidden");
            return;
        },
        .hijack_dns => {
            try respond(io, stream, "501 Not Implemented");
            return;
        },
    };

    const remote = dispatch.connect(io, tag, target) catch {
        try respond(io, stream, "502 Bad Gateway");
        return;
    };
    defer remote.close(io);

    _ = try stream.write(io, &.{"HTTP/1.1 200 Connection Established\r\n\r\n"});
    try relay.relay(io, stream, remote, dispatch.metrics());
}

fn readHeaders(io: std.Io, stream: Stream, buffer: []u8) !usize {
    var len: usize = 0;
    while (len < buffer.len) {
        var buffers = [_][]u8{buffer[len .. len + 1]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        len += 1;
        if (len >= 4 and std.mem.endsWith(u8, buffer[0..len], "\r\n\r\n")) {
            return len;
        }
    }
    return error.HeadersTooLarge;
}

fn respond(io: std.Io, stream: Stream, status: []const u8) !void {
    var buffer: [128]u8 = undefined;
    const response = std.fmt.bufPrint(
        &buffer,
        "HTTP/1.1 {s}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        .{status},
    ) catch return error.Unexpected;
    _ = try stream.write(io, &.{response});
}
