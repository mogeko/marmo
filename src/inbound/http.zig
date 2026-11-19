//! HTTP/1.1 inbound: CONNECT and forward proxying.

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const relay = @import("../core/relay.zig");
const Guard = @import("../core/connection_guard.zig").Guard;
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Metadata = @import("../routing/metadata.zig").Metadata;
const Stream = @import("../transport/stream.zig").Stream;

const headers_max = 8192;
const forward_head_max = headers_max + 1024;

pub const AbsoluteTarget = struct {
    endpoint: Endpoint,
    authority: []const u8,
    path: []const u8,
    needs_slash: bool,
};

pub fn handle(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    arena: std.mem.Allocator,
    guard: ?*Guard,
) !void {
    _ = arena;
    var buffer: [headers_max]u8 = undefined;
    const header_len = readHeaders(io, stream, &buffer) catch |err| switch (err) {
        error.HeadersTooLarge => {
            try respond(io, stream, "431 Request Header Fields Too Large");
            return;
        },
        else => return err,
    };

    const line_end = std.mem.findScalar(u8, buffer[0..header_len], '\r') orelse
        return error.BadRequest;
    const request_line = buffer[0..line_end];

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.BadRequest;
    const target_text = parts.next() orelse return error.BadRequest;
    const version = parts.next() orelse return error.BadRequest;
    if (parts.next() != null) return error.BadRequest;

    if (std.mem.eql(u8, method, "CONNECT")) {
        try handleConnect(io, stream, inbound_tag, dispatch, target_text, guard);
        return;
    }

    const header_block = buffer[line_end + 2 .. header_len - 2];
    try handleForward(
        io,
        stream,
        inbound_tag,
        dispatch,
        method,
        target_text,
        version,
        header_block,
        guard,
    );
}

fn handleConnect(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    target_text: []const u8,
    guard: ?*Guard,
) !void {
    const target = Endpoint.parse(target_text) catch {
        try respond(io, stream, "400 Bad Request");
        return;
    };

    const action = dispatch.route(&metadataFor(stream, inbound_tag, target));
    const tag = routeTag(action) orelse {
        try respond(io, stream, "403 Forbidden");
        return;
    };

    const remote = dispatch.connect(io, tag, target) catch {
        try respond(io, stream, "502 Bad Gateway");
        return;
    };
    defer remote.close(io);

    _ = try stream.write(io, &.{"HTTP/1.1 200 Connection Established\r\n\r\n"});
    try relay.relayWithGuard(io, stream, remote, dispatch.metrics(), guard);
}

fn handleForward(
    io: std.Io,
    stream: Stream,
    inbound_tag: []const u8,
    dispatch: Dispatch,
    method: []const u8,
    target_text: []const u8,
    version: []const u8,
    header_block: []const u8,
    guard: ?*Guard,
) !void {
    if (!isToken(method)) {
        try respond(io, stream, "400 Bad Request");
        return;
    }
    if (!isHttpVersion(version)) {
        try respond(io, stream, "505 HTTP Version Not Supported");
        return;
    }

    const target = parseAbsolute(target_text) catch |err| switch (err) {
        error.UnsupportedScheme => {
            try respond(io, stream, "501 Not Implemented");
            return;
        },
        else => {
            try respond(io, stream, "400 Bad Request");
            return;
        },
    };

    var head: [forward_head_max]u8 = undefined;
    const head_len = buildForwardHead(
        &head,
        method,
        version,
        target,
        header_block,
    ) catch |err| switch (err) {
        error.HeadersTooLarge => {
            try respond(io, stream, "431 Request Header Fields Too Large");
            return;
        },
        else => {
            try respond(io, stream, "400 Bad Request");
            return;
        },
    };

    const metadata = metadataFor(stream, inbound_tag, target.endpoint);
    const action = dispatch.route(&metadata);
    const tag = routeTag(action) orelse {
        try respond(io, stream, "403 Forbidden");
        return;
    };

    const remote = dispatch.connect(io, tag, target.endpoint) catch {
        try respond(io, stream, "502 Bad Gateway");
        return;
    };
    defer remote.close(io);

    _ = remote.write(io, &.{head[0..head_len]}) catch return error.Unexpected;
    try relay.relayWithGuard(io, stream, remote, dispatch.metrics(), guard);
}

fn metadataFor(
    stream: Stream,
    inbound_tag: []const u8,
    target: Endpoint,
) Metadata {
    return .{
        .network = .tcp,
        .source = stream.remote(),
        .destination = target,
        .domain = switch (target) {
            .domain => |domain| domain.name,
            .ip => null,
        },
        .inbound = inbound_tag,
    };
}

fn routeTag(action: @import("../routing/router.zig").Action) ?[]const u8 {
    return switch (action) {
        .route => |tag| tag,
        .direct => "direct",
        .reject, .hijack_dns => null,
    };
}

/// Parses an absolute-form `http://` request target.
pub fn parseAbsolute(uri: []const u8) !AbsoluteTarget {
    if (uri.len < 7 or !std.ascii.eqlIgnoreCase(uri[0..7], "http://")) {
        return error.UnsupportedScheme;
    }
    // A raw control character in the request target would be copied into the
    // upstream request line and become header/request injection.
    for (uri) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.BadRequest;
    }
    const rest = uri[7..];
    if (std.mem.findScalar(u8, rest, '#') != null) return error.BadRequest;

    var authority_end = rest.len;
    for (rest, 0..) |byte, index| {
        if (byte == '/' or byte == '?') {
            authority_end = index;
            break;
        }
    }

    const authority = rest[0..authority_end];
    if (authority.len == 0) return error.BadRequest;
    const endpoint = try parseAuthority(authority);

    var path: []const u8 = "/";
    var needs_slash = false;
    if (authority_end < rest.len) {
        if (rest[authority_end] == '/') {
            path = rest[authority_end..];
        } else {
            path = rest[authority_end..];
            needs_slash = true;
        }
    }

    return .{
        .endpoint = endpoint,
        .authority = authority,
        .path = path,
        .needs_slash = needs_slash,
    };
}

/// Parses an HTTP authority (`host[:port]` or `[ipv6][:port]`).
pub fn parseAuthority(authority: []const u8) !Endpoint {
    if (authority.len == 0) return error.BadRequest;
    if (std.mem.findScalar(u8, authority, '@') != null) return error.BadRequest;
    for (authority) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.BadRequest;
    }

    if (authority[0] == '[') {
        const close = std.mem.findScalar(u8, authority, ']') orelse
            return error.BadRequest;
        const host = authority[1..close];
        var port: u16 = 80;
        if (close + 1 < authority.len) {
            if (authority[close + 1] != ':') return error.BadRequest;
            port = try parsePort(authority[close + 2 ..]);
        }
        const ip = std.Io.net.IpAddress.parseIp6(host, port) catch
            return error.BadRequest;
        return .{ .ip = ip };
    }

    const colon = std.mem.findScalar(u8, authority, ':');
    if (colon) |index| {
        if (std.mem.findScalar(u8, authority[index + 1 ..], ':') != null) {
            return error.BadRequest;
        }
        const host = authority[0..index];
        if (host.len == 0) return error.BadRequest;
        const port = try parsePort(authority[index + 1 ..]);
        return parseHostPort(host, port);
    }
    return parseHostPort(authority, 80);
}

fn parseHostPort(host: []const u8, port: u16) !Endpoint {
    var buffer: [320]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{s}:{d}", .{ host, port }) catch
        return error.BadRequest;
    return Endpoint.parse(text) catch error.BadRequest;
}

fn parsePort(text: []const u8) !u16 {
    if (text.len == 0) return error.BadRequest;
    const port = std.fmt.parseInt(u16, text, 10) catch return error.BadRequest;
    if (port == 0) return error.BadRequest;
    return port;
}

/// Rewrites an absolute-form request into origin-form and strips hop-by-hop
/// headers. `out` must hold `forward_head_max` bytes.
pub fn buildForwardHead(
    out: []u8,
    method: []const u8,
    version: []const u8,
    target: AbsoluteTarget,
    header_block: []const u8,
) !usize {
    var length: usize = 0;
    const path_prefix: []const u8 = if (target.needs_slash) "/" else "";
    const request_line = std.fmt.bufPrint(
        out,
        "{s} {s}{s} {s}\r\n",
        .{ method, path_prefix, target.path, version },
    ) catch return error.HeadersTooLarge;
    length += request_line.len;

    try appendHeaders(out, &length, header_block);
    try append(out, &length, "Host: ");
    try append(out, &length, target.authority);
    try append(out, &length, "\r\nConnection: close\r\n\r\n");
    return length;
}

fn appendHeaders(out: []u8, length: *usize, header_block: []const u8) !void {
    var has_content_length = false;
    var has_transfer_encoding = false;

    if (header_block.len == 0) return;
    var lines = std.mem.splitSequence(u8, header_block, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') return error.BadRequest;

        const colon = std.mem.findScalar(u8, line, ':') orelse
            return error.BadRequest;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (name.len == 0 or !isToken(name)) return error.BadRequest;
        if (!isValidHeaderValue(value)) return error.BadRequest;

        if (std.ascii.eqlIgnoreCase(name, "host")) continue;
        if (std.ascii.eqlIgnoreCase(name, "connection")) continue;
        if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) continue;
        if (std.ascii.eqlIgnoreCase(name, "keep-alive")) continue;
        if (std.ascii.eqlIgnoreCase(name, "te")) continue;
        if (std.ascii.eqlIgnoreCase(name, "trailer")) continue;
        if (std.ascii.eqlIgnoreCase(name, "upgrade")) continue;
        if (std.ascii.eqlIgnoreCase(name, "proxy-authorization")) continue;

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (has_content_length) return error.BadRequest;
            has_content_length = true;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            has_transfer_encoding = true;
        }
        if (has_content_length and has_transfer_encoding) return error.BadRequest;

        try append(out, length, name);
        try append(out, length, ": ");
        try append(out, length, value);
        try append(out, length, "\r\n");
    }
}

fn append(out: []u8, length: *usize, bytes: []const u8) !void {
    if (bytes.len > out.len - length.*) return error.HeadersTooLarge;
    @memcpy(out[length.*..][0..bytes.len], bytes);
    length.* += bytes.len;
}

/// Accepts exactly `HTTP/1.<digit>`; anything else would be copied into the
/// upstream request line.
fn isHttpVersion(text: []const u8) bool {
    if (text.len != 8) return false;
    if (!std.mem.startsWith(u8, text, "HTTP/1.")) return false;
    return text[7] >= '0' and text[7] <= '9';
}

fn isToken(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) {
            if (std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) == null) {
                return false;
            }
        }
    }
    return true;
}

fn isValidHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte < 0x20 and byte != '\t') return false;
        if (byte == 0x7f) return false;
    }
    return true;
}

/// Reads one HTTP/1.1 head, including the terminating blank line.
pub fn readHeaders(io: std.Io, stream: Stream, buffer: []u8) !usize {
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

test "HTTP authority rejects an empty host" {
    try std.testing.expectError(error.BadRequest, parseAuthority(""));
    try std.testing.expectError(error.BadRequest, parseAuthority(":80"));
    try std.testing.expectError(error.BadRequest, parseAuthority("user@host:80"));
}

test "absolute targets reject control-character injection" {
    try std.testing.expectError(
        error.BadRequest,
        parseAbsolute("http://example.com/a\nInjected: yes"),
    );
    try std.testing.expectError(
        error.BadRequest,
        parseAbsolute("http://example.com/a\tb"),
    );
    _ = try parseAbsolute("http://example.com/a%0Ab");
}

test "HTTP versions are restricted to the exact token" {
    try std.testing.expect(isHttpVersion("HTTP/1.1"));
    try std.testing.expect(isHttpVersion("HTTP/1.0"));
    try std.testing.expect(!isHttpVersion("HTTP/1.1\nX: y"));
    try std.testing.expect(!isHttpVersion("HTTP/1."));
    try std.testing.expect(!isHttpVersion("HTTP/2.0"));
}
