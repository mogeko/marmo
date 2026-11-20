//! Bounded HTTP/1.1 opening-handshake helpers shared by client and server.

const std = @import("std");

pub const max_handshake = 8 * 1024;

pub const Error = error{
    Canceled,
    HandshakeFailed,
};

pub const Head = struct {
    buffer: [max_handshake]u8 = undefined,
    len: usize = 0,

    pub fn bytes(self: *const Head) []const u8 {
        return self.buffer[0..self.len];
    }
};

/// Reads one HTTP head, including the terminating CRLFCRLF.
///
/// Uses buffered reads rather than `readSliceShort`, which would wait for the
/// caller's whole buffer to fill.
pub fn readHead(input: *std.Io.Reader, head: *Head) Error!void {
    while (true) {
        if (input.bufferedLen() == 0) {
            input.fillMore() catch |err| switch (err) {
                error.EndOfStream => return error.HandshakeFailed,
                error.ReadFailed => return error.HandshakeFailed,
            };
        }
        const available = input.buffered();
        if (available.len == 0) return error.HandshakeFailed;
        for (available) |byte| {
            if (head.len == head.buffer.len) return error.HandshakeFailed;
            head.buffer[head.len] = byte;
            head.len += 1;
            input.toss(1);
            if (head.len >= 4 and
                std.mem.endsWith(u8, head.bytes(), "\r\n\r\n"))
            {
                return;
            }
        }
    }
}

/// Rejects obs-fold, whitespace before the colon, control bytes, and malformed
/// field names before any header is trusted.
pub fn validateHead(head: []const u8) Error!void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const start_line = lines.next() orelse return error.HandshakeFailed;
    if (start_line.len == 0) return error.HandshakeFailed;
    while (lines.next()) |line| {
        if (line.len == 0) return;
        if (line[0] == ' ' or line[0] == '\t') {
            return error.HandshakeFailed;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.HandshakeFailed;
        if (colon == 0) return error.HandshakeFailed;
        if (line[colon - 1] == ' ' or line[colon - 1] == '\t') {
            return error.HandshakeFailed;
        }
        for (line[0..colon]) |byte| {
            if (!isTokenChar(byte)) return error.HandshakeFailed;
        }
        for (line[colon + 1 ..]) |byte| {
            if (byte == 0 or byte == 0x7f) return error.HandshakeFailed;
            if (byte < 0x20 and byte != '\t') return error.HandshakeFailed;
        }
    }
    return error.HandshakeFailed;
}

pub fn headerCount(head: []const u8, name: []const u8) usize {
    var count: usize = 0;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const field = std.mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(field, name)) count += 1;
    }
    return count;
}

fn isTokenChar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '!' or byte == '#' or byte == '$' or byte == '%' or
        byte == '&' or byte == '\'' or byte == '*' or byte == '+' or
        byte == '-' or byte == '.' or byte == '^' or byte == '_' or
        byte == '`' or byte == '|' or byte == '~';
}

pub fn headerValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const field = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(field, name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

pub fn headerContainsToken(
    head: []const u8,
    name: []const u8,
    token: []const u8,
) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const field = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(field, name)) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        var parts = std.mem.splitScalar(u8, value, ',');
        while (parts.next()) |part| {
            if (std.ascii.eqlIgnoreCase(
                std.mem.trim(u8, part, " \t"),
                token,
            )) return true;
        }
    }
    return false;
}

pub const accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Validates a `Sec-WebSocket-Key` and returns 16 decoded bytes.
pub fn decodeKey(key: []const u8) Error![16]u8 {
    if (key.len != 24) return error.HandshakeFailed;
    var decoded: [18]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(key) catch
        return error.HandshakeFailed;
    if (size != 16) return error.HandshakeFailed;
    std.base64.standard.Decoder.decode(decoded[0..size], key) catch
        return error.HandshakeFailed;
    return decoded[0..16].*;
}

/// Computes the expected `Sec-WebSocket-Accept` value for a key.
pub fn acceptValue(key: []const u8, out: *[28]u8) Error!void {
    var digest: [20]u8 = undefined;
    var hash = std.crypto.hash.Sha1.init(.{});
    hash.update(key);
    hash.update(accept_guid);
    hash.final(&digest);
    _ = std.base64.standard.Encoder.encode(out, &digest);
}

pub fn validAccept(key: []const u8, value: []const u8) bool {
    if (value.len != 28) return false;
    var expected: [28]u8 = undefined;
    acceptValue(key, &expected) catch return false;
    const actual: [28]u8 = value[0..28].*;
    return std.crypto.timing_safe.eql([28]u8, expected, actual);
}

test "accept vector from RFC 6455" {
    var value: [28]u8 = undefined;
    try acceptValue("dGhlIHNhbXBsZSBub25jZQ==", &value);
    try std.testing.expectEqualStrings(
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        &value,
    );
    try std.testing.expect(validAccept(
        "dGhlIHNhbXBsZSBub25jZQ==",
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
    ));
}

test "header lookup is case-insensitive" {
    const head =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive, Upgrade\r\n\r\n";
    try std.testing.expectEqualStrings("websocket", headerValue(head, "upgrade").?);
    try std.testing.expect(headerContainsToken(head, "connection", "upgrade"));
    try std.testing.expect(!headerContainsToken(head, "connection", "close"));
}

test "readHead preserves bytes after the terminator" {
    const input_bytes =
        "GET /ws HTTP/1.1\r\nHost: x\r\n\r\n" ++
        "\x82\x05hello";
    var input = std.Io.Reader.fixed(input_bytes);
    var head: Head = .{};
    try readHead(&input, &head);
    try std.testing.expectEqualStrings(
        "GET /ws HTTP/1.1\r\nHost: x\r\n\r\n",
        head.bytes(),
    );
    try std.testing.expectEqualStrings("\x82\x05hello", input.buffered());
}

test "strict head validation rejects obs-fold and whitespace before colon" {
    try std.testing.expectError(
        error.HandshakeFailed,
        validateHead("GET / HTTP/1.1\r\n Upgrade: websocket\r\n\r\n"),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        validateHead("GET / HTTP/1.1\r\nUpgrade : websocket\r\n\r\n"),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        validateHead("GET / HTTP/1.1\r\nX-Test: bad\x00value\r\n\r\n"),
    );
    try validateHead("GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n");
}

test "headerCount counts duplicate fields" {
    const head =
        "GET / HTTP/1.1\r\n" ++
        "Host: a\r\n" ++
        "Host: b\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n\r\n";
    try std.testing.expectEqual(@as(usize, 2), headerCount(head, "host"));
    try std.testing.expect(headerContainsToken(head, "connection", "upgrade"));
}
