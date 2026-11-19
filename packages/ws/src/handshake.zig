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
        const space = head.buffer.len - head.len;
        if (space == 0) return error.HandshakeFailed;
        const count = @min(space, available.len);
        @memcpy(head.buffer[head.len..][0..count], available[0..count]);
        input.toss(count);
        head.len += count;
        if (std.mem.indexOf(u8, head.bytes(), "\r\n\r\n") != null) return;
    }
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
    const value = headerValue(head, name) orelse return false;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (std.ascii.eqlIgnoreCase(
            std.mem.trim(u8, part, " \t"),
            token,
        )) return true;
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
