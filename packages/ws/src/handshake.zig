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
    return headerValueAt(head, name, 0);
}

/// Returns the `index`-th occurrence of a header, in wire order.
pub fn headerValueAt(
    head: []const u8,
    name: []const u8,
    index: usize,
) ?[]const u8 {
    var seen: usize = 0;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const field = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(field, name)) continue;
        if (seen == index) {
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
        seen += 1;
    }
    return null;
}

pub fn isToken(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (!isTokenChar(byte)) return false;
    }
    return true;
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

pub const max_subprotocol = 64;
pub const max_subprotocols = 16;
pub const max_extension_values = 8;
pub const max_extension_params = 8;

pub const Extension = struct {
    name: []const u8,
    server_no_context_takeover: bool = false,
    client_no_context_takeover: bool = false,
    server_max_window_bits: ?u4 = null,
    client_max_window_bits: ?u4 = null,
    client_max_window_bits_present: bool = false,
};

/// Parses one `name; param; param=value` list element. The name is always
/// validated; RFC 7692 parameters are validated only for permessage-deflate.
pub fn parseExtension(text: []const u8, out: *Extension) Error!void {
    var parts = std.mem.splitScalar(u8, text, ';');
    const raw_name = parts.next() orelse return error.HandshakeFailed;
    const name = std.mem.trim(u8, raw_name, " \t");
    if (!isToken(name)) return error.HandshakeFailed;
    out.* = .{ .name = name };
    const deflate = std.mem.eql(u8, name, "permessage-deflate");

    var params: usize = 0;
    while (parts.next()) |raw| {
        params += 1;
        if (params > max_extension_params) return error.HandshakeFailed;
        const param = std.mem.trim(u8, raw, " \t");
        if (param.len == 0) return error.HandshakeFailed;
        const equals = std.mem.indexOfScalar(u8, param, '=');
        const param_name = std.mem.trim(
            u8,
            if (equals) |index| param[0..index] else param,
            " \t",
        );
        if (!isToken(param_name)) return error.HandshakeFailed;
        const value: ?[]const u8 = if (equals) |index|
            std.mem.trim(u8, param[index + 1 ..], " \t")
        else
            null;
        if (value) |text_value| {
            if (!isToken(text_value)) return error.HandshakeFailed;
        }
        if (!deflate) continue;
        try applyDeflateParameter(out, param_name, value);
    }
}

fn applyDeflateParameter(
    out: *Extension,
    name: []const u8,
    value: ?[]const u8,
) Error!void {
    if (std.mem.eql(u8, name, "server_no_context_takeover")) {
        if (value != null or out.server_no_context_takeover) {
            return error.HandshakeFailed;
        }
        out.server_no_context_takeover = true;
        return;
    }
    if (std.mem.eql(u8, name, "client_no_context_takeover")) {
        if (value != null or out.client_no_context_takeover) {
            return error.HandshakeFailed;
        }
        out.client_no_context_takeover = true;
        return;
    }
    if (std.mem.eql(u8, name, "server_max_window_bits")) {
        if (value == null or out.server_max_window_bits != null) {
            return error.HandshakeFailed;
        }
        out.server_max_window_bits = try parseWindowBits(value.?);
        return;
    }
    if (std.mem.eql(u8, name, "client_max_window_bits")) {
        if (out.client_max_window_bits_present) return error.HandshakeFailed;
        out.client_max_window_bits_present = true;
        if (value) |bits| out.client_max_window_bits = try parseWindowBits(bits);
        return;
    }
    return error.HandshakeFailed;
}

fn parseWindowBits(text: []const u8) Error!u4 {
    if (text.len == 0 or text.len > 2) return error.HandshakeFailed;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.HandshakeFailed;
    }
    const bits = std.fmt.parseInt(u4, text, 10) catch
        return error.HandshakeFailed;
    if (bits < 8 or bits > 15) return error.HandshakeFailed;
    return bits;
}

/// Collects every comma-separated extension token from all
/// `Sec-WebSocket-Extensions` headers, in wire order.
pub fn collectExtensions(
    head: []const u8,
    out: *[max_extension_values][]const u8,
) Error!usize {
    var count: usize = 0;
    var index: usize = 0;
    while (headerValueAt(head, "sec-websocket-extensions", index)) |value| {
        index += 1;
        var parts = std.mem.splitScalar(u8, value, ',');
        while (parts.next()) |raw| {
            const token = std.mem.trim(u8, raw, " \t");
            if (token.len == 0) return error.HandshakeFailed;
            if (count == out.len) return error.HandshakeFailed;
            out[count] = token;
            count += 1;
        }
    }
    return count;
}

/// Parses a comma-separated subprotocol offer into `out`.
pub fn parseProtocolList(
    value: []const u8,
    out: *[max_subprotocols][]const u8,
) Error!usize {
    var count: usize = 0;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw| {
        const protocol = std.mem.trim(u8, raw, " \t");
        if (!isToken(protocol) or protocol.len > max_subprotocol) {
            return error.HandshakeFailed;
        }
        if (count == out.len) return error.HandshakeFailed;
        out[count] = protocol;
        count += 1;
    }
    if (count == 0) return error.HandshakeFailed;
    return count;
}

/// Validates a single selected subprotocol token from a server response.
pub fn parseSelectedProtocol(value: []const u8) Error![]const u8 {
    const protocol = std.mem.trim(u8, value, " \t");
    if (!isToken(protocol) or protocol.len > max_subprotocol) {
        return error.HandshakeFailed;
    }
    return protocol;
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
    try std.testing.expectEqualStrings("a", headerValueAt(head, "host", 0).?);
    try std.testing.expectEqualStrings("b", headerValueAt(head, "host", 1).?);
    try std.testing.expect(headerValueAt(head, "host", 2) == null);
}

test "permessage-deflate parameters are parsed strictly" {
    var extension: Extension = undefined;
    try parseExtension(
        "permessage-deflate; client_max_window_bits; " ++
            "server_max_window_bits=12; client_no_context_takeover",
        &extension,
    );
    try std.testing.expectEqualStrings("permessage-deflate", extension.name);
    try std.testing.expect(extension.client_max_window_bits_present);
    try std.testing.expect(extension.client_max_window_bits == null);
    try std.testing.expectEqual(@as(?u4, 12), extension.server_max_window_bits);
    try std.testing.expect(extension.client_no_context_takeover);
    try std.testing.expect(!extension.server_no_context_takeover);

    try std.testing.expectError(
        error.HandshakeFailed,
        parseExtension("permessage-deflate; client_max_window_bits=7", &extension),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseExtension("permessage-deflate; client_max_window_bits=16", &extension),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseExtension(
            "permessage-deflate; server_no_context_takeover=1",
            &extension,
        ),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseExtension("permessage-deflate; unknown=1", &extension),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseExtension(
            "permessage-deflate; client_no_context_takeover; " ++
                "client_no_context_takeover",
            &extension,
        ),
    );
}

test "extension lists and subprotocols are bounded and validated" {
    const head =
        "GET / HTTP/1.1\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate, x-other\r\n" ++
        "Sec-WebSocket-Extensions: x-third\r\n\r\n";
    var values: [max_extension_values][]const u8 = undefined;
    const count = try collectExtensions(head, &values);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("x-other", values[1]);
    try std.testing.expectEqualStrings("x-third", values[2]);

    var protocols: [max_subprotocols][]const u8 = undefined;
    const protocol_count = try parseProtocolList("chat, superchat", &protocols);
    try std.testing.expectEqual(@as(usize, 2), protocol_count);
    try std.testing.expectEqualStrings("superchat", protocols[1]);
    try std.testing.expectError(
        error.HandshakeFailed,
        parseProtocolList("chat, bad protocol", &protocols),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseProtocolList("", &protocols),
    );
    try std.testing.expectEqualStrings(
        "chat",
        try parseSelectedProtocol(" chat "),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseSelectedProtocol("a, b"),
    );
}

test "arbitrary extension strings fail without panicking" {
    var input: [128]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x776562736f636b);
    const random = prng.random();
    var iteration: usize = 0;
    while (iteration < 512) : (iteration += 1) {
        const len = random.uintLessThan(usize, input.len);
        random.bytes(input[0..len]);
        var extension: Extension = undefined;
        _ = parseExtension(input[0..len], &extension) catch continue;
        var values: [max_extension_values][]const u8 = undefined;
        var head_buffer: [256]u8 = undefined;
        const head = std.fmt.bufPrint(
            &head_buffer,
            "GET / HTTP/1.1\r\nSec-WebSocket-Extensions: {s}\r\n\r\n",
            .{input[0..len]},
        ) catch continue;
        _ = collectExtensions(head, &values) catch continue;
        var protocols: [max_subprotocols][]const u8 = undefined;
        _ = parseProtocolList(input[0..len], &protocols) catch continue;
    }
}
