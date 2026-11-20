//! WebSocket client/server handshake and duplex byte connection.

const std = @import("std");
const handshake = @import("handshake.zig");
const frame = @import("frame.zig");

pub const Error = error{
    Canceled,
    Closed,
    HandshakeFailed,
    ProtocolViolation,
    Unexpected,
};

pub const max_message = 1024 * 1024;
pub const max_frames_per_read = 4096;
pub const max_controls_per_read = 1024;
pub const max_fragments_per_message = 1024;

pub const ClientOptions = struct {
    host: []const u8,
    path: []const u8 = "/",
};

pub const ServerOptions = struct {
    path: []const u8 = "/",
};

pub const Connection = struct {
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    role: frame.Role,
    write_lock: std.Io.Mutex = .init,
    pending_len: usize = 0,
    pending_offset: usize = 0,
    frame_payload: [frame.max_read_payload]u8 = undefined,
    mask_buffer: [frame.max_mask_scratch]u8 = undefined,
    in_message: bool = false,
    message_len: usize = 0,
    fragments: usize = 0,
    eof: bool = false,
    close_sent: bool = false,

    pub fn read(self: *Connection, buffers: [][]u8) Error!usize {
        if (totalCapacity(buffers) == 0) return error.Unexpected;
        if (self.pending_offset < self.pending_len) {
            return self.copyPending(buffers);
        }
        if (self.eof) return 0;

        var controls: usize = 0;
        var frames: usize = 0;
        while (true) {
            frames += 1;
            if (frames > max_frames_per_read) return error.ProtocolViolation;
            const parsed = frame.read(
                self.input,
                self.role,
                &self.frame_payload,
            ) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.EndOfStream => return error.ProtocolViolation,
                error.MessageTooBig => {
                    self.closeWithCode(1009);
                    return error.ProtocolViolation;
                },
                error.ProtocolViolation => return error.ProtocolViolation,
                error.Unexpected => return error.Unexpected,
            };
            switch (parsed.opcode) {
                frame.opcode_binary, frame.opcode_text => {
                    if (self.in_message) return error.ProtocolViolation;
                    if (parsed.payload.len > max_message) {
                        return error.ProtocolViolation;
                    }
                    self.message_len = parsed.payload.len;
                    self.fragments = 1;
                    self.in_message = !parsed.fin;
                    if (parsed.payload.len == 0) continue;
                    self.pending_len = parsed.payload.len;
                    self.pending_offset = 0;
                    return self.copyPending(buffers);
                },
                frame.opcode_continuation => {
                    if (!self.in_message) return error.ProtocolViolation;
                    self.message_len = std.math.add(
                        usize,
                        self.message_len,
                        parsed.payload.len,
                    ) catch return error.ProtocolViolation;
                    if (self.message_len > max_message) {
                        return error.ProtocolViolation;
                    }
                    self.fragments += 1;
                    if (self.fragments > max_fragments_per_message) {
                        return error.ProtocolViolation;
                    }
                    self.in_message = !parsed.fin;
                    if (parsed.payload.len == 0) continue;
                    self.pending_len = parsed.payload.len;
                    self.pending_offset = 0;
                    return self.copyPending(buffers);
                },
                frame.opcode_ping => {
                    controls += 1;
                    if (controls > max_controls_per_read) {
                        return error.ProtocolViolation;
                    }
                    try self.writeControl(frame.opcode_pong, parsed.payload);
                },
                frame.opcode_pong => {
                    controls += 1;
                    if (controls > max_controls_per_read) {
                        return error.ProtocolViolation;
                    }
                },
                frame.opcode_close => {
                    try self.receiveClose(parsed.payload);
                    return 0;
                },
                else => return error.ProtocolViolation,
            }
        }
    }

    pub fn write(self: *Connection, buffers: []const []const u8) Error!usize {
        self.write_lock.lock(self.io) catch return error.Canceled;
        defer self.write_lock.unlock(self.io);
        if (self.close_sent or self.eof) return error.Closed;

        var total: usize = 0;
        for (buffers) |buffer| {
            try self.writeMessageLocked(buffer);
            total += buffer.len;
        }
        self.output.flush() catch return error.Unexpected;
        return total;
    }

    pub fn end(self: *Connection) Error!void {
        const payload = [_]u8{ 0x03, 0xe8 };
        self.write_lock.lock(self.io) catch return error.Canceled;
        defer self.write_lock.unlock(self.io);
        if (self.close_sent) return;
        try self.writeFrameLocked(frame.opcode_close, true, &payload);
        self.close_sent = true;
        self.output.flush() catch return error.Unexpected;
    }

    pub fn deinit(self: *Connection) void {
        std.crypto.secureZero(u8, &self.frame_payload);
        std.crypto.secureZero(u8, &self.mask_buffer);
    }

    fn copyPending(self: *Connection, buffers: [][]u8) usize {
        const available = self.pending_len - self.pending_offset;
        var copied: usize = 0;
        for (buffers) |buffer| {
            if (copied == available) break;
            const count = @min(buffer.len, available - copied);
            @memcpy(
                buffer[0..count],
                self.frame_payload[self.pending_offset + copied ..][0..count],
            );
            copied += count;
        }
        self.pending_offset += copied;
        if (self.pending_offset == self.pending_len) {
            self.pending_len = 0;
            self.pending_offset = 0;
        }
        return copied;
    }

    fn writeMessageLocked(self: *Connection, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const chunk_len = @min(bytes.len - offset, frame.max_payload);
            const chunk = bytes[offset..][0..chunk_len];
            const fin = offset + chunk_len == bytes.len;
            const opcode = if (offset == 0)
                frame.opcode_binary
            else
                frame.opcode_continuation;
            try self.writeFrameLocked(opcode, fin, chunk);
            offset += chunk_len;
        }
    }

    fn writeControl(self: *Connection, opcode: u8, payload: []const u8) Error!void {
        self.write_lock.lock(self.io) catch return error.Canceled;
        defer self.write_lock.unlock(self.io);
        if (self.close_sent or self.eof) return;
        try self.writeFrameLocked(opcode, true, payload);
        self.output.flush() catch return error.Unexpected;
    }

    fn writeFrameLocked(
        self: *Connection,
        opcode: u8,
        fin: bool,
        payload: []const u8,
    ) Error!void {
        frame.write(
            self.io,
            self.output,
            self.role,
            opcode,
            fin,
            payload,
            &self.mask_buffer,
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.ProtocolViolation => return error.ProtocolViolation,
            else => return error.Unexpected,
        };
    }

    fn closeWithCode(self: *Connection, code: u16) void {
        self.write_lock.lock(self.io) catch return;
        defer self.write_lock.unlock(self.io);
        if (self.close_sent) return;
        var payload = [_]u8{
            @intCast(code >> 8),
            @intCast(code & 0xff),
        };
        self.writeFrameLocked(frame.opcode_close, true, &payload) catch return;
        self.close_sent = true;
        self.eof = true;
        self.output.flush() catch {};
    }

    fn receiveClose(self: *Connection, payload: []const u8) Error!void {
        if (payload.len == 1) {
            self.closeWithCode(1002);
            return error.ProtocolViolation;
        }
        var code: ?u16 = null;
        if (payload.len >= 2) {
            code = std.mem.readInt(u16, payload[0..2], .big);
        }
        var status: u16 = 1000;
        if (code) |value| {
            if (!validCloseCode(value)) status = 1002;
        }
        if (payload.len > 2 and
            !std.unicode.utf8ValidateSlice(payload[2..]))
        {
            status = 1007;
        }

        self.write_lock.lock(self.io) catch return error.Canceled;
        defer self.write_lock.unlock(self.io);
        if (!self.close_sent) {
            var status_payload = [_]u8{
                @intCast(status >> 8),
                @intCast(status & 0xff),
            };
            const response: []const u8 = if (status == 1000)
                if (payload.len >= 2) payload[0..2] else &.{}
            else
                &status_payload;
            try self.writeFrameLocked(frame.opcode_close, true, response);
            self.close_sent = true;
            self.output.flush() catch return error.Unexpected;
        }
        self.eof = true;
        if (status != 1000) return error.ProtocolViolation;
    }
};

pub fn clientHandshake(
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    connection: *Connection,
    options: ClientOptions,
) Error!void {
    if (!validHost(options.host) or !validPath(options.path)) {
        return error.HandshakeFailed;
    }
    connection.* = .{
        .io = io,
        .input = input,
        .output = output,
        .role = .client,
    };

    var key_bytes: [16]u8 = undefined;
    std.Io.randomSecure(io, &key_bytes) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.HandshakeFailed,
    };
    var key: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key, &key_bytes);

    var request_buffer: [handshake.max_handshake]u8 = undefined;
    var request = std.Io.Writer.fixed(&request_buffer);
    request.print(
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
        .{ options.path, options.host, key },
    ) catch return error.HandshakeFailed;
    output.writeAll(request.buffered()) catch return error.HandshakeFailed;
    output.flush() catch return error.HandshakeFailed;

    var head: handshake.Head = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&head));
    try handshake.readHead(input, &head);
    try handshake.validateHead(head.bytes());
    try validateClientResponse(head.bytes(), &key);
}

pub fn serverHandshake(
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    connection: *Connection,
    options: ServerOptions,
) Error!void {
    if (!validPath(options.path)) return error.HandshakeFailed;
    connection.* = .{
        .io = io,
        .input = input,
        .output = output,
        .role = .server,
    };

    var head: handshake.Head = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&head));
    try handshake.readHead(input, &head);
    try handshake.validateHead(head.bytes());
    const key = try validateServerRequest(head.bytes(), options.path);

    var accept: [28]u8 = undefined;
    handshake.acceptValue(key, &accept) catch return error.HandshakeFailed;
    var response_buffer: [256]u8 = undefined;
    var response = std.Io.Writer.fixed(&response_buffer);
    response.print(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    ) catch return error.HandshakeFailed;
    output.writeAll(response.buffered()) catch return error.HandshakeFailed;
    output.flush() catch return error.HandshakeFailed;
}

fn validateClientResponse(head: []const u8, key: *const [24]u8) Error!void {
    if (handshake.headerCount(head, "upgrade") != 1 or
        handshake.headerCount(head, "sec-websocket-accept") != 1 or
        handshake.headerCount(head, "content-length") != 0 or
        handshake.headerCount(head, "transfer-encoding") != 0)
    {
        return error.HandshakeFailed;
    }
    const first_line_end = std.mem.indexOf(u8, head, "\r\n") orelse
        return error.HandshakeFailed;
    const status = head[0..first_line_end];
    if (!std.mem.startsWith(u8, status, "HTTP/1.1 101") or
        status.len < 13 or status[12] != ' ')
    {
        return error.HandshakeFailed;
    }
    if (!handshake.headerContainsToken(head, "upgrade", "websocket")) {
        return error.HandshakeFailed;
    }
    if (!handshake.headerContainsToken(head, "connection", "upgrade")) {
        return error.HandshakeFailed;
    }
    const accept = handshake.headerValue(head, "sec-websocket-accept") orelse
        return error.HandshakeFailed;
    if (!handshake.validAccept(key, accept)) return error.HandshakeFailed;
}

fn validateServerRequest(head: []const u8, path: []const u8) Error![]const u8 {
    const first_line_end = std.mem.indexOf(u8, head, "\r\n") orelse
        return error.HandshakeFailed;
    var parts = std.mem.splitScalar(u8, head[0..first_line_end], ' ');
    const method = parts.next() orelse return error.HandshakeFailed;
    const request_path = parts.next() orelse return error.HandshakeFailed;
    const version = parts.next() orelse return error.HandshakeFailed;
    if (!std.mem.eql(u8, method, "GET")) return error.HandshakeFailed;
    if (!std.mem.eql(u8, request_path, path)) return error.HandshakeFailed;
    if (!std.mem.eql(u8, version, "HTTP/1.1")) return error.HandshakeFailed;
    if (parts.next() != null) return error.HandshakeFailed;
    const host = handshake.headerValue(head, "host") orelse
        return error.HandshakeFailed;
    if (host.len == 0) return error.HandshakeFailed;
    if (handshake.headerCount(head, "host") != 1 or
        handshake.headerCount(head, "upgrade") != 1 or
        handshake.headerCount(head, "sec-websocket-version") != 1 or
        handshake.headerCount(head, "sec-websocket-key") != 1 or
        handshake.headerCount(head, "content-length") != 0 or
        handshake.headerCount(head, "transfer-encoding") != 0)
    {
        return error.HandshakeFailed;
    }

    if (!handshake.headerContainsToken(head, "upgrade", "websocket")) {
        return error.HandshakeFailed;
    }
    if (!handshake.headerContainsToken(head, "connection", "upgrade")) {
        return error.HandshakeFailed;
    }
    const version_header = handshake.headerValue(
        head,
        "sec-websocket-version",
    ) orelse return error.HandshakeFailed;
    if (!std.mem.eql(u8, version_header, "13")) return error.HandshakeFailed;
    const key = handshake.headerValue(head, "sec-websocket-key") orelse
        return error.HandshakeFailed;
    _ = handshake.decodeKey(key) catch return error.HandshakeFailed;
    return key;
}

fn totalCapacity(buffers: [][]u8) usize {
    var total: usize = 0;
    for (buffers) |buffer| total += buffer.len;
    return total;
}

fn validCloseCode(code: u16) bool {
    if (code >= 3000 and code <= 4999) return true;
    return switch (code) {
        1000,
        1001,
        1002,
        1003,
        1007,
        1008,
        1009,
        1010,
        1011,
        1012,
        1013,
        1014,
        => true,
        else => false,
    };
}

fn validHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 255) return false;
    for (host) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn validPath(path: []const u8) bool {
    if (path.len == 0 or path.len > 255 or path[0] != '/') return false;
    for (path) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return false;
    }
    return true;
}

test "server rejects a mismatched path" {
    const request =
        "GET /other HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output_storage: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output_storage.deinit();
    var connection: Connection = undefined;
    try std.testing.expectError(
        error.HandshakeFailed,
        serverHandshake(
            std.testing.io,
            &input,
            &output_storage.writer,
            &connection,
            .{ .path = "/ws" },
        ),
    );
}

test "server accepts the RFC key and returns the accept value" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive, Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output_storage: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output_storage.deinit();
    var connection: Connection = undefined;
    try serverHandshake(
        std.testing.io,
        &input,
        &output_storage.writer,
        &connection,
        .{ .path = "/ws" },
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        output_storage.written(),
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
    ) != null);
}

const LoopContext = struct {
    listener: *std.Io.net.Server,
    error_code: ?anyerror = null,
};

fn loopServer(io: std.Io, context: *LoopContext) void {
    loopServerRun(io, context) catch |err| {
        context.error_code = err;
    };
}

fn loopServerRun(io: std.Io, context: *LoopContext) !void {
    const stream = try context.listener.accept(io);
    defer stream.close(io);
    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var input = stream.reader(io, &read_buffer);
    var output = stream.writer(io, &write_buffer);
    var connection: Connection = undefined;
    try serverHandshake(
        io,
        &input.interface,
        &output.interface,
        &connection,
        .{ .path = "/ws" },
    );
    var buffer: [64]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const len = try connection.read(&buffers);
    if (len == 0) return error.TestUnexpectedResult;
    _ = try connection.write(&.{buffer[0..len]});
    try connection.end();
}

test "loopback client/server echo" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var context: LoopContext = .{ .listener = &listener };
    var server_future = io.async(loopServer, .{ io, &context });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(
        listener.socket.address.getPort(),
    ) };
    const stream = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer stream.close(io);
    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var input = stream.reader(io, &read_buffer);
    var output = stream.writer(io, &write_buffer);
    var connection: Connection = undefined;
    try clientHandshake(
        io,
        &input.interface,
        &output.interface,
        &connection,
        .{ .host = "localhost", .path = "/ws" },
    );
    _ = try connection.write(&.{"hello"});
    var response: [5]u8 = undefined;
    var buffers = [_][]u8{&response};
    var offset: usize = 0;
    while (offset < response.len) {
        var slice = [_][]u8{buffers[0][offset..]};
        const len = try connection.read(&slice);
        if (len == 0) return error.EndOfStream;
        offset += len;
    }
    try std.testing.expectEqualStrings("hello", &response);
    try connection.end();
    _ = server_future.await(io);
    if (context.error_code) |err| return err;
}

test "end sends one close frame and blocks further data" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .client,
    };
    try connection.end();
    const close_len = storage.written().len;
    try connection.end();
    try std.testing.expectEqual(close_len, storage.written().len);
    try std.testing.expectError(
        error.Closed,
        connection.write(&.{"after-close"}),
    );
    try std.testing.expectEqual(close_len, storage.written().len);
}

test "a received close is echoed once and blocks further writes" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .server,
    };
    const close_payload = [_]u8{ 0x03, 0xe8 };
    try connection.receiveClose(&close_payload);
    const close_len = storage.written().len;
    try connection.end();
    try std.testing.expectEqual(close_len, storage.written().len);
    try std.testing.expectError(
        error.Closed,
        connection.write(&.{"after-close"}),
    );
}

test "invalid close codes are answered with 1002" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .server,
    };
    const payload = [_]u8{ 0x03, 0xed }; // 1005 is reserved
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.receiveClose(&payload),
    );
    const written = storage.written();
    try std.testing.expect(written.len >= 4);
    try std.testing.expectEqual(@as(u8, 0x03), written[2]);
    try std.testing.expectEqual(@as(u8, 0xea), written[3]);
}

test "invalid close reason is answered with 1007" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .server,
    };
    const payload = [_]u8{ 0x03, 0xe8, 0xff };
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.receiveClose(&payload),
    );
    const written = storage.written();
    try std.testing.expectEqual(@as(u8, 0x03), written[2]);
    try std.testing.expectEqual(@as(u8, 0xef), written[3]);
}

test "a fragmented message over 1 MiB is rejected" {
    const allocator = std.testing.allocator;
    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    var payload: [frame.max_payload]u8 = undefined;
    @memset(&payload, 'x');
    var scratch: [frame.max_mask_scratch]u8 = undefined;
    var remaining: usize = 17;
    while (remaining > 0) : (remaining -= 1) {
        const first = remaining == 17;
        const opcode = if (first) frame.opcode_binary else frame.opcode_continuation;
        const fin = remaining == 1;
        try frame.write(
            std.testing.io,
            &frames.writer,
            .client,
            opcode,
            fin,
            &payload,
            &scratch,
        );
    }

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
    };
    var buffer: [1024]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    while (true) {
        _ = connection.read(&buffers) catch |err| {
            try std.testing.expectEqual(error.ProtocolViolation, err);
            break;
        };
    }
}

test "zero-length read buffers are not clean EOF" {
    var input = std.Io.Reader.fixed(&.{});
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
    };
    try std.testing.expectError(
        error.Unexpected,
        connection.read(&.{}),
    );
}

test "writes over 64 KiB use continuation frames" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .client,
    };
    var payload: [100_000]u8 = undefined;
    @memset(&payload, 'x');
    _ = try connection.write(&.{&payload});

    var reader = std.Io.Reader.fixed(storage.written());
    var buffer: [frame.max_payload]u8 = undefined;
    const first = try frame.read(&reader, .server, &buffer);
    try std.testing.expectEqual(frame.opcode_binary, first.opcode);
    try std.testing.expect(!first.fin);
    try std.testing.expectEqual(@as(usize, frame.max_payload), first.payload.len);

    const second = try frame.read(&reader, .server, &buffer);
    try std.testing.expectEqual(frame.opcode_continuation, second.opcode);
    try std.testing.expect(second.fin);
    try std.testing.expectEqual(@as(usize, 100_000 - frame.max_payload), second.payload.len);
}

test "a standard-client sized single frame is delivered" {
    const payload_len = 100_000;
    var encoded: [payload_len + frame.header_max]u8 = undefined;
    encoded[0] = 0x82; // FIN | binary
    encoded[1] = 0x80 | 127;
    std.mem.writeInt(u64, encoded[2..10], payload_len, .big);
    const mask = [_]u8{ 1, 2, 3, 4 };
    @memcpy(encoded[10..14], &mask);
    for (0..payload_len) |index| {
        encoded[14 + index] = @as(u8, @intCast(index % 251)) ^ mask[index % 4];
    }

    var input = std.Io.Reader.fixed(&encoded);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
    };
    const buffer = try std.testing.allocator.alloc(u8, payload_len);
    defer std.testing.allocator.free(buffer);
    var buffers = [_][]u8{buffer};
    const read_len = try connection.read(&buffers);
    try std.testing.expectEqual(@as(usize, payload_len), read_len);
    for (buffer, 0..) |byte, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index % 251)), byte);
    }
}

test "empty frame floods are bounded per read" {
    const frame_count = max_frames_per_read + 1;
    // FIN|binary, MASK|0, then the mandatory four-byte mask key.
    const encoded = try std.testing.allocator.alloc(u8, frame_count * 6);
    defer std.testing.allocator.free(encoded);
    var index: usize = 0;
    while (index < frame_count) : (index += 1) {
        encoded[index * 6] = 0x82;
        encoded[index * 6 + 1] = 0x80;
        @memset(encoded[index * 6 + 2 ..][0..4], 0);
    }
    var input = std.Io.Reader.fixed(encoded);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
    };
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.read(&buffers),
    );
}
