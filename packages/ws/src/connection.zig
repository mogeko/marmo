//! WebSocket client/server handshake and duplex byte connection.

const std = @import("std");
const handshake = @import("handshake.zig");
const frame = @import("frame.zig");
const deflate = @import("deflate.zig");

pub const Error = error{
    Canceled,
    Closed,
    HandshakeFailed,
    ProtocolViolation,
    Unexpected,
};

pub const max_message = 1024 * 1024;
/// Compressed input may exceed the plain limit by one eighth (fixed-Huffman
/// literals above 143 use nine bits) plus the sync-flush header.
pub const max_compressed_message = max_message + max_message / 8 + 64;
pub const max_frames_per_read = 4096;
pub const max_controls_per_read = 1024;
pub const max_fragments_per_message = 1024;
pub const max_subprotocol = handshake.max_subprotocol;

/// RFC 7692 extension preferences. The local side is the client in
/// `ClientOptions` and the server in `ServerOptions`.
pub const DeflateOptions = struct {
    enabled: bool = false,
    /// Disable context takeover for messages this endpoint sends.
    no_context_takeover: bool = false,
    /// Request that the peer disable context takeover for its messages.
    peer_no_context_takeover: bool = false,
    /// LZ77 window bits this endpoint's compressor may use (8..15).
    max_window_bits: u4 = 15,
    /// Window bits requested for the peer's compressor (8..15).
    peer_max_window_bits: u4 = 15,
};

pub const DeflateNegotiated = struct {
    enabled: bool = false,
    local_no_context_takeover: bool = false,
    peer_no_context_takeover: bool = false,
    local_max_window_bits: u4 = 15,
    peer_max_window_bits: u4 = 15,
};

pub const ClientOptions = struct {
    host: []const u8,
    path: []const u8 = "/",
    /// Offered subprotocols, in preference order.
    subprotocols: []const []const u8 = &.{},
    deflate: DeflateOptions = .{},
};

pub const ServerOptions = struct {
    path: []const u8 = "/",
    /// Accepted subprotocols, in server preference order. A non-empty list
    /// requires the client to offer at least one of them.
    subprotocols: []const []const u8 = &.{},
    deflate: DeflateOptions = .{},
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
    /// Accumulates a compressed message before it is inflated into
    /// `frame_payload`. Four bytes stay reserved for the RFC 7692 suffix.
    message_buffer: [max_compressed_message]u8 = undefined,
    write_scratch: [frame.max_payload]u8 = undefined,
    mask_buffer: [frame.max_mask_scratch]u8 = undefined,
    deflate_encoder: deflate.Encoder = .{},
    inflater: deflate.Inflater = .{},
    deflate: DeflateNegotiated = .{},
    subprotocol: [max_subprotocol]u8 = undefined,
    subprotocol_len: usize = 0,
    in_message: bool = false,
    message_is_text: bool = false,
    message_compressed: bool = false,
    message_len: usize = 0,
    compressed_len: usize = 0,
    fragments: usize = 0,
    utf8_pending: [4]u8 = undefined,
    utf8_pending_len: usize = 0,
    /// Written by the reader and read by the writer without the write lock.
    eof: std.atomic.Value(bool) = .init(false),
    close_sent: std.atomic.Value(bool) = .init(false),
    /// A close frame waiting for the write lock; a reader never blocks here.
    close_pending: std.atomic.Value(u16) = .init(0),
    /// Pongs queued when a data writer holds the lock. The writer drains this
    /// bounded ring at frame boundaries; readers never block on the write lock.
    pong_lock: std.Io.Mutex = .init,
    pong_queue: [8][frame.max_control_payload]u8 = undefined,
    pong_lens: [8]u8 = @splat(0),
    pong_head: usize = 0,
    pong_count: usize = 0,

    pub fn read(self: *Connection, buffers: [][]u8) Error!usize {
        if (totalCapacity(buffers) == 0) return error.Unexpected;
        if (self.pending_offset < self.pending_len) {
            return self.copyPending(buffers);
        }
        if (self.eof.load(.acquire)) return 0;

        var controls: usize = 0;
        var frames: usize = 0;
        while (true) {
            frames += 1;
            if (frames > max_frames_per_read) return self.failWith(1002);
            const parsed = frame.readFrame(
                self.input,
                self.role,
                &self.frame_payload,
                .{ .allow_rsv1 = self.deflate.enabled },
            ) catch |err| return self.mapFrameError(err);
            switch (parsed.opcode) {
                frame.opcode_text, frame.opcode_binary => {
                    if (self.in_message) return self.failWith(1002);
                    if (try self.beginMessage(parsed, buffers)) |len| return len;
                },
                frame.opcode_continuation => {
                    if (!self.in_message) return self.failWith(1002);
                    if (try self.continueMessage(parsed, buffers)) |len| return len;
                },
                frame.opcode_ping => {
                    controls += 1;
                    if (controls > max_controls_per_read) {
                        return self.failWith(1002);
                    }
                    self.sendPong(parsed.payload);
                },
                frame.opcode_pong => {
                    controls += 1;
                    if (controls > max_controls_per_read) {
                        return self.failWith(1002);
                    }
                },
                frame.opcode_close => {
                    try self.receiveClose(parsed.payload);
                    return 0;
                },
                else => return self.failWith(1002),
            }
        }
    }

    pub fn write(self: *Connection, buffers: []const []const u8) Error!usize {
        self.write_lock.lock(self.io) catch return error.Canceled;
        defer self.write_lock.unlock(self.io);
        if (self.close_sent.load(.acquire)) return error.Closed;
        try self.checkPendingCloseLocked();
        try self.drainPendingPongsLocked();
        if (self.eof.load(.acquire)) return error.Closed;

        var total: usize = 0;
        for (buffers) |buffer| {
            if (buffer.len == 0) continue;
            try self.writeMessageLocked(buffer);
            total += buffer.len;
        }
        self.output.flush() catch return error.Unexpected;
        try self.checkPendingCloseLocked();
        return total;
    }

    pub fn end(self: *Connection) Error!void {
        self.write_lock.lock(self.io) catch return error.Canceled;
        defer self.write_lock.unlock(self.io);
        if (self.close_sent.load(.acquire)) return;
        const pending = self.close_pending.swap(0, .acq_rel);
        try self.sendCloseLocked(if (pending != 0) pending else 1000);
    }

    /// Sends a Close frame with an application-defined status code. The
    /// connection stops accepting reads and writes afterwards.
    pub fn closeWithCode(self: *Connection, code: u16) Error!void {
        if (!validCloseCode(code)) return error.ProtocolViolation;
        self.write_lock.lock(self.io) catch return error.Canceled;
        defer self.write_lock.unlock(self.io);
        if (self.close_sent.load(.acquire)) return;
        try self.sendCloseLocked(code);
    }

    /// The subprotocol selected during the opening handshake, if any.
    pub fn selectedSubprotocol(self: *const Connection) ?[]const u8 {
        if (self.subprotocol_len == 0) return null;
        return self.subprotocol[0..self.subprotocol_len];
    }

    /// True when permessage-deflate was negotiated.
    pub fn compressionEnabled(self: *const Connection) bool {
        return self.deflate.enabled;
    }

    pub fn deinit(self: *Connection) void {
        std.crypto.secureZero(u8, &self.frame_payload);
        std.crypto.secureZero(u8, &self.message_buffer);
        std.crypto.secureZero(u8, &self.write_scratch);
        std.crypto.secureZero(u8, &self.mask_buffer);
        std.crypto.secureZero(u8, &self.deflate_encoder.history);
        std.crypto.secureZero(u32, &self.deflate_encoder.head);
        std.crypto.secureZero(u8, &self.inflater.window);
        std.crypto.secureZero(u8, &self.utf8_pending);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.pong_queue));
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

    fn beginMessage(
        self: *Connection,
        parsed: frame.Frame,
        buffers: [][]u8,
    ) Error!?usize {
        self.message_len = 0;
        self.compressed_len = 0;
        self.fragments = 1;
        self.in_message = !parsed.fin;
        self.message_is_text = parsed.opcode == frame.opcode_text;
        self.message_compressed = parsed.rsv1;
        self.utf8_pending_len = 0;

        if (self.message_compressed) {
            if (!self.deflate.enabled) return self.failWith(1002);
            if (self.deflate.peer_no_context_takeover) {
                self.inflater.resetContext();
            }
            if (!self.appendCompressed(parsed.payload)) {
                return self.failWith(1009);
            }
            if (!parsed.fin) return null;
            return self.finishCompressed(buffers);
        }
        if (!self.appendPlain(parsed.payload)) return self.failWith(1009);
        return self.deliverPlain(parsed.payload, parsed.fin, buffers);
    }

    fn continueMessage(
        self: *Connection,
        parsed: frame.Frame,
        buffers: [][]u8,
    ) Error!?usize {
        self.fragments += 1;
        if (self.fragments > max_fragments_per_message) {
            return self.failWith(1009);
        }
        self.in_message = !parsed.fin;
        if (self.message_compressed) {
            if (!self.appendCompressed(parsed.payload)) {
                return self.failWith(1009);
            }
            if (!parsed.fin) return null;
            return self.finishCompressed(buffers);
        }
        if (!self.appendPlain(parsed.payload)) return self.failWith(1009);
        return self.deliverPlain(parsed.payload, parsed.fin, buffers);
    }

    fn appendCompressed(self: *Connection, payload: []const u8) bool {
        const limit = max_compressed_message - 4;
        std.debug.assert(self.compressed_len <= limit);
        if (payload.len > limit - self.compressed_len) return false;
        @memcpy(self.message_buffer[self.compressed_len..][0..payload.len], payload);
        self.compressed_len += payload.len;
        return true;
    }

    fn appendPlain(self: *Connection, payload: []const u8) bool {
        self.message_len = std.math.add(
            usize,
            self.message_len,
            payload.len,
        ) catch return false;
        return self.message_len <= max_message;
    }

    fn finishCompressed(
        self: *Connection,
        buffers: [][]u8,
    ) Error!?usize {
        std.debug.assert(self.compressed_len <= max_compressed_message - 4);
        const length = self.inflater.decompress(
            &self.message_buffer,
            self.compressed_len,
            &self.frame_payload,
        ) catch |err| switch (err) {
            error.InvalidData => return self.failWith(1002),
            error.MessageTooBig => return self.failWith(1009),
        };
        if (self.message_is_text) {
            if (!self.validateUtf8(self.frame_payload[0..length], true)) {
                return self.failWith(1007);
            }
        }
        self.in_message = false;
        if (length == 0) return null;
        return @as(?usize, try self.deliver(
            self.frame_payload[0..length],
            buffers,
        ));
    }

    fn deliverPlain(
        self: *Connection,
        payload: []const u8,
        final: bool,
        buffers: [][]u8,
    ) Error!?usize {
        if (self.message_is_text) {
            if (!self.validateUtf8(payload, final)) {
                return self.failWith(1007);
            }
        }
        self.in_message = !final;
        if (payload.len == 0) return null;
        return @as(?usize, try self.deliver(payload, buffers));
    }

    fn deliver(
        self: *Connection,
        payload: []const u8,
        buffers: [][]u8,
    ) Error!usize {
        std.debug.assert(payload.len != 0);
        std.debug.assert(self.pending_len == 0);
        self.pending_len = payload.len;
        self.pending_offset = 0;
        return self.copyPending(buffers);
    }

    fn validateUtf8(self: *Connection, bytes: []const u8, final: bool) bool {
        std.debug.assert(self.utf8_pending_len < 4);
        var remaining = bytes;
        if (self.utf8_pending_len != 0) {
            const first = self.utf8_pending[0];
            const need = std.unicode.utf8ByteSequenceLength(first) catch
                return false;
            const missing = @as(usize, need) - self.utf8_pending_len;
            const take = @min(missing, remaining.len);
            @memcpy(
                self.utf8_pending[self.utf8_pending_len..][0..take],
                remaining[0..take],
            );
            self.utf8_pending_len += take;
            remaining = remaining[take..];
            if (self.utf8_pending_len < need) return !final;
            if (!std.unicode.utf8ValidateSlice(
                self.utf8_pending[0..need],
            )) return false;
            self.utf8_pending_len = 0;
        }

        const split = incompleteUtf8Tail(remaining) orelse remaining.len;
        if (!std.unicode.utf8ValidateSlice(remaining[0..split])) return false;
        const tail = remaining[split..];
        if (tail.len > 3) return false;
        @memcpy(self.utf8_pending[0..tail.len], tail);
        self.utf8_pending_len = tail.len;
        if (final and self.utf8_pending_len != 0) return false;
        return true;
    }

    fn writeMessageLocked(self: *Connection, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        if (self.deflate.enabled) {
            try self.checkPendingCloseLocked();
            if (self.deflate.local_no_context_takeover) {
                self.deflate_encoder.resetContext();
            }
            var sink: CompressedSink = .{ .connection = self };
            try self.deflate_encoder.encode(&sink, bytes);
            try sink.finish();
            return;
        }
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.checkPendingCloseLocked();
            try self.drainPendingPongsLocked();
            const chunk_len = @min(bytes.len - offset, frame.max_payload);
            const chunk = bytes[offset..][0..chunk_len];
            const fin = offset + chunk_len == bytes.len;
            const opcode = if (offset == 0)
                frame.opcode_binary
            else
                frame.opcode_continuation;
            try self.writeFrameLocked(opcode, fin, chunk, .{});
            offset += chunk_len;
        }
    }

    /// Answers a ping immediately when the write lock is free; otherwise
    /// queues the payload for the writer to drain at its next frame boundary.
    /// The queue is bounded, so a ping flood can still evict older pongs, but
    /// a normal long data write does not drop keepalives.
    fn sendPong(self: *Connection, payload: []const u8) void {
        if (payload.len > frame.max_control_payload) return;
        if (self.write_lock.tryLock()) {
            defer self.write_lock.unlock(self.io);
            if (self.close_sent.load(.acquire) or self.eof.load(.acquire)) return;
            self.writeFrameLocked(
                frame.opcode_pong,
                true,
                payload,
                .{},
            ) catch return;
            self.output.flush() catch return;
            return;
        }
        self.pong_lock.lock(self.io) catch return;
        defer self.pong_lock.unlock(self.io);
        if (self.eof.load(.acquire) or self.close_sent.load(.acquire)) return;
        if (self.pong_count == self.pong_queue.len) {
            self.pong_head = (self.pong_head + 1) % self.pong_queue.len;
            self.pong_count -= 1;
        }
        const index = (self.pong_head + self.pong_count) % self.pong_queue.len;
        @memcpy(self.pong_queue[index][0..payload.len], payload);
        self.pong_lens[index] = @intCast(payload.len);
        self.pong_count += 1;
    }

    fn drainPendingPongsLocked(self: *Connection) Error!void {
        if (self.eof.load(.acquire) or self.close_sent.load(.acquire)) return;
        while (true) {
            var payload: [frame.max_control_payload]u8 = undefined;
            var len: usize = 0;
            self.pong_lock.lock(self.io) catch return error.Canceled;
            {
                defer self.pong_lock.unlock(self.io);
                if (self.pong_count == 0) return;
                len = self.pong_lens[self.pong_head];
                @memcpy(payload[0..len], self.pong_queue[self.pong_head][0..len]);
                self.pong_head = (self.pong_head + 1) % self.pong_queue.len;
                self.pong_count -= 1;
            }
            try self.writeFrameLocked(
                frame.opcode_pong,
                true,
                payload[0..len],
                .{},
            );
        }
    }

    fn writeFrameLocked(
        self: *Connection,
        opcode: u8,
        fin: bool,
        payload: []const u8,
        options: frame.WriteOptions,
    ) Error!void {
        frame.writeFrame(
            self.io,
            self.output,
            self.role,
            opcode,
            fin,
            payload,
            &self.mask_buffer,
            options,
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.ProtocolViolation => return error.ProtocolViolation,
            error.EndOfStream, error.MessageTooBig => return error.Unexpected,
            error.Unexpected => return error.Unexpected,
        };
    }

    fn sendCloseLocked(self: *Connection, code: u16) Error!void {
        if (self.close_sent.load(.acquire)) return;
        var payload = [_]u8{
            @intCast(code >> 8),
            @intCast(code & 0xff),
        };
        try self.writeFrameLocked(
            frame.opcode_close,
            true,
            &payload,
            .{},
        );
        self.close_sent.store(true, .release);
        self.eof.store(true, .release);
        self.output.flush() catch return error.Unexpected;
    }

    /// Reports a protocol failure with the correct RFC 6455 close code. A
    /// concurrent writer may hold the lock; in that case the writer sends the
    /// queued close at its next frame boundary instead of blocking this read.
    fn failWith(self: *Connection, code: u16) Error {
        std.debug.assert(code >= 1000 and code <= 4999);
        self.eof.store(true, .release);
        self.close_pending.store(code, .release);
        self.trySendPendingClose();
        return error.ProtocolViolation;
    }

    fn trySendPendingClose(self: *Connection) void {
        var attempts: usize = 0;
        while (attempts < 8) : (attempts += 1) {
            if (!self.write_lock.tryLock()) {
                std.atomic.spinLoopHint();
                continue;
            }
            defer self.write_lock.unlock(self.io);
            const code = self.close_pending.swap(0, .acq_rel);
            if (code == 0 or self.close_sent.load(.acquire)) return;
            // A failed best-effort close means the transport is already gone.
            self.sendCloseLocked(code) catch return;
            return;
        }
    }

    fn checkPendingCloseLocked(self: *Connection) Error!void {
        const code = self.close_pending.swap(0, .acq_rel);
        if (code == 0) return;
        try self.sendCloseLocked(code);
        return error.Closed;
    }

    fn mapFrameError(self: *Connection, err: frame.Error) Error {
        return switch (err) {
            error.Canceled => error.Canceled,
            error.EndOfStream => blk: {
                self.eof.store(true, .release);
                break :blk error.ProtocolViolation;
            },
            error.MessageTooBig => self.failWith(1009),
            error.ProtocolViolation => self.failWith(1002),
            error.Unexpected => error.Unexpected,
        };
    }

    fn receiveClose(self: *Connection, payload: []const u8) Error!void {
        std.debug.assert(payload.len <= frame.max_control_payload);
        if (payload.len == 1) return self.failWith(1002);
        var status: u16 = 1000;
        var protocol_error = false;
        if (payload.len >= 2) {
            const code = std.mem.readInt(u16, payload[0..2], .big);
            if (validCloseCode(code)) {
                status = code;
            } else {
                status = 1002;
                protocol_error = true;
            }
        }
        if (payload.len > 2 and
            !std.unicode.utf8ValidateSlice(payload[2..]))
        {
            status = 1007;
            protocol_error = true;
        }

        self.eof.store(true, .release);
        self.in_message = false;
        if (self.close_sent.load(.acquire)) {
            if (protocol_error) return error.ProtocolViolation;
            return;
        }
        self.close_pending.store(status, .release);
        self.trySendPendingClose();
        if (protocol_error) return error.ProtocolViolation;
    }
};

const CompressedSink = struct {
    connection: *Connection,
    len: usize = 0,
    frames: usize = 0,

    pub fn writeByte(self: *CompressedSink, byte: u8) deflate.Error!void {
        if (self.len == self.connection.write_scratch.len) {
            try self.emit(false);
        }
        self.connection.write_scratch[self.len] = byte;
        self.len += 1;
    }

    fn emit(self: *CompressedSink, fin: bool) deflate.Error!void {
        self.connection.checkPendingCloseLocked() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => return error.Closed,
            error.ProtocolViolation => return error.ProtocolViolation,
            else => return error.Unexpected,
        };
        self.connection.drainPendingPongsLocked() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => return error.Closed,
            error.ProtocolViolation => return error.ProtocolViolation,
            else => return error.Unexpected,
        };
        const opcode = if (self.frames == 0)
            frame.opcode_binary
        else
            frame.opcode_continuation;
        self.connection.writeFrameLocked(
            opcode,
            fin,
            self.connection.write_scratch[0..self.len],
            .{ .rsv1 = self.frames == 0 },
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.ProtocolViolation => return error.ProtocolViolation,
            error.Closed => return error.Closed,
            else => return error.Unexpected,
        };
        self.frames += 1;
        self.len = 0;
    }

    fn finish(self: *CompressedSink) deflate.Error!void {
        try self.emit(true);
    }
};

fn incompleteUtf8Tail(bytes: []const u8) ?usize {
    if (bytes.len == 0) return null;
    const start = if (bytes.len > 3) bytes.len - 3 else 0;
    var index = start;
    while (index < bytes.len) : (index += 1) {
        const first = bytes[index];
        if (first < 0x80) continue;
        // An invalid lead byte is left for the slice validator to reject.
        const need = std.unicode.utf8ByteSequenceLength(first) catch continue;
        if (index + need > bytes.len) {
            for (bytes[index + 1 ..]) |byte| {
                if (byte & 0xC0 != 0x80) return null;
            }
            return index;
        }
    }
    return null;
}

pub fn clientHandshake(
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    connection: *Connection,
    options: ClientOptions,
) Error!void {
    if (!validHost(options.host) or !validPath(options.path) or
        !validNegotiation(options.subprotocols, options.deflate))
    {
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
            "Sec-WebSocket-Version: 13\r\n",
        .{ options.path, options.host, key },
    ) catch return error.HandshakeFailed;
    try writeProtocolOffer(&request, options.subprotocols);
    if (options.deflate.enabled) {
        var offer_buffer: [192]u8 = undefined;
        var offer = std.Io.Writer.fixed(&offer_buffer);
        try writeClientDeflateOffer(&offer, options.deflate);
        request.print(
            "Sec-WebSocket-Extensions: {s}\r\n",
            .{offer.buffered()},
        ) catch return error.HandshakeFailed;
    }
    request.writeAll("\r\n") catch return error.HandshakeFailed;
    output.writeAll(request.buffered()) catch return error.HandshakeFailed;
    output.flush() catch return error.HandshakeFailed;

    var head: handshake.Head = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&head));
    try handshake.readHead(input, &head);
    try handshake.validateHead(head.bytes());
    try validateClientResponse(head.bytes(), &key);
    try applyClientNegotiation(connection, head.bytes(), options);
}

pub fn serverHandshake(
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    connection: *Connection,
    options: ServerOptions,
) Error!void {
    if (!validPath(options.path) or
        !validNegotiation(options.subprotocols, options.deflate))
    {
        return error.HandshakeFailed;
    }
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
    const subprotocol = try selectSubprotocol(head.bytes(), options.subprotocols);
    if (subprotocol) |selected| {
        @memcpy(connection.subprotocol[0..selected.len], selected);
        connection.subprotocol_len = selected.len;
    }
    const accepted = try acceptDeflateOffer(head.bytes(), options.deflate);
    if (accepted) |negotiated| {
        connection.deflate = negotiated.negotiated;
        connection.inflater.ready = false;
        connection.deflate_encoder.setWindowBits(
            negotiated.negotiated.local_max_window_bits,
        );
    }

    var accept: [28]u8 = undefined;
    handshake.acceptValue(key, &accept) catch return error.HandshakeFailed;
    var response_buffer: [512]u8 = undefined;
    var response = std.Io.Writer.fixed(&response_buffer);
    response.print(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n",
        .{accept},
    ) catch return error.HandshakeFailed;
    if (subprotocol) |selected| {
        response.print(
            "Sec-WebSocket-Protocol: {s}\r\n",
            .{selected},
        ) catch return error.HandshakeFailed;
    }
    if (accepted) |negotiated| {
        try writeServerDeflateResponse(&response, negotiated);
    }
    response.writeAll("\r\n") catch return error.HandshakeFailed;
    output.writeAll(response.buffered()) catch return error.HandshakeFailed;
    output.flush() catch return error.HandshakeFailed;
}

fn validNegotiation(
    subprotocols: []const []const u8,
    options: DeflateOptions,
) bool {
    if (subprotocols.len > handshake.max_subprotocols) return false;
    for (subprotocols) |protocol| {
        if (!handshake.isToken(protocol) or
            protocol.len > handshake.max_subprotocol)
        {
            return false;
        }
    }
    if (!options.enabled) return true;
    return options.max_window_bits >= 8 and
        options.max_window_bits <= 15 and
        options.peer_max_window_bits >= 8 and
        options.peer_max_window_bits <= 15;
}

fn writeProtocolOffer(
    writer: *std.Io.Writer,
    subprotocols: []const []const u8,
) Error!void {
    if (subprotocols.len == 0) return;
    writer.writeAll("Sec-WebSocket-Protocol: ") catch
        return error.HandshakeFailed;
    for (subprotocols, 0..) |protocol, index| {
        if (index != 0) {
            writer.writeAll(", ") catch return error.HandshakeFailed;
        }
        writer.writeAll(protocol) catch return error.HandshakeFailed;
    }
    writer.writeAll("\r\n") catch return error.HandshakeFailed;
}

fn writeClientDeflateOffer(
    writer: *std.Io.Writer,
    options: DeflateOptions,
) Error!void {
    writer.writeAll("permessage-deflate") catch return error.HandshakeFailed;
    if (options.peer_no_context_takeover) {
        writer.writeAll("; server_no_context_takeover") catch
            return error.HandshakeFailed;
    }
    if (options.no_context_takeover) {
        writer.writeAll("; client_no_context_takeover") catch
            return error.HandshakeFailed;
    }
    if (options.peer_max_window_bits < 15) {
        writer.print(
            "; server_max_window_bits={d}",
            .{options.peer_max_window_bits},
        ) catch return error.HandshakeFailed;
    }
    if (options.max_window_bits < 15) {
        writer.print(
            "; client_max_window_bits={d}",
            .{options.max_window_bits},
        ) catch return error.HandshakeFailed;
    } else {
        writer.writeAll("; client_max_window_bits") catch
            return error.HandshakeFailed;
    }
}

fn selectSubprotocol(
    head: []const u8,
    subprotocols: []const []const u8,
) Error!?[]const u8 {
    const count = handshake.headerCount(head, "sec-websocket-protocol");
    if (count > 1) return error.HandshakeFailed;
    const value = handshake.headerValue(head, "sec-websocket-protocol");
    if (subprotocols.len == 0) return null;
    const offer = value orelse return error.HandshakeFailed;
    var offered: [handshake.max_subprotocols][]const u8 = undefined;
    const offered_count = try handshake.parseProtocolList(offer, &offered);
    for (subprotocols) |server_protocol| {
        for (offered[0..offered_count]) |client_protocol| {
            if (std.mem.eql(u8, server_protocol, client_protocol)) {
                return server_protocol;
            }
        }
    }
    return error.HandshakeFailed;
}

fn applyClientNegotiation(
    connection: *Connection,
    head: []const u8,
    options: ClientOptions,
) Error!void {
    const protocol_count = handshake.headerCount(
        head,
        "sec-websocket-protocol",
    );
    if (protocol_count > 1) return error.HandshakeFailed;
    if (handshake.headerValue(head, "sec-websocket-protocol")) |value| {
        if (options.subprotocols.len == 0) return error.HandshakeFailed;
        const selected = try handshake.parseSelectedProtocol(value);
        var requested = false;
        for (options.subprotocols) |protocol| {
            if (std.mem.eql(u8, protocol, selected)) requested = true;
        }
        if (!requested) return error.HandshakeFailed;
        @memcpy(connection.subprotocol[0..selected.len], selected);
        connection.subprotocol_len = selected.len;
    }

    connection.deflate = try validateDeflateResponse(head, options.deflate);
    if (connection.deflate.enabled) {
        connection.deflate_encoder.setWindowBits(
            connection.deflate.local_max_window_bits,
        );
        connection.inflater.ready = false;
    }
}

const ServerDeflate = struct {
    negotiated: DeflateNegotiated,
    echo_server_bits: ?u4 = null,
    echo_client_bits: ?u4 = null,
};

fn acceptDeflateOffer(
    head: []const u8,
    options: DeflateOptions,
) Error!?ServerDeflate {
    var values: [handshake.max_extension_values][]const u8 = undefined;
    // RFC 6455 section 9.1: a malformed extension header fails the opening
    // handshake even when the server does not enable that extension.
    const count = try handshake.collectExtensions(head, &values);
    for (values[0..count]) |value| {
        var extension: handshake.Extension = undefined;
        try handshake.parseExtension(value, &extension);
        if (!options.enabled) continue;
        if (!std.mem.eql(
            u8,
            extension.name,
            "permessage-deflate",
        )) continue;

        var local_bits = options.max_window_bits;
        var echo_server_bits: ?u4 = null;
        if (extension.server_max_window_bits) |offered| {
            local_bits = @min(local_bits, offered);
            echo_server_bits = local_bits;
        }
        var peer_bits: u4 = 15;
        var echo_client_bits: ?u4 = null;
        if (extension.client_max_window_bits) |offered| {
            peer_bits = offered;
        }
        if (extension.client_max_window_bits_present and
            options.peer_max_window_bits < 15)
        {
            peer_bits = @min(peer_bits, options.peer_max_window_bits);
            echo_client_bits = peer_bits;
        }
        return .{
            .negotiated = .{
                .enabled = true,
                .local_no_context_takeover = options.no_context_takeover or
                    extension.server_no_context_takeover,
                .peer_no_context_takeover = options.peer_no_context_takeover or
                    extension.client_no_context_takeover,
                .local_max_window_bits = local_bits,
                .peer_max_window_bits = peer_bits,
            },
            .echo_server_bits = echo_server_bits,
            .echo_client_bits = echo_client_bits,
        };
    }
    return null;
}

fn validateDeflateResponse(
    head: []const u8,
    options: DeflateOptions,
) Error!DeflateNegotiated {
    var values: [handshake.max_extension_values][]const u8 = undefined;
    const count = handshake.collectExtensions(head, &values) catch
        return error.HandshakeFailed;
    if (!options.enabled) {
        if (count != 0) return error.HandshakeFailed;
        return .{};
    }
    if (count == 0) return .{};
    if (count != 1) return error.HandshakeFailed;
    var extension: handshake.Extension = undefined;
    try handshake.parseExtension(values[0], &extension);
    if (!std.mem.eql(
        u8,
        extension.name,
        "permessage-deflate",
    )) return error.HandshakeFailed;

    var peer_bits: u4 = 15;
    if (extension.server_max_window_bits) |offered| {
        if (options.peer_max_window_bits < 15 and
            offered > options.peer_max_window_bits)
        {
            return error.HandshakeFailed;
        }
        peer_bits = offered;
    } else if (options.peer_max_window_bits < 15) {
        return error.HandshakeFailed;
    }

    var local_bits = options.max_window_bits;
    if (extension.client_max_window_bits_present) {
        const value = extension.client_max_window_bits orelse
            return error.HandshakeFailed;
        if (value > options.max_window_bits) return error.HandshakeFailed;
        local_bits = value;
    }
    if (options.peer_no_context_takeover and
        !extension.server_no_context_takeover)
    {
        return error.HandshakeFailed;
    }
    return .{
        .enabled = true,
        .local_no_context_takeover = options.no_context_takeover or
            extension.client_no_context_takeover,
        .peer_no_context_takeover = extension.server_no_context_takeover,
        .local_max_window_bits = local_bits,
        .peer_max_window_bits = peer_bits,
    };
}

fn writeServerDeflateResponse(
    writer: *std.Io.Writer,
    accepted: ServerDeflate,
) Error!void {
    writer.writeAll("Sec-WebSocket-Extensions: permessage-deflate") catch
        return error.HandshakeFailed;
    if (accepted.negotiated.local_no_context_takeover) {
        writer.writeAll("; server_no_context_takeover") catch
            return error.HandshakeFailed;
    }
    if (accepted.negotiated.peer_no_context_takeover) {
        writer.writeAll("; client_no_context_takeover") catch
            return error.HandshakeFailed;
    }
    if (accepted.echo_server_bits) |bits| {
        writer.print("; server_max_window_bits={d}", .{bits}) catch
            return error.HandshakeFailed;
    }
    if (accepted.echo_client_bits) |bits| {
        writer.print("; client_max_window_bits={d}", .{bits}) catch
            return error.HandshakeFailed;
    }
    writer.writeAll("\r\n") catch return error.HandshakeFailed;
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
    const frame_count = 4096 + 1;
    // FIN|binary, MASK|0, then the mandatory four-byte mask key. A valid data
    // frame follows the flood: without the bound, read would return its byte
    // instead of ProtocolViolation, so the test detects a removed bound.
    const encoded = try std.testing.allocator.alloc(u8, frame_count * 6 + 7);
    defer std.testing.allocator.free(encoded);
    var index: usize = 0;
    while (index < frame_count) : (index += 1) {
        encoded[index * 6] = 0x82;
        encoded[index * 6 + 1] = 0x80;
        @memset(encoded[index * 6 + 2 ..][0..4], 0);
    }
    const tail = frame_count * 6;
    encoded[tail] = 0x82;
    encoded[tail + 1] = 0x81;
    @memset(encoded[tail + 2 ..][0..4], 0);
    encoded[tail + 6] = 'x';
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

test "a fragmented message over 1 MiB sends close 1009" {
    const chunk = 64 * 1024;
    const frame_count = 17; // 17 * 64 KiB > 1 MiB
    const encoded_len = frame_count * (14 + chunk);
    const encoded = try std.testing.allocator.alloc(u8, encoded_len);
    defer std.testing.allocator.free(encoded);
    var offset: usize = 0;
    for (0..frame_count) |index| {
        encoded[offset] = if (index == 0) 0x02 else 0x00; // binary, no FIN
        encoded[offset + 1] = 0x80 | 127;
        std.mem.writeInt(u64, encoded[offset + 2 ..][0..8], chunk, .big);
        @memset(encoded[offset + 10 ..][0..4], 0);
        @memset(encoded[offset + 14 ..][0..chunk], 'x');
        offset += 14 + chunk;
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
    var buffer: [16 * 1024]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    while (true) {
        _ = connection.read(&buffers) catch |err| {
            try std.testing.expectEqual(error.ProtocolViolation, err);
            break;
        };
    }
    try std.testing.expect(connection.close_sent.load(.acquire));
    const written = output.written();
    try std.testing.expect(written.len >= 4);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x88, 0x02, 0x03, 0xf1 },
        written[written.len - 4 ..],
    );
}

const TestSink = struct {
    storage: *std.Io.Writer.Allocating,

    pub fn writeByte(self: *TestSink, byte: u8) deflate.Error!void {
        self.storage.writer.writeByte(byte) catch return error.Unexpected;
    }
};

fn appendFrame(
    storage: *std.Io.Writer.Allocating,
    opcode: u8,
    fin: bool,
    rsv1: bool,
    payload: []const u8,
) !void {
    var scratch: [4096]u8 = undefined;
    try frame.writeFrame(
        std.testing.io,
        &storage.writer,
        .client,
        opcode,
        fin,
        payload,
        &scratch,
        .{ .rsv1 = rsv1 },
    );
}

fn appendEncoded(
    frames: *std.Io.Writer.Allocating,
    encoder: *deflate.Encoder,
    message: []const u8,
    opcode: u8,
) !void {
    var compressed: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer compressed.deinit();
    var sink: TestSink = .{ .storage = &compressed };
    try encoder.encode(&sink, message);

    const bytes = compressed.written();
    var offset: usize = 0;
    while (offset < bytes.len) {
        const chunk_len = @min(bytes.len - offset, frame.max_payload);
        const chunk = bytes[offset..][0..chunk_len];
        const first = offset == 0;
        try appendFrame(
            frames,
            if (first) opcode else frame.opcode_continuation,
            offset + chunk_len == bytes.len,
            first,
            chunk,
        );
        offset += chunk_len;
    }
}

fn expectLastClose(output: []const u8, code: u16) !void {
    var expected = [_]u8{ 0x88, 0x02, 0, 0 };
    std.mem.writeInt(u16, expected[2..4], code, .big);
    try std.testing.expect(output.len >= 4);
    try std.testing.expectEqualSlices(
        u8,
        &expected,
        output[output.len - 4 ..],
    );
}

test "server negotiates subprotocol and permessage-deflate" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: other, chat\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; " ++
        "client_max_window_bits\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try serverHandshake(
        std.testing.io,
        &input,
        &output.writer,
        &connection,
        .{
            .path = "/ws",
            .subprotocols = &.{ "superchat", "chat" },
            .deflate = .{ .enabled = true },
        },
    );
    try std.testing.expectEqualStrings(
        "chat",
        connection.selectedSubprotocol().?,
    );
    try std.testing.expect(connection.compressionEnabled());
    try std.testing.expect(connection.deflate.enabled);
    try std.testing.expect(!connection.deflate.local_no_context_takeover);
    const written = output.written();
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "Sec-WebSocket-Protocol: chat\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "Sec-WebSocket-Extensions: permessage-deflate\r\n",
    ) != null);
}

test "server rejects a request with no acceptable subprotocol" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: other\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try std.testing.expectError(
        error.HandshakeFailed,
        serverHandshake(
            std.testing.io,
            &input,
            &output.writer,
            &connection,
            .{ .path = "/ws", .subprotocols = &.{"chat"} },
        ),
    );
}

test "client rejects unrequested protocols and extensions" {
    const head =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Protocol: chat\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; " ++
        "server_no_context_takeover; client_max_window_bits=12\r\n\r\n";
    var connection: Connection = .{
        .io = std.testing.io,
        .input = undefined,
        .output = undefined,
        .role = .client,
    };
    var options: ClientOptions = .{
        .host = "localhost",
        .subprotocols = &.{"chat"},
        .deflate = .{ .enabled = true },
    };
    try applyClientNegotiation(&connection, head, options);
    try std.testing.expectEqualStrings("chat", connection.selectedSubprotocol().?);
    try std.testing.expect(connection.deflate.enabled);
    try std.testing.expect(connection.deflate.peer_no_context_takeover);
    try std.testing.expectEqual(@as(u4, 12), connection.deflate.local_max_window_bits);

    options.subprotocols = &.{};
    try std.testing.expectError(
        error.HandshakeFailed,
        applyClientNegotiation(&connection, head, options),
    );
    options.subprotocols = &.{"superchat"};
    try std.testing.expectError(
        error.HandshakeFailed,
        applyClientNegotiation(&connection, head, options),
    );
    options.subprotocols = &.{"chat"};
    options.deflate.enabled = false;
    try std.testing.expectError(
        error.HandshakeFailed,
        applyClientNegotiation(&connection, head, options),
    );
}

test "client rejects invalid deflate responses" {
    const cases = [_][]const u8{
        "permessage-deflate; unknown=1",
        "x-unknown-extension",
        "permessage-deflate; server_max_window_bits=14",
        "permessage-deflate; client_max_window_bits",
    };
    for (cases) |extension| {
        var head_buffer: [256]u8 = undefined;
        const head = try std.fmt.bufPrint(
            &head_buffer,
            "HTTP/1.1 101\r\nSec-WebSocket-Extensions: {s}\r\n\r\n",
            .{extension},
        );
        try std.testing.expectError(
            error.HandshakeFailed,
            validateDeflateResponse(
                head,
                .{ .enabled = true, .peer_max_window_bits = 12 },
            ),
        );
    }
}

test "compressed messages round-trip with context takeover" {
    const allocator = std.testing.allocator;
    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    var encoder = deflate.Encoder.init();
    const first = "the quick brown fox jumps over the lazy dog";
    const second = "the quick brown fox jumps over the lazy dog again";
    try appendEncoded(&frames, &encoder, first, frame.opcode_binary);
    try appendEncoded(&frames, &encoder, second, frame.opcode_binary);
    try appendFrame(&frames, frame.opcode_close, true, false, &.{ 0x03, 0xe8 });

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
        .deflate = .{ .enabled = true },
    };
    var buffer: [256]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const first_len = try connection.read(&buffers);
    try std.testing.expectEqualStrings(first, buffer[0..first_len]);
    const second_len = try connection.read(&buffers);
    try std.testing.expectEqualStrings(second, buffer[0..second_len]);
    try std.testing.expectEqual(@as(usize, 0), try connection.read(&buffers));
}

test "compressed expansion over the message limit sends close 1009" {
    const allocator = std.testing.allocator;
    const message = try allocator.alloc(u8, max_message + 1);
    defer allocator.free(message);
    @memset(message, 'a');

    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    var encoder = deflate.Encoder.init();
    try appendEncoded(&frames, &encoder, message, frame.opcode_binary);

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
        .deflate = .{ .enabled = true },
    };
    var buffer: [1024]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.read(&buffers),
    );
    try std.testing.expect(connection.close_sent.load(.acquire));
    try expectLastClose(output.written(), 1009);
}

test "text messages validate UTF-8 across fragments" {
    const allocator = std.testing.allocator;
    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    try appendFrame(&frames, frame.opcode_text, false, false, "\xe2\x82");
    try appendFrame(&frames, frame.opcode_continuation, true, false, "\xac");
    try appendFrame(&frames, frame.opcode_text, false, false, "\xe2\x82");
    try appendFrame(&frames, frame.opcode_continuation, true, false, "\x28");

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
    };
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const first_len = try connection.read(&buffers);
    try std.testing.expectEqualSlices(u8, "\xe2\x82", buffer[0..first_len]);
    const second_len = try connection.read(&buffers);
    try std.testing.expectEqual(@as(u8, 0xac), buffer[second_len - 1]);
    _ = try connection.read(&buffers);
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.read(&buffers),
    );
    try expectLastClose(output.written(), 1007);
}

test "RSV1 without negotiation sends close 1002" {
    const allocator = std.testing.allocator;
    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    try appendFrame(&frames, frame.opcode_binary, true, true, "x");

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
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
    try expectLastClose(output.written(), 1002);
}

test "control frames are never compressed" {
    const allocator = std.testing.allocator;
    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    try appendFrame(&frames, frame.opcode_ping, true, false, "hi");

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
        .deflate = .{ .enabled = true },
    };
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.read(&buffers),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x8a, 0x02, 'h', 'i' },
        output.written()[0..4],
    );
}

test "closeWithCode sends 1008 and blocks later data" {
    const allocator = std.testing.allocator;
    var input = std.Io.Reader.fixed(&.{});
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
    };
    try connection.closeWithCode(1008);
    try expectLastClose(output.written(), 1008);
    const length = output.written().len;
    try std.testing.expectError(
        error.Closed,
        connection.write(&.{"after-close"}),
    );
    try connection.end();
    try std.testing.expectEqual(length, output.written().len);
}

test "a blocked writer receives the queued close instead of blocking reads" {
    const allocator = std.testing.allocator;
    var bytes = [_]u8{ 0x82, 0x00 };
    var input = std.Io.Reader.fixed(&bytes);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
    };
    connection.write_lock.lock(std.testing.io) catch return error.TestUnexpectedResult;
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.read(&buffers),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
    connection.write_lock.unlock(std.testing.io);
    try std.testing.expectError(
        error.Closed,
        connection.write(&.{}),
    );
    try expectLastClose(output.written(), 1002);
    try std.testing.expectEqual(
        @as(usize, 4),
        output.written().len,
    );
}

const DeflateLoopContext = struct {
    listener: *std.Io.net.Server,
    messages: []const []const u8,
    error_code: ?anyerror = null,
};

fn deflateLoopServer(io: std.Io, context: *DeflateLoopContext) void {
    deflateLoopServerRun(io, context) catch |err| {
        context.error_code = err;
    };
}

fn deflateLoopServerRun(
    io: std.Io,
    context: *DeflateLoopContext,
) !void {
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
        .{
            .path = "/ws",
            .subprotocols = &.{"chat"},
            .deflate = .{ .enabled = true },
        },
    );
    if (!connection.compressionEnabled()) return error.TestUnexpectedResult;
    const selected = connection.selectedSubprotocol() orelse
        return error.TestUnexpectedResult;
    if (!std.mem.eql(u8, selected, "chat")) return error.TestUnexpectedResult;

    var buffer: [128 * 1024]u8 = undefined;
    for (context.messages) |expected| {
        var total: usize = 0;
        while (total < expected.len) {
            var slice = [_][]u8{buffer[total..]};
            const len = try connection.read(&slice);
            if (len == 0) return error.EndOfStream;
            total += len;
        }
        if (!std.mem.eql(u8, buffer[0..total], expected)) {
            return error.TestUnexpectedResult;
        }
        _ = try connection.write(&.{buffer[0..total]});
    }
    try connection.end();
}

test "loopback compressed messages negotiate a subprotocol" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const large = try std.testing.allocator.alloc(u8, 100_000);
    defer std.testing.allocator.free(large);
    for (large, 0..) |*byte, index| byte.* = @intCast(index % 251);
    const messages = [_][]const u8{ large, "small message" };

    var context: DeflateLoopContext = .{
        .listener = &listener,
        .messages = &messages,
    };
    var server_future = io.async(deflateLoopServer, .{ io, &context });

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
        .{
            .host = "localhost",
            .path = "/ws",
            .subprotocols = &.{ "other", "chat" },
            .deflate = .{ .enabled = true },
        },
    );
    try std.testing.expect(connection.compressionEnabled());
    try std.testing.expectEqualStrings(
        "chat",
        connection.selectedSubprotocol().?,
    );

    for (messages) |message| {
        _ = try connection.write(&.{message});
        var response: [128 * 1024]u8 = undefined;
        var total: usize = 0;
        while (total < message.len) {
            var slice = [_][]u8{response[total..]};
            const len = try connection.read(&slice);
            if (len == 0) return error.EndOfStream;
            total += len;
        }
        try std.testing.expectEqualSlices(u8, message, response[0..total]);
    }
    try connection.end();
    _ = server_future.await(io);
    if (context.error_code) |err| return err;
}

test "fragmented compressed messages interleave control frames" {
    const allocator = std.testing.allocator;
    const message = try allocator.alloc(u8, 100_000);
    defer allocator.free(message);
    var state: u32 = 1;
    for (message) |*byte| {
        state = state *% 1_664_525 +% 1_013_904_223;
        byte.* = @truncate(state >> 24);
    }

    var compressed: std.Io.Writer.Allocating = .init(allocator);
    defer compressed.deinit();
    var encoder = deflate.Encoder.init();
    var sink: TestSink = .{ .storage = &compressed };
    try encoder.encode(&sink, message);
    const bytes = compressed.written();
    try std.testing.expect(bytes.len > frame.max_payload);

    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    const first_len = frame.max_payload;
    try appendFrame(
        &frames,
        frame.opcode_binary,
        bytes.len == first_len,
        true,
        bytes[0..first_len],
    );
    try appendFrame(&frames, frame.opcode_ping, true, false, "p");
    var offset: usize = first_len;
    while (offset < bytes.len) {
        const chunk_len = @min(bytes.len - offset, frame.max_payload);
        try appendFrame(
            &frames,
            frame.opcode_continuation,
            offset + chunk_len == bytes.len,
            false,
            bytes[offset..][0..chunk_len],
        );
        offset += chunk_len;
    }
    try appendFrame(&frames, frame.opcode_close, true, false, &.{ 0x03, 0xe8 });

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
        .deflate = .{ .enabled = true },
    };
    var buffer: [4096]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    var total: usize = 0;
    while (total < message.len) {
        const len = try connection.read(&buffers);
        if (len == 0) return error.EndOfStream;
        try std.testing.expectEqualSlices(
            u8,
            message[total..][0..len],
            buffer[0..len],
        );
        total += len;
    }
    try std.testing.expectEqual(message.len, total);
    try std.testing.expectEqual(@as(usize, 0), try connection.read(&buffers));
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x8a, 0x01, 'p' },
        output.written()[0..3],
    );
}

test "no context takeover resets both compressor and inflater" {
    const allocator = std.testing.allocator;
    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    var encoder = deflate.Encoder.init();
    const messages = [_][]const u8{
        "repeat me repeat me repeat me",
        "repeat me repeat me repeat me",
    };
    for (messages) |message| {
        encoder.resetContext();
        try appendEncoded(&frames, &encoder, message, frame.opcode_text);
    }
    try appendFrame(&frames, frame.opcode_close, true, false, &.{ 0x03, 0xe8 });

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
        .deflate = .{ .enabled = true, .peer_no_context_takeover = true },
    };
    var buffer: [64]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    for (messages) |message| {
        const len = try connection.read(&buffers);
        try std.testing.expectEqualStrings(message, buffer[0..len]);
    }
    try std.testing.expectEqual(@as(usize, 0), try connection.read(&buffers));
}

test "server declines compression when disabled" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try serverHandshake(
        std.testing.io,
        &input,
        &output.writer,
        &connection,
        .{ .path = "/ws" },
    );
    try std.testing.expect(!connection.compressionEnabled());
    try std.testing.expect(std.mem.indexOf(
        u8,
        output.written(),
        "Sec-WebSocket-Extensions",
    ) == null);

    const disabled =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";
    var input_disabled = std.Io.Reader.fixed(disabled);
    output.clearRetainingCapacity();
    try serverHandshake(
        std.testing.io,
        &input_disabled,
        &output.writer,
        &connection,
        .{ .path = "/ws", .deflate = .{ .enabled = true } },
    );
    try std.testing.expect(!connection.compressionEnabled());
}

test "server echoes requested no-context takeover and window bits" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; " ++
        "server_max_window_bits=12; client_max_window_bits\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try serverHandshake(
        std.testing.io,
        &input,
        &output.writer,
        &connection,
        .{
            .path = "/ws",
            .deflate = .{
                .enabled = true,
                .no_context_takeover = true,
                .peer_no_context_takeover = true,
                .max_window_bits = 10,
                .peer_max_window_bits = 12,
            },
        },
    );
    try std.testing.expect(connection.deflate.enabled);
    try std.testing.expect(connection.deflate.local_no_context_takeover);
    try std.testing.expect(connection.deflate.peer_no_context_takeover);
    try std.testing.expectEqual(@as(u4, 10), connection.deflate.local_max_window_bits);
    try std.testing.expectEqual(@as(u4, 12), connection.deflate.peer_max_window_bits);
    const written = output.written();
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "server_no_context_takeover",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "client_no_context_takeover",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "server_max_window_bits=10",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "client_max_window_bits=12",
    ) != null);
}

test "compressed text with invalid UTF-8 sends close 1007" {
    const allocator = std.testing.allocator;
    var frames: std.Io.Writer.Allocating = .init(allocator);
    defer frames.deinit();
    var encoder = deflate.Encoder.init();
    try appendEncoded(&frames, &encoder, "\xff\xfe", frame.opcode_text);

    var input = std.Io.Reader.fixed(frames.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &output.writer,
        .role = .server,
        .deflate = .{ .enabled = true },
    };
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.read(&buffers),
    );
    try expectLastClose(output.written(), 1007);
}

test "server rejects duplicate subprotocol headers" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: chat\r\n" ++
        "Sec-WebSocket-Protocol: chat\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try std.testing.expectError(
        error.HandshakeFailed,
        serverHandshake(
            std.testing.io,
            &input,
            &output.writer,
            &connection,
            .{ .path = "/ws", .subprotocols = &.{"chat"} },
        ),
    );
}

test "a frame coalesced with the handshake is delivered" {
    const allocator = std.testing.allocator;
    var bytes: std.Io.Writer.Allocating = .init(allocator);
    defer bytes.deinit();
    try bytes.writer.writeAll(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    );
    var scratch: [16]u8 = undefined;
    try frame.write(
        std.testing.io,
        &bytes.writer,
        .client,
        frame.opcode_binary,
        true,
        "hi",
        &scratch,
    );

    var input = std.Io.Reader.fixed(bytes.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try serverHandshake(
        std.testing.io,
        &input,
        &output.writer,
        &connection,
        .{ .path = "/ws" },
    );
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const len = try connection.read(&buffers);
    try std.testing.expectEqualStrings("hi", buffer[0..len]);
}

test "server honors a client no-context-takeover offer" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; " ++
        "client_no_context_takeover; server_no_context_takeover\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try serverHandshake(
        std.testing.io,
        &input,
        &output.writer,
        &connection,
        .{ .path = "/ws", .deflate = .{ .enabled = true } },
    );
    try std.testing.expect(connection.deflate.local_no_context_takeover);
    try std.testing.expect(connection.deflate.peer_no_context_takeover);
    const written = output.written();
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "server_no_context_takeover",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        written,
        "client_no_context_takeover",
    ) != null);
}

test "server rejects a malformed deflate offer" {
    const request =
        "GET /ws HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; " ++
        "server_max_window_bits=99\r\n\r\n";
    var input = std.Io.Reader.fixed(request);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var connection: Connection = undefined;
    try std.testing.expectError(
        error.HandshakeFailed,
        serverHandshake(
            std.testing.io,
            &input,
            &output.writer,
            &connection,
            .{ .path = "/ws", .deflate = .{ .enabled = true } },
        ),
    );
}

test "a valid close code is echoed" {
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
    const payload = [_]u8{ 0x03, 0xe9 }; // 1001
    try connection.receiveClose(&payload);
    try expectLastClose(storage.written(), 1001);
}

test "a pong is queued while a data writer holds the lock" {
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
    try connection.write_lock.lock(std.testing.io);
    connection.sendPong("p");
    connection.write_lock.unlock(std.testing.io);
    try std.testing.expectEqual(@as(usize, 1), connection.pong_count);
    _ = try connection.write(&.{"a"});
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x8a, 0x01, 'p', 0x82, 0x01, 'a' },
        storage.written(),
    );
}
