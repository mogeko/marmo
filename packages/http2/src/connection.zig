//! HTTP/2 connection and one-stream transport.

const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");

pub const Error = error{
    Canceled,
    Closed,
    ConnectionReset,
    HandshakeFailed,
    OutOfMemory,
    ProtocolViolation,
    Unexpected,
};

pub const Header = hpack.Header;

pub const our_initial_window = 1024 * 1024;
pub const max_header_block = 64 * 1024;
pub const max_continuations = 16;

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const setting_header_table_size: u16 = 0x1;
const setting_enable_push: u16 = 0x2;
const setting_max_concurrent_streams: u16 = 0x3;
const setting_initial_window_size: u16 = 0x4;
const setting_max_frame_size: u16 = 0x5;
const setting_max_header_list_size: u16 = 0x6;

pub const Stream = struct {
    connection: *Connection,
    id: u32,

    pub fn read(self: Stream, buffers: [][]u8) Error!usize {
        return self.connection.readStream(self.id, buffers);
    }

    pub fn write(self: Stream, buffers: []const []const u8) Error!usize {
        return self.connection.writeStream(self.id, buffers);
    }

    pub fn close(self: Stream) Error!void {
        return self.connection.closeStream(self.id);
    }

    pub fn cancel(self: Stream) void {
        self.connection.cancel();
    }

    pub fn sendHeaders(
        self: Stream,
        headers: []const Header,
        end_stream: bool,
    ) Error!void {
        if (self.id != self.connection.stream_id) {
            return error.ProtocolViolation;
        }
        return self.connection.sendHeaders(headers, end_stream);
    }
};

pub const Role = enum { client, server };

pub const Connection = struct {
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    role: Role,
    input_mutex: std.Io.Mutex = .init,
    write_mutex: std.Io.Mutex = .init,
    writer_serial: std.Io.Mutex = .init,
    window_event: std.Io.Event = .unset,
    decoder: hpack.Decoder = .{},
    frame_buffer: [frame.max_frame_size]u8 = undefined,
    header_block: [max_header_block]u8 = undefined,
    header_block_len: usize = 0,
    header_storage: [max_header_block]u8 = undefined,
    header_list: [hpack.max_headers]Header = undefined,
    header_count: usize = 0,
    stream_id: u32 = 0,
    peer_initial_window: i64 = frame.default_window,
    peer_max_frame_size: u32 = frame.max_frame_size,
    send_window: std.atomic.Value(i64) = .init(frame.default_window),
    conn_send_window: std.atomic.Value(i64) = .init(frame.default_window),
    pending: [frame.max_frame_size]u8 = undefined,
    pending_len: usize = 0,
    pending_offset: usize = 0,
    remote_end_stream: std.atomic.Value(bool) = .init(false),
    stream_aborted: std.atomic.Value(bool) = .init(false),
    canceled: std.atomic.Value(bool) = .init(false),
    local_closed: bool = false,
    response_headers_seen: bool = false,

    pub fn stream(self: *Connection) ?Stream {
        if (self.stream_id == 0) return null;
        return .{ .connection = self, .id = self.stream_id };
    }

    pub fn headers(self: *const Connection) []const Header {
        return self.header_list[0..self.header_count];
    }

    pub fn deinit(self: *Connection) void {
        std.crypto.secureZero(u8, &self.header_storage);
        std.crypto.secureZero(u8, &self.header_block);
        std.crypto.secureZero(u8, &self.pending);
        std.crypto.secureZero(u8, &self.decoder.storage);
    }

    pub fn cancel(self: *Connection) void {
        self.canceled.store(true, .release);
        self.window_event.set(self.io);
    }

    fn readStream(
        self: *Connection,
        stream_id: u32,
        buffers: [][]u8,
    ) Error!usize {
        self.input_mutex.lock(self.io) catch return error.Canceled;
        defer self.input_mutex.unlock(self.io);
        if (stream_id != self.stream_id) return error.ProtocolViolation;
        if (totalCapacity(buffers) == 0) return error.Unexpected;
        if (self.pending_offset < self.pending_len) {
            return self.copyPending(buffers);
        }

        while (!self.remote_end_stream.load(.acquire)) {
            if (self.canceled.load(.acquire)) return error.Canceled;
            if (self.stream_aborted.load(.acquire)) return error.ConnectionReset;
            self.processFrame() catch |err| {
                self.stream_aborted.store(true, .release);
                self.window_event.set(self.io);
                return switch (err) {
                    error.Canceled => error.Canceled,
                    error.Closed => error.ConnectionReset,
                    else => err,
                };
            };
            if (self.pending_offset < self.pending_len) {
                return self.copyPending(buffers);
            }
        }
        if (self.stream_aborted.load(.acquire)) return error.ConnectionReset;
        return 0;
    }

    fn writeStream(
        self: *Connection,
        stream_id: u32,
        buffers: []const []const u8,
    ) Error!usize {
        if (stream_id != self.stream_id) return error.ProtocolViolation;
        self.writer_serial.lock(self.io) catch return error.Canceled;
        defer self.writer_serial.unlock(self.io);
        if (self.canceled.load(.acquire)) return error.Canceled;
        if (self.local_closed) return error.Closed;
        var total: usize = 0;
        for (buffers) |buffer| {
            try self.writeData(buffer);
            total += buffer.len;
        }
        return total;
    }

    fn closeStream(self: *Connection, stream_id: u32) Error!void {
        self.writer_serial.lock(self.io) catch return error.Canceled;
        defer self.writer_serial.unlock(self.io);
        self.write_mutex.lock(self.io) catch return error.Canceled;
        defer self.write_mutex.unlock(self.io);
        if (stream_id != self.stream_id or self.local_closed) return;
        try self.sendFrameLocked(frame.type_data, frame.flag_end_stream, stream_id, &.{});
        self.local_closed = true;
        self.output.flush() catch return error.Unexpected;
    }

    fn copyPending(self: *Connection, buffers: [][]u8) usize {
        const available = self.pending_len - self.pending_offset;
        var copied: usize = 0;
        for (buffers) |buffer| {
            if (copied == available) break;
            const count = @min(buffer.len, available - copied);
            const source = self.pending_offset + copied;
            @memcpy(buffer[0..count], self.pending[source..][0..count]);
            copied += count;
        }
        self.pending_offset += copied;
        if (self.pending_offset == self.pending_len) {
            self.pending_len = 0;
            self.pending_offset = 0;
        }
        return copied;
    }

    fn processFrame(self: *Connection) Error!void {
        const parsed = frame.read(self.input, &self.frame_buffer) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.EndOfStream => return error.Closed,
            error.ProtocolViolation => return error.ProtocolViolation,
            error.Unexpected => return error.Unexpected,
        };
        try self.handleFrame(parsed);
    }

    fn handleFrame(self: *Connection, parsed: frame.Frame) Error!void {
        switch (parsed.frame_type) {
            frame.type_data => try self.processData(parsed),
            frame.type_headers => {
                if (parsed.stream_id != self.stream_id) {
                    return error.ProtocolViolation;
                }
                const decoded = try self.readHeaderBlock(parsed);
                if (self.role == .client and !self.response_headers_seen) {
                    const status = findHeader(decoded, ":status") orelse
                        return error.ProtocolViolation;
                    const code = std.fmt.parseInt(u16, status, 10) catch
                        return error.ProtocolViolation;
                    if (code < 200 or code >= 300) {
                        return error.ProtocolViolation;
                    }
                    self.response_headers_seen = true;
                }
                if (parsed.flags & frame.flag_end_stream != 0) {
                    self.remote_end_stream.store(true, .release);
                }
            },
            frame.type_settings => try self.processSettings(parsed),
            frame.type_ping => try self.processPing(parsed),
            frame.type_window_update => try self.processWindowUpdate(parsed),
            frame.type_goaway => {
                if (parsed.payload.len < 8) return error.ProtocolViolation;
                const last_stream_id = std.mem.readInt(
                    u32,
                    parsed.payload[0..4],
                    .big,
                ) & 0x7fffffff;
                const error_code = std.mem.readInt(
                    u32,
                    parsed.payload[4..8],
                    .big,
                );
                if (error_code != 0 or
                    (self.stream_id != 0 and last_stream_id < self.stream_id))
                {
                    self.stream_aborted.store(true, .release);
                }
                self.window_event.set(self.io);
            },
            frame.type_rst_stream => {
                if (parsed.payload.len != 4) return error.ProtocolViolation;
                if (parsed.stream_id == self.stream_id) {
                    self.stream_aborted.store(true, .release);
                    self.window_event.set(self.io);
                }
            },
            frame.type_priority => {},
            frame.type_push_promise => return error.ProtocolViolation,
            frame.type_continuation => return error.ProtocolViolation,
            else => {},
        }
    }

    fn processData(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id == 0 or parsed.stream_id != self.stream_id) {
            return error.ProtocolViolation;
        }
        if (self.remote_end_stream.load(.acquire)) return error.ProtocolViolation;
        if (self.pending_len != 0) return error.ProtocolViolation;
        var payload = parsed.payload;
        if (parsed.flags & frame.flag_padded != 0) {
            if (payload.len == 0) return error.ProtocolViolation;
            const pad_len = payload[0];
            if (pad_len > payload.len - 1) return error.ProtocolViolation;
            payload = payload[1 .. payload.len - pad_len];
        }
        if (payload.len > self.pending.len) {
            return error.ProtocolViolation;
        }
        @memcpy(self.pending[0..payload.len], payload);
        self.pending_len = payload.len;
        self.pending_offset = 0;
        if (parsed.flags & frame.flag_end_stream != 0) {
            self.remote_end_stream.store(true, .release);
        }
        if (parsed.payload.len != 0) {
            try self.sendWindowUpdate(0, parsed.payload.len);
            if (parsed.flags & frame.flag_end_stream == 0) {
                try self.sendWindowUpdate(self.stream_id, parsed.payload.len);
            }
        }
    }

    fn processSettings(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id != 0) return error.ProtocolViolation;
        if (parsed.flags & frame.flag_ack != 0) {
            if (parsed.payload.len != 0) return error.ProtocolViolation;
            return;
        }
        if (parsed.payload.len % 6 != 0) return error.ProtocolViolation;
        var index: usize = 0;
        while (index < parsed.payload.len) : (index += 6) {
            const identifier = std.mem.readInt(u16, parsed.payload[index..][0..2], .big);
            const value = std.mem.readInt(u32, parsed.payload[index + 2 ..][0..4], .big);
            try self.applySetting(identifier, value);
        }
        try self.sendFrame(frame.type_settings, frame.flag_ack, 0, &.{});
    }

    fn applySetting(self: *Connection, identifier: u16, value: u32) Error!void {
        switch (identifier) {
            setting_initial_window_size => {
                if (value > frame.max_window) return error.ProtocolViolation;
                const delta = @as(i64, value) - self.peer_initial_window;
                const current = self.send_window.load(.acquire);
                const next = current + delta;
                if (next > frame.max_window or next < -frame.max_window) {
                    return error.ProtocolViolation;
                }
                _ = self.send_window.fetchAdd(delta, .acq_rel);
                self.peer_initial_window = value;
                self.window_event.set(self.io);
            },
            setting_max_frame_size => {
                if (value < frame.max_frame_size or value > 0x00ffffff) {
                    return error.ProtocolViolation;
                }
                self.peer_max_frame_size = value;
            },
            setting_max_concurrent_streams => {},
            setting_enable_push => {
                // A client may send 0 or 1. A server MUST NOT send this
                // setting, and values above 1 are invalid.
                // A server MUST NOT send 1; 0 is legal and common.
                if (self.role == .client and value != 0) {
                    return error.ProtocolViolation;
                }
                if (value > 1) return error.ProtocolViolation;
            },
            setting_header_table_size,
            setting_max_header_list_size,
            => {},
            else => {},
        }
    }

    fn processPing(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id != 0 or parsed.payload.len != 8) {
            return error.ProtocolViolation;
        }
        if (parsed.flags & frame.flag_ack != 0) return;
        try self.sendFrame(frame.type_ping, frame.flag_ack, 0, parsed.payload);
    }

    fn processWindowUpdate(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.payload.len != 4) return error.ProtocolViolation;
        const increment = std.mem.readInt(u32, parsed.payload[0..4], .big) & 0x7fffffff;
        if (increment == 0) return error.ProtocolViolation;
        if (parsed.stream_id == 0) {
            const current = self.conn_send_window.load(.acquire);
            if (current + increment > frame.max_window) {
                return error.ProtocolViolation;
            }
            _ = self.conn_send_window.fetchAdd(increment, .acq_rel);
        } else if (parsed.stream_id == self.stream_id) {
            const current = self.send_window.load(.acquire);
            if (current + increment > frame.max_window) {
                return error.ProtocolViolation;
            }
            _ = self.send_window.fetchAdd(increment, .acq_rel);
        }
        self.window_event.set(self.io);
    }

    fn readHeaderBlock(self: *Connection, first: frame.Frame) Error![]Header {
        if (first.stream_id == 0) return error.ProtocolViolation;
        self.header_block_len = 0;
        var payload = first.payload;
        var offset: usize = 0;
        var pad_len: usize = 0;
        if (first.flags & frame.flag_padded != 0) {
            if (payload.len == 0) return error.ProtocolViolation;
            pad_len = payload[0];
            offset = 1;
        }
        if (first.flags & frame.flag_priority != 0) {
            if (payload.len - offset < 5) return error.ProtocolViolation;
            offset += 5;
        }
        if (payload.len < offset + pad_len) return error.ProtocolViolation;
        try self.appendHeaderFragment(payload[offset .. payload.len - pad_len]);

        var end_headers = first.flags & frame.flag_end_headers != 0;
        var continuations: usize = 0;
        while (!end_headers) {
            continuations += 1;
            if (continuations > max_continuations) {
                return error.ProtocolViolation;
            }
            const next = frame.read(self.input, &self.frame_buffer) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.EndOfStream => return error.ProtocolViolation,
                error.ProtocolViolation => return error.ProtocolViolation,
                error.Unexpected => return error.Unexpected,
            };
            if (next.frame_type != frame.type_continuation or
                next.stream_id != first.stream_id)
            {
                return error.ProtocolViolation;
            }
            try self.appendHeaderFragment(next.payload);
            end_headers = next.flags & frame.flag_end_headers != 0;
        }

        self.header_count = 0;
        const list = self.decoder.decode(
            self.header_block[0..self.header_block_len],
            &self.header_storage,
            &self.header_list,
        ) catch |err| switch (err) {
            error.Malformed, error.OutOfMemory => return error.ProtocolViolation,
        };
        self.header_count = list.len;
        return self.header_list[0..self.header_count];
    }

    fn appendHeaderFragment(self: *Connection, bytes: []const u8) Error!void {
        if (self.header_block.len - self.header_block_len < bytes.len) {
            return error.ProtocolViolation;
        }
        @memcpy(
            self.header_block[self.header_block_len..][0..bytes.len],
            bytes,
        );
        self.header_block_len += bytes.len;
    }

    fn writeData(self: *Connection, bytes: []const u8) Error!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const limit = try self.waitForWindow();
            if (limit == 0) return error.Closed;
            const chunk_len = @min(@as(usize, @intCast(limit)), bytes.len - offset);
            self.write_mutex.lock(self.io) catch return error.Canceled;
            defer self.write_mutex.unlock(self.io);
            const chunk = bytes[offset..][0..chunk_len];
            try self.sendFrameLocked(frame.type_data, 0, self.stream_id, chunk);
            _ = self.conn_send_window.fetchSub(@intCast(chunk_len), .acq_rel);
            _ = self.send_window.fetchSub(@intCast(chunk_len), .acq_rel);
            self.output.flush() catch return error.Unexpected;
            offset += chunk_len;
        }
    }

    fn waitForWindow(self: *Connection) Error!i64 {
        while (true) {
            if (self.canceled.load(.acquire)) return error.Canceled;
            if (self.stream_aborted.load(.acquire)) return error.Closed;
            const stream_window = self.send_window.load(.acquire);
            const connection_window = self.conn_send_window.load(.acquire);
            const available = @min(stream_window, connection_window);
            if (available > 0) {
                return @min(
                    @min(available, @as(i64, self.peer_max_frame_size)),
                    @as(i64, frame.max_frame_size),
                );
            }
            if (self.input_mutex.tryLock()) {
                defer self.input_mutex.unlock(self.io);
                self.processFrame() catch |err| {
                    self.stream_aborted.store(true, .release);
                    self.window_event.set(self.io);
                    return switch (err) {
                        error.Canceled => error.Canceled,
                        error.Closed => error.Closed,
                        else => err,
                    };
                };
                continue;
            }
            self.window_event.wait(self.io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            self.window_event.reset();
        }
    }

    fn sendWindowUpdate(
        self: *Connection,
        stream_id: u32,
        increment: usize,
    ) Error!void {
        if (increment == 0 or increment > frame.max_window) return;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, @intCast(increment), .big);
        try self.sendFrame(frame.type_window_update, 0, stream_id, &payload);
    }

    fn sendFrame(
        self: *Connection,
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: []const u8,
    ) Error!void {
        self.write_mutex.lock(self.io) catch return error.Canceled;
        defer self.write_mutex.unlock(self.io);
        try self.sendFrameLocked(frame_type, flags, stream_id, payload);
        self.output.flush() catch return error.Unexpected;
    }

    fn sendFrameLocked(
        self: *Connection,
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: []const u8,
    ) Error!void {
        frame.write(
            self.output,
            frame_type,
            flags,
            stream_id,
            payload,
        ) catch |err| switch (err) {
            error.ProtocolViolation => return error.ProtocolViolation,
            else => return error.Unexpected,
        };
    }

    fn sendHeaders(self: *Connection, header_list: []const Header, end_stream: bool) Error!void {
        var block: [max_header_block]u8 = undefined;
        var block_len: usize = 0;
        var regular_seen = false;
        for (header_list) |header| {
            if (header.name.len != 0 and header.name[0] == ':') {
                if (regular_seen) return error.ProtocolViolation;
            } else {
                regular_seen = true;
            }
            hpack.encodeHeader(&block, &block_len, header.name, header.value) catch |err| {
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.Malformed => error.ProtocolViolation,
                };
            };
        }

        self.write_mutex.lock(self.io) catch return error.Canceled;
        defer self.write_mutex.unlock(self.io);

        var offset: usize = 0;
        var first = true;
        while (true) {
            const remaining = block_len - offset;
            const chunk_len = @min(remaining, @as(usize, frame.max_frame_size));
            const last = offset + chunk_len == block_len;
            var flags: u8 = 0;
            if (last) flags |= frame.flag_end_headers;
            if (last and end_stream) flags |= frame.flag_end_stream;
            const frame_type = if (first) frame.type_headers else frame.type_continuation;
            try self.sendFrameLocked(
                frame_type,
                flags,
                self.stream_id,
                block[offset..][0..chunk_len],
            );
            offset += chunk_len;
            first = false;
            if (last) break;
        }
        self.output.flush() catch return error.Unexpected;
        if (end_stream) self.local_closed = true;
    }

    fn sendOurSettings(self: *Connection) Error!void {
        var payload: [32]u8 = undefined;
        var len: usize = 0;
        if (self.role == .client) {
            len = appendSetting(&payload, len, setting_enable_push, 0);
        }
        len = appendSetting(&payload, len, setting_max_concurrent_streams, 1);
        len = appendSetting(
            &payload,
            len,
            setting_initial_window_size,
            our_initial_window,
        );
        len = appendSetting(
            &payload,
            len,
            setting_max_frame_size,
            frame.max_frame_size,
        );
        len = appendSetting(
            &payload,
            len,
            setting_max_header_list_size,
            64 * 1024,
        );
        try self.sendFrame(frame.type_settings, 0, 0, payload[0..len]);
        try self.sendWindowUpdate(
            0,
            our_initial_window - frame.default_window,
        );
    }
};

fn appendSetting(
    buffer: []u8,
    offset: usize,
    identifier: u16,
    value: u32,
) usize {
    std.mem.writeInt(u16, buffer[offset..][0..2], identifier, .big);
    std.mem.writeInt(u32, buffer[offset + 2 ..][0..4], value, .big);
    return offset + 6;
}

fn totalCapacity(buffers: [][]u8) usize {
    var total: usize = 0;
    for (buffers) |buffer| total += buffer.len;
    return total;
}

fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return header.value;
    }
    return null;
}

fn validateRequest(headers: []const Header, path: ?[]const u8) Error!void {
    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;
    for (headers) |header| {
        if (header.name.len == 0) return error.ProtocolViolation;
        for (header.name) |byte| {
            if (byte >= 'A' and byte <= 'Z') return error.ProtocolViolation;
            if (byte == 0 or byte == '\r' or byte == '\n') {
                return error.ProtocolViolation;
            }
        }
        for (header.value) |byte| {
            if (byte == 0 or byte == '\r' or byte == '\n') {
                return error.ProtocolViolation;
            }
        }
        if (std.mem.eql(u8, header.name, ":method")) {
            if (seen_method) return error.ProtocolViolation;
            seen_method = true;
        } else if (std.mem.eql(u8, header.name, ":scheme")) {
            if (seen_scheme) return error.ProtocolViolation;
            seen_scheme = true;
        } else if (std.mem.eql(u8, header.name, ":path")) {
            if (seen_path) return error.ProtocolViolation;
            seen_path = true;
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            if (seen_authority) return error.ProtocolViolation;
            seen_authority = true;
        } else if (std.mem.eql(u8, header.name, "connection")) {
            return error.ProtocolViolation;
        } else if (std.mem.eql(u8, header.name, "te")) {
            if (!std.mem.eql(u8, header.value, "trailers")) {
                return error.ProtocolViolation;
            }
        }
    }
    const method = findHeader(headers, ":method") orelse
        return error.ProtocolViolation;
    const authority = findHeader(headers, ":authority") orelse
        return error.ProtocolViolation;
    if (method.len == 0 or authority.len == 0) {
        return error.ProtocolViolation;
    }
    const request_path = findHeader(headers, ":path");
    if (!std.mem.eql(u8, method, "CONNECT")) {
        const scheme = findHeader(headers, ":scheme") orelse
            return error.ProtocolViolation;
        const value = request_path orelse return error.ProtocolViolation;
        if (scheme.len == 0 or value.len == 0) {
            return error.ProtocolViolation;
        }
        if (value[0] != '/' and
            !(std.mem.eql(u8, method, "OPTIONS") and std.mem.eql(u8, value, "*")))
        {
            return error.ProtocolViolation;
        }
    }
    if (path) |expected| {
        const value = request_path orelse return error.ProtocolViolation;
        if (!std.mem.eql(u8, value, expected)) {
            return error.ProtocolViolation;
        }
    }
}

pub const Client = struct {
    connection: Connection,

    pub fn init(
        io: std.Io,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
    ) Error!Client {
        var client: Client = .{ .connection = .{
            .io = io,
            .input = input,
            .output = output,
            .role = .client,
        } };
        output.writeAll(preface) catch return error.HandshakeFailed;
        try client.connection.sendOurSettings();
        try clientHandshake(&client.connection);
        return client;
    }

    pub fn openStream(self: *Client, headers: []const Header) Error!Stream {
        self.connection.stream_id = 1;
        self.connection.send_window.store(
            self.connection.peer_initial_window,
            .release,
        );
        try self.connection.sendHeaders(headers, false);
        return .{ .connection = &self.connection, .id = 1 };
    }

    pub fn stream(self: *Client) ?Stream {
        return self.connection.stream();
    }

    pub fn deinit(self: *Client) void {
        self.connection.deinit();
    }
};

pub const ServerOptions = struct {
    path: ?[]const u8 = null,
};

pub const Server = struct {
    connection: Connection,
    path: ?[]const u8 = null,

    pub fn init(
        io: std.Io,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
    ) Error!Server {
        return initWithOptions(io, input, output, .{});
    }

    pub fn initWithOptions(
        io: std.Io,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        options: ServerOptions,
    ) Error!Server {
        var server: Server = .{
            .connection = .{
                .io = io,
                .input = input,
                .output = output,
                .role = .server,
            },
            .path = options.path,
        };
        var preface_buffer: [preface.len]u8 = undefined;
        frame.readExact(input, &preface_buffer, false) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.HandshakeFailed,
        };
        if (!std.mem.eql(u8, &preface_buffer, preface)) {
            return error.HandshakeFailed;
        }

        const first = frame.read(input, &server.connection.frame_buffer) catch
            return error.HandshakeFailed;
        if (first.frame_type != frame.type_settings or first.stream_id != 0 or
            first.flags & frame.flag_ack != 0)
        {
            return error.HandshakeFailed;
        }
        try server.connection.sendOurSettings();
        try server.connection.processSettings(first);
        return server;
    }

    pub fn acceptStream(self: *Server) Error!Stream {
        while (true) {
            const parsed = frame.read(
                self.connection.input,
                &self.connection.frame_buffer,
            ) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.EndOfStream => return error.Closed,
                error.ProtocolViolation => return error.ProtocolViolation,
                error.Unexpected => return error.Unexpected,
            };
            switch (parsed.frame_type) {
                frame.type_settings,
                frame.type_ping,
                frame.type_window_update,
                => try self.connection.handleFrame(parsed),
                frame.type_headers => {
                    if (parsed.stream_id == 0 or parsed.stream_id % 2 == 0) {
                        return error.ProtocolViolation;
                    }
                    const decoded = try self.connection.readHeaderBlock(parsed);
                    try validateRequest(decoded, self.path);
                    self.connection.stream_id = parsed.stream_id;
                    self.connection.send_window.store(
                        self.connection.peer_initial_window,
                        .release,
                    );
                    if (parsed.flags & frame.flag_end_stream != 0) {
                        self.connection.remote_end_stream.store(true, .release);
                    }
                    return .{
                        .connection = &self.connection,
                        .id = self.connection.stream_id,
                    };
                },
                frame.type_goaway => return error.Closed,
                frame.type_rst_stream => return error.Closed,
                frame.type_priority => {},
                frame.type_data => return error.ProtocolViolation,
                else => {},
            }
        }
    }

    pub fn headers(self: *const Server) []const Header {
        return self.connection.headers();
    }

    pub fn stream(self: *Server) ?Stream {
        return self.connection.stream();
    }

    pub fn deinit(self: *Server) void {
        self.connection.deinit();
    }
};

fn clientHandshake(connection: *Connection) Error!void {
    var got_settings = false;
    var got_ack = false;
    var frames: usize = 0;
    while (!got_settings or !got_ack) {
        frames += 1;
        if (frames > 32) return error.HandshakeFailed;
        const parsed = frame.read(connection.input, &connection.frame_buffer) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.HandshakeFailed,
        };
        if (parsed.frame_type == frame.type_settings and
            parsed.flags & frame.flag_ack != 0)
        {
            got_ack = true;
            continue;
        }
        if (parsed.frame_type == frame.type_settings) {
            connection.processSettings(parsed) catch return error.HandshakeFailed;
            got_settings = true;
            continue;
        }
        if (parsed.frame_type == frame.type_ping) {
            connection.processPing(parsed) catch return error.HandshakeFailed;
            continue;
        }
        if (parsed.frame_type == frame.type_window_update) {
            connection.processWindowUpdate(parsed) catch return error.HandshakeFailed;
            continue;
        }
        if (parsed.frame_type == frame.type_goaway) {
            return error.HandshakeFailed;
        }
    }
}

test "client settings include one concurrent stream" {
    var connection: Connection = .{
        .io = std.testing.io,
        .input = undefined,
        .output = undefined,
        .role = .client,
    };
    try std.testing.expectEqual(@as(i64, frame.default_window), connection.send_window.load(.acquire));
}

test "client ENABLE_PUSH settings are accepted by a server" {
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
    try connection.applySetting(setting_enable_push, 0);
    try connection.applySetting(setting_enable_push, 1);
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.applySetting(setting_enable_push, 2),
    );

    connection.role = .client;
    try connection.applySetting(setting_enable_push, 0);
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.applySetting(setting_enable_push, 1),
    );
}

test "curl/nghttp2 settings are accepted by a server" {
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
    // curl --http2-prior-knowledge sends these three settings.
    try connection.applySetting(setting_max_concurrent_streams, 100);
    try connection.applySetting(setting_initial_window_size, 0x000a0000);
    try connection.applySetting(setting_enable_push, 0);
}

test "END_STREAM from the peer does not block the local write side" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .server,
        .stream_id = 1,
    };
    connection.remote_end_stream.store(true, .release);
    _ = try connection.writeStream(1, &.{"x"});
    try std.testing.expect(storage.written().len > 0);
    try connection.closeStream(1);
    try std.testing.expectError(
        error.Closed,
        connection.writeStream(1, &.{"y"}),
    );
}

test "HEADERS for another stream is rejected" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .server,
        .stream_id = 1,
    };
    var payload: [0]u8 = .{};
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.handleFrame(.{
            .frame_type = frame.type_headers,
            .flags = frame.flag_end_stream,
            .stream_id = 3,
            .payload = &payload,
        }),
    );
}

test "RST_STREAM and truncating GOAWAY abort the stream" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .server,
        .stream_id = 1,
    };

    var rst = [_]u8{ 0, 0, 0, 0 };
    var bad_rst = [_]u8{0};
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.handleFrame(.{
            .frame_type = frame.type_rst_stream,
            .flags = 0,
            .stream_id = 1,
            .payload = &bad_rst,
        }),
    );
    try connection.handleFrame(.{
        .frame_type = frame.type_rst_stream,
        .flags = 0,
        .stream_id = 1,
        .payload = &rst,
    });
    try std.testing.expect(connection.stream_aborted.load(.acquire));

    connection.stream_aborted.store(false, .release);
    var goaway = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    try connection.handleFrame(.{
        .frame_type = frame.type_goaway,
        .flags = 0,
        .stream_id = 0,
        .payload = &goaway,
    });
    try std.testing.expect(connection.stream_aborted.load(.acquire));
}

test "server accepts curl settings and responds to a no-body request" {
    const allocator = std.testing.allocator;
    var input_buffer: [1024]u8 = undefined;
    var input_writer = std.Io.Writer.fixed(&input_buffer);
    input_writer.writeAll(preface) catch return error.TestUnexpectedResult;

    var settings = [_]u8{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH=0, as sent by curl
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS=100
    };
    try frame.write(&input_writer, frame.type_settings, 0, 0, &settings);

    var header_block: [128]u8 = undefined;
    var block_len: usize = 0;
    try hpack.encodeHeader(&header_block, &block_len, ":method", "GET");
    try hpack.encodeHeader(&header_block, &block_len, ":scheme", "https");
    try hpack.encodeHeader(&header_block, &block_len, ":path", "/");
    try hpack.encodeHeader(&header_block, &block_len, ":authority", "example.com");
    try frame.write(
        &input_writer,
        frame.type_headers,
        frame.flag_end_headers | frame.flag_end_stream,
        1,
        header_block[0..block_len],
    );

    var input = std.Io.Reader.fixed(input_writer.buffered());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    var server = try Server.init(std.testing.io, &input, &output.writer);
    defer server.deinit();
    var out_reader = std.Io.Reader.fixed(output.written());
    var out_frame: [frame.max_frame_size]u8 = undefined;
    const first_out = try frame.read(&out_reader, &out_frame);
    try std.testing.expectEqual(frame.type_settings, first_out.frame_type);
    try std.testing.expectEqual(@as(u8, 0), first_out.flags & frame.flag_ack);
    const stream = try server.acceptStream();
    const response = [_]Header{
        .{ .name = ":status", .value = "200" },
    };
    try stream.sendHeaders(&response, false);
    _ = try stream.write(&.{"ok"});
    try std.testing.expect(output.written().len > 0);
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
        .stream_id = 1,
    };
    try std.testing.expectError(
        error.Unexpected,
        connection.readStream(1, &.{}),
    );
}

test "request pseudo headers and configured path are enforced" {
    const headers = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/ws" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try validateRequest(&headers, "/ws");
    try std.testing.expectError(
        error.ProtocolViolation,
        validateRequest(&headers, "/other"),
    );
    const missing_authority = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/ws" },
    };
    try std.testing.expectError(
        error.ProtocolViolation,
        validateRequest(&missing_authority, null),
    );
}

test "padded DATA strips padding before delivery" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    var input = std.Io.Reader.fixed(&.{});
    var connection: Connection = .{
        .io = std.testing.io,
        .input = &input,
        .output = &storage.writer,
        .role = .client,
        .stream_id = 1,
    };
    var payload = [_]u8{ 3, 'h', 'i', 0, 0, 0 };
    try connection.handleFrame(.{
        .frame_type = frame.type_data,
        .flags = frame.flag_padded,
        .stream_id = 1,
        .payload = &payload,
    });
    var buffer: [8]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const read_len = try connection.readStream(1, &buffers);
    try std.testing.expectEqual(@as(usize, 2), read_len);
    try std.testing.expectEqualStrings("hi", buffer[0..2]);

    connection.remote_end_stream.store(false, .release);
    payload[0] = 6;
    connection.pending_len = 0;
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.handleFrame(.{
            .frame_type = frame.type_data,
            .flags = frame.flag_padded,
            .stream_id = 1,
            .payload = &payload,
        }),
    );
}
