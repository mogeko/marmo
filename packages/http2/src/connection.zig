//! Bounded HTTP/2 (RFC 9113) connection multiplexer.
//!
//! The connection owns a fixed stream table, one HPACK decoder, and a single
//! frame pump. Readers for different streams serialize on the input mutex for
//! one frame at a time; frames for other streams are copied into that stream's
//! bounded DATA queue. The public surface stays a duplex byte stream per
//! stream, plus header/trailer accessors for gRPC-style callers.

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
    TooManyStreams,
    Unexpected,
};

pub const Header = hpack.Header;

pub const stream_window_bytes: usize = 8 * 1024;
pub const stream_recv_window: i64 = stream_window_bytes;
pub const max_concurrent_streams: usize = 16;
pub const connection_recv_window: i64 = stream_recv_window * max_concurrent_streams;
pub const max_header_block = 64 * 1024;
pub const max_continuations = 16;

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const setting_header_table_size: u16 = 0x1;
const setting_enable_push: u16 = 0x2;
const setting_max_concurrent_streams: u16 = 0x3;
const setting_initial_window_size: u16 = 0x4;
const setting_max_frame_size: u16 = 0x5;
const setting_max_header_list_size: u16 = 0x6;

pub const error_code_no_error: u32 = 0x0;
pub const error_code_protocol: u32 = 0x1;
pub const error_code_internal: u32 = 0x2;
pub const error_code_flow_control: u32 = 0x3;
pub const error_code_stream_closed: u32 = 0x5;
pub const error_code_frame_size: u32 = 0x6;
pub const error_code_refused_stream: u32 = 0x7;
pub const error_code_cancel: u32 = 0x8;
pub const error_code_compression: u32 = 0x9;
pub const error_code_enhance_your_calm: u32 = 0xb;

pub const Stream = struct {
    connection: *Connection,
    id: u32,

    pub fn read(self: Stream, buffers: [][]u8) Error!usize {
        return self.connection.readStream(self.id, buffers);
    }

    pub fn write(self: Stream, buffers: []const []const u8) Error!usize {
        return self.connection.writeStream(self.id, buffers);
    }

    /// Half-closes the local side with END_STREAM. The stream remains readable.
    pub fn close(self: Stream) Error!void {
        return self.connection.closeStream(self.id);
    }

    /// Aborts the whole connection. Kept for the root `Stream` adapter.
    pub fn cancel(self: Stream) void {
        self.connection.cancel();
    }

    /// Aborts one stream with RST_STREAM and leaves the connection usable.
    pub fn reset(self: Stream, error_code: u32) Error!void {
        return self.connection.resetStream(self.id, error_code);
    }

    pub fn sendHeaders(
        self: Stream,
        header_list: []const Header,
        end_stream: bool,
    ) Error!void {
        return self.connection.sendHeaders(self.id, header_list, end_stream);
    }

    /// Sends a second HEADERS block with END_STREAM (HTTP/2 trailers).
    pub fn sendTrailers(
        self: Stream,
        header_list: []const Header,
    ) Error!void {
        return self.connection.sendTrailers(self.id, header_list);
    }

    pub fn headers(self: Stream) []const Header {
        return self.connection.streamHeaders(self.id);
    }

    pub fn trailers(self: Stream) []const Header {
        return self.connection.streamTrailers(self.id);
    }

    /// Last 1xx `:status` received on this stream, or 0 if none.
    pub fn informationalStatus(self: Stream) u16 {
        return self.connection.informationalStatus(self.id);
    }
};

pub const Role = enum { client, server };

const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

const stream_entries_default: [max_concurrent_streams]StreamEntry = @splat(.{});

const StreamEntry = struct {
    id: u32 = 0,
    state: StreamState = .idle,
    send_window: i64 = frame.default_window,
    recv_window: i64 = stream_recv_window,
    data: [stream_window_bytes]u8 = undefined,
    data_head: usize = 0,
    data_len: usize = 0,
    header_storage: [hpack.max_header_list]u8 = undefined,
    header_list: [hpack.max_headers]Header = undefined,
    header_count: usize = 0,
    trailer_storage: [hpack.max_header_list]u8 = undefined,
    trailer_list: [hpack.max_headers]Header = undefined,
    trailer_count: usize = 0,
    headers_seen: bool = false,
    headers_sent: bool = false,
    remote_end: bool = false,
    local_end: bool = false,
    aborted: bool = false,
    accepted: bool = false,
    informational_status: u16 = 0,

    fn zeroizeBuffers(self: *StreamEntry) void {
        std.crypto.secureZero(u8, &self.data);
        std.crypto.secureZero(u8, &self.header_storage);
        std.crypto.secureZero(u8, &self.trailer_storage);
        self.data_len = 0;
        self.data_head = 0;
        self.header_count = 0;
        self.trailer_count = 0;
    }

    fn zeroize(self: *StreamEntry) void {
        self.zeroizeBuffers();
        self.id = 0;
        self.informational_status = 0;
    }

    fn reset(self: *StreamEntry) void {
        self.zeroize();
        self.* = .{};
    }

    fn appendData(self: *StreamEntry, bytes: []const u8) Error!void {
        if (bytes.len > self.data.len - self.data_len) {
            return error.ProtocolViolation;
        }
        const write_index = (self.data_head + self.data_len) % self.data.len;
        const first = @min(bytes.len, self.data.len - write_index);
        @memcpy(self.data[write_index..][0..first], bytes[0..first]);
        if (first < bytes.len) {
            @memcpy(self.data[0 .. bytes.len - first], bytes[first..]);
        }
        self.data_len += bytes.len;
        if (self.data_len == 0) self.data_head = 0;
    }

    fn copyData(self: *StreamEntry, buffers: [][]u8) usize {
        var total: usize = 0;
        for (buffers) |buffer| {
            var index: usize = 0;
            while (index < buffer.len and total < self.data_len) {
                const source = (self.data_head + total) % self.data.len;
                const chunk = @min(
                    buffer.len - index,
                    @min(self.data.len - source, self.data_len - total),
                );
                @memcpy(buffer[index..][0..chunk], self.data[source..][0..chunk]);
                index += chunk;
                total += chunk;
            }
        }
        self.data_head = (self.data_head + total) % self.data.len;
        self.data_len -= total;
        if (self.data_len == 0) self.data_head = 0;
        return total;
    }

    fn refreshState(self: *StreamEntry) void {
        if (self.aborted) {
            self.state = .closed;
        } else if (self.local_end and self.remote_end) {
            self.state = .closed;
        } else if (self.local_end) {
            self.state = .half_closed_local;
        } else if (self.remote_end) {
            self.state = .half_closed_remote;
        } else {
            self.state = .open;
        }
    }
};

const Action = union(enum) {
    none,
    reset: u32,
    connection: u32,
};

pub const Connection = struct {
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    role: Role,

    /// One frame reader at a time; also protects `header_block`.
    input_mutex: std.Io.Mutex = .init,
    /// Protects the stream table, queues, header storage, and windows.
    state_mutex: std.Io.Mutex = .init,
    /// Serializes complete frame sequences (HEADERS + CONTINUATION).
    write_mutex: std.Io.Mutex = .init,
    writer_serial: std.Io.Mutex = .init,
    window_event: std.Io.Event = .unset,

    decoder: hpack.Decoder = .{},
    frame_buffer: [frame.max_frame_size]u8 = undefined,
    header_block: [max_header_block]u8 = undefined,
    header_block_len: usize = 0,
    send_block: [max_header_block]u8 = undefined,

    streams: [max_concurrent_streams]StreamEntry = stream_entries_default,
    last_peer_stream_id: u32 = 0,
    last_local_stream_id: u32 = 0,
    last_stream_id: u32 = 0,
    last_accepted_id: u32 = 0,
    /// Legacy single-stream hint used by the root adapter's struct literal.
    /// Multiplexed callers use stream ids from `openStream`/`acceptStream`.
    stream_id: u32 = 0,

    peer_initial_window: i64 = frame.default_window,
    peer_max_frame_size: u32 = frame.max_frame_size,
    peer_max_concurrent: u32 = std.math.maxInt(u32),
    conn_send_window: i64 = frame.default_window,
    conn_recv_window: i64 = connection_recv_window,

    canceled: std.atomic.Value(bool) = .init(false),
    send_updates_disabled: std.atomic.Value(bool) = .init(false),
    goaway_received: bool = false,
    goaway_sent: bool = false,
    goaway_error: u32 = error_code_no_error,

    pub fn stream(self: *Connection) ?Stream {
        self.state_mutex.lock(self.io) catch return null;
        defer self.state_mutex.unlock(self.io);
        if (self.last_stream_id == 0) return null;
        return .{ .connection = self, .id = self.last_stream_id };
    }

    pub fn headers(self: *Connection) []const Header {
        self.state_mutex.lock(self.io) catch return &.{};
        defer self.state_mutex.unlock(self.io);
        const index = self.streamIndex(self.last_accepted_id) orelse
            return &.{};
        return self.streams[index].header_list[0..self.streams[index].header_count];
    }

    pub fn streamHeaders(self: *Connection, id: u32) []const Header {
        self.state_mutex.lock(self.io) catch return &.{};
        defer self.state_mutex.unlock(self.io);
        const index = self.streamIndex(id) orelse return &.{};
        return self.streams[index].header_list[0..self.streams[index].header_count];
    }

    pub fn streamTrailers(self: *Connection, id: u32) []const Header {
        self.state_mutex.lock(self.io) catch return &.{};
        defer self.state_mutex.unlock(self.io);
        const index = self.streamIndex(id) orelse return &.{};
        return self.streams[index].trailer_list[0..self.streams[index].trailer_count];
    }

    pub fn informationalStatus(self: *Connection, id: u32) u16 {
        self.state_mutex.lock(self.io) catch return 0;
        defer self.state_mutex.unlock(self.io);
        const index = self.streamIndex(id) orelse return 0;
        return self.streams[index].informational_status;
    }

    pub fn deinit(self: *Connection) void {
        for (&self.streams) |*entry| entry.zeroize();
        self.decoder.zeroize();
        std.crypto.secureZero(u8, &self.frame_buffer);
        std.crypto.secureZero(u8, &self.header_block);
        std.crypto.secureZero(u8, &self.send_block);
        self.header_block_len = 0;
    }

    pub fn cancel(self: *Connection) void {
        self.canceled.store(true, .release);
        self.window_event.set(self.io);
    }

    /// Sends a last-stream GOAWAY and leaves in-flight streams running.
    pub fn closeGracefully(self: *Connection) Error!void {
        return self.sendGoaway(error_code_no_error);
    }

    fn streamIndex(self: *const Connection, id: u32) ?usize {
        for (&self.streams, 0..) |*entry, index| {
            if (entry.id == id and entry.state != .idle) return index;
        }
        return null;
    }

    fn freeStreamIndex(self: *Connection) ?usize {
        for (&self.streams, 0..) |*entry, index| {
            if (entry.state == .idle) return index;
            if (entry.state == .closed and entry.id != 0) return index;
        }
        return null;
    }

    fn activeStreamCount(self: *const Connection) usize {
        var count: usize = 0;
        for (&self.streams) |*entry| {
            if (entry.state == .open or
                entry.state == .half_closed_local or
                entry.state == .half_closed_remote)
            {
                count += 1;
            }
        }
        return count;
    }

    fn allocStream(
        self: *Connection,
        id: u32,
        send_window: i64,
    ) ?usize {
        const index = self.freeStreamIndex() orelse return null;
        self.streams[index].reset();
        self.streams[index].id = id;
        self.streams[index].state = .open;
        self.streams[index].send_window = send_window;
        self.streams[index].recv_window = stream_recv_window;
        return index;
    }

    fn abortStream(self: *Connection, id: u32) void {
        self.state_mutex.lock(self.io) catch return;
        defer self.state_mutex.unlock(self.io);
        const index = self.streamIndex(id) orelse return;
        const entry = &self.streams[index];
        entry.aborted = true;
        entry.remote_end = true;
        entry.local_end = true;
        entry.zeroizeBuffers();
        entry.refreshState();
        self.window_event.set(self.io);
    }

    fn markLocalEnd(self: *Connection, id: u32) void {
        self.state_mutex.lock(self.io) catch return;
        defer self.state_mutex.unlock(self.io);
        const index = self.streamIndex(id) orelse return;
        self.streams[index].local_end = true;
        self.streams[index].refreshState();
    }

    fn markRemoteEnd(self: *Connection, entry: *StreamEntry) void {
        _ = self;
        entry.remote_end = true;
        entry.refreshState();
    }

    fn takeAccepted(self: *Connection) ?u32 {
        self.state_mutex.lock(self.io) catch return null;
        defer self.state_mutex.unlock(self.io);
        for (&self.streams) |*entry| {
            if (entry.state == .idle or entry.state == .closed) continue;
            if (!entry.headers_seen or entry.accepted) continue;
            entry.accepted = true;
            self.last_accepted_id = entry.id;
            self.last_stream_id = entry.id;
            return entry.id;
        }
        return null;
    }

    fn acceptNext(self: *Connection) Error!Stream {
        while (true) {
            if (self.canceled.load(.acquire)) return error.Canceled;
            if (self.takeAccepted()) |id| {
                return .{ .connection = self, .id = id };
            }
            var stopping = false;
            {
                self.state_mutex.lock(self.io) catch return error.Canceled;
                defer self.state_mutex.unlock(self.io);
                stopping = self.goaway_received or self.goaway_sent;
            }
            if (stopping) return error.Closed;
            self.pumpFrame() catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => return error.Closed,
                error.ProtocolViolation => return error.ProtocolViolation,
                error.Unexpected => return error.Unexpected,
                else => return error.Unexpected,
            };
        }
    }

    fn readStream(
        self: *Connection,
        id: u32,
        buffers: [][]u8,
    ) Error!usize {
        if (totalCapacity(buffers) == 0) return error.Unexpected;
        while (true) {
            if (self.canceled.load(.acquire)) return error.Canceled;
            var credit: usize = 0;
            var result: ?usize = null;
            var aborted = false;
            {
                self.state_mutex.lock(self.io) catch return error.Canceled;
                defer self.state_mutex.unlock(self.io);
                const index = self.streamIndex(id) orelse return error.Closed;
                const entry = &self.streams[index];
                if (entry.aborted) {
                    aborted = true;
                } else if (entry.data_len != 0) {
                    credit = entry.copyData(buffers);
                    result = credit;
                } else if (entry.remote_end) {
                    result = 0;
                }
            }
            if (aborted) return error.ConnectionReset;
            if (result) |copied| {
                if (credit != 0) self.replenish(id, credit);
                return copied;
            }
            self.pumpFrame() catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => return error.ConnectionReset,
                else => return err,
            };
        }
    }

    fn writeStream(
        self: *Connection,
        id: u32,
        buffers: []const []const u8,
    ) Error!usize {
        var total: usize = 0;
        for (buffers) |bytes| {
            var offset: usize = 0;
            while (offset < bytes.len) {
                const allowed = try self.waitForWindow(id);
                const chunk_len = @min(allowed, bytes.len - offset);
                const chunk = bytes[offset..][0..chunk_len];
                self.write_mutex.lock(self.io) catch return error.Canceled;
                var sent: usize = 0;
                {
                    defer self.write_mutex.unlock(self.io);
                    self.state_mutex.lock(self.io) catch return error.Canceled;
                    {
                        defer self.state_mutex.unlock(self.io);
                        const index = self.streamIndex(id) orelse
                            return error.Closed;
                        const entry = &self.streams[index];
                        if (entry.aborted or entry.local_end) {
                            return error.Closed;
                        }
                        const window = @min(
                            entry.send_window,
                            self.conn_send_window,
                        );
                        if (window < @as(i64, @intCast(chunk_len))) {
                            // A SETTINGS update can shrink the window between
                            // waiting and reserving; retry with the new value.
                            continue;
                        }
                        entry.send_window -= @intCast(chunk_len);
                        self.conn_send_window -= @intCast(chunk_len);
                        sent = chunk_len;
                    }
                    try self.sendFrameLocked(
                        frame.type_data,
                        0,
                        id,
                        chunk,
                    );
                    self.output.flush() catch {
                        self.failConnection(error_code_internal);
                        return error.Unexpected;
                    };
                }
                if (sent == 0) continue;
                offset += sent;
            }
            total += bytes.len;
        }
        return total;
    }

    fn waitForWindow(self: *Connection, id: u32) Error!usize {
        while (true) {
            if (self.canceled.load(.acquire)) return error.Canceled;
            var allowed: usize = 0;
            var closed = false;
            var aborted = false;
            {
                self.state_mutex.lock(self.io) catch return error.Canceled;
                defer self.state_mutex.unlock(self.io);
                const index = self.streamIndex(id) orelse return error.Closed;
                const entry = &self.streams[index];
                aborted = entry.aborted;
                closed = entry.local_end;
                const window = @min(entry.send_window, self.conn_send_window);
                if (window > 0) {
                    const frame_limit = @min(
                        self.peer_max_frame_size,
                        frame.max_frame_size,
                    );
                    allowed = @intCast(@min(window, @as(i64, frame_limit)));
                }
            }
            if (aborted or closed) return error.Closed;
            if (allowed != 0) return allowed;

            // A blocked writer must keep the frame pump alive: in a
            // single-threaded embedder nobody else will read the
            // WINDOW_UPDATE. DATA for this stream is queued (bounded by the
            // receive window) for the application reader.
            if (self.input_mutex.tryLock()) {
                defer self.input_mutex.unlock(self.io);
                self.processFrame() catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    error.Closed => return error.Closed,
                    else => return err,
                };
                continue;
            }
            self.window_event.wait(self.io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            self.window_event.reset();
        }
    }

    fn closeStream(self: *Connection, id: u32) Error!void {
        var needs_reset = false;
        var send_end = false;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            const index = self.streamIndex(id) orelse return error.Closed;
            const entry = &self.streams[index];
            if (entry.aborted) return error.Closed;
            if (entry.local_end) return;
            if (!entry.headers_sent) {
                needs_reset = true;
            } else {
                send_end = true;
            }
        }
        if (needs_reset) {
            try self.resetStream(id, error_code_cancel);
            return;
        }
        if (!send_end) return;
        self.write_mutex.lock(self.io) catch return error.Canceled;
        {
            defer self.write_mutex.unlock(self.io);
            try self.sendFrameLocked(
                frame.type_data,
                frame.flag_end_stream,
                id,
                &.{},
            );
            self.output.flush() catch return error.Unexpected;
        }
        self.markLocalEnd(id);
    }

    fn resetStream(self: *Connection, id: u32, code: u32) Error!void {
        try self.sendReset(id, code);
        self.abortStream(id);
    }

    fn sendReset(self: *Connection, id: u32, code: u32) Error!void {
        if (id == 0) return;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, code, .big);
        try self.sendFrame(frame.type_rst_stream, 0, id, &payload);
    }

    fn sendGoaway(self: *Connection, code: u32) Error!void {
        var last_stream_id: u32 = 0;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            if (self.goaway_sent) return;
            self.goaway_sent = true;
            last_stream_id = self.last_peer_stream_id;
        }
        var payload: [8]u8 = undefined;
        std.mem.writeInt(
            u32,
            payload[0..4],
            last_stream_id & 0x7fffffff,
            .big,
        );
        std.mem.writeInt(u32, payload[4..8], code, .big);
        try self.sendFrame(frame.type_goaway, 0, 0, &payload);
    }

    fn failConnection(self: *Connection, code: u32) void {
        self.sendGoaway(code) catch {};
        self.cancel();
    }

    fn connectionError(self: *Connection, code: u32) Error {
        self.failConnection(code);
        return error.ProtocolViolation;
    }

    fn pumpFrame(self: *Connection) Error!void {
        self.input_mutex.lock(self.io) catch return error.Canceled;
        defer self.input_mutex.unlock(self.io);
        if (self.canceled.load(.acquire)) return error.Canceled;
        return self.processFrame();
    }

    fn processFrame(self: *Connection) Error!void {
        const parsed = self.readFrame() catch |err| {
            switch (err) {
                error.ProtocolViolation => self.failConnection(
                    error_code_protocol,
                ),
                else => {},
            }
            return err;
        };
        self.handleFrame(parsed) catch |err| {
            if (err == error.ProtocolViolation) self.cancel();
            return err;
        };
    }

    fn readFrame(self: *Connection) Error!frame.Frame {
        return frame.read(self.input, &self.frame_buffer) catch |err| switch (err) {
            error.Canceled => error.Canceled,
            error.EndOfStream => error.Closed,
            error.ProtocolViolation => error.ProtocolViolation,
            error.Unexpected => error.Unexpected,
        };
    }

    fn handleFrame(self: *Connection, parsed: frame.Frame) Error!void {
        switch (parsed.frame_type) {
            frame.type_data => try self.handleData(parsed),
            frame.type_headers => try self.handleHeadersFrame(parsed),
            frame.type_settings => try self.handleSettings(parsed),
            frame.type_ping => try self.handlePing(parsed),
            frame.type_window_update => try self.handleWindowUpdate(parsed),
            frame.type_goaway => try self.handleGoaway(parsed),
            frame.type_rst_stream => try self.handleReset(parsed),
            frame.type_priority => try self.handlePriority(parsed),
            frame.type_push_promise => return self.connectionError(
                error_code_protocol,
            ),
            frame.type_continuation => return self.connectionError(
                error_code_protocol,
            ),
            else => {},
        }
    }

    fn handleData(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id == 0) {
            return self.connectionError(error_code_protocol);
        }
        var payload = parsed.payload;
        var pad_bytes: usize = 0;
        if (parsed.flags & frame.flag_padded != 0) {
            if (payload.len == 0) {
                return self.connectionError(error_code_protocol);
            }
            const pad_len = payload[0];
            if (pad_len > payload.len - 1) {
                return self.connectionError(error_code_protocol);
            }
            pad_bytes = @as(usize, pad_len) + 1;
            payload = payload[1 .. payload.len - pad_len];
        }
        const flow_len = parsed.payload.len;
        var action: Action = .none;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            action = self.receiveData(
                parsed.stream_id,
                payload,
                flow_len,
                parsed.flags & frame.flag_end_stream != 0,
            );
        }
        switch (action) {
            .none => {
                if (pad_bytes != 0) self.replenish(parsed.stream_id, pad_bytes);
            },
            .reset => |code| {
                self.sendReset(parsed.stream_id, code) catch {};
                self.abortStream(parsed.stream_id);
            },
            .connection => |code| return self.connectionError(code),
        }
    }

    fn receiveData(
        self: *Connection,
        id: u32,
        data: []const u8,
        flow_len: usize,
        end_stream: bool,
    ) Action {
        const index = self.streamIndex(id) orelse {
            if (id <= self.last_peer_stream_id or
                id <= self.last_local_stream_id)
            {
                return .{ .reset = error_code_stream_closed };
            }
            return .{ .connection = error_code_protocol };
        };
        const entry = &self.streams[index];
        if (entry.aborted or entry.state == .closed or entry.remote_end) {
            return .{ .reset = error_code_stream_closed };
        }
        const flow: i64 = @intCast(flow_len);
        if (flow > entry.recv_window or flow > self.conn_recv_window) {
            return .{ .connection = error_code_flow_control };
        }
        entry.recv_window -= flow;
        self.conn_recv_window -= flow;
        entry.appendData(data) catch {
            return .{ .connection = error_code_flow_control };
        };
        if (end_stream) self.markRemoteEnd(entry);
        self.window_event.set(self.io);
        return .none;
    }

    fn replenish(self: *Connection, id: u32, bytes: usize) void {
        if (bytes == 0) return;
        if (self.send_updates_disabled.load(.acquire)) return;
        var active = false;
        {
            self.state_mutex.lock(self.io) catch return;
            defer self.state_mutex.unlock(self.io);
            if (self.streamIndex(id)) |index| {
                const entry = &self.streams[index];
                if (!entry.aborted and entry.state != .closed) {
                    const credit: i64 = @intCast(bytes);
                    entry.recv_window = @min(
                        entry.recv_window + credit,
                        stream_recv_window,
                    );
                    active = true;
                }
            }
            const credit: i64 = @intCast(bytes);
            self.conn_recv_window = @min(
                self.conn_recv_window + credit,
                connection_recv_window,
            );
        }
        if (active) {
            self.sendWindowUpdate(id, bytes) catch {
                self.send_updates_disabled.store(true, .release);
                return;
            };
        }
        self.sendWindowUpdate(0, bytes) catch {
            self.send_updates_disabled.store(true, .release);
        };
    }

    fn handleHeadersFrame(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id == 0) {
            return self.connectionError(error_code_protocol);
        }
        const block = self.readHeaderBlock(parsed) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return self.connectionError(error_code_protocol),
        };
        if (self.role == .server) {
            return self.serverHeaders(parsed, block);
        }
        return self.clientHeaders(parsed, block);
    }

    fn readHeaderBlock(
        self: *Connection,
        first: frame.Frame,
    ) Error![]const u8 {
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
            const next = self.readFrame() catch |err| switch (err) {
                error.Closed => return error.ProtocolViolation,
                else => return err,
            };
            if (next.frame_type != frame.type_continuation or
                next.stream_id != first.stream_id)
            {
                return error.ProtocolViolation;
            }
            try self.appendHeaderFragment(next.payload);
            end_headers = next.flags & frame.flag_end_headers != 0;
        }
        return self.header_block[0..self.header_block_len];
    }

    fn appendHeaderFragment(
        self: *Connection,
        bytes: []const u8,
    ) Error!void {
        if (self.header_block.len - self.header_block_len < bytes.len) {
            return error.ProtocolViolation;
        }
        @memcpy(
            self.header_block[self.header_block_len..][0..bytes.len],
            bytes,
        );
        self.header_block_len += bytes.len;
    }

    fn serverHeaders(
        self: *Connection,
        parsed: frame.Frame,
        block: []const u8,
    ) Error!void {
        const id = parsed.stream_id;
        if (id % 2 == 0) {
            return self.connectionError(error_code_protocol);
        }
        var action: Action = .none;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            if (self.streamIndex(id)) |index| {
                action = self.serverExistingHeaders(
                    &self.streams[index],
                    parsed,
                    block,
                );
            } else if (id <= self.last_peer_stream_id) {
                action = .{ .reset = error_code_stream_closed };
            } else if (self.activeStreamCount() >= max_concurrent_streams) {
                action = .{ .connection = error_code_protocol };
            } else {
                action = self.serverNewStream(id, parsed, block);
            }
        }
        return self.applyAction(id, action);
    }

    fn serverExistingHeaders(
        self: *Connection,
        entry: *StreamEntry,
        parsed: frame.Frame,
        block: []const u8,
    ) Action {
        if (entry.aborted or entry.state == .closed or entry.remote_end) {
            return .{ .reset = error_code_stream_closed };
        }
        if (!entry.headers_seen) {
            return .{ .reset = error_code_protocol };
        }
        if (parsed.flags & frame.flag_end_stream == 0) {
            return .{ .reset = error_code_protocol };
        }
        self.decodeTrailers(entry, block) catch |err| {
            return self.headerDecodeAction(err);
        };
        validateTrailers(
            entry.trailer_list[0..entry.trailer_count],
        ) catch {
            return .{ .reset = error_code_protocol };
        };
        self.markRemoteEnd(entry);
        self.window_event.set(self.io);
        return .none;
    }

    fn serverNewStream(
        self: *Connection,
        id: u32,
        parsed: frame.Frame,
        block: []const u8,
    ) Action {
        const index = self.allocStream(id, self.peer_initial_window) orelse {
            return .{ .reset = error_code_refused_stream };
        };
        const entry = &self.streams[index];
        self.last_peer_stream_id = id;
        self.last_stream_id = id;
        entry.headers_seen = true;
        self.decodeInitial(entry, block) catch |err| {
            entry.reset();
            return self.headerDecodeAction(err);
        };
        validateRequest(entry.header_list[0..entry.header_count], null) catch {
            entry.reset();
            return .{ .reset = error_code_protocol };
        };
        if (parsed.flags & frame.flag_end_stream != 0) {
            self.markRemoteEnd(entry);
        }
        self.window_event.set(self.io);
        return .none;
    }

    fn clientHeaders(
        self: *Connection,
        parsed: frame.Frame,
        block: []const u8,
    ) Error!void {
        const id = parsed.stream_id;
        if (id % 2 == 0) {
            return self.connectionError(error_code_protocol);
        }
        var action: Action = .none;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            if (self.streamIndex(id)) |index| {
                action = self.clientStreamHeaders(
                    &self.streams[index],
                    parsed,
                    block,
                );
            } else if (id <= self.last_local_stream_id) {
                action = .{ .reset = error_code_stream_closed };
            } else {
                action = .{ .connection = error_code_protocol };
            }
        }
        return self.applyAction(id, action);
    }

    fn clientStreamHeaders(
        self: *Connection,
        entry: *StreamEntry,
        parsed: frame.Frame,
        block: []const u8,
    ) Action {
        if (entry.aborted or entry.state == .closed) {
            return .{ .reset = error_code_stream_closed };
        }
        const end_stream = parsed.flags & frame.flag_end_stream != 0;
        if (!entry.headers_seen) {
            self.decodeInitial(entry, block) catch |err| {
                return self.headerDecodeAction(err);
            };
            const status = validateResponseInitial(
                entry.header_list[0..entry.header_count],
            ) catch {
                entry.header_count = 0;
                return .{ .reset = error_code_protocol };
            };
            if (status < 200) {
                if (end_stream) {
                    entry.header_count = 0;
                    return .{ .reset = error_code_protocol };
                }
                entry.informational_status = status;
                entry.header_count = 0;
                return .none;
            }
            entry.headers_seen = true;
        } else {
            if (!end_stream or entry.remote_end) {
                return .{ .reset = error_code_protocol };
            }
            self.decodeTrailers(entry, block) catch |err| {
                return self.headerDecodeAction(err);
            };
            validateTrailers(
                entry.trailer_list[0..entry.trailer_count],
            ) catch {
                return .{ .reset = error_code_protocol };
            };
        }
        if (end_stream) self.markRemoteEnd(entry);
        self.window_event.set(self.io);
        return .none;
    }

    fn decodeInitial(
        self: *Connection,
        entry: *StreamEntry,
        block: []const u8,
    ) hpack.Error!void {
        const list = try self.decoder.decodeBounded(
            block,
            &entry.header_storage,
            &entry.header_list,
            hpack.max_header_list,
        );
        entry.header_count = list.len;
    }

    fn decodeTrailers(
        self: *Connection,
        entry: *StreamEntry,
        block: []const u8,
    ) hpack.Error!void {
        const list = try self.decoder.decodeBounded(
            block,
            &entry.trailer_storage,
            &entry.trailer_list,
            hpack.max_header_list,
        );
        entry.trailer_count = list.len;
    }

    fn headerDecodeAction(self: *Connection, err: hpack.Error) Action {
        _ = self;
        return switch (err) {
            error.Malformed => .{ .connection = error_code_compression },
            error.OutOfMemory => .{ .reset = error_code_enhance_your_calm },
        };
    }

    fn applyAction(
        self: *Connection,
        id: u32,
        action: Action,
    ) Error!void {
        switch (action) {
            .none => {},
            .reset => |code| {
                self.sendReset(id, code) catch {};
                self.abortStream(id);
            },
            .connection => |code| return self.connectionError(code),
        }
    }

    fn handleSettings(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id != 0) {
            return self.connectionError(error_code_protocol);
        }
        if (parsed.flags & frame.flag_ack != 0) {
            if (parsed.payload.len != 0) {
                return self.connectionError(error_code_frame_size);
            }
            return;
        }
        if (parsed.payload.len % 6 != 0) {
            return self.connectionError(error_code_frame_size);
        }
        var failure: u32 = 0;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            var index: usize = 0;
            while (index < parsed.payload.len) : (index += 6) {
                const identifier = std.mem.readInt(
                    u16,
                    parsed.payload[index..][0..2],
                    .big,
                );
                const value = std.mem.readInt(
                    u32,
                    parsed.payload[index + 2 ..][0..4],
                    .big,
                );
                failure = self.applySettingLocked(identifier, value);
                if (failure != 0) break;
            }
        }
        if (failure != 0) return self.connectionError(failure);
        try self.sendFrame(frame.type_settings, frame.flag_ack, 0, &.{});
    }

    fn applySettingLocked(
        self: *Connection,
        identifier: u16,
        value: u32,
    ) u32 {
        switch (identifier) {
            setting_initial_window_size => {
                if (value > frame.max_window) return error_code_flow_control;
                const delta = @as(i64, value) - self.peer_initial_window;
                for (&self.streams) |*entry| {
                    if (entry.state == .idle) continue;
                    const next = entry.send_window + delta;
                    if (next > frame.max_window or next < -frame.max_window) {
                        return error_code_flow_control;
                    }
                }
                for (&self.streams) |*entry| {
                    if (entry.state == .idle) continue;
                    entry.send_window += delta;
                }
                self.peer_initial_window = value;
                self.window_event.set(self.io);
            },
            setting_max_frame_size => {
                if (value < frame.max_frame_size or value > 0x00ffffff) {
                    return error_code_protocol;
                }
                self.peer_max_frame_size = value;
            },
            setting_max_concurrent_streams => {
                self.peer_max_concurrent = value;
            },
            setting_enable_push => {
                // RFC 9113 forbids a server from sending this setting, but
                // hyper-h2 4.4.1 sends ENABLE_PUSH=0 from servers and some
                // deployments tolerate it. Accept 0 (push disabled); never
                // allow 1, which would require server-push support.
                if (value > 1) return error_code_protocol;
                if (self.role == .client and value == 1) {
                    return error_code_protocol;
                }
            },
            setting_header_table_size,
            setting_max_header_list_size,
            => {},
            else => {},
        }
        return 0;
    }

    fn handlePing(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id != 0) {
            return self.connectionError(error_code_protocol);
        }
        if (parsed.payload.len != 8) {
            return self.connectionError(error_code_frame_size);
        }
        if (parsed.flags & frame.flag_ack != 0) return;
        try self.sendFrame(
            frame.type_ping,
            frame.flag_ack,
            0,
            parsed.payload,
        );
    }

    fn handleWindowUpdate(
        self: *Connection,
        parsed: frame.Frame,
    ) Error!void {
        if (parsed.payload.len != 4) {
            return self.connectionError(error_code_frame_size);
        }
        const increment = std.mem.readInt(
            u32,
            parsed.payload[0..4],
            .big,
        ) & 0x7fffffff;
        if (increment == 0) {
            if (parsed.stream_id == 0) {
                return self.connectionError(error_code_protocol);
            }
            return self.resetStream(parsed.stream_id, error_code_protocol);
        }
        var failure: u32 = 0;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            failure = self.applyWindowUpdate(parsed.stream_id, increment);
            self.window_event.set(self.io);
        }
        if (failure != 0) return self.connectionError(failure);
    }

    fn applyWindowUpdate(
        self: *Connection,
        id: u32,
        increment: u32,
    ) u32 {
        const credit: i64 = @intCast(increment);
        if (id == 0) {
            if (self.conn_send_window > frame.max_window - credit) {
                return error_code_flow_control;
            }
            self.conn_send_window += credit;
            return 0;
        }
        const index = self.streamIndex(id) orelse {
            if (id > self.last_peer_stream_id and
                id > self.last_local_stream_id)
            {
                return error_code_protocol;
            }
            return 0;
        };
        const entry = &self.streams[index];
        if (entry.state == .closed) return 0;
        if (entry.send_window > frame.max_window - credit) {
            return error_code_flow_control;
        }
        entry.send_window += credit;
        return 0;
    }

    fn handleReset(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id == 0) {
            return self.connectionError(error_code_protocol);
        }
        if (parsed.payload.len != 4) {
            return self.connectionError(error_code_frame_size);
        }
        var idle = false;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            if (self.streamIndex(parsed.stream_id)) |index| {
                const entry = &self.streams[index];
                entry.aborted = true;
                entry.remote_end = true;
                entry.local_end = true;
                entry.zeroizeBuffers();
                entry.refreshState();
                self.window_event.set(self.io);
            } else if (parsed.stream_id > self.last_peer_stream_id and
                parsed.stream_id > self.last_local_stream_id)
            {
                idle = true;
            }
        }
        if (idle) return self.connectionError(error_code_protocol);
    }

    fn handlePriority(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id == 0) {
            return self.connectionError(error_code_protocol);
        }
        if (parsed.payload.len != 5) {
            return self.connectionError(error_code_frame_size);
        }
    }

    fn handleGoaway(self: *Connection, parsed: frame.Frame) Error!void {
        if (parsed.stream_id != 0) {
            return self.connectionError(error_code_protocol);
        }
        if (parsed.payload.len < 8) {
            return self.connectionError(error_code_frame_size);
        }
        const last_stream_id = std.mem.readInt(
            u32,
            parsed.payload[0..4],
            .big,
        ) & 0x7fffffff;
        const code = std.mem.readInt(u32, parsed.payload[4..8], .big);
        self.state_mutex.lock(self.io) catch return error.Canceled;
        defer self.state_mutex.unlock(self.io);
        self.goaway_received = true;
        self.goaway_error = code;
        for (&self.streams) |*entry| {
            if (entry.state == .idle) continue;
            if (code != error_code_no_error or entry.id > last_stream_id) {
                entry.aborted = true;
                entry.remote_end = true;
                entry.local_end = true;
                entry.zeroizeBuffers();
                entry.refreshState();
            }
        }
        self.window_event.set(self.io);
    }

    fn sendHeaders(
        self: *Connection,
        id: u32,
        header_list: []const Header,
        end_stream: bool,
    ) Error!void {
        try self.prepareHeaders(id, header_list, end_stream);
        self.writer_serial.lock(self.io) catch return error.Canceled;
        defer self.writer_serial.unlock(self.io);
        const block_len = try self.encodeHeaderBlock(header_list);
        try self.writeHeaderBlock(id, block_len, end_stream);
        try self.finishHeaders(id, end_stream);
    }

    fn prepareHeaders(
        self: *Connection,
        id: u32,
        header_list: []const Header,
        end_stream: bool,
    ) Error!void {
        var first = false;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            const index = self.streamIndex(id) orelse return error.Closed;
            const entry = &self.streams[index];
            if (entry.aborted or entry.state == .closed or entry.local_end) {
                return error.Closed;
            }
            first = !entry.headers_sent;
            if (!first and !end_stream) return error.ProtocolViolation;
        }
        if (first) {
            if (self.role == .client) {
                try validateRequest(header_list, null);
            } else {
                _ = try validateResponseInitial(header_list);
            }
        } else {
            try validateTrailers(header_list);
        }
    }

    fn encodeHeaderBlock(
        self: *Connection,
        header_list: []const Header,
    ) Error!usize {
        var block_len: usize = 0;
        for (header_list) |header| {
            hpack.encodeHeader(
                &self.send_block,
                &block_len,
                header.name,
                header.value,
            ) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.Malformed => error.ProtocolViolation,
            };
        }
        return block_len;
    }

    fn writeHeaderBlock(
        self: *Connection,
        id: u32,
        block_len: usize,
        end_stream: bool,
    ) Error!void {
        self.state_mutex.lock(self.io) catch return error.Canceled;
        const max_chunk = @min(
            frame.max_frame_size,
            self.peer_max_frame_size,
        );
        self.state_mutex.unlock(self.io);

        self.write_mutex.lock(self.io) catch return error.Canceled;
        defer self.write_mutex.unlock(self.io);
        var offset: usize = 0;
        var is_first = true;
        while (true) {
            const remaining = block_len - offset;
            const chunk_len = @min(remaining, max_chunk);
            const last = offset + chunk_len == block_len;
            var flags: u8 = 0;
            if (last) flags |= frame.flag_end_headers;
            if (last and end_stream) flags |= frame.flag_end_stream;
            const frame_type = if (is_first)
                frame.type_headers
            else
                frame.type_continuation;
            try self.sendFrameLocked(
                frame_type,
                flags,
                id,
                self.send_block[offset..][0..chunk_len],
            );
            offset += chunk_len;
            is_first = false;
            if (last) break;
        }
        self.output.flush() catch return error.Unexpected;
    }

    fn finishHeaders(
        self: *Connection,
        id: u32,
        end_stream: bool,
    ) Error!void {
        self.state_mutex.lock(self.io) catch return error.Canceled;
        defer self.state_mutex.unlock(self.io);
        const index = self.streamIndex(id) orelse return error.Closed;
        const entry = &self.streams[index];
        entry.headers_sent = true;
        if (end_stream) {
            entry.local_end = true;
            entry.refreshState();
        }
    }

    fn sendTrailers(
        self: *Connection,
        id: u32,
        header_list: []const Header,
    ) Error!void {
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            const index = self.streamIndex(id) orelse return error.Closed;
            if (!self.streams[index].headers_sent) {
                return error.ProtocolViolation;
            }
        }
        return self.sendHeaders(id, header_list, true);
    }

    fn openStream(
        self: *Connection,
        header_list: []const Header,
    ) Error!Stream {
        try validateRequest(header_list, null);
        var id: u32 = 0;
        {
            self.state_mutex.lock(self.io) catch return error.Canceled;
            defer self.state_mutex.unlock(self.io);
            if (self.goaway_received or self.goaway_sent) return error.Closed;
            if (self.activeStreamCount() >= max_concurrent_streams) {
                return error.TooManyStreams;
            }
            if (self.activeStreamCount() >= self.peer_max_concurrent) {
                return error.TooManyStreams;
            }
            if (self.last_local_stream_id == 0) {
                id = 1;
            } else {
                if (self.last_local_stream_id > 0x7ffffffd) {
                    return error.Closed;
                }
                id = self.last_local_stream_id + 2;
            }
            _ = self.allocStream(id, self.peer_initial_window) orelse {
                return error.TooManyStreams;
            };
            self.last_local_stream_id = id;
            self.last_stream_id = id;
        }
        errdefer self.abortStream(id);
        try self.sendHeaders(id, header_list, false);
        return .{ .connection = self, .id = id };
    }

    fn sendWindowUpdate(
        self: *Connection,
        id: u32,
        increment: usize,
    ) Error!void {
        if (increment == 0 or increment > frame.max_window) return;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, @intCast(increment), .big);
        try self.sendFrame(frame.type_window_update, 0, id, &payload);
    }

    fn sendFrame(
        self: *Connection,
        frame_type: u8,
        flags: u8,
        id: u32,
        payload: []const u8,
    ) Error!void {
        self.write_mutex.lock(self.io) catch return error.Canceled;
        defer self.write_mutex.unlock(self.io);
        try self.sendFrameLocked(frame_type, flags, id, payload);
        self.output.flush() catch return error.Unexpected;
    }

    fn sendFrameLocked(
        self: *Connection,
        frame_type: u8,
        flags: u8,
        id: u32,
        payload: []const u8,
    ) Error!void {
        frame.write(
            self.output,
            frame_type,
            flags,
            id,
            payload,
        ) catch |err| switch (err) {
            error.ProtocolViolation => return error.ProtocolViolation,
            else => return error.Unexpected,
        };
    }

    fn sendOurSettings(self: *Connection) Error!void {
        var payload: [64]u8 = undefined;
        var len: usize = 0;
        if (self.role == .client) {
            len = appendSetting(&payload, len, setting_enable_push, 0);
        }
        len = appendSetting(
            &payload,
            len,
            setting_max_concurrent_streams,
            max_concurrent_streams,
        );
        len = appendSetting(
            &payload,
            len,
            setting_initial_window_size,
            stream_recv_window,
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
            hpack.max_header_list,
        );
        try self.sendFrame(frame.type_settings, 0, 0, payload[0..len]);
        try self.sendWindowUpdate(
            0,
            @intCast(connection_recv_window - frame.default_window),
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

const FieldKind = enum { request, response, trailers };

fn validateFields(headers: []const Header, kind: FieldKind) Error!void {
    var regular_seen = false;
    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;
    var seen_status = false;
    var list_size: usize = 0;
    for (headers) |header| {
        if (header.name.len == 0) return error.ProtocolViolation;
        list_size += header.name.len + header.value.len + 32;
        if (list_size > hpack.max_header_list) {
            return error.ProtocolViolation;
        }
        if (!validFieldValue(header.value)) return error.ProtocolViolation;
        if (header.name[0] == ':') {
            if (regular_seen or kind == .trailers) {
                return error.ProtocolViolation;
            }
            if (std.mem.eql(u8, header.name, ":method")) {
                if (kind != .request or seen_method) return error.ProtocolViolation;
                seen_method = true;
            } else if (std.mem.eql(u8, header.name, ":scheme")) {
                if (kind != .request or seen_scheme) return error.ProtocolViolation;
                seen_scheme = true;
            } else if (std.mem.eql(u8, header.name, ":path")) {
                if (kind != .request or seen_path) return error.ProtocolViolation;
                seen_path = true;
            } else if (std.mem.eql(u8, header.name, ":authority")) {
                if (kind != .request or seen_authority) return error.ProtocolViolation;
                seen_authority = true;
            } else if (std.mem.eql(u8, header.name, ":status")) {
                if (kind != .response or seen_status) return error.ProtocolViolation;
                seen_status = true;
            } else {
                return error.ProtocolViolation;
            }
            continue;
        }
        regular_seen = true;
        if (!validFieldName(header.name)) return error.ProtocolViolation;
        if (isConnectionSpecific(header.name)) return error.ProtocolViolation;
        if (std.mem.eql(u8, header.name, "te") and
            !std.mem.eql(u8, header.value, "trailers"))
        {
            return error.ProtocolViolation;
        }
    }
}

fn validateRequest(headers: []const Header, path: ?[]const u8) Error!void {
    try validateFields(headers, .request);
    const method = findHeader(headers, ":method") orelse
        return error.ProtocolViolation;
    if (method.len == 0) return error.ProtocolViolation;
    const scheme = findHeader(headers, ":scheme");
    const request_path = findHeader(headers, ":path");
    const authority = findHeader(headers, ":authority");
    const host = findHeader(headers, "host");
    const target = authority orelse host orelse
        return error.ProtocolViolation;
    if (target.len == 0) return error.ProtocolViolation;
    if (authority != null and host != null and
        !std.mem.eql(u8, authority.?, host.?))
    {
        return error.ProtocolViolation;
    }

    if (std.mem.eql(u8, method, "CONNECT")) {
        if (scheme != null or request_path != null) {
            return error.ProtocolViolation;
        }
    } else {
        const value = scheme orelse return error.ProtocolViolation;
        const route = request_path orelse return error.ProtocolViolation;
        if (value.len == 0 or route.len == 0) {
            return error.ProtocolViolation;
        }
        if (route[0] != '/' and
            !(std.mem.eql(u8, method, "OPTIONS") and
                std.mem.eql(u8, route, "*")))
        {
            return error.ProtocolViolation;
        }
    }
    if (path) |expected| {
        const route = request_path orelse return error.ProtocolViolation;
        if (!std.mem.eql(u8, route, expected)) {
            return error.ProtocolViolation;
        }
    }
}

fn validateResponseInitial(headers: []const Header) Error!u16 {
    try validateFields(headers, .response);
    const status = findHeader(headers, ":status") orelse
        return error.ProtocolViolation;
    if (status.len != 3) return error.ProtocolViolation;
    for (status) |byte| {
        if (byte < '0' or byte > '9') return error.ProtocolViolation;
    }
    const code = std.fmt.parseInt(u16, status, 10) catch
        return error.ProtocolViolation;
    if (code < 100 or code > 599) return error.ProtocolViolation;
    return code;
}

fn validateTrailers(headers: []const Header) Error!void {
    try validateFields(headers, .trailers);
}

fn validFieldName(name: []const u8) bool {
    if (name.len == 0 or name[0] == ':') return false;
    for (name) |byte| {
        if (!isToken(byte)) return false;
    }
    return true;
}

fn validFieldValue(value: []const u8) bool {
    if (value.len != 0 and
        (value[0] == ' ' or value[0] == '\t' or
            value[value.len - 1] == ' ' or value[value.len - 1] == '\t'))
    {
        return false;
    }
    for (value) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or byte == 0x7f) {
            return false;
        }
        if (byte < 0x20 and byte != '\t') return false;
    }
    return true;
}

fn isToken(byte: u8) bool {
    if (byte >= 'A' and byte <= 'Z') return false;
    return std.ascii.isAlphanumeric(byte) or
        byte == '!' or byte == '#' or byte == '$' or byte == '%' or
        byte == '&' or byte == '\'' or byte == '*' or byte == '+' or
        byte == '-' or byte == '.' or byte == '^' or byte == '_' or
        byte == '`' or byte == '|' or byte == '~';
}

fn isConnectionSpecific(name: []const u8) bool {
    const names = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    };
    for (names) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return true;
    }
    return false;
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

    pub fn openStream(
        self: *Client,
        headers: []const Header,
    ) Error!Stream {
        return self.connection.openStream(headers);
    }

    pub fn stream(self: *Client) ?Stream {
        return self.connection.stream();
    }

    pub fn closeGracefully(self: *Client) Error!void {
        return self.connection.closeGracefully();
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
        try server.connection.handleSettings(first);
        return server;
    }

    pub fn acceptStream(self: *Server) Error!Stream {
        return self.connection.acceptNext();
    }

    pub fn headers(self: *Server) []const Header {
        return self.connection.headers();
    }

    pub fn stream(self: *Server) ?Stream {
        return self.connection.stream();
    }

    pub fn closeGracefully(self: *Server) Error!void {
        return self.connection.closeGracefully();
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
        const parsed = connection.readFrame() catch |err| switch (err) {
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
            connection.handleSettings(parsed) catch
                return error.HandshakeFailed;
            got_settings = true;
            continue;
        }
        if (parsed.frame_type == frame.type_ping) {
            connection.handlePing(parsed) catch return error.HandshakeFailed;
            continue;
        }
        if (parsed.frame_type == frame.type_window_update) {
            connection.handleWindowUpdate(parsed) catch
                return error.HandshakeFailed;
            continue;
        }
        if (parsed.frame_type == frame.type_goaway) {
            return error.HandshakeFailed;
        }
    }
}

fn testConnection(
    role: Role,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
) Connection {
    return .{
        .io = std.testing.io,
        .input = input,
        .output = output,
        .role = role,
    };
}

fn encodeBlock(block: []u8, header_list: []const Header) !usize {
    var len: usize = 0;
    for (header_list) |header| {
        try hpack.encodeHeader(block, &len, header.name, header.value);
    }
    return len;
}

fn writeHeaders(
    writer: *std.Io.Writer,
    id: u32,
    header_list: []const Header,
    end_stream: bool,
) !void {
    var block: [4096]u8 = undefined;
    const len = try encodeBlock(&block, header_list);
    var flags: u8 = frame.flag_end_headers;
    if (end_stream) flags |= frame.flag_end_stream;
    try frame.write(writer, frame.type_headers, flags, id, block[0..len]);
}

test "client settings include the advertised stream limit" {
    const connection: Connection = .{
        .io = std.testing.io,
        .input = undefined,
        .output = undefined,
        .role = .client,
    };
    try std.testing.expectEqual(
        @as(i64, frame.default_window),
        connection.conn_send_window,
    );
}

test "server demultiplexes interleaved streams" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const input_writer = &input_storage.writer;
    const request = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try writeHeaders(input_writer, 1, &request, false);
    try writeHeaders(input_writer, 3, &request, false);
    try frame.write(input_writer, frame.type_data, 0, 3, "three");
    try frame.write(
        input_writer,
        frame.type_data,
        frame.flag_end_stream,
        1,
        "one",
    );

    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();

    const first = try connection.acceptNext();
    try std.testing.expectEqual(@as(u32, 1), first.id);
    const second = try connection.acceptNext();
    try std.testing.expectEqual(@as(u32, 3), second.id);

    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const first_len = try first.read(&buffers);
    try std.testing.expectEqualStrings("one", buffer[0..first_len]);
    const second_len = try second.read(&buffers);
    try std.testing.expectEqualStrings("three", buffer[0..second_len]);
}

test "client accepts 1xx, final headers, and trailers" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const input_writer = &input_storage.writer;
    const informational = [_]Header{
        .{ .name = ":status", .value = "103" },
        .{ .name = "link", .value = "</style.css>" },
    };
    const final = [_]Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    };
    const trailers = [_]Header{
        .{ .name = "grpc-status", .value = "0" },
    };
    try writeHeaders(input_writer, 1, &informational, false);
    try writeHeaders(input_writer, 1, &final, false);
    try writeHeaders(input_writer, 1, &trailers, true);

    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var client = Client{ .connection = testConnection(
        .client,
        &input,
        &output.writer,
    ) };
    defer client.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/grpc.Service/Method" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const stream = try client.openStream(&request);
    var buffer: [8]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectEqual(@as(usize, 0), try stream.read(&buffers));
    try std.testing.expectEqual(@as(u16, 103), stream.informationalStatus());
    try std.testing.expectEqualStrings(
        "200",
        findHeader(stream.headers(), ":status").?,
    );
    try std.testing.expectEqualStrings(
        "0",
        findHeader(stream.trailers(), "grpc-status").?,
    );
}

test "server exposes request trailers with END_STREAM" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const input_writer = &input_storage.writer;
    const request = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/grpc.Service/Method" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const trailers = [_]Header{
        .{ .name = "grpc-status", .value = "12" },
    };
    try writeHeaders(input_writer, 1, &request, false);
    try frame.write(input_writer, frame.type_data, 0, 1, "grpc-body");
    try writeHeaders(input_writer, 1, &trailers, true);

    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    const stream = try connection.acceptNext();
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const len = try stream.read(&buffers);
    try std.testing.expectEqualStrings("grpc-body", buffer[0..len]);
    try std.testing.expectEqual(@as(usize, 0), try stream.read(&buffers));
    try std.testing.expectEqualStrings(
        "12",
        findHeader(stream.trailers(), "grpc-status").?,
    );
}

test "server sends RST_STREAM for an invalid request and stays usable" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const input_writer = &input_storage.writer;
    const invalid = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "connection", .value = "keep-alive" },
    };
    const valid = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/ok" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try writeHeaders(input_writer, 1, &invalid, true);
    try writeHeaders(input_writer, 3, &valid, true);

    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    const stream = try connection.acceptNext();
    try std.testing.expectEqual(@as(u32, 3), stream.id);

    var offset: usize = 0;
    var reader = std.Io.Reader.fixed(output.written());
    var buffer: [frame.max_frame_size]u8 = undefined;
    const reset = try frame.read(&reader, &buffer);
    _ = &offset;
    try std.testing.expectEqual(frame.type_rst_stream, reset.frame_type);
    try std.testing.expectEqual(
        error_code_protocol,
        std.mem.readInt(u32, reset.payload[0..4], .big),
    );
}

test "receive flow-control violation sends GOAWAY with FLOW_CONTROL_ERROR" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const input_writer = &input_storage.writer;
    const request = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try writeHeaders(input_writer, 1, &request, false);
    var oversized: [stream_window_bytes + 1]u8 = undefined;
    @memset(&oversized, 'a');
    try frame.write(input_writer, frame.type_data, 0, 1, &oversized);

    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    const stream = try connection.acceptNext();
    var sink: [8]u8 = undefined;
    var buffers = [_][]u8{&sink};
    try std.testing.expectError(
        error.ProtocolViolation,
        stream.read(&buffers),
    );

    var reader = std.Io.Reader.fixed(output.written());
    var buffer: [frame.max_frame_size]u8 = undefined;
    const goaway = try frame.read(&reader, &buffer);
    try std.testing.expectEqual(frame.type_goaway, goaway.frame_type);
    try std.testing.expectEqual(
        error_code_flow_control,
        std.mem.readInt(u32, goaway.payload[4..8], .big),
    );
}

test "DATA on stream zero sends GOAWAY" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    try frame.write(&input_storage.writer, frame.type_data, 0, 0, "x");
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.acceptNext(),
    );
    var reader = std.Io.Reader.fixed(output.written());
    var buffer: [frame.max_frame_size]u8 = undefined;
    const goaway = try frame.read(&reader, &buffer);
    try std.testing.expectEqual(frame.type_goaway, goaway.frame_type);
    try std.testing.expectEqual(
        error_code_protocol,
        std.mem.readInt(u32, goaway.payload[4..8], .big),
    );
}

test "server rejects an even stream id" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try writeHeaders(&input_storage.writer, 2, &request, true);
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.acceptNext(),
    );
}

test "client rejects a response on an unopened stream" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const response = [_]Header{
        .{ .name = ":status", .value = "200" },
    };
    try writeHeaders(&input_storage.writer, 1, &response, true);
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.client, &input, &output.writer);
    defer connection.deinit();
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.acceptNext(),
    );
}

test "SETTINGS_INITIAL_WINDOW_SIZE adjusts existing streams" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try writeHeaders(&input_storage.writer, 1, &request, true);
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    _ = try connection.acceptNext();
    var payload: [6]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], setting_initial_window_size, .big);
    std.mem.writeInt(u32, payload[2..6], 100_000, .big);
    connection.state_mutex.lock(std.testing.io) catch unreachable;
    const failure = connection.applySettingLocked(
        setting_initial_window_size,
        100_000,
    );
    connection.state_mutex.unlock(std.testing.io);
    try std.testing.expectEqual(@as(u32, 0), failure);
    try std.testing.expectEqual(
        @as(i64, 100_000),
        connection.streams[0].send_window,
    );
}

test "graceful close sends GOAWAY with NO_ERROR" {
    const allocator = std.testing.allocator;
    var input = std.Io.Reader.fixed(&.{});
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    try connection.closeGracefully();
    var reader = std.Io.Reader.fixed(output.written());
    var buffer: [frame.max_frame_size]u8 = undefined;
    const goaway = try frame.read(&reader, &buffer);
    try std.testing.expectEqual(frame.type_goaway, goaway.frame_type);
    try std.testing.expectEqual(
        error_code_no_error,
        std.mem.readInt(u32, goaway.payload[4..8], .big),
    );
}

test "stream half-close sends END_STREAM and blocks further writes" {
    const allocator = std.testing.allocator;
    var input = std.Io.Reader.fixed(&.{});
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    const index = connection.allocStream(1, frame.default_window).?;
    connection.last_stream_id = 1;
    const stream = connection.stream().?;
    const response = [_]Header{
        .{ .name = ":status", .value = "200" },
    };
    try stream.sendHeaders(&response, false);
    try stream.close();
    try std.testing.expectError(error.Closed, stream.write(&.{"x"}));
    var buffer: [8]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    connection.state_mutex.lock(std.testing.io) catch unreachable;
    connection.streams[index].remote_end = true;
    connection.streams[index].refreshState();
    connection.state_mutex.unlock(std.testing.io);
    try std.testing.expectEqual(@as(usize, 0), try stream.read(&buffers));
}

test "openStream enforces the concurrent stream limit" {
    const allocator = std.testing.allocator;
    var input = std.Io.Reader.fixed(&.{});
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var client = Client{ .connection = testConnection(
        .client,
        &input,
        &output.writer,
    ) };
    defer client.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var index: usize = 0;
    while (index < max_concurrent_streams) : (index += 1) {
        const stream = try client.openStream(&request);
        try std.testing.expectEqual(
            @as(u32, @intCast(index * 2 + 1)),
            stream.id,
        );
    }
    try std.testing.expectError(
        error.TooManyStreams,
        client.openStream(&request),
    );
}

test "send flow control pumps WINDOW_UPDATE frames" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    var window_payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &window_payload, 32, .big);
    try frame.write(
        &input_storage.writer,
        frame.type_window_update,
        0,
        0,
        &window_payload,
    );
    try frame.write(
        &input_storage.writer,
        frame.type_window_update,
        0,
        1,
        &window_payload,
    );
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.client, &input, &output.writer);
    defer connection.deinit();
    const index = connection.allocStream(1, frame.default_window).?;
    connection.streams[index].headers_sent = true;
    connection.last_stream_id = 1;
    connection.state_mutex.lock(std.testing.io) catch unreachable;
    connection.conn_send_window = 0;
    connection.streams[index].send_window = 0;
    connection.state_mutex.unlock(std.testing.io);
    const stream = connection.stream().?;
    _ = try stream.write(&.{"hello"});
    var reader = std.Io.Reader.fixed(output.written());
    var buffer: [frame.max_frame_size]u8 = undefined;
    const data = try frame.read(&reader, &buffer);
    try std.testing.expectEqual(frame.type_data, data.frame_type);
    try std.testing.expectEqualStrings("hello", data.payload);
}

test "RST_STREAM aborts one stream and keeps the connection usable" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try writeHeaders(&input_storage.writer, 1, &request, false);
    try writeHeaders(&input_storage.writer, 3, &request, false);
    var reset_payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &reset_payload, error_code_cancel, .big);
    try frame.write(
        &input_storage.writer,
        frame.type_rst_stream,
        0,
        1,
        &reset_payload,
    );
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    const first = try connection.acceptNext();
    const second = try connection.acceptNext();
    try std.testing.expectEqual(@as(u32, 1), first.id);
    try std.testing.expectEqual(@as(u32, 3), second.id);

    var buffer: [8]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    // The RST is read while the first stream waits for DATA.
    try std.testing.expectError(
        error.ConnectionReset,
        first.read(&buffers),
    );
    // The second stream is unaffected.
    connection.state_mutex.lock(std.testing.io) catch unreachable;
    const index = connection.streamIndex(3).?;
    connection.streams[index].remote_end = true;
    connection.streams[index].refreshState();
    connection.state_mutex.unlock(std.testing.io);
    try std.testing.expectEqual(@as(usize, 0), try second.read(&buffers));
}

test "GOAWAY aborts only streams above the last stream id" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try writeHeaders(&input_storage.writer, 1, &request, false);
    try writeHeaders(&input_storage.writer, 3, &request, false);
    var goaway: [8]u8 = undefined;
    std.mem.writeInt(u32, goaway[0..4], 1, .big);
    std.mem.writeInt(u32, goaway[4..8], error_code_no_error, .big);
    try frame.write(
        &input_storage.writer,
        frame.type_goaway,
        0,
        0,
        &goaway,
    );
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    const first = try connection.acceptNext();
    const second = try connection.acceptNext();
    var buffer: [8]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(error.ConnectionReset, second.read(&buffers));
    _ = first;
    try std.testing.expectError(error.Closed, connection.acceptNext());
}

test "trailers without END_STREAM reset the stream" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const trailers = [_]Header{
        .{ .name = "grpc-status", .value = "0" },
    };
    try writeHeaders(&input_storage.writer, 1, &request, false);
    try writeHeaders(&input_storage.writer, 1, &trailers, false);
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    _ = try connection.acceptNext();
    var buffer: [8]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(
        error.ConnectionReset,
        connection.readStream(1, &buffers),
    );
    var reader = std.Io.Reader.fixed(output.written());
    var frame_buffer: [frame.max_frame_size]u8 = undefined;
    const reset = try frame.read(&reader, &frame_buffer);
    try std.testing.expectEqual(frame.type_rst_stream, reset.frame_type);
    try std.testing.expectEqual(
        error_code_protocol,
        std.mem.readInt(u32, reset.payload[0..4], .big),
    );
}

test "informational response with END_STREAM resets the stream" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    const informational = [_]Header{
        .{ .name = ":status", .value = "100" },
    };
    try writeHeaders(&input_storage.writer, 1, &informational, true);
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var client = Client{ .connection = testConnection(
        .client,
        &input,
        &output.writer,
    ) };
    defer client.deinit();
    const request = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    const stream = try client.openStream(&request);
    var buffer: [8]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    try std.testing.expectError(
        error.ConnectionReset,
        stream.read(&buffers),
    );
}

test "SETTINGS with a bad frame size sends GOAWAY" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    var payload: [6]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], setting_max_frame_size, .big);
    std.mem.writeInt(u32, payload[2..6], 1024, .big);
    try frame.write(
        &input_storage.writer,
        frame.type_settings,
        0,
        0,
        &payload,
    );
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    try std.testing.expectError(
        error.ProtocolViolation,
        connection.acceptNext(),
    );
    var reader = std.Io.Reader.fixed(output.written());
    var buffer: [frame.max_frame_size]u8 = undefined;
    const goaway = try frame.read(&reader, &buffer);
    try std.testing.expectEqual(frame.type_goaway, goaway.frame_type);
}

test "client accepts ENABLE_PUSH=0 but never enables push" {
    const allocator = std.testing.allocator;
    var input = std.Io.Reader.fixed(&.{});
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.client, &input, &output.writer);
    defer connection.deinit();
    connection.state_mutex.lock(std.testing.io) catch unreachable;
    const zero = connection.applySettingLocked(setting_enable_push, 0);
    const one = connection.applySettingLocked(setting_enable_push, 1);
    const two = connection.applySettingLocked(setting_enable_push, 2);
    connection.streams[0].reset();
    connection.state_mutex.unlock(std.testing.io);
    try std.testing.expectEqual(@as(u32, 0), zero);
    try std.testing.expectEqual(error_code_protocol, one);
    try std.testing.expectEqual(error_code_protocol, two);
}

test "sendTrailers emits a second HEADERS block with END_STREAM" {
    const allocator = std.testing.allocator;
    var input = std.Io.Reader.fixed(&.{});
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    const index = connection.allocStream(1, frame.default_window).?;
    connection.last_stream_id = 1;
    const stream = connection.stream().?;
    const response = [_]Header{
        .{ .name = ":status", .value = "200" },
    };
    const trailers = [_]Header{
        .{ .name = "grpc-status", .value = "0" },
    };
    try stream.sendHeaders(&response, false);
    try stream.sendTrailers(&trailers);
    try std.testing.expectError(error.Closed, stream.write(&.{"x"}));

    var reader = std.Io.Reader.fixed(output.written());
    var buffer: [frame.max_frame_size]u8 = undefined;
    const first = try frame.read(&reader, &buffer);
    try std.testing.expectEqual(frame.type_headers, first.frame_type);
    const second = try frame.read(&reader, &buffer);
    try std.testing.expectEqual(frame.type_headers, second.frame_type);
    try std.testing.expect(
        second.flags & frame.flag_end_stream != 0,
    );
    _ = index;
}

test "stateful frame pump returns typed errors for arbitrary frames" {
    const allocator = std.testing.allocator;
    var input_storage: std.Io.Writer.Allocating = .init(allocator);
    defer input_storage.deinit();
    var seed: u64 = 0x9e3779b97f4a7c15;
    var payload: [64]u8 = undefined;
    var index: usize = 0;
    while (index < 256) : (index += 1) {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const frame_type: u8 = @intCast((seed >> 33) % 10);
        const flags: u8 = @intCast((seed >> 41) & 0xff);
        const ids = [_]u32{ 0, 1, 2, 3, 5 };
        const id = ids[(seed >> 21) % ids.len];
        const length: usize = @intCast((seed >> 13) % (payload.len + 1));
        for (payload[0..length], 0..) |*byte, i| {
            byte.* = @intCast((seed >> @intCast((i % 8) * 8)) & 0xff);
        }
        try frame.write(
            &input_storage.writer,
            frame_type,
            flags,
            id,
            payload[0..length],
        );
    }
    var input = std.Io.Reader.fixed(input_storage.written());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var connection = testConnection(.server, &input, &output.writer);
    defer connection.deinit();
    var iterations: usize = 0;
    while (iterations < 256) : (iterations += 1) {
        connection.pumpFrame() catch |err| switch (err) {
            error.Canceled,
            error.Closed,
            error.ConnectionReset,
            error.ProtocolViolation,
            error.Unexpected,
            error.OutOfMemory,
            error.TooManyStreams,
            error.HandshakeFailed,
            => break,
        };
    }
}

test "header validation rejects malformed fields" {
    const duplicate = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(
        error.ProtocolViolation,
        validateRequest(&duplicate, null),
    );
    const uppercase = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "X-Test", .value = "1" },
    };
    try std.testing.expectError(
        error.ProtocolViolation,
        validateRequest(&uppercase, null),
    );
    const bad_te = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "te", .value = "gzip" },
    };
    try std.testing.expectError(
        error.ProtocolViolation,
        validateRequest(&bad_te, null),
    );
    const connect = [_]Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    try validateRequest(&connect, null);
    const bad_connect = [_]Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    try std.testing.expectError(
        error.ProtocolViolation,
        validateRequest(&bad_connect, null),
    );
    const bad_trailer = [_]Header{
        .{ .name = ":status", .value = "200" },
    };
    try std.testing.expectError(
        error.ProtocolViolation,
        validateTrailers(&bad_trailer),
    );
}
