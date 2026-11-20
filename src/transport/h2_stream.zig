//! Adapter from `Stream` to the HTTP/2 package.
//!
//! A connection is represented by `H2Client` or `H2Server`; `H2Stream` is one
//! HTTP/2 stream on that connection. `H2Server.accept` may be called
//! repeatedly; the `Instance` inbound currently consumes one stream per
//! connection and leaves root-level multiplexing as follow-up work.

const std = @import("std");
const http2 = @import("http2");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("stream.zig").Stream;
const Guard = @import("lifetime.zig").Guard;

pub const socket_buffer_len = 16 * 1024;
pub const default_handshake_timeout_ns = 10 * std.time.ns_per_s;

pub const ClientOptions = struct {
    host: []const u8,
    path: []const u8 = "/",
    scheme: []const u8 = "https",
    handshake_timeout_ns: u64 = default_handshake_timeout_ns,
};

pub const ServerOptions = struct {
    path: ?[]const u8 = null,
    handshake_timeout_ns: u64 = default_handshake_timeout_ns,
};

pub const CreateError = error{
    Canceled,
    HandshakeFailed,
    OutOfMemory,
    TimedOut,
};

pub const OpenError = error{
    Canceled,
    Closed,
    ConnectionReset,
    OutOfMemory,
    ProtocolViolation,
    TooManyStreams,
    Unexpected,
};

/// Optional callback for data movement on a stream. The inbound uses it to
/// keep the shared HTTP/2 connection's idle deadline alive while one stream
/// is active.
pub const Activity = struct {
    ctx: *anyopaque,
    touch: *const fn (ctx: *anyopaque) void,

    pub fn notify(self: Activity) void {
        self.touch(self.ctx);
    }
};

pub const H2Client = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    inner: Stream,
    closed: std.atomic.Value(bool) = .init(false),
    socket_reader: SocketReader,
    socket_writer: SocketWriter,
    client: http2.Client,
    socket_read_buffer: [socket_buffer_len]u8 = undefined,
    socket_write_buffer: [socket_buffer_len]u8 = undefined,

    /// Creates the connection and performs the HTTP/2 preface/SETTINGS
    /// exchange. The caller owns `inner` on success.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ClientOptions,
    ) CreateError!*H2Client {
        const self = try gpa.create(H2Client);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.io = io;
        self.inner = inner;
        self.closed = .init(false);
        self.socket_reader = SocketReader.init(
            inner,
            io,
            &self.socket_read_buffer,
        );
        self.socket_writer = SocketWriter.init(
            inner,
            io,
            &self.socket_write_buffer,
        );
        self.client = try runClientHandshake(self, options);
        return self;
    }

    pub fn open(
        self: *H2Client,
        options: ClientOptions,
    ) OpenError!http2.Stream {
        if (self.closed.load(.acquire)) return error.Canceled;
        const headers = [_]http2.Header{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = options.scheme },
            .{ .name = ":path", .value = options.path },
            .{ .name = ":authority", .value = options.host },
            .{ .name = "content-type", .value = "application/octet-stream" },
        };
        return self.client.openStream(&headers) catch |err| {
            if (self.socket_reader.err) |inner| switch (inner) {
                error.Canceled => return error.Canceled,
                error.ConnectionReset => return error.ConnectionReset,
                else => {},
            };
            return mapOpenError(err);
        };
    }

    pub fn close(self: *H2Client) void {
        if (self.closed.swap(true, .acq_rel)) return;
        self.client.connection.cancel();
        self.inner.close(self.io);
        self.client.deinit();
        std.crypto.secureZero(u8, &self.socket_read_buffer);
        std.crypto.secureZero(u8, &self.socket_write_buffer);
        self.gpa.destroy(self);
    }
};

pub const H2Server = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    inner: Stream,
    closed: std.atomic.Value(bool) = .init(false),
    socket_reader: SocketReader,
    socket_writer: SocketWriter,
    server: http2.Server,
    socket_read_buffer: [socket_buffer_len]u8 = undefined,
    socket_write_buffer: [socket_buffer_len]u8 = undefined,

    /// Creates the connection and performs the HTTP/2 preface/SETTINGS
    /// exchange. The caller owns `inner` on success.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ServerOptions,
    ) CreateError!*H2Server {
        const self = try gpa.create(H2Server);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.io = io;
        self.inner = inner;
        self.closed = .init(false);
        self.socket_reader = SocketReader.init(
            inner,
            io,
            &self.socket_read_buffer,
        );
        self.socket_writer = SocketWriter.init(
            inner,
            io,
            &self.socket_write_buffer,
        );
        self.server = try runServerHandshake(self, options);
        return self;
    }

    /// Accepts the next request stream and sends the HTTP/2 200 response head.
    /// The returned stream does not own the connection.
    pub fn accept(self: *H2Server) OpenError!*H2Stream {
        if (self.closed.load(.acquire)) return error.Canceled;
        const h2_stream = self.server.acceptStream() catch |err| {
            if (self.socket_reader.err) |inner| switch (inner) {
                error.Canceled => return error.Canceled,
                error.ConnectionReset => return error.ConnectionReset,
                else => {},
            };
            return mapOpenError(err);
        };
        const headers = [_]http2.Header{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "application/octet-stream" },
        };
        h2_stream.sendHeaders(&headers, false) catch |err| {
            h2_stream.reset(http2.connection.error_code_internal) catch {};
            return mapOpenError(err);
        };
        return H2Stream.createForServer(self, h2_stream);
    }

    /// Aborts the connection and unblocks all streams without freeing the
    /// adapter. The owner must wait for stream tasks before calling `deinit`.
    pub fn cancel(self: *H2Server) void {
        if (self.closed.swap(true, .acq_rel)) return;
        self.server.connection.cancel();
        self.inner.close(self.io);
    }

    /// Releases the adapter. Must only be called after every stream task has
    /// finished because stream wrappers borrow this endpoint.
    pub fn deinit(self: *H2Server) void {
        self.cancel();
        self.server.deinit();
        std.crypto.secureZero(u8, &self.socket_read_buffer);
        std.crypto.secureZero(u8, &self.socket_write_buffer);
        self.gpa.destroy(self);
    }

    pub fn close(self: *H2Server) void {
        self.deinit();
    }
};

pub const H2Stream = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},
    activity: ?Activity = null,
    mode: Mode,

    const Mode = union(enum) {
        client: struct {
            endpoint: *H2Client,
            stream: http2.Stream,
            owns_endpoint: bool,
        },
        server: struct {
            endpoint: *H2Server,
            stream: http2.Stream,
            owns_endpoint: bool,
        },
    };

    /// One-shot client: owns `inner` and the whole HTTP/2 connection.
    pub fn createClient(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ClientOptions,
    ) CreateError!*H2Stream {
        const endpoint = try H2Client.create(io, gpa, inner, options);
        errdefer endpoint.close();
        const h2_stream = endpoint.open(options) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.HandshakeFailed,
        };
        return H2Stream.createForClient(endpoint, h2_stream, true);
    }

    /// One-shot server: owns `inner` and the whole HTTP/2 connection.
    pub fn createServer(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ServerOptions,
    ) CreateError!*H2Stream {
        const endpoint = try H2Server.create(io, gpa, inner, options);
        errdefer endpoint.close();
        const stream_handle = endpoint.accept() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.HandshakeFailed,
        };
        stream_handle.mode.server.owns_endpoint = true;
        return stream_handle;
    }

    fn createForClient(
        endpoint: *H2Client,
        h2_stream: http2.Stream,
        owns_endpoint: bool,
    ) CreateError!*H2Stream {
        const self = try endpoint.gpa.create(H2Stream);
        self.* = .{
            .gpa = endpoint.gpa,
            .io = endpoint.io,
            .mode = .{ .client = .{
                .endpoint = endpoint,
                .stream = h2_stream,
                .owns_endpoint = owns_endpoint,
            } },
        };
        return self;
    }

    fn createForServer(
        endpoint: *H2Server,
        h2_stream: http2.Stream,
    ) OpenError!*H2Stream {
        const self = try endpoint.gpa.create(H2Stream);
        self.* = .{
            .gpa = endpoint.gpa,
            .io = endpoint.io,
            .mode = .{ .server = .{
                .endpoint = endpoint,
                .stream = h2_stream,
                .owns_endpoint = false,
            } },
        };
        return self;
    }

    pub fn stream(self: *H2Stream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn setActivity(self: *H2Stream, activity: ?Activity) void {
        self.activity = activity;
    }

    fn underlying(self: *const H2Stream) Stream {
        return switch (self.mode) {
            .client => |mode| mode.endpoint.inner,
            .server => |mode| mode.endpoint.inner,
        };
    }

    fn socketReadError(self: *const H2Stream) ?Stream.ReadError {
        return switch (self.mode) {
            .client => |mode| mode.endpoint.socket_reader.err,
            .server => |mode| mode.endpoint.socket_reader.err,
        };
    }

    fn socketWriteError(self: *const H2Stream) ?Stream.WriteError {
        return switch (self.mode) {
            .client => |mode| mode.endpoint.socket_writer.err,
            .server => |mode| mode.endpoint.socket_writer.err,
        };
    }

    fn h2Stream(self: *const H2Stream) http2.Stream {
        return switch (self.mode) {
            .client => |mode| mode.stream,
            .server => |mode| mode.stream,
        };
    }

    fn read(
        ctx: *anyopaque,
        io: std.Io,
        buffers: [][]u8,
    ) Stream.ReadError!usize {
        _ = io;
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(self.io);
        if (self.closed.load(.acquire)) return error.Canceled;
        const read_len = self.h2Stream().read(buffers) catch |err| {
            if (self.socketReadError()) |socket_error| switch (socket_error) {
                error.Canceled => return error.Canceled,
                error.ConnectionReset => return error.ConnectionReset,
                else => {},
            };
            return switch (err) {
                error.Canceled => error.Canceled,
                error.Closed => 0,
                error.ConnectionReset => error.ConnectionReset,
                error.ProtocolViolation => error.ProtocolViolation,
                else => error.Unexpected,
            };
        };
        if (read_len != 0) {
            if (self.activity) |activity| activity.notify();
        }
        return read_len;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        _ = io;
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(self.io);
        if (self.closed.load(.acquire)) return error.Canceled;
        const written = self.h2Stream().write(buffers) catch |err| {
            if (self.socketWriteError()) |socket_error| switch (socket_error) {
                error.Canceled => return error.Canceled,
                error.BrokenPipe => return error.BrokenPipe,
                else => {},
            };
            return switch (err) {
                error.Canceled => error.Canceled,
                error.Closed => error.BrokenPipe,
                error.ConnectionReset => error.BrokenPipe,
                error.ProtocolViolation => error.ProtocolViolation,
                else => error.Unexpected,
            };
        };
        if (written != 0) {
            if (self.activity) |activity| activity.notify();
        }
        return written;
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        switch (how) {
            // An HTTP/2 stream cannot half-close the shared TCP read side.
            .recv => return,
            .send => {
                self.h2Stream().close() catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    error.Closed,
                    error.ConnectionReset,
                    error.ProtocolViolation,
                    => {},
                    else => return error.Unexpected,
                };
                // Keep the connection open for WINDOW_UPDATE/control frames;
                // `.send` means H2 END_STREAM, not TCP FIN.
                return;
            },
            .both => {
                self.h2Stream().reset(http2.connection.error_code_cancel) catch {};
                return;
            },
        }
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        // Abort this stream first so a pending reader returns before the
        // adapter is freed.
        self.h2Stream().reset(http2.connection.error_code_cancel) catch {};
        self.guard.waitIdle(io);
        switch (self.mode) {
            .client => |mode| {
                if (mode.owns_endpoint) mode.endpoint.close();
            },
            .server => |mode| {
                if (mode.owns_endpoint) mode.endpoint.close();
            },
        }
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        return self.underlying().local();
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        return self.underlying().remote();
    }

    const vtable: Stream.VTable = .{
        .read = read,
        .write = write,
        .shutdown = shutdown,
        .close = close,
        .local = local,
        .remote = remote,
    };
};

const Handshake = union(enum) {
    timeout: std.Io.Cancelable!void,
};

const HandshakeState = enum(u8) { running, done, fired };

const HandshakeTimer = struct {
    io: std.Io,
    inner: Stream,
    timeout_ns: u64,
    state: std.atomic.Value(HandshakeState) = .init(.running),

    fn run(self: *HandshakeTimer) std.Io.Cancelable!void {
        try std.Io.sleep(
            self.io,
            .{ .nanoseconds = @intCast(self.timeout_ns) },
            .awake,
        );
        // `Io.Threaded` sleep is not always interruptible on every platform.
        // Once the handshake has completed, a late timer must not abort a
        // live connection.
        if (self.state.cmpxchgStrong(
            .running,
            .fired,
            .acq_rel,
            .acquire,
        )) |_| return;
        // Abort the underlying transport so a handshake blocked on a read
        // returns instead of waiting forever.
        self.inner.shutdown(self.io, .both) catch {};
    }

    fn finish(self: *HandshakeTimer) bool {
        if (self.state.cmpxchgStrong(
            .running,
            .done,
            .acq_rel,
            .acquire,
        )) |actual| return actual == .fired;
        return false;
    }
};

fn runClientHandshake(
    self: *H2Client,
    options: ClientOptions,
) CreateError!http2.Client {
    if (options.handshake_timeout_ns == 0) {
        return clientHandshake(self) catch |err|
            return mapHandshakeError(err);
    }
    var timer: HandshakeTimer = .{
        .io = self.io,
        .inner = self.inner,
        .timeout_ns = options.handshake_timeout_ns,
    };
    var buffer: [1]Handshake = undefined;
    var select: std.Io.Select(Handshake) = .init(self.io, &buffer);
    select.concurrent(.timeout, HandshakeTimer.run, .{&timer}) catch |err| {
        drainHandshake(&select);
        if (err == error.ConcurrencyUnavailable) {
            return clientHandshake(self) catch |handshake_err|
                return mapHandshakeError(handshake_err);
        }
        return error.HandshakeFailed;
    };

    const value = clientHandshake(self) catch |err| {
        const timed_out = timer.finish();
        drainHandshake(&select);
        if (timed_out) return error.TimedOut;
        return mapHandshakeError(err);
    };
    const timed_out = timer.finish();
    drainHandshake(&select);
    if (timed_out) return error.TimedOut;
    return value;
}

fn runServerHandshake(
    self: *H2Server,
    options: ServerOptions,
) CreateError!http2.Server {
    if (options.handshake_timeout_ns == 0) {
        return serverHandshake(self, options) catch |err|
            return mapHandshakeError(err);
    }
    var timer: HandshakeTimer = .{
        .io = self.io,
        .inner = self.inner,
        .timeout_ns = options.handshake_timeout_ns,
    };
    var buffer: [1]Handshake = undefined;
    var select: std.Io.Select(Handshake) = .init(self.io, &buffer);
    select.concurrent(.timeout, HandshakeTimer.run, .{&timer}) catch |err| {
        drainHandshake(&select);
        if (err == error.ConcurrencyUnavailable) {
            return serverHandshake(self, options) catch |handshake_err|
                return mapHandshakeError(handshake_err);
        }
        return error.HandshakeFailed;
    };

    const value = serverHandshake(self, options) catch |err| {
        const timed_out = timer.finish();
        drainHandshake(&select);
        if (timed_out) return error.TimedOut;
        return mapHandshakeError(err);
    };
    const timed_out = timer.finish();
    drainHandshake(&select);
    if (timed_out) return error.TimedOut;
    return value;
}

fn clientHandshake(self: *H2Client) anyerror!http2.Client {
    return http2.Client.init(
        self.io,
        &self.socket_reader.interface,
        &self.socket_writer.interface,
    );
}

fn serverHandshake(
    self: *H2Server,
    options: ServerOptions,
) anyerror!http2.Server {
    return http2.Server.initWithOptions(
        self.io,
        &self.socket_reader.interface,
        &self.socket_writer.interface,
        .{ .path = options.path },
    );
}

fn drainHandshake(select: *std.Io.Select(Handshake)) void {
    while (select.cancel()) |result| {
        switch (result) {
            .timeout => |timed_out| timed_out catch {},
        }
    }
}

fn mapHandshakeError(err: anyerror) CreateError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        else => error.HandshakeFailed,
    };
}

fn mapOpenError(err: anyerror) OpenError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.Closed => error.Closed,
        error.ConnectionReset => error.ConnectionReset,
        error.OutOfMemory => error.OutOfMemory,
        error.ProtocolViolation => error.ProtocolViolation,
        error.TooManyStreams => error.TooManyStreams,
        else => error.Unexpected,
    };
}

const SocketReader = struct {
    io: std.Io,
    inner: Stream,
    interface: std.Io.Reader,
    err: ?Stream.ReadError = null,

    fn init(inner: Stream, io: std.Io, buffer: []u8) SocketReader {
        return .{
            .io = io,
            .inner = inner,
            .interface = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamImpl(
        io_r: *std.Io.Reader,
        io_w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *SocketReader = @alignCast(@fieldParentPtr("interface", io_r));
        const dest = limit.slice(io_w.writableSliceGreedy(1) catch
            return error.WriteFailed);
        var buffers = [_][]u8{dest};
        const read_len = self.inner.read(self.io, &buffers) catch |err| {
            self.err = err;
            return error.ReadFailed;
        };
        if (read_len == 0) return error.EndOfStream;
        io_w.advance(read_len);
        return read_len;
    }
};

const SocketWriter = struct {
    io: std.Io,
    inner: Stream,
    interface: std.Io.Writer,
    err: ?Stream.WriteError = null,

    fn init(inner: Stream, io: std.Io, buffer: []u8) SocketWriter {
        return .{
            .io = io,
            .inner = inner,
            .interface = .{
                .vtable = &.{ .drain = drain },
                .buffer = buffer,
            },
        };
    }

    fn drain(
        io_w: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *SocketWriter = @alignCast(@fieldParentPtr("interface", io_w));
        if (io_w.end != 0) {
            self.writeAll(io_w.buffer[0..io_w.end]) catch |err| {
                self.err = err;
                return error.WriteFailed;
            };
            io_w.end = 0;
        }

        var consumed: usize = 0;
        for (data, 0..) |slice, index| {
            const repeat = if (index + 1 == data.len) splat else 1;
            var i: usize = 0;
            while (i < repeat) : (i += 1) {
                self.writeAll(slice) catch |err| {
                    self.err = err;
                    return error.WriteFailed;
                };
                consumed += slice.len;
            }
        }
        return consumed;
    }

    fn writeAll(self: *SocketWriter, bytes: []const u8) Stream.WriteError!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const written = try self.inner.write(self.io, &.{bytes[offset..]});
            if (written == 0) return error.BrokenPipe;
            offset += written;
        }
    }
};

const ShutdownRecorder = struct {
    shutdown_calls: std.atomic.Value(u32) = .init(0),
    closed: bool = false,

    fn stream(self: *ShutdownRecorder) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(_: *anyopaque, _: std.Io, _: [][]u8) Stream.ReadError!usize {
        return 0;
    }

    fn write(
        _: *anyopaque,
        _: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        var total: usize = 0;
        for (buffers) |buffer| total += buffer.len;
        return total;
    }

    fn shutdown(
        ctx: *anyopaque,
        _: std.Io,
        _: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *ShutdownRecorder = @ptrCast(@alignCast(ctx));
        _ = self.shutdown_calls.fetchAdd(1, .acq_rel);
    }

    fn close(ctx: *anyopaque, _: std.Io) void {
        const self: *ShutdownRecorder = @ptrCast(@alignCast(ctx));
        self.closed = true;
    }

    fn local(_: *anyopaque) Endpoint {
        return .{ .ip = .{ .ip4 = .loopback(0) } };
    }

    fn remote(_: *anyopaque) Endpoint {
        return .{ .ip = .{ .ip4 = .loopback(0) } };
    }

    const vtable: Stream.VTable = .{
        .read = read,
        .write = write,
        .shutdown = shutdown,
        .close = close,
        .local = local,
        .remote = remote,
    };
};

test "a late handshake timer does not abort a completed connection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var inner: ShutdownRecorder = .{};
    var timer: HandshakeTimer = .{
        .io = io,
        .inner = inner.stream(),
        .timeout_ns = 10 * std.time.ns_per_ms,
    };
    var future = try io.concurrent(HandshakeTimer.run, .{&timer});
    try std.testing.expect(!timer.finish());
    try future.await(io);
    try std.testing.expectEqual(
        @as(u32, 0),
        inner.shutdown_calls.load(.acquire),
    );
}

test "H2 shutdown(.send) does not close the TCP write side" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var inner: ShutdownRecorder = .{};
    var endpoint: H2Server = undefined;
    endpoint.gpa = std.testing.allocator;
    endpoint.io = io;
    endpoint.inner = inner.stream();
    endpoint.closed = .init(false);
    endpoint.server = .{
        .connection = .{
            .io = io,
            .input = undefined,
            .output = undefined,
            .role = .server,
            .stream_id = 1,
        },
    };
    var adapter: H2Stream = .{
        .gpa = std.testing.allocator,
        .io = io,
        .mode = .{ .server = .{
            .endpoint = &endpoint,
            .stream = .{
                .connection = &endpoint.server.connection,
                .id = 1,
            },
            .owns_endpoint = false,
        } },
    };

    try adapter.stream().shutdown(io, .send);
    try std.testing.expectEqual(
        @as(u32, 0),
        inner.shutdown_calls.load(.acquire),
    );
}
