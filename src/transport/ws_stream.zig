//! Adapter from `Stream` to the WebSocket package.

const std = @import("std");
const ws = @import("ws");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("stream.zig").Stream;
const Guard = @import("lifetime.zig").Guard;

pub const socket_buffer_len = 4096;
pub const default_handshake_timeout_ns = 10 * std.time.ns_per_s;

pub const ClientOptions = struct {
    host: []const u8,
    path: []const u8 = "/",
    handshake_timeout_ns: u64 = default_handshake_timeout_ns,
};

pub const ServerOptions = struct {
    path: []const u8 = "/",
    /// Zero disables the per-connection timer. Inbound servers must instead
    /// enforce ADR-0015 handshake deadlines with the connection reaper; each
    /// enabled timer costs one sleeping task on `Io.Threaded`.
    handshake_timeout_ns: u64 = 0,
};

pub const CreateError = error{
    Canceled,
    HandshakeFailed,
    OutOfMemory,
    TimedOut,
};

const Handshake = union(enum) {
    timeout: std.Io.Cancelable!void,
};

const HandshakeTimer = struct {
    io: std.Io,
    inner: Stream,
    timeout_ns: u64,
    fired: std.atomic.Value(bool) = .init(false),

    fn run(self: *HandshakeTimer) std.Io.Cancelable!void {
        try std.Io.sleep(
            self.io,
            .{ .nanoseconds = @intCast(self.timeout_ns) },
            .awake,
        );
        self.fired.store(true, .release);
        // The handshake runs on the calling task; aborting the transport is
        // the only portable way to unblock its pending read.
        self.inner.shutdown(self.io, .both) catch {};
    }
};

pub const WsStream = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    inner: Stream,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},
    socket_reader: SocketReader,
    socket_writer: SocketWriter,
    connection: ws.Connection,
    socket_read_buffer: [socket_buffer_len]u8 = undefined,
    socket_write_buffer: [socket_buffer_len]u8 = undefined,

    /// Takes ownership of `inner` on success; the caller closes it on error.
    pub fn createClient(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ClientOptions,
    ) CreateError!*WsStream {
        const self = try createBase(io, gpa, inner);
        errdefer destroyBase(self);
        const result = runHandshake(self, .{ .client = options });
        if (result) |_| return self else |err| return err;
    }

    /// Takes ownership of `inner` on success; the caller closes it on error.
    pub fn createServer(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ServerOptions,
    ) CreateError!*WsStream {
        const self = try createBase(io, gpa, inner);
        errdefer destroyBase(self);
        const result = runHandshake(self, .{ .server = options });
        if (result) |_| return self else |err| return err;
    }

    fn createBase(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
    ) CreateError!*WsStream {
        const self = try gpa.create(WsStream);
        self.gpa = gpa;
        self.io = io;
        self.inner = inner;
        self.closed = .init(false);
        self.guard = .{};
        self.socket_reader = SocketReader.init(inner, io, &self.socket_read_buffer);
        self.socket_writer = SocketWriter.init(inner, io, &self.socket_write_buffer);
        self.connection = undefined;
        return self;
    }

    fn destroyBase(self: *WsStream) void {
        // A failed handshake may have buffered request headers (Authorization,
        // Cookie) or early frame bytes.
        std.crypto.secureZero(u8, &self.socket_read_buffer);
        std.crypto.secureZero(u8, &self.socket_write_buffer);
        self.gpa.destroy(self);
    }

    pub fn stream(self: *WsStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        _ = io;
        const self: *WsStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(self.io);
        if (self.closed.load(.acquire)) return error.Canceled;
        return self.connection.read(buffers) catch |err| {
            if (self.socket_reader.err) |inner| switch (inner) {
                error.Canceled => return error.Canceled,
                error.ConnectionReset => return error.ConnectionReset,
                else => {},
            };
            return switch (err) {
                error.Canceled => error.Canceled,
                error.Closed => 0,
                error.ProtocolViolation => error.ProtocolViolation,
                else => error.Unexpected,
            };
        };
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        _ = io;
        const self: *WsStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(self.io);
        if (self.closed.load(.acquire)) return error.Canceled;
        return self.connection.write(buffers) catch |err| {
            if (self.socket_writer.err) |inner| switch (inner) {
                error.Canceled => return error.Canceled,
                error.BrokenPipe => return error.BrokenPipe,
                else => {},
            };
            return switch (err) {
                error.Canceled => error.Canceled,
                error.Closed => error.BrokenPipe,
                error.ProtocolViolation => error.ProtocolViolation,
                else => error.Unexpected,
            };
        };
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *WsStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        switch (how) {
            .recv => return self.inner.shutdown(io, .recv),
            .send => {
                self.connection.end() catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    error.Closed => {},
                    else => return error.Unexpected,
                };
                return self.inner.shutdown(io, .send);
            },
            .both => return self.inner.shutdown(io, .both),
        }
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *WsStream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        self.guard.waitIdle(io);
        self.connection.deinit();
        std.crypto.secureZero(u8, &self.socket_read_buffer);
        std.crypto.secureZero(u8, &self.socket_write_buffer);
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *WsStream = @ptrCast(@alignCast(ctx));
        return self.inner.local();
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *WsStream = @ptrCast(@alignCast(ctx));
        return self.inner.remote();
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

const HandshakeOptions = union(enum) {
    client: ClientOptions,
    server: ServerOptions,
};

fn runHandshake(
    self: *WsStream,
    options: HandshakeOptions,
) CreateError!void {
    const timeout_ns = switch (options) {
        .client => |client_options| client_options.handshake_timeout_ns,
        .server => |server_options| server_options.handshake_timeout_ns,
    };
    if (timeout_ns == 0) {
        return handshake(self, options) catch |err| mapHandshakeError(err);
    }

    // One timer task, not one task per handshake phase: the handshake itself
    // stays on the calling task.
    var timer: HandshakeTimer = .{
        .io = self.io,
        .inner = self.inner,
        .timeout_ns = timeout_ns,
    };
    var buffer: [1]Handshake = undefined;
    var select: std.Io.Select(Handshake) = .init(self.io, &buffer);
    select.concurrent(.timeout, HandshakeTimer.run, .{&timer}) catch |err| {
        drainHandshake(&select);
        if (err == error.ConcurrencyUnavailable) {
            // Single-threaded embedders cannot host a timer task. Run the
            // handshake on this task and let the caller's guard bound it.
            return handshake(self, options) catch |handshake_err|
                mapHandshakeError(handshake_err);
        }
        return error.HandshakeFailed;
    };

    const result = handshake(self, options);
    drainHandshake(&select);
    if (timer.fired.load(.acquire)) return error.TimedOut;
    result catch |err| return mapHandshakeError(err);
}

fn handshake(self: *WsStream, options: HandshakeOptions) anyerror!void {
    switch (options) {
        .client => |client_options| return ws.clientHandshake(
            self.io,
            &self.socket_reader.interface,
            &self.socket_writer.interface,
            &self.connection,
            .{ .host = client_options.host, .path = client_options.path },
        ),
        .server => |server_options| return ws.serverHandshake(
            self.io,
            &self.socket_reader.interface,
            &self.socket_writer.interface,
            &self.connection,
            .{ .path = server_options.path },
        ),
    }
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

const BlockingInner = struct {
    started: std.Io.Event = .unset,
    release: std.Io.Event = .unset,

    fn stream(self: *BlockingInner) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(
        ctx: *anyopaque,
        io: std.Io,
        buffers: [][]u8,
    ) Stream.ReadError!usize {
        _ = buffers;
        const self: *BlockingInner = @ptrCast(@alignCast(ctx));
        self.started.set(io);
        self.release.waitUncancelable(io);
        return error.Canceled;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        _ = ctx;
        _ = io;
        return buffers[0].len;
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        _ = how;
        const self: *BlockingInner = @ptrCast(@alignCast(ctx));
        self.release.set(io);
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *BlockingInner = @ptrCast(@alignCast(ctx));
        self.release.set(io);
    }

    fn local(ctx: *anyopaque) Endpoint {
        _ = ctx;
        return .{ .ip = .{ .ip4 = .loopback(0) } };
    }

    fn remote(ctx: *anyopaque) Endpoint {
        _ = ctx;
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

fn blockedRead(io: std.Io, stream: Stream) anyerror!void {
    var buffer: [16]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    _ = try stream.read(io, &buffers);
}

test "close waits for a blocked read before freeing the adapter" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var inner: BlockingInner = .{};
    const adapter = try WsStream.createBase(io, std.testing.allocator, inner.stream());
    adapter.connection = .{
        .io = io,
        .input = &adapter.socket_reader.interface,
        .output = &adapter.socket_writer.interface,
        .role = .server,
    };
    const stream = adapter.stream();
    var future = io.async(blockedRead, .{ io, stream });
    try inner.started.wait(io);
    stream.close(io);
    try std.testing.expectError(error.Canceled, future.await(io));
}

test "handshake timeout aborts a silent peer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var inner: BlockingInner = .{};
    const result = WsStream.createServer(
        io,
        std.testing.allocator,
        inner.stream(),
        .{ .handshake_timeout_ns = 20 * std.time.ns_per_ms },
    );
    try std.testing.expectError(error.TimedOut, result);
}
