//! Adapter from `Stream` to the HTTP/2 package.

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

const Handshake = union(enum) {
    done: anyerror!void,
    timeout: std.Io.Cancelable!void,
};

const Mode = union(enum) {
    client: http2.Client,
    server: http2.Server,
};

const HandshakeOptions = union(enum) {
    client: ClientOptions,
    server: ServerOptions,
};

pub const H2Stream = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    inner: Stream,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},
    socket_reader: SocketReader,
    socket_writer: SocketWriter,
    mode: Mode,
    h2_stream: http2.Stream,
    socket_read_buffer: [socket_buffer_len]u8 = undefined,
    socket_write_buffer: [socket_buffer_len]u8 = undefined,

    pub fn createClient(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ClientOptions,
    ) CreateError!*H2Stream {
        const self = try createBase(io, gpa, inner);
        errdefer self.gpa.destroy(self);
        const result = runHandshake(self, .{ .client = options });
        if (result) |_| return self else |err| return err;
    }

    pub fn createServer(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: ServerOptions,
    ) CreateError!*H2Stream {
        const self = try createBase(io, gpa, inner);
        errdefer self.gpa.destroy(self);
        const result = runHandshake(self, .{ .server = options });
        if (result) |_| return self else |err| return err;
    }

    fn createBase(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
    ) CreateError!*H2Stream {
        const self = try gpa.create(H2Stream);
        self.gpa = gpa;
        self.io = io;
        self.inner = inner;
        self.closed = .init(false);
        self.guard = .{};
        self.socket_reader = SocketReader.init(inner, io, &self.socket_read_buffer);
        self.socket_writer = SocketWriter.init(inner, io, &self.socket_write_buffer);
        self.mode = undefined;
        self.h2_stream = undefined;
        return self;
    }

    pub fn stream(self: *H2Stream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        _ = io;
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(self.io);
        if (self.closed.load(.acquire)) return error.Canceled;
        return self.h2_stream.read(buffers) catch |err| {
            if (self.socket_reader.err) |inner| switch (inner) {
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
        return self.h2_stream.write(buffers) catch |err| {
            if (self.socket_writer.err) |inner| switch (inner) {
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
            .recv => return self.inner.shutdown(io, .recv),
            .send => {
                self.h2_stream.close() catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    error.Closed,
                    error.ConnectionReset,
                    error.ProtocolViolation,
                    => {},
                    else => return error.Unexpected,
                };
                // Keep the TCP write side open for WINDOW_UPDATE/control
                // frames; `.send` means H2 END_STREAM, not TCP FIN.
                return;
            },
            .both => {
                self.h2_stream.cancel();
                return self.inner.shutdown(io, .both);
            },
        }
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        switch (self.mode) {
            .client => |*client| client.connection.cancel(),
            .server => |*server| server.connection.cancel(),
        }
        self.inner.close(io);
        self.guard.waitIdle(io);
        switch (self.mode) {
            .client => |*client| client.deinit(),
            .server => |*server| server.deinit(),
        }
        std.crypto.secureZero(u8, &self.socket_read_buffer);
        std.crypto.secureZero(u8, &self.socket_write_buffer);
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
        return self.inner.local();
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *H2Stream = @ptrCast(@alignCast(ctx));
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

fn runHandshake(
    self: *H2Stream,
    options: HandshakeOptions,
) CreateError!void {
    const timeout_ns = switch (options) {
        .client => |client_options| client_options.handshake_timeout_ns,
        .server => |server_options| server_options.handshake_timeout_ns,
    };
    if (timeout_ns == 0) {
        return handshake(self, options) catch |err| mapHandshakeError(err);
    }

    var buffer: [2]Handshake = undefined;
    var select: std.Io.Select(Handshake) = .init(self.io, &buffer);
    select.concurrent(.done, handshake, .{ self, options }) catch {
        drainHandshake(&select);
        return error.HandshakeFailed;
    };
    select.concurrent(.timeout, handshakeTimeout, .{
        self.io,
        timeout_ns,
    }) catch {
        drainHandshake(&select);
        return error.HandshakeFailed;
    };

    const result = select.await() catch |err| {
        drainHandshake(&select);
        switch (err) {
            error.Canceled => return error.Canceled,
        }
    };
    switch (result) {
        .done => |done| {
            drainHandshake(&select);
            done catch |err| return mapHandshakeError(err);
        },
        .timeout => |timed_out| {
            drainHandshake(&select);
            timed_out catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.TimedOut;
        },
    }
}

fn handshake(self: *H2Stream, options: HandshakeOptions) anyerror!void {
    switch (options) {
        .client => |client_options| {
            self.mode = .{ .client = try http2.Client.init(
                self.io,
                &self.socket_reader.interface,
                &self.socket_writer.interface,
            ) };
            const headers = [_]http2.Header{
                .{ .name = ":method", .value = "POST" },
                .{ .name = ":scheme", .value = client_options.scheme },
                .{ .name = ":path", .value = client_options.path },
                .{ .name = ":authority", .value = client_options.host },
                .{ .name = "content-type", .value = "application/octet-stream" },
            };
            self.h2_stream = try self.mode.client.openStream(&headers);
        },
        .server => |server_options| {
            self.mode = .{ .server = try http2.Server.initWithOptions(
                self.io,
                &self.socket_reader.interface,
                &self.socket_writer.interface,
                .{ .path = server_options.path },
            ) };
            self.h2_stream = try self.mode.server.acceptStream();
            const headers = [_]http2.Header{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-type", .value = "application/octet-stream" },
            };
            try self.h2_stream.sendHeaders(&headers, false);
        },
    }
}

fn drainHandshake(select: *std.Io.Select(Handshake)) void {
    while (select.cancel()) |result| {
        switch (result) {
            .done => |done| done catch {},
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

fn handshakeTimeout(io: std.Io, timeout_ns: u64) std.Io.Cancelable!void {
    try std.Io.sleep(io, .{ .nanoseconds = @intCast(timeout_ns) }, .awake);
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

test "H2 shutdown(.send) does not close the TCP write side" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var inner: ShutdownRecorder = .{};
    const adapter = try H2Stream.createBase(io, std.testing.allocator, inner.stream());
    defer adapter.stream().close(io);
    adapter.mode = .{ .server = .{
        .connection = .{
            .io = io,
            .input = &adapter.socket_reader.interface,
            .output = &adapter.socket_writer.interface,
            .role = .server,
            .stream_id = 1,
        },
    } };
    adapter.h2_stream = .{
        .connection = &adapter.mode.server.connection,
        .id = 1,
    };

    try adapter.stream().shutdown(io, .send);
    try std.testing.expectEqual(
        @as(u32, 0),
        inner.shutdown_calls.load(.acquire),
    );
}
