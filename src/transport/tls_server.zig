//! Adapter from `Stream` to the TLS 1.3 package server.

const std = @import("std");
const tls13 = @import("tls13");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("stream.zig").Stream;
const writeSlices = @import("write.zig").writeSlices;
const Guard = @import("lifetime.zig").Guard;

pub const socket_buffer_len = tls13.min_buffer_len;
const plain_buffer_len = 4096;

pub const Options = struct {
    /// DER certificate chain, leaf first.
    certificate_chain: []const []const u8,
    private_key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    /// ALPN protocols in server preference order.
    alpn_protocols: []const []const u8 = &.{},
    /// Treat a missing client close_notify as EOF instead of truncation.
    allow_truncation_attacks: bool = false,
    /// Bounded handshake duration. Zero disables the timeout.
    handshake_timeout_ns: u64 = 10 * std.time.ns_per_s,
};

pub const CreateError = error{
    Canceled,
    HandshakeFailed,
    OutOfMemory,
    TimedOut,
};

const ServerHandshake = union(enum) {
    server: anyerror!*tls13.Server,
    timeout: std.Io.Cancelable!void,
};

pub const TlsServerStream = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    inner: Stream,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},
    write_lock: std.Io.Mutex = .init,
    socket_reader: SocketReader,
    socket_writer: SocketWriter,
    server: *tls13.Server,
    plain_read_buffer: [plain_buffer_len]u8 = undefined,
    plain_write_buffer: [plain_buffer_len]u8 = undefined,
    socket_read_buffer: [socket_buffer_len]u8 = undefined,
    socket_write_buffer: [socket_buffer_len]u8 = undefined,

    /// Takes ownership of `inner` on success; the caller closes it on error.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        options: Options,
    ) CreateError!*TlsServerStream {
        const self = try gpa.create(TlsServerStream);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.io = io;
        self.inner = inner;
        self.closed = .init(false);
        self.guard = .{};
        self.write_lock = .init;
        self.socket_reader = SocketReader.init(inner, io, &self.socket_read_buffer);
        self.socket_writer = SocketWriter.init(inner, io, &self.socket_write_buffer);

        if (options.handshake_timeout_ns == 0) {
            self.server = serverHandshake(self, options) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.HandshakeFailed,
            };
            return self;
        }

        var buffer: [2]ServerHandshake = undefined;
        var select: std.Io.Select(ServerHandshake) = .init(io, &buffer);
        select.concurrent(.server, serverHandshake, .{ self, options }) catch |err| {
            drainServerHandshake(&select);
            if (err == error.ConcurrencyUnavailable) {
                self.server = serverHandshake(self, options) catch |handshake_err|
                    switch (handshake_err) {
                        error.Canceled => return error.Canceled,
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.HandshakeFailed,
                    };
                return self;
            }
            return error.HandshakeFailed;
        };
        select.concurrent(.timeout, handshakeTimeout, .{
            io,
            options.handshake_timeout_ns,
        }) catch {
            drainServerHandshake(&select);
            return error.HandshakeFailed;
        };

        const result = select.await() catch |err| {
            drainServerHandshake(&select);
            switch (err) {
                error.Canceled => return error.Canceled,
            }
        };
        switch (result) {
            .server => |server_result| {
                drainServerHandshake(&select);
                self.server = server_result catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.HandshakeFailed,
                };
                return self;
            },
            .timeout => |timed_out| {
                drainServerHandshake(&select);
                timed_out catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
                return error.TimedOut;
            },
        }
    }

    fn serverHandshake(
        self: *TlsServerStream,
        options: Options,
    ) anyerror!*tls13.Server {
        return tls13.Server.create(
            self.io,
            self.gpa,
            &self.socket_reader.interface,
            &self.socket_writer.interface,
            .{
                .certificate_chain = options.certificate_chain,
                .private_key = options.private_key,
                .alpn_protocols = options.alpn_protocols,
                .allow_truncation_attacks = options.allow_truncation_attacks,
                .read_buffer = &self.plain_read_buffer,
                .write_buffer = &self.plain_write_buffer,
            },
        );
    }

    pub fn negotiatedProtocol(self: *const TlsServerStream) ?[]const u8 {
        return self.server.negotiatedProtocol();
    }

    fn drainServerHandshake(select: *std.Io.Select(ServerHandshake)) void {
        while (select.cancel()) |result| {
            switch (result) {
                .server => |server_result| {
                    if (server_result) |server| server.deinit() else |_| {}
                },
                .timeout => |timed_out| timed_out catch {},
            }
        }
    }

    pub fn stream(self: *TlsServerStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        _ = io;
        const self: *TlsServerStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(self.io);
        if (self.closed.load(.acquire)) return error.Canceled;
        const read_len = tls13.readSome(self.server.reader(), buffers) catch
            return self.readFailure();
        if (read_len == 0 and !self.server.eof) {
            return error.ConnectionReset;
        }
        return read_len;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *TlsServerStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        var total: usize = 0;
        for (buffers) |buffer| total += buffer.len;

        self.write_lock.lock(io) catch return error.Canceled;
        defer self.write_lock.unlock(io);
        writeSlices(self.server.writer(), buffers) catch
            return self.writeFailure();
        self.server.flush() catch return self.writeFailure();
        return total;
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *TlsServerStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        switch (how) {
            .recv => return self.inner.shutdown(io, .recv),
            .send => {
                self.write_lock.lock(io) catch return error.Canceled;
                defer self.write_lock.unlock(io);
                self.server.end() catch return self.shutdownFailure();
                return self.inner.shutdown(io, .send);
            },
            // Abort path: do not send close_notify while another task may be
            // writing; the transport close is enough to unblock both sides.
            .both => return self.inner.shutdown(io, .both),
        }
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *TlsServerStream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        self.guard.waitIdle(io);
        self.server.deinit();
        std.crypto.secureZero(u8, &self.plain_read_buffer);
        std.crypto.secureZero(u8, &self.plain_write_buffer);
        std.crypto.secureZero(u8, &self.socket_read_buffer);
        std.crypto.secureZero(u8, &self.socket_write_buffer);
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *TlsServerStream = @ptrCast(@alignCast(ctx));
        return self.inner.local();
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *TlsServerStream = @ptrCast(@alignCast(ctx));
        return self.inner.remote();
    }

    fn readFailure(self: *TlsServerStream) Stream.ReadError {
        if (self.socket_reader.err) |inner| switch (inner) {
            error.Canceled => return error.Canceled,
            error.ConnectionReset => return error.ConnectionReset,
            else => {},
        };
        return switch (self.server.readError() orelse return error.Unexpected) {
            error.Canceled => error.Canceled,
            error.ProtocolViolation, error.HandshakeFailed => error.ProtocolViolation,
            error.Closed => error.Unexpected,
            error.Truncated => error.ConnectionReset,
            error.OutOfMemory => error.Unexpected,
        };
    }

    fn writeFailure(self: *TlsServerStream) Stream.WriteError {
        return switch (self.server.writeError() orelse return error.Unexpected) {
            error.Canceled => error.Canceled,
            error.Closed => error.BrokenPipe,
            else => error.ProtocolViolation,
        };
    }

    fn shutdownFailure(self: *TlsServerStream) Stream.ShutdownError {
        return switch (self.server.writeError() orelse return error.Unexpected) {
            error.Canceled => error.Canceled,
            error.Closed => error.NotConnected,
            else => error.Unexpected,
        };
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
        std.debug.assert(dest.len > 0);
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
        std.debug.assert(data.len > 0);
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
