//! Adapter from `Stream` to the TLS 1.3 package client.

const std = @import("std");
const tls13 = @import("tls13");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("stream.zig").Stream;
const writeSlices = @import("write.zig").writeSlices;
const Guard = @import("lifetime.zig").Guard;

pub const socket_buffer_len = tls13.min_buffer_len;
const plain_buffer_len = 4096;

pub const Options = struct {
    /// Server name for SNI and certificate host verification.
    server_name: ?[]const u8,
    /// Skip CA-chain verification. The hostname is still checked when
    /// `server_name` is present.
    insecure: bool,
    ca: ?*tls13.Ca = null,
    /// ALPN protocols in preference order.
    alpn_protocols: []const []const u8 = &.{},
    /// Require this negotiated ALPN protocol.
    required_alpn: ?[]const u8 = null,
    /// Treat a missing close_notify as EOF instead of a truncation error.
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

const ClientHandshake = union(enum) {
    client: tls13.InitError!tls13.Client,
    timeout: std.Io.Cancelable!void,
};

pub const TlsClientStream = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    inner: Stream,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},
    write_lock: std.Io.Mutex = .init,
    socket_reader: SocketReader,
    socket_writer: SocketWriter,
    client: tls13.Client,
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
    ) CreateError!*TlsClientStream {
        const self = try gpa.create(TlsClientStream);
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
            self.client = clientHandshake(self, options) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed, error.Truncated, error.HandshakeFailed => return error.HandshakeFailed,
            };
            return self;
        }

        var buffer: [2]ClientHandshake = undefined;
        var select: std.Io.Select(ClientHandshake) = .init(io, &buffer);
        select.concurrent(.client, clientHandshake, .{ self, options }) catch {
            drainClientHandshake(&select);
            return error.HandshakeFailed;
        };
        select.concurrent(.timeout, handshakeTimeout, .{
            io,
            options.handshake_timeout_ns,
        }) catch {
            drainClientHandshake(&select);
            return error.HandshakeFailed;
        };

        const result = select.await() catch |err| {
            drainClientHandshake(&select);
            switch (err) {
                error.Canceled => return error.Canceled,
            }
        };
        switch (result) {
            .client => |client_result| {
                drainClientHandshake(&select);
                self.client = client_result catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    error.Closed, error.Truncated, error.HandshakeFailed => return error.HandshakeFailed,
                };
                return self;
            },
            .timeout => |timed_out| {
                drainClientHandshake(&select);
                timed_out catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
                return error.TimedOut;
            },
        }
    }

    fn clientHandshake(
        self: *TlsClientStream,
        options: Options,
    ) tls13.InitError!tls13.Client {
        return tls13.Client.init(
            self.io,
            &self.socket_reader.interface,
            &self.socket_writer.interface,
            .{
                .server_name = options.server_name,
                .verify = !options.insecure,
                .ca = options.ca,
                .alpn_protocols = options.alpn_protocols,
                .required_alpn = options.required_alpn,
                .allow_truncation_attacks = options.allow_truncation_attacks,
                .read_buffer = &self.plain_read_buffer,
                .write_buffer = &self.plain_write_buffer,
            },
        );
    }

    pub fn negotiatedProtocol(self: *const TlsClientStream) ?[]const u8 {
        return self.client.negotiatedProtocol();
    }

    fn drainClientHandshake(select: *std.Io.Select(ClientHandshake)) void {
        while (select.cancel()) |result| {
            switch (result) {
                .client => |client_result| {
                    if (client_result) |client_value| {
                        var client = client_value;
                        client.deinit();
                    } else |_| {}
                },
                .timeout => |timed_out| timed_out catch {},
            }
        }
    }

    pub fn stream(self: *TlsClientStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        _ = io;
        const self: *TlsClientStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(self.io);
        if (self.closed.load(.acquire)) return error.Canceled;
        const read_len = tls13.readSome(self.client.reader(), buffers) catch
            return self.readFailure();
        if (read_len == 0 and !self.client.eof()) {
            return error.ConnectionReset;
        }
        return read_len;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *TlsClientStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        var total: usize = 0;
        for (buffers) |buffer| total += buffer.len;

        self.write_lock.lock(io) catch return error.Canceled;
        defer self.write_lock.unlock(io);
        writeSlices(self.client.writer(), buffers) catch
            return self.writeFailure();
        // The TLS writer encrypts into the socket writer but does not flush
        // the underlying transport, so both layers need an explicit flush.
        self.client.writer().flush() catch return self.writeFailure();
        self.socket_writer.interface.flush() catch return self.writeFailure();
        return total;
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *TlsClientStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        switch (how) {
            .recv => return self.inner.shutdown(io, .recv),
            .send => {
                self.write_lock.lock(io) catch return error.Canceled;
                defer self.write_lock.unlock(io);
                self.client.end() catch return self.shutdownFailure();
                self.socket_writer.interface.flush() catch
                    return self.shutdownFailure();
                return self.inner.shutdown(io, .send);
            },
            // `shutdown(.both)` is also used to abort a relay from the reading
            // direction. Only touch the underlying transport there.
            .both => return self.inner.shutdown(io, .both),
        }
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *TlsClientStream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        self.guard.waitIdle(io);
        self.client.deinit();
        std.crypto.secureZero(u8, &self.plain_read_buffer);
        std.crypto.secureZero(u8, &self.plain_write_buffer);
        std.crypto.secureZero(u8, &self.socket_read_buffer);
        std.crypto.secureZero(u8, &self.socket_write_buffer);
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *TlsClientStream = @ptrCast(@alignCast(ctx));
        return self.inner.local();
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *TlsClientStream = @ptrCast(@alignCast(ctx));
        return self.inner.remote();
    }

    fn readFailure(self: *TlsClientStream) Stream.ReadError {
        if (self.socket_reader.err) |inner| switch (inner) {
            error.Canceled => return error.Canceled,
            error.ConnectionReset => return error.ConnectionReset,
            else => {},
        };
        const err = self.client.readError() orelse {
            return self.socket_reader.err orelse error.ProtocolViolation;
        };
        return switch (err) {
            error.Canceled => error.Canceled,
            error.Closed => error.Unexpected,
            error.Truncated => error.ConnectionReset,
            error.HandshakeFailed => error.ProtocolViolation,
        };
    }

    fn writeFailure(self: *TlsClientStream) Stream.WriteError {
        return self.socket_writer.err orelse error.Unexpected;
    }

    fn shutdownFailure(self: *TlsClientStream) Stream.ShutdownError {
        const err = self.socket_writer.err orelse return error.Unexpected;
        return switch (err) {
            error.Canceled => error.Canceled,
            error.BrokenPipe => error.NotConnected,
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

test "TLS truncation maps to ConnectionReset" {
    var client: tls13.Client = undefined;
    client.read_error = error.Truncated;
    var stream: TlsClientStream = undefined;
    stream.client = client;
    try std.testing.expectEqual(
        error.ConnectionReset,
        stream.readFailure(),
    );
}
