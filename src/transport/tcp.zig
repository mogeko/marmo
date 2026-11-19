//! Adapter from `std.Io.net.Stream` to the public `Stream` interface.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("stream.zig").Stream;
const writeSlices = @import("write.zig").writeSlices;
const Guard = @import("lifetime.zig").Guard;

pub const TcpStream = struct {
    gpa: std.mem.Allocator,
    inner: std.Io.net.Stream,
    local_endpoint: Endpoint,
    remote_endpoint: Endpoint,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},

    pub fn create(
        gpa: std.mem.Allocator,
        inner: std.Io.net.Stream,
        local_endpoint: Endpoint,
        remote_endpoint: Endpoint,
    ) !*TcpStream {
        const self = try gpa.create(TcpStream);
        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .local_endpoint = local_endpoint,
            .remote_endpoint = remote_endpoint,
        };
        return self;
    }

    pub fn stream(self: *TcpStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        const self: *TcpStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        return self.inner.read(io, buffers) catch |err| switch (err) {
            error.Canceled => error.Canceled,
            error.ConnectionResetByPeer => error.ConnectionReset,
            else => error.Unexpected,
        };
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *TcpStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        var writer = std.Io.net.Stream.Writer.init(self.inner, io, &.{});
        writeSlices(&writer.interface, buffers) catch {
            return writeError(writer.err);
        };
        writer.interface.flush() catch {
            return writeError(writer.err);
        };
        var total: usize = 0;
        for (buffers) |buffer| total += buffer.len;
        return total;
    }

    fn writeError(err: ?std.Io.net.Stream.Writer.Error) Stream.WriteError {
        const actual = err orelse return error.Unexpected;
        return switch (actual) {
            error.Canceled => error.Canceled,
            error.ConnectionResetByPeer, error.SocketUnconnected => error.BrokenPipe,
            else => error.Unexpected,
        };
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *TcpStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        const inner_how: std.Io.net.ShutdownHow = switch (how) {
            .recv => .recv,
            .send => .send,
            .both => .both,
        };
        return self.inner.shutdown(io, inner_how) catch |err| switch (err) {
            error.Canceled => error.Canceled,
            error.SocketUnconnected => error.NotConnected,
            else => error.Unexpected,
        };
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *TcpStream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        self.guard.waitIdle(io);
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *TcpStream = @ptrCast(@alignCast(ctx));
        return self.local_endpoint;
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *TcpStream = @ptrCast(@alignCast(ctx));
        return self.remote_endpoint;
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
