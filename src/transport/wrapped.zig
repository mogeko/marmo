//! Adapter for streams whose endpoints differ from the underlying transport.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("stream.zig").Stream;
const Guard = @import("lifetime.zig").Guard;

/// Used by protocol tunnels (for example HTTP CONNECT): reads and writes
/// delegate to `inner`, while `remote` reports the tunnel target.
pub const WrappedStream = struct {
    gpa: std.mem.Allocator,
    inner: Stream,
    local_endpoint: Endpoint,
    remote_endpoint: Endpoint,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},

    pub fn create(
        gpa: std.mem.Allocator,
        inner: Stream,
        local_endpoint: Endpoint,
        remote_endpoint: Endpoint,
    ) !*WrappedStream {
        const self = try gpa.create(WrappedStream);
        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .local_endpoint = local_endpoint,
            .remote_endpoint = remote_endpoint,
        };
        return self;
    }

    pub fn stream(self: *WrappedStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        const self: *WrappedStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        return self.inner.read(io, buffers);
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *WrappedStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        return self.inner.write(io, buffers);
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *WrappedStream = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        return self.inner.shutdown(io, how);
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *WrappedStream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        self.guard.waitIdle(io);
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *WrappedStream = @ptrCast(@alignCast(ctx));
        return self.local_endpoint;
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *WrappedStream = @ptrCast(@alignCast(ctx));
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
