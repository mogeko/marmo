//! Ordered byte streams.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;

/// A duplex, ordered byte stream owned by the connection.
pub const Stream = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const ShutdownHow = enum { recv, send, both };

    pub const ReadError = error{
        Canceled,
        ConnectionReset,
        Unexpected,
    };

    pub const WriteError = error{
        BrokenPipe,
        Canceled,
        Unexpected,
    };

    pub const ShutdownError = error{
        Canceled,
        NotConnected,
        Unexpected,
    };

    /// `read` returns 0 only on clean EOF.
    ///
    /// `close` is idempotent and must unblock pending reads and writes. It does
    /// not free the memory owned by the parent connection.
    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, io: std.Io, buffers: [][]u8) ReadError!usize,
        write: *const fn (
            ctx: *anyopaque,
            io: std.Io,
            buffers: []const []const u8,
        ) WriteError!usize,
        shutdown: *const fn (
            ctx: *anyopaque,
            io: std.Io,
            how: ShutdownHow,
        ) ShutdownError!void,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
        local: *const fn (ctx: *anyopaque) Endpoint,
        remote: *const fn (ctx: *anyopaque) Endpoint,
    };

    pub fn read(self: Stream, io: std.Io, buffers: [][]u8) ReadError!usize {
        return self.vtable.read(self.ctx, io, buffers);
    }

    pub fn write(self: Stream, io: std.Io, buffers: []const []const u8) WriteError!usize {
        return self.vtable.write(self.ctx, io, buffers);
    }

    pub fn shutdown(self: Stream, io: std.Io, how: ShutdownHow) ShutdownError!void {
        return self.vtable.shutdown(self.ctx, io, how);
    }

    pub fn close(self: Stream, io: std.Io) void {
        self.vtable.close(self.ctx, io);
    }

    pub fn local(self: Stream) Endpoint {
        return self.vtable.local(self.ctx);
    }

    pub fn remote(self: Stream) Endpoint {
        return self.vtable.remote(self.ctx);
    }
};
