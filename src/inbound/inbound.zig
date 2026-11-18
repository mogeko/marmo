//! Inbound listener interface.

const std = @import("std");
const Connection = @import("connection.zig").Connection;

/// A configured listener.
///
/// The inbound owns its accept state. Every returned connection is owned by the
/// caller until `Connection.deinit` is called.
pub const Inbound = struct {
    tag: []const u8,
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const AcceptError = error{
        Canceled,
        Closed,
        Unexpected,
    };

    pub const VTable = struct {
        accept: *const fn (ctx: *anyopaque, io: std.Io) AcceptError!*Connection,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
    };

    pub fn accept(self: *const Inbound, io: std.Io) AcceptError!*Connection {
        return self.vtable.accept(self.ctx, io);
    }

    /// `close` is idempotent and unblocks `accept`.
    pub fn close(self: *const Inbound, io: std.Io) void {
        self.vtable.close(self.ctx, io);
    }
};
