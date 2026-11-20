//! Tracks in-flight stream operations so `close` can unblock I/O and only
//! release the adapter after every reader/writer has returned.

const std = @import("std");

pub const Guard = struct {
    active: std.atomic.Value(u32) = .init(0),
    idle: std.Io.Event = .unset,

    pub fn enter(self: *Guard) void {
        _ = self.active.fetchAdd(1, .acq_rel);
    }

    pub fn leave(self: *Guard, io: std.Io) void {
        if (self.active.fetchSub(1, .acq_rel) == 1) self.idle.set(io);
    }

    /// Called by `close` after the underlying transport has been closed to
    /// unblock pending operations. Does not return until all in-flight
    /// operations have left the guard.
    pub fn waitIdle(self: *Guard, io: std.Io) void {
        while (true) {
            if (self.active.load(.acquire) == 0) return;
            self.idle.waitUncancelable(io);
            self.idle.reset();
        }
    }
};
