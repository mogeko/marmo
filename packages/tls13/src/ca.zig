//! Lazy, shareable system CA bundle for TLS clients.

const std = @import("std");

pub const LoadError = error{
    Canceled,
    LoadFailed,
};

/// One bundle per TLS transport. `ensure` may be called concurrently; the
/// handshake takes a shared lock while it verifies a chain.
pub const Ca = struct {
    gpa: std.mem.Allocator,
    bundle: std.crypto.Certificate.Bundle = .empty,
    lock: std.Io.RwLock = .init,
    loaded: bool = false,

    pub fn init(gpa: std.mem.Allocator) Ca {
        return .{ .gpa = gpa };
    }

    pub fn ensure(self: *Ca, io: std.Io) LoadError!void {
        try self.lock.lock(io);
        defer self.lock.unlock(io);
        if (self.loaded) return;

        self.bundle.rescan(
            self.gpa,
            io,
            std.Io.Timestamp.now(io, .real),
        ) catch {
            self.bundle.deinit(self.gpa);
            self.bundle = .empty;
            return error.LoadFailed;
        };
        self.loaded = true;
    }

    /// Must only run after every connection that uses this bundle is done.
    pub fn deinit(self: *Ca) void {
        if (self.loaded) self.bundle.deinit(self.gpa);
        self.bundle = .empty;
        self.loaded = false;
    }

    pub fn bundlePtr(self: *Ca) *std.crypto.Certificate.Bundle {
        std.debug.assert(self.loaded);
        return &self.bundle;
    }

    pub fn lockPtr(self: *Ca) *std.Io.RwLock {
        return &self.lock;
    }
};
