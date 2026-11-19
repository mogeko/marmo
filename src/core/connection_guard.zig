//! Per-connection handshake/idle/half-close deadlines (ADR-0015).
//!
//! A single `Registry` is scanned by one task per `Instance`. Per-connection
//! watchdog tasks were rejected during implementation because
//! `Io.Threaded` dispatches them as blocking pool workers; enough sleeping
//! watchdogs can starve the connection tasks they are meant to police.

const std = @import("std");
const Metrics = @import("metrics.zig").Metrics;
const Stream = @import("../transport/stream.zig").Stream;

pub const Timeouts = struct {
    handshake_ns: u64,
    idle_ns: u64,
    uplink_only_ns: u64,
    downlink_only_ns: u64,
};

pub const Phase = enum(u8) {
    handshake,
    relay,
    uplink_only,
    downlink_only,
    done,
};

pub const HalfClose = enum { uplink, downlink };

const never = std.math.maxInt(i64);

pub const Registry = struct {
    entries: []?*Guard,
    mutex: std.Io.Mutex = .init,

    pub fn init(allocator: std.mem.Allocator, capacity: u32) !Registry {
        const entries = try allocator.alloc(?*Guard, capacity);
        @memset(entries, null);
        return .{ .entries = entries };
    }

    pub fn deinit(self: *Registry, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = undefined;
    }

    fn add(self: *Registry, io: std.Io, guard: *Guard) bool {
        self.mutex.lock(io) catch return false;
        defer self.mutex.unlock(io);
        for (self.entries) |*entry| {
            if (entry.* == null) {
                entry.* = guard;
                return true;
            }
        }
        return false;
    }

    fn remove(self: *Registry, io: std.Io, guard: *Guard) void {
        self.mutex.lock(io) catch return;
        defer self.mutex.unlock(io);
        for (self.entries) |*entry| {
            if (entry.* == guard) {
                entry.* = null;
                return;
            }
        }
    }

    /// Scans every registered guard. The caller owns the schedule.
    pub fn scan(self: *Registry, io: std.Io, now: i64) void {
        self.mutex.lock(io) catch return;
        defer self.mutex.unlock(io);
        for (self.entries) |entry| {
            if (entry) |guard| guard.checkExpired(now);
        }
    }
};

pub const Guard = struct {
    io: std.Io,
    registry: *Registry,
    metrics: *Metrics,
    abort_stream: Stream,
    timeouts: Timeouts,
    phase: std.atomic.Value(Phase) = .init(.handshake),
    deadline_ns: std.atomic.Value(i64) = .init(0),
    done: std.atomic.Value(bool) = .init(false),
    fired: std.atomic.Value(bool) = .init(false),

    /// The handshake deadline starts at accept. Registration happens before
    /// the connection task is spawned.
    pub fn init(
        io: std.Io,
        registry: *Registry,
        metrics: *Metrics,
        abort_stream: Stream,
        timeouts: Timeouts,
    ) Guard {
        var guard: Guard = .{
            .io = io,
            .registry = registry,
            .metrics = metrics,
            .abort_stream = abort_stream,
            .timeouts = timeouts,
        };
        guard.arm(.handshake, timeouts.handshake_ns);
        return guard;
    }

    pub fn register(self: *Guard) bool {
        return self.registry.add(self.io, self);
    }

    /// Called by the relay once the connection is established. Switches from
    /// the absolute handshake deadline to the activity-based idle deadline.
    pub fn markRelay(self: *Guard) void {
        if (self.done.load(.acquire)) return;
        if (self.phase.load(.acquire) != .handshake) return;
        self.arm(.relay, self.timeouts.idle_ns);
    }

    /// Records application payload movement in either direction.
    pub fn touch(self: *Guard) void {
        if (self.done.load(.acquire)) return;
        if (self.phase.load(.acquire) != .relay) return;
        if (self.timeouts.idle_ns == 0) return;
        const deadline = addTimeout(nowNs(self.io), self.timeouts.idle_ns);
        self.deadline_ns.store(deadline, .release);
    }

    /// Starts the absolute grace timer after one direction half-closes.
    pub fn halfClose(self: *Guard, which: HalfClose) void {
        if (self.done.load(.acquire)) return;
        const phase = self.phase.load(.acquire);
        if (phase == .handshake or phase == .done) return;
        switch (which) {
            .uplink => self.arm(.downlink_only, self.timeouts.downlink_only_ns),
            .downlink => self.arm(.uplink_only, self.timeouts.uplink_only_ns),
        }
    }

    /// Removes the guard from the reaper before the stream is closed.
    pub fn stop(self: *Guard) void {
        if (self.done.swap(true, .acq_rel)) return;
        self.registry.remove(self.io, self);
    }

    fn arm(self: *Guard, phase: Phase, timeout_ns: u64) void {
        self.phase.store(phase, .release);
        self.deadline_ns.store(
            addTimeout(nowNs(self.io), timeout_ns),
            .release,
        );
    }

    fn checkExpired(self: *Guard, now: i64) void {
        if (self.done.load(.acquire)) return;
        const phase = self.phase.load(.acquire);
        if (phase == .done) return;
        if (now < self.deadline_ns.load(.acquire)) return;
        self.fire(phase);
    }

    fn fire(self: *Guard, phase: Phase) void {
        if (self.fired.swap(true, .acq_rel)) return;
        switch (phase) {
            .handshake => self.metrics.timeoutHandshake(),
            .relay, .uplink_only, .downlink_only => self.metrics.timeoutIdle(),
            .done => return,
        }
        self.phase.store(.done, .release);
        // Some platforms report ENOTCONN for `.both` after a peer half-close;
        // try the directions separately so the remaining side still sees EOF.
        self.abort_stream.shutdown(self.io, .send) catch {};
        self.abort_stream.shutdown(self.io, .recv) catch {};
    }
};

pub fn nowNs(io: std.Io) i64 {
    const timestamp = std.Io.Timestamp.now(io, .awake);
    return std.math.cast(i64, timestamp.nanoseconds) orelse
        std.math.maxInt(i64);
}

fn addTimeout(now: i64, timeout_ns: u64) i64 {
    if (timeout_ns == 0) return never;
    if (timeout_ns > std.math.maxInt(i64)) return never;
    return std.math.add(i64, now, @intCast(timeout_ns)) catch never;
}
