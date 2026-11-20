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
        // Cancellation must not leave a pointer to a soon-to-be-freed guard
        // in the registry; removal is a short, bounded critical section.
        self.mutex.lockUncancelable(io);
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
    handshake_deadline_ns: std.atomic.Value(i64) = .init(never),
    idle_deadline_ns: std.atomic.Value(i64) = .init(never),
    grace_deadline_ns: std.atomic.Value(i64) = .init(never),
    peer_stream: ?Stream = null,
    peer_lock: std.Io.Mutex = .init,
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
        guard.handshake_deadline_ns.store(
            addDeadline(nowNs(io), timeouts.handshake_ns, false),
            .release,
        );
        guard.phase.store(.handshake, .release);
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
        self.phase.store(.relay, .release);
        self.handshake_deadline_ns.store(never, .release);
        self.idle_deadline_ns.store(
            addDeadline(nowNs(self.io), self.timeouts.idle_ns, true),
            .release,
        );
        self.grace_deadline_ns.store(never, .release);
    }

    /// Records application payload movement in either direction.
    pub fn touch(self: *Guard) void {
        if (self.done.load(.acquire)) return;
        const phase = self.phase.load(.acquire);
        if (phase == .handshake or phase == .done) return;
        if (self.timeouts.idle_ns == 0) return;
        self.idle_deadline_ns.store(
            addDeadline(nowNs(self.io), self.timeouts.idle_ns, true),
            .release,
        );
    }

    /// Starts the absolute grace timer after one direction half-closes.
    pub fn halfClose(self: *Guard, which: HalfClose) void {
        if (self.done.load(.acquire)) return;
        const phase = self.phase.load(.acquire);
        if (phase == .handshake or phase == .done) return;
        const grace = switch (which) {
            .uplink => self.timeouts.downlink_only_ns,
            .downlink => self.timeouts.uplink_only_ns,
        };
        self.phase.store(
            switch (which) {
                .uplink => .downlink_only,
                .downlink => .uplink_only,
            },
            .release,
        );
        self.grace_deadline_ns.store(
            addDeadline(nowNs(self.io), grace, false),
            .release,
        );
    }

    /// Removes the guard from the reaper before the stream is closed.
    pub fn stop(self: *Guard) void {
        if (self.done.swap(true, .acq_rel)) return;
        self.clearPeer();
        self.registry.remove(self.io, self);
    }

    pub fn clearPeer(self: *Guard) void {
        self.peer_lock.lockUncancelable(self.io);
        defer self.peer_lock.unlock(self.io);
        self.peer_stream = null;
    }

    pub fn setPeer(self: *Guard, peer: Stream) void {
        self.peer_lock.lockUncancelable(self.io);
        defer self.peer_lock.unlock(self.io);
        self.peer_stream = peer;
    }

    fn checkExpired(self: *Guard, now: i64) void {
        if (self.done.load(.acquire)) return;
        const phase = self.phase.load(.acquire);
        if (phase == .done) return;
        const deadline = @min(
            self.handshake_deadline_ns.load(.acquire),
            @min(
                self.idle_deadline_ns.load(.acquire),
                self.grace_deadline_ns.load(.acquire),
            ),
        );
        if (now < deadline) return;
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

        // Keep the peer lock across the abort. `stop`/`clearPeer` then cannot
        // let the connection task free the adapter while it is being aborted.
        // Adapters implement `.both` without a write lock or close frame.
        self.peer_lock.lockUncancelable(self.io);
        defer self.peer_lock.unlock(self.io);
        const peer = self.peer_stream;
        self.peer_stream = null;
        if (peer) |stream| {
            stream.shutdown(self.io, .both) catch {};
        }
    }
};

pub fn nowNs(io: std.Io) i64 {
    const timestamp = std.Io.Timestamp.now(io, .awake);
    return std.math.cast(i64, timestamp.nanoseconds) orelse
        std.math.maxInt(i64);
}

fn addDeadline(now: i64, timeout_ns: u64, zero_means_never: bool) i64 {
    if (timeout_ns == 0) return if (zero_means_never) never else now;
    if (timeout_ns > std.math.maxInt(i64)) return never;
    return std.math.add(i64, now, @intCast(timeout_ns)) catch never;
}

test "zero grace is immediate while zero idle is disabled" {
    try std.testing.expectEqual(
        @as(i64, 100),
        addDeadline(100, 0, false),
    );
    try std.testing.expectEqual(never, addDeadline(100, 0, true));
}

test "idle and grace deadlines remain independent" {
    var entries: [0]?*Guard = .{};
    var registry: Registry = .{ .entries = entries[0..] };
    var metrics: Metrics = .{};
    var guard = Guard.init(
        std.testing.io,
        &registry,
        &metrics,
        undefined,
        .{
            .handshake_ns = std.time.ns_per_s,
            .idle_ns = 2 * std.time.ns_per_s,
            .uplink_only_ns = 5 * std.time.ns_per_s,
            .downlink_only_ns = 5 * std.time.ns_per_s,
        },
    );
    guard.markRelay();
    const idle = guard.idle_deadline_ns.load(.acquire);
    guard.halfClose(.uplink);
    const grace = guard.grace_deadline_ns.load(.acquire);
    try std.testing.expect(idle < grace);
    try std.testing.expectEqual(idle, guard.idle_deadline_ns.load(.acquire));
    guard.touch();
    try std.testing.expect(guard.idle_deadline_ns.load(.acquire) >= idle);
}
