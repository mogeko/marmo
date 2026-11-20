//! Atomic counters exposed to embedders.

const std = @import("std");

pub const Metrics = struct {
    connections_total: std.atomic.Value(u64) = .init(0),
    connections_active: std.atomic.Value(u64) = .init(0),
    connections_rejected: std.atomic.Value(u64) = .init(0),
    timeouts_handshake: std.atomic.Value(u64) = .init(0),
    timeouts_idle: std.atomic.Value(u64) = .init(0),
    bytes_to_remote: std.atomic.Value(u64) = .init(0),
    bytes_to_client: std.atomic.Value(u64) = .init(0),
    udp_sessions_total: std.atomic.Value(u64) = .init(0),

    pub const Snapshot = struct {
        connections_total: u64,
        connections_active: u64,
        connections_rejected: u64,
        timeouts_handshake: u64,
        timeouts_idle: u64,
        bytes_to_remote: u64,
        bytes_to_client: u64,
        udp_sessions_total: u64,
    };

    pub fn connectionOpened(self: *Metrics) void {
        _ = self.connections_total.fetchAdd(1, .monotonic);
        _ = self.connections_active.fetchAdd(1, .monotonic);
    }

    pub fn connectionClosed(self: *Metrics) void {
        _ = self.connections_active.fetchSub(1, .monotonic);
    }

    pub fn connectionRejected(self: *Metrics) void {
        _ = self.connections_rejected.fetchAdd(1, .monotonic);
    }

    pub fn timeoutHandshake(self: *Metrics) void {
        _ = self.timeouts_handshake.fetchAdd(1, .monotonic);
    }

    pub fn timeoutIdle(self: *Metrics) void {
        _ = self.timeouts_idle.fetchAdd(1, .monotonic);
    }

    pub fn udpSessionOpened(self: *Metrics) void {
        _ = self.udp_sessions_total.fetchAdd(1, .monotonic);
    }

    pub fn addToRemote(self: *Metrics, bytes: usize) void {
        _ = self.bytes_to_remote.fetchAdd(bytes, .monotonic);
    }

    pub fn addToClient(self: *Metrics, bytes: usize) void {
        _ = self.bytes_to_client.fetchAdd(bytes, .monotonic);
    }

    pub fn snapshot(self: *const Metrics) Snapshot {
        return .{
            .connections_total = self.connections_total.load(.monotonic),
            .connections_active = self.connections_active.load(.monotonic),
            .connections_rejected = self.connections_rejected.load(.monotonic),
            .timeouts_handshake = self.timeouts_handshake.load(.monotonic),
            .timeouts_idle = self.timeouts_idle.load(.monotonic),
            .bytes_to_remote = self.bytes_to_remote.load(.monotonic),
            .bytes_to_client = self.bytes_to_client.load(.monotonic),
            .udp_sessions_total = self.udp_sessions_total.load(.monotonic),
        };
    }
};

test "metrics count connections and bytes" {
    var metrics: Metrics = .{};
    metrics.connectionOpened();
    metrics.connectionOpened();
    metrics.connectionClosed();
    metrics.connectionRejected();
    metrics.timeoutHandshake();
    metrics.timeoutIdle();
    metrics.addToRemote(10);
    metrics.addToClient(20);

    const snapshot = metrics.snapshot();
    try std.testing.expectEqual(@as(u64, 2), snapshot.connections_total);
    try std.testing.expectEqual(@as(u64, 1), snapshot.connections_active);
    try std.testing.expectEqual(@as(u64, 1), snapshot.connections_rejected);
    try std.testing.expectEqual(@as(u64, 1), snapshot.timeouts_handshake);
    try std.testing.expectEqual(@as(u64, 1), snapshot.timeouts_idle);
    try std.testing.expectEqual(@as(u64, 10), snapshot.bytes_to_remote);
    try std.testing.expectEqual(@as(u64, 20), snapshot.bytes_to_client);
}
