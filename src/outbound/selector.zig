//! Outbound selector with passive latency tracking.

const std = @import("std");
const config = @import("../config/config.zig");
const Strategy = config.Config.Strategy;
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("../transport/dialer.zig").Dialer;
const ConnectError = Dialer.ConnectError;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;
const Outbound = @import("outbound.zig").Outbound;

pub const Health = struct {
    target: Endpoint,
    interval_ns: u64,
    timeout_ns: u64,
};

const ProbeResult = union(enum) {
    connect: ConnectError!Stream,
    timeout: std.Io.Cancelable!void,
};

pub const Selector = struct {
    nodes: []*const Outbound,
    strategy: Strategy,
    latency_ms: []std.atomic.Value(u64),
    failures: []std.atomic.Value(u32),
    next: std.atomic.Value(u64) = .init(0),
    health: ?Health = null,

    pub fn init(
        allocator: std.mem.Allocator,
        nodes: []*const Outbound,
        strategy: Strategy,
        health: ?Health,
    ) !*Selector {
        const self = try allocator.create(Selector);
        const latencies = try allocator.alloc(std.atomic.Value(u64), nodes.len);
        errdefer allocator.free(latencies);
        const failures = try allocator.alloc(std.atomic.Value(u32), nodes.len);
        for (latencies) |*latency| latency.* = .init(std.math.maxInt(u64));
        for (failures) |*failure| failure.* = .init(0);

        self.* = .{
            .nodes = nodes,
            .strategy = strategy,
            .latency_ms = latencies,
            .failures = failures,
            .health = health,
        };
        return self;
    }

    pub fn hasHealth(self: *const Selector) bool {
        return self.health != null;
    }

    pub fn runHealth(self: *Selector, io: std.Io) std.Io.Cancelable!void {
        const health = self.health orelse return;
        while (true) {
            for (self.nodes, 0..) |_, index| {
                self.probeNode(io, index) catch |err| switch (err) {
                    error.Canceled => return,
                };
            }
            try std.Io.sleep(io, .{ .nanoseconds = health.interval_ns }, .awake);
        }
    }

    fn probeNode(self: *Selector, io: std.Io, index: usize) std.Io.Cancelable!void {
        const health = self.health orelse return;
        var buffer: [2]ProbeResult = undefined;
        var select: std.Io.Select(ProbeResult) = .init(io, &buffer);

        select.concurrent(.connect, probeConnect, .{
            self.nodes[index],
            io,
            health.target,
        }) catch {
            drainProbe(&select, io);
            return;
        };
        select.concurrent(.timeout, probeSleep, .{
            io,
            health.timeout_ns,
        }) catch {
            drainProbe(&select, io);
            return;
        };

        const begin = std.Io.Timestamp.now(io, .awake);
        const result = select.await() catch |err| {
            drainProbe(&select, io);
            switch (err) {
                error.Canceled => return error.Canceled,
            }
        };
        const end = std.Io.Timestamp.now(io, .awake);
        drainProbe(&select, io);

        switch (result) {
            .connect => |connected| {
                if (connected) |stream| {
                    stream.close(io);
                    self.recordSuccess(index, elapsedMs(begin, end));
                } else |err| {
                    if (err == error.Canceled) return error.Canceled;
                    self.recordFailure(index);
                }
            },
            .timeout => |timed_out| {
                timed_out catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
                self.recordFailure(index);
            },
        }
    }

    pub fn asDialer(self: *Selector) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn supportsUdp(self: *const Selector) bool {
        for (self.nodes) |node| {
            if (node.supports_udp) return true;
        }
        return false;
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!Stream {
        const self: *Selector = @ptrCast(@alignCast(ctx));
        return self.connectAny(io, target);
    }

    fn connectPacket(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!PacketConn {
        const self: *Selector = @ptrCast(@alignCast(ctx));
        return self.connectPacketAny(io, target);
    }

    fn connectAny(self: *Selector, io: std.Io, target: Endpoint) ConnectError!Stream {
        if (self.nodes.len == 0) return error.Unsupported;
        if (self.strategy == .manual) return self.connectNode(io, 0, target);

        const start = self.startIndex(io);
        var last_error: ConnectError = error.Unexpected;

        if (self.connectNode(io, start, target)) |stream| {
            return stream;
        } else |err| {
            if (err == error.Canceled) return err;
            last_error = err;
        }

        var index: usize = 0;
        while (index < self.nodes.len) : (index += 1) {
            if (index == start) continue;
            if (self.connectNode(io, index, target)) |stream| {
                return stream;
            } else |err| {
                if (err == error.Canceled) return err;
                last_error = err;
            }
        }
        return last_error;
    }

    fn connectPacketAny(
        self: *Selector,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!PacketConn {
        if (self.nodes.len == 0) return error.Unsupported;
        if (self.strategy == .manual) {
            const node = self.nodes[0];
            if (!node.supports_udp) return error.Unsupported;
            return self.connectPacketNode(io, 0, target);
        }

        const start = self.startIndex(io);
        var last_error: ConnectError = error.Unsupported;
        var attempted = false;

        if (self.nodes[start].supports_udp) {
            attempted = true;
            if (self.connectPacketNode(io, start, target)) |packets| {
                return packets;
            } else |err| {
                if (err == error.Canceled) return err;
                last_error = err;
            }
        }

        var index: usize = 0;
        while (index < self.nodes.len) : (index += 1) {
            if (index == start or !self.nodes[index].supports_udp) continue;
            attempted = true;
            if (self.connectPacketNode(io, index, target)) |packets| {
                return packets;
            } else |err| {
                if (err == error.Canceled) return err;
                last_error = err;
            }
        }
        if (!attempted) return error.Unsupported;
        return last_error;
    }

    fn connectNode(
        self: *Selector,
        io: std.Io,
        index: usize,
        target: Endpoint,
    ) ConnectError!Stream {
        const begin = std.Io.Timestamp.now(io, .awake);
        const stream = self.nodes[index].connect(io, target) catch |err| {
            self.recordFailure(index);
            return err;
        };
        const end = std.Io.Timestamp.now(io, .awake);
        self.recordSuccess(index, elapsedMs(begin, end));
        return stream;
    }

    fn connectPacketNode(
        self: *Selector,
        io: std.Io,
        index: usize,
        target: Endpoint,
    ) ConnectError!PacketConn {
        const begin = std.Io.Timestamp.now(io, .awake);
        const packets = self.nodes[index].connect_packet(io, target) catch |err| {
            self.recordFailure(index);
            return err;
        };
        const end = std.Io.Timestamp.now(io, .awake);
        self.recordSuccess(index, elapsedMs(begin, end));
        return packets;
    }

    fn startIndex(self: *Selector, io: std.Io) usize {
        return switch (self.strategy) {
            .manual, .fallback => 0,
            .round_robin => @intCast(self.next.fetchAdd(1, .monotonic) % self.nodes.len),
            .random => randomIndex(io, self.nodes.len),
            .least_latency => self.bestIndex(),
        };
    }

    fn bestIndex(self: *const Selector) usize {
        // Sample every healthy node at least once before ranking known latencies.
        for (self.nodes, 0..) |_, index| {
            const latency = self.latency_ms[index].load(.monotonic);
            if (latency == std.math.maxInt(u64) and
                self.failures[index].load(.monotonic) == 0)
            {
                return index;
            }
        }

        var best: usize = 0;
        var best_score: u64 = std.math.maxInt(u64);

        for (self.nodes, 0..) |_, index| {
            const latency = self.latency_ms[index].load(.monotonic);
            var score = latency;
            if (score != std.math.maxInt(u64)) {
                score +|= @as(u64, self.failures[index].load(.monotonic)) * 1000;
            }
            if (score < best_score) {
                best = index;
                best_score = score;
            }
        }
        return best;
    }

    fn recordSuccess(self: *Selector, index: usize, sample_ms: u64) void {
        const old = self.latency_ms[index].load(.monotonic);
        const sample = @max(sample_ms, 1);
        const next = if (old == std.math.maxInt(u64))
            sample
        else
            (old *| 4 +| sample) / 5;
        self.latency_ms[index].store(@max(next, 1), .monotonic);
        self.failures[index].store(0, .monotonic);
    }

    fn recordFailure(self: *Selector, index: usize) void {
        _ = self.failures[index].fetchAdd(1, .monotonic);
    }

    const vtable: Dialer.VTable = .{
        .connect = connect,
        .connect_packet = connectPacket,
    };
};

fn probeConnect(
    node: *const Outbound,
    io: std.Io,
    target: Endpoint,
) ConnectError!Stream {
    return node.connect(io, target);
}

fn probeSleep(io: std.Io, timeout_ns: u64) std.Io.Cancelable!void {
    try std.Io.sleep(io, .{ .nanoseconds = @intCast(timeout_ns) }, .awake);
}

fn drainProbe(select: *std.Io.Select(ProbeResult), io: std.Io) void {
    while (select.cancel()) |result| {
        switch (result) {
            .connect => |connected| {
                if (connected) |stream| stream.close(io) else |_| {}
            },
            .timeout => |timed_out| timed_out catch {},
        }
    }
}

fn elapsedMs(begin: std.Io.Timestamp, end: std.Io.Timestamp) u64 {
    const nanoseconds = begin.durationTo(end).nanoseconds;
    if (nanoseconds <= 0) return 1;
    return @intCast(@divTrunc(nanoseconds, std.time.ns_per_ms));
}

fn randomIndex(io: std.Io, count: usize) usize {
    var bytes: [8]u8 = undefined;
    std.Io.random(io, &bytes);
    return @intCast(std.mem.readInt(u64, &bytes, .little) % count);
}
