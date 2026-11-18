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

pub const Selector = struct {
    nodes: []*const Outbound,
    strategy: Strategy,
    latency_ms: []std.atomic.Value(u64),
    failures: []std.atomic.Value(u32),
    next: std.atomic.Value(u64) = .init(0),

    pub fn init(
        allocator: std.mem.Allocator,
        nodes: []*const Outbound,
        strategy: Strategy,
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
        };
        return self;
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
