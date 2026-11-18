//! Connection state owned by an inbound.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Metadata = @import("../routing/metadata.zig").Metadata;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;

/// A connection and its arena.
///
/// The inbound allocates `Connection` with its long-lived allocator and builds
/// all metadata slices in `arena`. `deinit` must be called exactly once: it
/// closes the transports and frees the connection and its arena.
pub const Connection = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    stream: ?Stream = null,
    packets: ?PacketConn = null,
    metadata: Metadata,

    pub fn allocator(self: *Connection) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn deinit(self: *Connection, io: std.Io) void {
        const gpa = self.gpa;

        if (self.stream) |stream| stream.close(io);
        if (self.packets) |packets| packets.close(io);

        self.arena.deinit();
        gpa.destroy(self);
    }

    pub fn local(self: *const Connection) ?Endpoint {
        if (self.stream) |stream| return stream.local();
        return null;
    }

    pub fn remote(self: *const Connection) ?Endpoint {
        if (self.stream) |stream| return stream.remote();
        return null;
    }
};
