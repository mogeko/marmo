//! What an inbound handler needs from the instance.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Metadata = @import("../routing/metadata.zig").Metadata;
const Action = @import("../routing/router.zig").Action;
const Dialer = @import("../transport/dialer.zig").Dialer;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;
const Metrics = @import("metrics.zig").Metrics;

/// Decouples inbound protocol handlers from `Instance` and its config.
pub const Dispatch = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        route: *const fn (ctx: *anyopaque, metadata: *const Metadata) Action,
        connect: *const fn (
            ctx: *anyopaque,
            io: std.Io,
            tag: []const u8,
            target: Endpoint,
        ) Dialer.ConnectError!Stream,
        connect_packet: *const fn (
            ctx: *anyopaque,
            io: std.Io,
            tag: []const u8,
            target: Endpoint,
        ) Dialer.ConnectError!PacketConn,
        metrics: *const fn (ctx: *anyopaque) *Metrics,
    };

    pub fn route(self: Dispatch, metadata: *const Metadata) Action {
        return self.vtable.route(self.ctx, metadata);
    }

    pub fn connect(
        self: Dispatch,
        io: std.Io,
        tag: []const u8,
        target: Endpoint,
    ) Dialer.ConnectError!Stream {
        return self.vtable.connect(self.ctx, io, tag, target);
    }

    pub fn connect_packet(
        self: Dispatch,
        io: std.Io,
        tag: []const u8,
        target: Endpoint,
    ) Dialer.ConnectError!PacketConn {
        return self.vtable.connect_packet(self.ctx, io, tag, target);
    }

    pub fn metrics(self: Dispatch) *Metrics {
        return self.vtable.metrics(self.ctx);
    }
};
