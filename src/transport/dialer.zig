//! Outbound connection establishment.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const PacketConn = @import("packet.zig").PacketConn;
const Stream = @import("stream.zig").Stream;

/// Establishes a stream or packet connection to a target.
///
/// Transports wrap another dialer; the innermost dialer owns the socket. The
/// dialer context is owned by the configuration and outlives every call; this
/// interface has no deinit.
pub const Dialer = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const ConnectError = error{
        Canceled,
        ConnectionRefused,
        HostUnreachable,
        TimedOut,
        Unexpected,
        Unsupported,
    };

    pub const VTable = struct {
        connect: *const fn (
            ctx: *anyopaque,
            io: std.Io,
            target: Endpoint,
        ) ConnectError!Stream,
        connect_packet: ?*const fn (
            ctx: *anyopaque,
            io: std.Io,
            target: Endpoint,
        ) ConnectError!PacketConn = null,
    };

    pub fn connect(self: Dialer, io: std.Io, target: Endpoint) ConnectError!Stream {
        return self.vtable.connect(self.ctx, io, target);
    }

    pub fn connect_packet(
        self: Dialer,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!PacketConn {
        const connect_packet_fn = self.vtable.connect_packet orelse
            return error.Unsupported;
        return connect_packet_fn(self.ctx, io, target);
    }
};
