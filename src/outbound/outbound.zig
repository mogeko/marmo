//! A named outbound and its dialer.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("../transport/dialer.zig").Dialer;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;

/// `tag` and the dialer context are owned by the configuration that created
/// them and must outlive the outbound.
pub const Outbound = struct {
    tag: []const u8,
    dialer: Dialer,
    supports_udp: bool = false,

    pub fn connect(
        self: *const Outbound,
        io: std.Io,
        target: Endpoint,
    ) Dialer.ConnectError!Stream {
        return self.dialer.connect(io, target);
    }

    pub fn connect_packet(
        self: *const Outbound,
        io: std.Io,
        target: Endpoint,
    ) Dialer.ConnectError!PacketConn {
        if (!self.supports_udp) return error.Unsupported;
        return self.dialer.connect_packet(io, target);
    }
};
