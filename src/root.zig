//! marmo public API.
//!
//! The library never owns threads, an event loop, a global allocator, or a
//! process-level signal handler. Every I/O operation takes `std.Io`.

const std = @import("std");

pub const Endpoint = @import("net/endpoint.zig").Endpoint;

pub const Metadata = @import("routing/metadata.zig").Metadata;
pub const Network = @import("routing/metadata.zig").Network;
pub const ProcessInfo = @import("routing/metadata.zig").ProcessInfo;
pub const SniffedProtocol = @import("routing/metadata.zig").SniffedProtocol;

pub const Action = @import("routing/router.zig").Action;
pub const RejectReason = @import("routing/router.zig").RejectReason;
pub const Router = @import("routing/router.zig").Router;

pub const Dialer = @import("transport/dialer.zig").Dialer;
pub const ConnectError = Dialer.ConnectError;
pub const PacketConn = @import("transport/packet.zig").PacketConn;
pub const Received = PacketConn.Received;
pub const Stream = @import("transport/stream.zig").Stream;
pub const ShutdownHow = Stream.ShutdownHow;

pub const Outbound = @import("outbound/outbound.zig").Outbound;

pub const Connection = @import("inbound/connection.zig").Connection;
pub const Inbound = @import("inbound/inbound.zig").Inbound;
pub const AcceptError = Inbound.AcceptError;

pub const limits = @import("core/limits.zig");

test {
    std.testing.refAllDecls(@This());
}
