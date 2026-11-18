//! Connection metadata used for routing.

const Endpoint = @import("../net/endpoint.zig").Endpoint;

pub const Network = enum { tcp, udp };

pub const SniffedProtocol = enum { tls, http, quic };

pub const ProcessInfo = struct {
    pid: u32,
    name: []const u8,
    path: ?[]const u8 = null,
};

/// Immutable routing input for one connection or UDP session.
///
/// All slices are borrowed from the connection arena and stay valid until the
/// connection is destroyed.
pub const Metadata = struct {
    network: Network,
    source: Endpoint,
    destination: Endpoint,
    domain: ?[]const u8 = null,
    inbound: []const u8,
    process: ?ProcessInfo = null,
    sniffed: ?SniffedProtocol = null,
};
