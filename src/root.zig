//! marmo public API.
//!
//! The library never owns threads, an event loop, a global allocator, or a
//! process-level signal handler. Every I/O operation takes `std.Io`.

const std = @import("std");

pub const Endpoint = @import("net/endpoint.zig").Endpoint;
pub const Cidr = @import("net/cidr.zig").Cidr;

pub const Config = @import("config/config.zig").Config;
pub const ParsedConfig = @import("config/config.zig").Parsed;
pub const Diagnostic = @import("core/diagnostic.zig").Diagnostic;
pub const Metrics = @import("core/metrics.zig").Metrics;

pub const Metadata = @import("routing/metadata.zig").Metadata;
pub const Network = @import("routing/metadata.zig").Network;
pub const ProcessInfo = @import("routing/metadata.zig").ProcessInfo;
pub const SniffedProtocol = @import("routing/metadata.zig").SniffedProtocol;

pub const Action = @import("routing/router.zig").Action;
pub const RejectReason = @import("routing/router.zig").RejectReason;
pub const Router = @import("routing/router.zig").Router;
pub const RuleSet = @import("routing/rules.zig").RuleSet;
pub const Shadowsocks2022 = @import("protocol/shadowsocks2022.zig");
pub const VlessProtocol = @import("protocol/vless.zig");

pub const Dialer = @import("transport/dialer.zig").Dialer;
pub const ConnectError = Dialer.ConnectError;
pub const PacketConn = @import("transport/packet.zig").PacketConn;
pub const Received = PacketConn.Received;
pub const Stream = @import("transport/stream.zig").Stream;
pub const ShutdownHow = Stream.ShutdownHow;
pub const TcpStream = @import("transport/tcp.zig").TcpStream;
pub const TlsClientStream = @import("transport/tls_client.zig").TlsClientStream;
pub const TlsDialer = @import("transport/tls_dialer.zig").TlsDialer;
pub const TlsServerStream = @import("transport/tls_server.zig").TlsServerStream;
pub const UdpPacketConn = @import("transport/udp.zig").UdpPacketConn;

pub const Outbound = @import("outbound/outbound.zig").Outbound;
pub const Direct = @import("outbound/direct.zig").Direct;
pub const HttpConnect = @import("outbound/http_connect.zig").HttpConnect;
pub const Vless = @import("outbound/vless.zig").Vless;

pub const Instance = @import("instance.zig").Instance;

pub const Connection = @import("inbound/connection.zig").Connection;
pub const Inbound = @import("inbound/inbound.zig").Inbound;
pub const AcceptError = Inbound.AcceptError;

pub const limits = @import("core/limits.zig");

test {
    _ = @import("transport/write.zig");
    std.testing.refAllDecls(@This());
}
