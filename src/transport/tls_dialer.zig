//! TLS transport dialer: wraps another dialer and adds a TLS 1.3 handshake.

const std = @import("std");
const tls13 = @import("tls13");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("dialer.zig").Dialer;
const Stream = @import("stream.zig").Stream;
const TlsClientStream = @import("tls_client.zig").TlsClientStream;

pub const TlsDialer = struct {
    gpa: std.mem.Allocator,
    base: Dialer,
    /// SNI and certificate host; null disables both.
    server_name: ?[]const u8,
    insecure: bool,
    handshake_timeout_ns: u64,
    alpn_protocols: []const []const u8 = &.{},
    required_alpn: ?[]const u8 = null,
    allow_truncation_attacks: bool = false,
    ca: tls13.Ca,

    pub fn init(
        gpa: std.mem.Allocator,
        base: Dialer,
        server_name: ?[]const u8,
        insecure: bool,
        handshake_timeout_ns: u64,
    ) TlsDialer {
        return .{
            .gpa = gpa,
            .base = base,
            .server_name = server_name,
            .insecure = insecure,
            .handshake_timeout_ns = handshake_timeout_ns,
            .ca = .init(gpa),
        };
    }

    pub fn asDialer(self: *TlsDialer) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn deinit(self: *TlsDialer) void {
        self.ca.deinit();
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        endpoint: Endpoint,
    ) Dialer.ConnectError!Stream {
        const self: *TlsDialer = @ptrCast(@alignCast(ctx));
        const inner = try self.base.connect(io, endpoint);
        const tls_stream = TlsClientStream.create(io, self.gpa, inner, .{
            .server_name = self.server_name,
            .insecure = self.insecure,
            .ca = if (self.insecure) null else &self.ca,
            .alpn_protocols = self.alpn_protocols,
            .required_alpn = self.required_alpn,
            .allow_truncation_attacks = self.allow_truncation_attacks,
            .handshake_timeout_ns = self.handshake_timeout_ns,
        }) catch |err| {
            inner.close(io);
            return switch (err) {
                error.Canceled => error.Canceled,
                error.OutOfMemory => error.Unexpected,
                error.HandshakeFailed => error.ProtocolViolation,
                error.TimedOut => error.TimedOut,
            };
        };
        return tls_stream.stream();
    }

    const vtable: Dialer.VTable = .{ .connect = connect };
};
