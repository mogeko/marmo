//! WebSocket transport dialer: wraps another dialer and performs the RFC 6455
//! opening handshake.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("dialer.zig").Dialer;
const Stream = @import("stream.zig").Stream;
const ws_stream = @import("ws_stream.zig");

pub const WsDialer = struct {
    gpa: std.mem.Allocator,
    base: Dialer,
    host: []const u8,
    path: []const u8 = "/",
    subprotocols: []const []const u8 = &.{},
    compression: bool = false,
    compression_no_context_takeover: bool = false,
    handshake_timeout_ns: u64 = ws_stream.default_handshake_timeout_ns,

    pub fn init(
        gpa: std.mem.Allocator,
        base: Dialer,
        host: []const u8,
        path: []const u8,
    ) WsDialer {
        return .{
            .gpa = gpa,
            .base = base,
            .host = host,
            .path = path,
        };
    }

    pub fn asDialer(self: *WsDialer) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn deinit(self: *WsDialer) void {
        _ = self;
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        endpoint: Endpoint,
    ) Dialer.ConnectError!Stream {
        const self: *WsDialer = @ptrCast(@alignCast(ctx));
        const inner = try self.base.connect(io, endpoint);
        const ws = ws_stream.WsStream.createClient(io, self.gpa, inner, .{
            .host = self.host,
            .path = self.path,
            .subprotocols = self.subprotocols,
            .compression = self.compression,
            .compression_no_context_takeover = self.compression_no_context_takeover,
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
        return ws.stream();
    }

    const vtable: Dialer.VTable = .{ .connect = connect };
};
