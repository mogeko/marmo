//! HTTP/2 transport dialer: wraps another dialer and opens one H2 stream.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("dialer.zig").Dialer;
const Stream = @import("stream.zig").Stream;
const h2_stream = @import("h2_stream.zig");

pub const H2Dialer = struct {
    gpa: std.mem.Allocator,
    base: Dialer,
    host: []const u8,
    path: []const u8 = "/",
    scheme: []const u8 = "https",
    handshake_timeout_ns: u64 = h2_stream.default_handshake_timeout_ns,

    pub fn init(
        gpa: std.mem.Allocator,
        base: Dialer,
        host: []const u8,
        path: []const u8,
    ) H2Dialer {
        return .{
            .gpa = gpa,
            .base = base,
            .host = host,
            .path = path,
        };
    }

    pub fn asDialer(self: *H2Dialer) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn deinit(self: *H2Dialer) void {
        _ = self;
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        endpoint: Endpoint,
    ) Dialer.ConnectError!Stream {
        const self: *H2Dialer = @ptrCast(@alignCast(ctx));
        const inner = try self.base.connect(io, endpoint);
        const h2 = h2_stream.H2Stream.createClient(io, self.gpa, inner, .{
            .host = self.host,
            .path = self.path,
            .scheme = self.scheme,
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
        return h2.stream();
    }

    const vtable: Dialer.VTable = .{ .connect = connect };
};
