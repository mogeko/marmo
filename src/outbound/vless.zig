//! VLESS outbound (TCP over any stream transport).

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const vless = @import("../protocol/vless.zig");
const Dialer = @import("../transport/dialer.zig").Dialer;
const Stream = @import("../transport/stream.zig").Stream;

pub const Vless = struct {
    gpa: std.mem.Allocator,
    server: Endpoint,
    uuid: vless.Uuid,
    transport: Dialer,
    transport_cleanup: ?*const fn (ctx: *anyopaque) void = null,
    transport_cleanup_ctx: ?*anyopaque = null,

    pub fn deinit(self: *Vless) void {
        if (self.transport_cleanup) |cleanup| cleanup(self.transport_cleanup_ctx.?);
    }

    pub fn asDialer(self: *Vless) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) Dialer.ConnectError!Stream {
        const self: *Vless = @ptrCast(@alignCast(ctx));
        const inner = try self.transport.connect(io, self.server);
        const client = vless.ClientStream.create(
            io,
            self.gpa,
            inner,
            &self.uuid,
            target,
            inner.local(),
        ) catch |err| {
            inner.close(io);
            return mapCreateError(err);
        };
        return client.stream();
    }

    const vtable: Dialer.VTable = .{ .connect = connect };
};

fn mapCreateError(err: anyerror) Dialer.ConnectError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.InvalidDomain, error.NoSpace => error.ProtocolViolation,
        error.ProtocolViolation => error.ProtocolViolation,
        else => error.Unexpected,
    };
}
