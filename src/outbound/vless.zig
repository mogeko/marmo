//! VLESS outbound (TCP and UDP over any stream transport).

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const vless = @import("../protocol/vless.zig");
const Dialer = @import("../transport/dialer.zig").Dialer;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;
const UdpClient = @import("vless_udp.zig").UdpClient;

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

    fn connectPacket(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) Dialer.ConnectError!PacketConn {
        const self: *Vless = @ptrCast(@alignCast(ctx));
        const inner = try self.transport.connect(io, self.server);
        const client = UdpClient.create(
            io,
            self.gpa,
            inner,
            &self.uuid,
            target,
        ) catch |err| {
            inner.close(io);
            return mapUdpError(err);
        };
        return client.packetConn();
    }

    const vtable: Dialer.VTable = .{
        .connect = connect,
        .connect_packet = connectPacket,
    };
};

fn mapUdpError(err: anyerror) Dialer.ConnectError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.Unexpected,
        else => error.ProtocolViolation,
    };
}

fn mapCreateError(err: anyerror) Dialer.ConnectError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.InvalidDomain, error.NoSpace => error.ProtocolViolation,
        error.ProtocolViolation => error.ProtocolViolation,
        else => error.Unexpected,
    };
}
