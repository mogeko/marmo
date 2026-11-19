//! Trojan outbound (TCP and UDP over any stream transport).

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const trojan = @import("../protocol/trojan.zig");
const Dialer = @import("../transport/dialer.zig").Dialer;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;
const UdpClient = @import("trojan_udp.zig").UdpClient;

pub const Trojan = struct {
    gpa: std.mem.Allocator,
    server: Endpoint,
    password_hash: trojan.PasswordHash,
    transport: Dialer,
    transport_cleanup: ?*const fn (ctx: *anyopaque) void = null,
    transport_cleanup_ctx: ?*anyopaque = null,

    pub fn deinit(self: *Trojan) void {
        std.crypto.secureZero(u8, &self.password_hash);
        if (self.transport_cleanup) |cleanup| cleanup(self.transport_cleanup_ctx.?);
    }

    pub fn asDialer(self: *Trojan) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) Dialer.ConnectError!Stream {
        const self: *Trojan = @ptrCast(@alignCast(ctx));
        const inner = try self.transport.connect(io, self.server);
        const client = trojan.ClientStream.create(
            io,
            self.gpa,
            inner,
            &self.password_hash,
            target,
            inner.local(),
            trojan.command_connect,
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
        const self: *Trojan = @ptrCast(@alignCast(ctx));
        const inner = try self.transport.connect(io, self.server);
        const client = UdpClient.create(
            io,
            self.gpa,
            inner,
            &self.password_hash,
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
        error.InvalidDomain, error.NoSpace, error.CommandUnsupported => error.ProtocolViolation,
        error.ProtocolViolation => error.ProtocolViolation,
        else => error.Unexpected,
    };
}

test "deinit zeroizes the Trojan password hash" {
    var value: Trojan = undefined;
    value.password_hash = @splat(0xff);
    value.transport_cleanup = null;
    value.transport_cleanup_ctx = null;
    value.deinit();
    for (value.password_hash) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}
