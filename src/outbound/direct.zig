//! Direct TCP and UDP outbound.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("../transport/dialer.zig").Dialer;
const ConnectError = Dialer.ConnectError;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;
const TcpStream = @import("../transport/tcp.zig").TcpStream;
const UdpPacketConn = @import("../transport/udp.zig").UdpPacketConn;

pub const Direct = struct {
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator) Direct {
        return .{ .gpa = gpa };
    }

    pub fn dialer(self: *Direct) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!Stream {
        const self: *Direct = @ptrCast(@alignCast(ctx));
        const address = target.resolve(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.ResolveFailed => return error.HostUnreachable,
        };

        const inner = std.Io.net.IpAddress.connect(
            &address,
            io,
            .{ .mode = .stream },
        ) catch |err| return connectError(err);

        const local_endpoint: Endpoint = .{ .ip = inner.socket.address };
        const tcp = TcpStream.create(self.gpa, inner, local_endpoint, target) catch {
            inner.close(io);
            return error.Unexpected;
        };
        return tcp.stream();
    }

    fn connectPacket(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!PacketConn {
        const self: *Direct = @ptrCast(@alignCast(ctx));
        const address = target.resolve(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.ResolveFailed => return error.HostUnreachable,
        };

        const bind_address: std.Io.net.IpAddress = switch (address) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = std.Io.net.IpAddress.bind(
            &bind_address,
            io,
            .{ .mode = .dgram, .protocol = .udp },
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.AddressFamilyUnsupported => return error.Unsupported,
            else => return error.Unexpected,
        };

        const udp = UdpPacketConn.create(self.gpa, socket) catch {
            socket.close(io);
            return error.Unexpected;
        };
        return udp.packetConn();
    }

    fn connectError(err: std.Io.net.IpAddress.ConnectError) ConnectError {
        return switch (err) {
            error.Canceled => error.Canceled,
            error.ConnectionRefused => error.ConnectionRefused,
            error.HostUnreachable,
            error.NetworkUnreachable,
            error.NetworkDown,
            => error.HostUnreachable,
            error.Timeout => error.TimedOut,
            else => error.Unexpected,
        };
    }

    const vtable: Dialer.VTable = .{
        .connect = connect,
        .connect_packet = connectPacket,
    };
};
