//! Adapter from `std.Io.net.Socket` to the public `PacketConn` interface.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const PacketConn = @import("packet.zig").PacketConn;
const Guard = @import("lifetime.zig").Guard;

pub const max_datagram_size: usize = 65507;

pub const UdpPacketConn = struct {
    gpa: std.mem.Allocator,
    socket: std.Io.net.Socket,
    closed: std.atomic.Value(bool) = .init(false),
    guard: Guard = .{},

    pub fn create(gpa: std.mem.Allocator, socket: std.Io.net.Socket) !*UdpPacketConn {
        const self = try gpa.create(UdpPacketConn);
        self.* = .{ .gpa = gpa, .socket = socket };
        return self;
    }

    pub fn packetConn(self: *UdpPacketConn) PacketConn {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn sendTo(
        ctx: *anyopaque,
        io: std.Io,
        destination: Endpoint,
        data: []const u8,
    ) PacketConn.SendError!void {
        const self: *UdpPacketConn = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        const address = destination.resolve(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.ResolveFailed => return error.Unexpected,
        };
        self.socket.send(io, &address, data) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.MessageOversize => return error.MessageTooBig,
            else => return error.Unexpected,
        };
    }

    fn receive(
        ctx: *anyopaque,
        io: std.Io,
        buffer: []u8,
    ) PacketConn.ReceiveError!PacketConn.Received {
        const self: *UdpPacketConn = @ptrCast(@alignCast(ctx));
        self.guard.enter();
        defer self.guard.leave(io);
        if (self.closed.load(.acquire)) return error.Canceled;
        const message = self.socket.receive(io, buffer) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.Unexpected,
        };
        if (message.flags.trunc) return error.MessageTooBig;
        return .{
            .data_len = message.data.len,
            .source = .{ .ip = message.from },
        };
    }

    fn maxDatagramSize(ctx: *anyopaque) usize {
        _ = ctx;
        return max_datagram_size;
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *UdpPacketConn = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.socket.close(io);
        self.guard.waitIdle(io);
        self.gpa.destroy(self);
    }

    const vtable: PacketConn.VTable = .{
        .send_to = sendTo,
        .receive = receive,
        .max_datagram_size = maxDatagramSize,
        .close = close,
    };
};
