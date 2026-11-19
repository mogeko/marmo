//! Trojan UDP client over a stream transport.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const trojan = @import("../protocol/trojan.zig");
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;

pub const UdpClient = struct {
    gpa: std.mem.Allocator,
    inner: Stream,
    domain_buffer: [trojan.max_domain_len]u8 = undefined,
    closed: std.atomic.Value(bool) = .init(false),

    /// Takes ownership of `inner` on success; the caller closes it on error.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        hash: *const trojan.PasswordHash,
        target: Endpoint,
    ) !*UdpClient {
        const self = try gpa.create(UdpClient);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .inner = inner,
        };
        try trojan.writeRequestHeader(
            io,
            inner,
            hash,
            target,
            trojan.command_udp_associate,
        );
        return self;
    }

    pub fn packetConn(self: *UdpClient) PacketConn {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn sendTo(
        ctx: *anyopaque,
        io: std.Io,
        destination: Endpoint,
        data: []const u8,
    ) PacketConn.SendError!void {
        const self: *UdpClient = @ptrCast(@alignCast(ctx));
        if (data.len == 0) return;
        if (data.len > trojan.max_udp_payload) return error.MessageTooBig;

        var header: [trojan.udp_header_max]u8 = undefined;
        const header_len = trojan.encodeUdpHeader(
            &header,
            destination,
            data.len,
        ) catch |err| switch (err) {
            error.MessageTooBig => return error.MessageTooBig,
            else => return error.ProtocolViolation,
        };
        const written = self.inner.write(io, &.{
            header[0..header_len],
            data,
        }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.ProtocolViolation,
        };
        if (written != header_len + data.len) return error.ProtocolViolation;
    }

    fn receive(
        ctx: *anyopaque,
        io: std.Io,
        buffer: []u8,
    ) PacketConn.ReceiveError!PacketConn.Received {
        const self: *UdpClient = @ptrCast(@alignCast(ctx));
        while (true) {
            const packet = trojan.readUdpPacket(
                io,
                self.inner,
                buffer,
                &self.domain_buffer,
            ) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.MessageTooBig => return error.MessageTooBig,
                else => return error.ProtocolViolation,
            };
            if (packet.data_len == 0) continue;
            return .{
                .data_len = packet.data_len,
                .source = packet.endpoint,
            };
        }
    }

    fn maxDatagramSize(ctx: *anyopaque) usize {
        _ = ctx;
        return trojan.max_udp_payload;
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *UdpClient = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        self.gpa.destroy(self);
    }

    const vtable: PacketConn.VTable = .{
        .send_to = sendTo,
        .receive = receive,
        .max_datagram_size = maxDatagramSize,
        .close = close,
    };
};
