//! Datagram transports.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;

/// A datagram socket owned by the connection or UDP session.
///
/// `send_to` sends exactly one datagram. `receive` fills `buffer` and reports
/// the payload length; the source endpoint is borrowed.
pub const PacketConn = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const SendError = error{
        Canceled,
        MessageTooBig,
        Unexpected,
    };

    pub const ReceiveError = error{
        Canceled,
        Unexpected,
    };

    pub const Received = struct {
        data_len: usize,
        source: Endpoint,
    };

    pub const VTable = struct {
        send_to: *const fn (
            ctx: *anyopaque,
            io: std.Io,
            destination: Endpoint,
            data: []const u8,
        ) SendError!void,
        receive: *const fn (
            ctx: *anyopaque,
            io: std.Io,
            buffer: []u8,
        ) ReceiveError!Received,
        max_datagram_size: *const fn (ctx: *anyopaque) usize,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
    };

    pub fn send_to(
        self: PacketConn,
        io: std.Io,
        destination: Endpoint,
        data: []const u8,
    ) SendError!void {
        return self.vtable.send_to(self.ctx, io, destination, data);
    }

    pub fn receive(self: PacketConn, io: std.Io, buffer: []u8) ReceiveError!Received {
        return self.vtable.receive(self.ctx, io, buffer);
    }

    pub fn max_datagram_size(self: PacketConn) usize {
        return self.vtable.max_datagram_size(self.ctx);
    }

    /// `close` is idempotent and unblocks pending sends and receives.
    pub fn close(self: PacketConn, io: std.Io) void {
        self.vtable.close(self.ctx, io);
    }
};
