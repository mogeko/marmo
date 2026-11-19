//! VLESS UDP client using XUDP framing (Xray-compatible).

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const vless = @import("../protocol/vless.zig");
const xudp = @import("../protocol/xudp.zig");
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;

pub const XudpClient = struct {
    gpa: std.mem.Allocator,
    inner: Stream,
    target: Endpoint,
    owned_target_name: ?[]u8 = null,
    resolved_source: ?Endpoint = null,
    response_started: bool = false,
    closed: std.atomic.Value(bool) = .init(false),

    /// Takes ownership of `inner`; the caller closes it on error.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        uuid: *const vless.Uuid,
        target: Endpoint,
    ) !*XudpClient {
        const self = try gpa.create(XudpClient);
        errdefer gpa.destroy(self);

        var stored_target = target;
        var owned_name: ?[]u8 = null;
        errdefer if (owned_name) |name| gpa.free(name);
        switch (target) {
            .ip => {},
            .domain => |domain| {
                const name = try gpa.dupe(u8, domain.name);
                owned_name = name;
                stored_target = .{ .domain = .{
                    .name = name,
                    .port = domain.port,
                } };
            },
        }

        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .target = stored_target,
            .owned_target_name = owned_name,
        };
        try vless.writeMuxRequestHeader(io, inner, uuid);
        // Establish the XUDP session before the first payload so a concurrent
        // receive can read the VLESS response header without waiting for data.
        try xudp.writeNew(io, inner, stored_target, &.{});
        return self;
    }

    pub fn packetConn(self: *XudpClient) PacketConn {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn sendTo(
        ctx: *anyopaque,
        io: std.Io,
        destination: Endpoint,
        data: []const u8,
    ) PacketConn.SendError!void {
        const self: *XudpClient = @ptrCast(@alignCast(ctx));
        if (!Endpoint.eql(self.target, destination)) {
            return error.ProtocolViolation;
        }
        if (data.len == 0) return;
        if (data.len > xudp.max_data_len) return error.MessageTooBig;

        xudp.writeKeep(io, self.inner, data) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.MessageTooBig => return error.MessageTooBig,
            else => return error.ProtocolViolation,
        };
    }

    fn receive(
        ctx: *anyopaque,
        io: std.Io,
        buffer: []u8,
    ) PacketConn.ReceiveError!PacketConn.Received {
        const self: *XudpClient = @ptrCast(@alignCast(ctx));
        if (!self.response_started) {
            var addons: [vless.addon_len_max]u8 = undefined;
            vless.readResponseHeader(io, self.inner, &addons) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return error.ProtocolViolation,
            };
            self.response_started = true;
        }

        var meta: [xudp.max_meta_len]u8 = undefined;
        while (true) {
            const frame = xudp.readFrame(
                io,
                self.inner,
                &meta,
                buffer,
            ) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.MessageTooBig => return error.MessageTooBig,
                else => return error.ProtocolViolation,
            };
            switch (frame.status) {
                xudp.status_new, xudp.status_keep => {
                    if (frame.data.len == 0) continue;
                    return .{
                        .data_len = frame.data.len,
                        .source = self.sourceEndpoint(io) catch |err| switch (err) {
                            error.Canceled => return error.Canceled,
                            else => return error.Unexpected,
                        },
                    };
                },
                xudp.status_keepalive => continue,
                xudp.status_end => return error.ProtocolViolation,
                else => return error.ProtocolViolation,
            }
        }
    }

    fn sourceEndpoint(self: *XudpClient, io: std.Io) !Endpoint {
        if (self.resolved_source) |source| return source;
        const source: Endpoint = switch (self.target) {
            .ip => self.target,
            .domain => .{ .ip = self.target.resolve(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.ResolveFailed => return error.ResolveFailed,
            } },
        };
        self.resolved_source = source;
        return source;
    }

    fn maxDatagramSize(ctx: *anyopaque) usize {
        _ = ctx;
        return xudp.max_data_len;
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *XudpClient = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        if (self.owned_target_name) |name| self.gpa.free(name);
        self.gpa.destroy(self);
    }

    const vtable: PacketConn.VTable = .{
        .send_to = sendTo,
        .receive = receive,
        .max_datagram_size = maxDatagramSize,
        .close = close,
    };
};
