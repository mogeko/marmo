//! Shadowsocks 2022 outbound (TCP).

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const s2022 = @import("../protocol/shadowsocks2022.zig");
const Dialer = @import("../transport/dialer.zig").Dialer;
const Stream = @import("../transport/stream.zig").Stream;

pub const Shadowsocks = struct {
    gpa: std.mem.Allocator,
    server: Endpoint,
    method: s2022.Method,
    key: s2022.Key,
    direct_dialer: Dialer,

    pub fn asDialer(self: *Shadowsocks) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn deinit(self: *Shadowsocks) void {
        self.key.deinit();
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) Dialer.ConnectError!Stream {
        const self: *Shadowsocks = @ptrCast(@alignCast(ctx));
        const inner = try self.direct_dialer.connect(io, self.server);

        const client = s2022.ClientStream.create(
            io,
            self.gpa,
            inner,
            self.method,
            &self.key,
            target,
            inner.local(),
        ) catch |err| {
            inner.close(io);
            return switch (err) {
                error.Canceled => error.Canceled,
                else => error.ProtocolViolation,
            };
        };
        return client.stream();
    }

    const vtable: Dialer.VTable = .{ .connect = connect };
};
