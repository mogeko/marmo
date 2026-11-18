//! HTTP CONNECT outbound.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("../transport/dialer.zig").Dialer;
const ConnectError = Dialer.ConnectError;
const Stream = @import("../transport/stream.zig").Stream;
const WrappedStream = @import("../transport/wrapped.zig").WrappedStream;

pub const HttpConnect = struct {
    gpa: std.mem.Allocator,
    server: Endpoint,
    dialer: Dialer,

    pub fn connect(
        self: *HttpConnect,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!Stream {
        const inner = try self.dialer.connect(io, self.server);
        errdefer inner.close(io);

        try writeConnect(io, inner, target);
        try readResponse(io, inner);

        const wrapped = WrappedStream.create(
            self.gpa,
            inner,
            inner.local(),
            target,
        ) catch return error.Unexpected;
        return wrapped.stream();
    }

    pub fn asDialer(self: *HttpConnect) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn connectVtable(
        ctx: *anyopaque,
        io: std.Io,
        target: Endpoint,
    ) ConnectError!Stream {
        const self: *HttpConnect = @ptrCast(@alignCast(ctx));
        return self.connect(io, target);
    }

    const vtable: Dialer.VTable = .{ .connect = connectVtable };

    fn writeConnect(
        io: std.Io,
        stream: Stream,
        target: Endpoint,
    ) ConnectError!void {
        var buffer: [512]u8 = undefined;
        const request = std.fmt.bufPrint(
            &buffer,
            "CONNECT {f} HTTP/1.1\r\nHost: {f}\r\n\r\n",
            .{ target, target },
        ) catch return error.Unexpected;
        _ = stream.write(io, &.{request}) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.Unexpected,
        };
    }

    fn readResponse(io: std.Io, stream: Stream) ConnectError!void {
        var response: [8192]u8 = undefined;
        var len: usize = 0;

        while (len < response.len) {
            var buffers = [_][]u8{response[len .. len + 1]};
            const read_len = stream.read(io, &buffers) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return error.Unexpected,
            };
            if (read_len == 0) return error.Unexpected;
            len += 1;
            if (len >= 4 and std.mem.endsWith(u8, response[0..len], "\r\n\r\n")) {
                break;
            }
        }
        if (len == response.len) return error.Unexpected;

        const first_line_end = std.mem.findScalar(u8, response[0..len], '\r') orelse
            return error.Unexpected;
        const first_line = response[0..first_line_end];
        const status_start = std.mem.findScalar(u8, first_line, ' ') orelse
            return error.Unexpected;
        if (first_line.len < status_start + 4) return error.Unexpected;

        const status = std.fmt.parseInt(u16, first_line[status_start + 1 ..][0..3], 10) catch
            return error.Unexpected;
        if (status < 200 or status > 299) return error.ConnectionRefused;
    }
};
