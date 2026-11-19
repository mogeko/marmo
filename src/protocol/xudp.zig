//! XUDP framing used by Xray-compatible VLESS UDP.
//!
//! XUDP is a subset of Mux.Cool carried under a VLESS Mux command:
//!
//!   [2B metadata length][metadata][2B data length][data]
//!
//! The metadata starts with the 2-byte session ID (XUDP uses 0), status, and
//! option bytes. New/Keep frames with per-packet destinations add a network
//! byte, port, and address. This implementation supports one fixed UDP target
//! per stream and does not implement cone NAT/GlobalID semantics.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const vless = @import("vless.zig");
const Stream = @import("../transport/stream.zig").Stream;

pub const session_id: u16 = 0;
pub const status_new: u8 = 1;
pub const status_keep: u8 = 2;
pub const status_end: u8 = 3;
pub const status_keepalive: u8 = 4;
pub const option_data: u8 = 1;
pub const network_udp: u8 = 2;
pub const max_meta_len: usize = 512;
pub const max_data_len: usize = 65535;

pub const Frame = struct {
    status: u8,
    option: u8,
    target: ?Endpoint,
    data: []u8,
};

pub fn isMuxTarget(endpoint: Endpoint) bool {
    return switch (endpoint) {
        .domain => |domain| domain.port == 666 and
            std.mem.eql(u8, domain.name, "v1.mux.cool"),
        .ip => false,
    };
}

pub fn readFrame(
    io: std.Io,
    stream: Stream,
    meta_buffer: *[max_meta_len]u8,
    data_buffer: []u8,
) !Frame {
    var meta_len_bytes: [2]u8 = undefined;
    try readExact(io, stream, &meta_len_bytes);
    const meta_len = std.mem.readInt(u16, &meta_len_bytes, .big);
    if (meta_len < 4 or meta_len > max_meta_len) return error.ProtocolViolation;
    try readExact(io, stream, meta_buffer[0..meta_len]);
    const meta = meta_buffer[0..meta_len];

    const frame_session = std.mem.readInt(u16, meta[0..2], .big);
    if (frame_session != session_id) return error.ProtocolViolation;
    const status = meta[2];
    const option = meta[3];
    var target: ?Endpoint = null;

    switch (status) {
        status_new => {
            if (meta.len < 7) return error.ProtocolViolation;
            if (meta[4] != network_udp) return error.ProtocolViolation;
            const port = std.mem.readInt(u16, meta[5..7], .big);
            const parsed = try parseAddress(meta, 7, port);
            // New frames carry an 8-byte GlobalID when sent by XUDP clients.
            const remaining = meta.len - parsed.next;
            if (remaining != 0 and remaining != 8) {
                return error.ProtocolViolation;
            }
            target = parsed.endpoint;
        },
        status_keep => {
            if (meta.len == 4) {
                // No per-packet destination: the stream target is fixed.
            } else {
                if (meta.len < 7 or meta[4] != network_udp) {
                    return error.ProtocolViolation;
                }
                const port = std.mem.readInt(u16, meta[5..7], .big);
                const parsed = try parseAddress(meta, 7, port);
                if (parsed.next != meta.len) return error.ProtocolViolation;
                target = parsed.endpoint;
            }
        },
        status_end, status_keepalive => {
            if (meta.len != 4) return error.ProtocolViolation;
        },
        else => return error.ProtocolViolation,
    }

    var data: []u8 = &.{};
    if (option & option_data != 0) {
        var data_len_bytes: [2]u8 = undefined;
        try readExact(io, stream, &data_len_bytes);
        const data_len = std.mem.readInt(u16, &data_len_bytes, .big);
        if (data_len > data_buffer.len) return error.MessageTooBig;
        try readExact(io, stream, data_buffer[0..data_len]);
        data = data_buffer[0..data_len];
    }
    return .{
        .status = status,
        .option = option,
        .target = target,
        .data = data,
    };
}

pub fn writeNew(
    io: std.Io,
    stream: Stream,
    target: Endpoint,
    data: []const u8,
) !void {
    if (data.len > max_data_len) return error.MessageTooBig;

    var meta: [max_meta_len]u8 = undefined;
    std.mem.writeInt(u16, meta[0..2], session_id, .big);
    meta[2] = status_new;
    meta[3] = option_data;
    meta[4] = network_udp;
    std.mem.writeInt(u16, meta[5..7], target.port(), .big);
    const address_len = try vless.encodeAddress(meta[7..], target);
    var offset = 7 + address_len;
    // GlobalID: fixed-target XUDP does not use cone NAT.
    @memset(meta[offset..][0..8], 0);
    offset += 8;
    try writeFrame(io, stream, meta[0..offset], data);
}

pub fn writeKeep(
    io: std.Io,
    stream: Stream,
    data: []const u8,
) !void {
    if (data.len > max_data_len) return error.MessageTooBig;
    var meta: [4]u8 = undefined;
    std.mem.writeInt(u16, meta[0..2], session_id, .big);
    meta[2] = status_keep;
    meta[3] = option_data;
    try writeFrame(io, stream, &meta, data);
}

fn writeFrame(
    io: std.Io,
    stream: Stream,
    meta: []const u8,
    data: []const u8,
) !void {
    var header: [2 + max_meta_len + 2]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], @intCast(meta.len), .big);
    @memcpy(header[2..][0..meta.len], meta);
    const data_len_offset = 2 + meta.len;
    std.mem.writeInt(
        u16,
        header[data_len_offset..][0..2],
        @intCast(data.len),
        .big,
    );
    const header_len = data_len_offset + 2;
    const written = try stream.write(io, &.{ header[0..header_len], data });
    if (written != header_len + data.len) return error.BrokenPipe;
}

const ParsedAddress = struct {
    endpoint: Endpoint,
    next: usize,
};

fn parseAddress(
    buffer: []const u8,
    offset: usize,
    port: u16,
) !ParsedAddress {
    if (offset >= buffer.len) return error.ProtocolViolation;
    const address_type = buffer[offset];
    var cursor = offset + 1;
    switch (address_type) {
        vless.address_ipv4 => {
            if (buffer.len - cursor < 4) return error.ProtocolViolation;
            const bytes = buffer[cursor..][0..4].*;
            cursor += 4;
            return .{
                .endpoint = .{ .ip = .{ .ip4 = .{
                    .bytes = bytes,
                    .port = port,
                } } },
                .next = cursor,
            };
        },
        vless.address_domain => {
            if (buffer.len - cursor < 1) return error.ProtocolViolation;
            const name_len = buffer[cursor];
            cursor += 1;
            if (name_len == 0 or buffer.len - cursor < name_len) {
                return error.ProtocolViolation;
            }
            const name = buffer[cursor..][0..name_len];
            cursor += name_len;
            return .{
                .endpoint = .{ .domain = .{
                    .name = name,
                    .port = port,
                } },
                .next = cursor,
            };
        },
        vless.address_ipv6 => {
            if (buffer.len - cursor < 16) return error.ProtocolViolation;
            const bytes = buffer[cursor..][0..16].*;
            cursor += 16;
            return .{
                .endpoint = .{ .ip = .{ .ip6 = .{
                    .bytes = bytes,
                    .port = port,
                } } },
                .next = cursor,
            };
        },
        else => return error.ProtocolViolation,
    }
}

fn readExact(io: std.Io, stream: Stream, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var buffers = [_][]u8{buffer[offset..]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
}

const MemoryStream = struct {
    bytes: []u8,
    len: usize = 0,
    read_offset: usize = 0,

    fn stream(self: *MemoryStream) Stream {
        return .{ .ctx = self, .vtable = &memory_vtable };
    }

    fn read(
        ctx: *anyopaque,
        io: std.Io,
        buffers: [][]u8,
    ) Stream.ReadError!usize {
        _ = io;
        const self: *MemoryStream = @ptrCast(@alignCast(ctx));
        var copied: usize = 0;
        for (buffers) |buffer| {
            const count = @min(buffer.len, self.len - self.read_offset - copied);
            @memcpy(buffer[0..count], self.bytes[self.read_offset + copied ..][0..count]);
            copied += count;
            if (self.read_offset + copied == self.len) break;
        }
        self.read_offset += copied;
        return copied;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        _ = io;
        const self: *MemoryStream = @ptrCast(@alignCast(ctx));
        var total: usize = 0;
        for (buffers) |buffer| {
            if (self.bytes.len - self.len < buffer.len) return error.BrokenPipe;
            @memcpy(self.bytes[self.len..][0..buffer.len], buffer);
            self.len += buffer.len;
            total += buffer.len;
        }
        return total;
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        _ = ctx;
        _ = io;
        _ = how;
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        _ = ctx;
        _ = io;
    }

    fn endpoint(ctx: *anyopaque) Endpoint {
        _ = ctx;
        return .{ .ip = .{ .ip4 = .loopback(1) } };
    }

    const memory_vtable: Stream.VTable = .{
        .read = read,
        .write = write,
        .shutdown = shutdown,
        .close = close,
        .local = endpoint,
        .remote = endpoint,
    };
};

test "XUDP New and Keep frames roundtrip" {
    var storage: [1024]u8 = undefined;
    var writer_memory: MemoryStream = .{ .bytes = &storage };
    const writer_stream = writer_memory.stream();
    const target = try Endpoint.parse("1.2.3.4:5353");
    try writeNew(std.testing.io, writer_stream, target, "first");
    try writeKeep(std.testing.io, writer_stream, "second");

    var reader_memory: MemoryStream = .{
        .bytes = storage[0..writer_memory.len],
        .len = writer_memory.len,
    };
    const reader_stream = reader_memory.stream();
    var meta: [max_meta_len]u8 = undefined;
    var data: [max_data_len]u8 = undefined;

    const first = try readFrame(std.testing.io, reader_stream, &meta, &data);
    try std.testing.expectEqual(status_new, first.status);
    try std.testing.expectEqual(option_data, first.option);
    try std.testing.expect(first.target != null);
    try std.testing.expect(Endpoint.eql(target, first.target.?));
    try std.testing.expectEqualStrings("first", first.data);

    const second = try readFrame(std.testing.io, reader_stream, &meta, &data);
    try std.testing.expectEqual(status_keep, second.status);
    try std.testing.expect(second.target == null);
    try std.testing.expectEqualStrings("second", second.data);
}
