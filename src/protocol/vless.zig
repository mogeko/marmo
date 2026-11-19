//! VLESS client and inbound codec (TCP and UDP).

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("../transport/stream.zig").Stream;

pub const version: u8 = 0;
pub const uuid_len: usize = 16;
pub const addon_len_max: usize = 255;
pub const request_header_max: usize =
    1 + uuid_len + 1 + 1 + 2 + 1 + 255;

comptime {
    // Version, UUID, addon length, command, and port precede the address type.
    std.debug.assert(1 + uuid_len + 1 + 1 + 2 == 21);
}

pub const command_tcp: u8 = 1;
pub const command_udp: u8 = 2;
pub const command_mux: u8 = 3;
pub const command_rvs: u8 = 4;
pub const max_udp_payload: usize = 65535;
pub const address_ipv4: u8 = 1;
pub const address_domain: u8 = 2;
pub const address_ipv6: u8 = 3;
pub const max_domain_len: usize = 255;

pub const Uuid = [uuid_len]u8;

/// Parses a canonical `8-4-4-4-12` UUID or 32 hexadecimal digits.
pub fn parseUuid(text: []const u8) !Uuid {
    var uuid: Uuid = undefined;
    switch (text.len) {
        36 => try parseHyphenatedUuid(text, &uuid),
        32 => {
            _ = std.fmt.hexToBytes(&uuid, text) catch return error.InvalidUuid;
        },
        else => return error.InvalidUuid,
    }
    return uuid;
}

fn parseHyphenatedUuid(text: []const u8, uuid: *Uuid) !void {
    std.debug.assert(text.len == 36);
    std.debug.assert(uuid.*.len == uuid_len);
    var source: usize = 0;
    var target: usize = 0;
    while (target < uuid.len) : (target += 1) {
        if (target == 4 or target == 6 or target == 8 or target == 10) {
            if (text[source] != '-') return error.InvalidUuid;
            source += 1;
        }
        uuid[target] = std.fmt.parseInt(u8, text[source..][0..2], 16) catch
            return error.InvalidUuid;
        source += 2;
    }
    if (source != text.len) return error.InvalidUuid;
}

/// Encodes the VLESS address type and address, excluding the port.
pub fn encodeAddress(out: []u8, endpoint: Endpoint) !usize {
    switch (endpoint) {
        .ip => |ip| switch (ip) {
            .ip4 => |ip4| {
                if (out.len < 5) return error.NoSpace;
                out[0] = address_ipv4;
                @memcpy(out[1..5], &ip4.bytes);
                return 5;
            },
            .ip6 => |ip6| {
                if (out.len < 17) return error.NoSpace;
                out[0] = address_ipv6;
                @memcpy(out[1..17], &ip6.bytes);
                return 17;
            },
        },
        .domain => |domain| {
            if (domain.name.len == 0 or domain.name.len > max_domain_len) {
                return error.InvalidDomain;
            }
            if (out.len < 2 + domain.name.len) return error.NoSpace;
            out[0] = address_domain;
            out[1] = @intCast(domain.name.len);
            @memcpy(out[2 .. 2 + domain.name.len], domain.name);
            return 2 + domain.name.len;
        },
    }
}

/// Encodes a VLESS TCP request header.
pub fn encodeRequest(
    out: []u8,
    uuid: *const Uuid,
    target: Endpoint,
) !usize {
    return encodeRequestCommand(out, uuid, target, command_tcp);
}

pub fn encodeRequestCommand(
    out: []u8,
    uuid: *const Uuid,
    target: Endpoint,
    command: u8,
) !usize {
    if (out.len < 1 + uuid_len + 1 + 1 + 2) return error.NoSpace;
    out[0] = version;
    @memcpy(out[1 .. 1 + uuid_len], uuid);
    out[1 + uuid_len] = 0; // No addons.
    out[1 + uuid_len + 1] = command;
    std.mem.writeInt(
        u16,
        out[1 + uuid_len + 2 ..][0..2],
        target.port(),
        .big,
    );

    const address_len = try encodeAddress(
        out[1 + uuid_len + 4 ..],
        target,
    );
    return 1 + uuid_len + 4 + address_len;
}

pub const Request = struct {
    command: u8,
    target: Endpoint,
};

pub fn writeMuxRequestHeader(
    io: std.Io,
    stream: Stream,
    uuid: *const Uuid,
) !void {
    var buffer: [1 + uuid_len + 1 + 1]u8 = undefined;
    buffer[0] = version;
    @memcpy(buffer[1 .. 1 + uuid_len], uuid);
    buffer[1 + uuid_len] = 0; // No addons.
    buffer[1 + uuid_len + 1] = command_mux;
    try writeAll(io, stream, &buffer);
}

pub fn writeRequestHeader(
    io: std.Io,
    stream: Stream,
    uuid: *const Uuid,
    target: Endpoint,
    command: u8,
) !void {
    var buffer: [request_header_max]u8 = undefined;
    const length = try encodeRequestCommand(&buffer, uuid, target, command);
    try writeAll(io, stream, buffer[0..length]);
}

/// Writes one UDP frame. Callers normally skip empty datagrams.
pub fn writeUdpPacket(
    io: std.Io,
    stream: Stream,
    payload: []const u8,
) !void {
    if (payload.len > max_udp_payload) return error.MessageTooBig;
    var length: [2]u8 = undefined;
    std.mem.writeInt(u16, &length, @intCast(payload.len), .big);
    const written = try stream.write(io, &.{ length[0..], payload });
    if (written != length.len + payload.len) return error.BrokenPipe;
}

/// Reads one UDP frame. A zero-length frame returns 0; callers decide whether
/// to skip it. If `buffer` is too small the frame body is left unread and the
/// caller must close the stream.
pub fn readUdpPacket(
    io: std.Io,
    stream: Stream,
    buffer: []u8,
) !usize {
    var length: [2]u8 = undefined;
    try readExact(io, stream, &length);
    const payload_len = std.mem.readInt(u16, &length, .big);
    if (payload_len > buffer.len) return error.MessageTooBig;
    try readExact(io, stream, buffer[0..payload_len]);
    return payload_len;
}

/// Reads a VLESS TCP/UDP request from a server-side stream. Domain names are
/// copied into `domain_buffer`; the caller must keep that buffer alive for as
/// long as the returned endpoint is used.
pub fn readRequestHeader(
    io: std.Io,
    stream: Stream,
    expected_uuid: *const Uuid,
    domain_buffer: *[max_domain_len]u8,
) !Request {
    var fixed: [1 + uuid_len + 1]u8 = undefined;
    try readExact(io, stream, &fixed);
    if (fixed[0] != version) return error.ProtocolViolation;

    const received_uuid: Uuid = fixed[1..][0..uuid_len].*;
    if (!std.crypto.timing_safe.eql(Uuid, expected_uuid.*, received_uuid)) {
        return error.AuthenticationFailed;
    }

    const addon_len = fixed[1 + uuid_len];
    if (addon_len != 0) {
        var addons: [addon_len_max]u8 = undefined;
        try readExact(io, stream, addons[0..addon_len]);
    }

    var command_bytes: [1]u8 = undefined;
    try readExact(io, stream, &command_bytes);
    if (command_bytes[0] == command_mux) {
        // Mux and Reverse omit the address on the wire; XUDP uses the
        // synthetic Mux target below and carries destinations per frame.
        return .{
            .command = command_mux,
            .target = .{ .domain = .{
                .name = "v1.mux.cool",
                .port = 666,
            } },
        };
    }
    if (command_bytes[0] == command_rvs) return error.CommandUnsupported;

    var port_bytes: [2]u8 = undefined;
    try readExact(io, stream, &port_bytes);
    const port = std.mem.readInt(u16, &port_bytes, .big);

    var address_type: [1]u8 = undefined;
    try readExact(io, stream, &address_type);
    const target = switch (address_type[0]) {
        address_ipv4 => blk: {
            var bytes: [4]u8 = undefined;
            try readExact(io, stream, &bytes);
            break :blk Endpoint{
                .ip = .{ .ip4 = .{ .bytes = bytes, .port = port } },
            };
        },
        address_domain => blk: {
            var length: [1]u8 = undefined;
            try readExact(io, stream, &length);
            if (length[0] == 0) return error.InvalidDomain;
            try readExact(io, stream, domain_buffer[0..length[0]]);
            break :blk Endpoint{
                .domain = .{
                    .name = domain_buffer[0..length[0]],
                    .port = port,
                },
            };
        },
        address_ipv6 => blk: {
            var bytes: [16]u8 = undefined;
            try readExact(io, stream, &bytes);
            break :blk Endpoint{
                .ip = .{ .ip6 = .{ .bytes = bytes, .port = port } },
            };
        },
        else => return error.UnsupportedAddress,
    };
    return .{ .command = command_bytes[0], .target = target };
}

/// Writes the empty VLESS response header.
pub fn writeResponseHeader(io: std.Io, stream: Stream) !void {
    try writeAll(io, stream, &.{ version, 0 });
}

/// Reads and validates the VLESS response header.
pub fn readResponseHeader(
    io: std.Io,
    stream: Stream,
    addons: *[addon_len_max]u8,
) !void {
    var header: [2]u8 = undefined;
    try readExact(io, stream, &header);
    if (header[0] != version) return error.ProtocolViolation;
    if (header[1] != 0) {
        try readExact(io, stream, addons[0..header[1]]);
    }
}

pub const ClientStream = struct {
    gpa: std.mem.Allocator,
    inner: Stream,
    local_endpoint: Endpoint,
    remote_endpoint: Endpoint,
    response_started: bool = false,
    closed: std.atomic.Value(bool) = .init(false),

    /// Takes ownership of `inner`; the caller closes it on error.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        uuid: *const Uuid,
        target: Endpoint,
        local_endpoint: Endpoint,
    ) !*ClientStream {
        const self = try gpa.create(ClientStream);
        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .local_endpoint = local_endpoint,
            .remote_endpoint = target,
        };
        errdefer gpa.destroy(self);

        var header: [request_header_max]u8 = undefined;
        const header_len = try encodeRequest(&header, uuid, target);
        try writeAll(io, inner, header[0..header_len]);
        return self;
    }

    pub fn stream(self: *ClientStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        if (!self.response_started) {
            var addons: [addon_len_max]u8 = undefined;
            readResponseHeader(io, self.inner, &addons) catch |err|
                return mapReadError(err);
            self.response_started = true;
        }
        return self.inner.read(io, buffers);
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        return self.inner.write(io, buffers);
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        return self.inner.shutdown(io, how);
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        return self.local_endpoint;
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        return self.remote_endpoint;
    }

    const vtable: Stream.VTable = .{
        .read = read,
        .write = write,
        .shutdown = shutdown,
        .close = close,
        .local = local,
        .remote = remote,
    };
};

fn readExact(io: std.Io, stream: Stream, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var buffers = [_][]u8{buffer[offset..]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
}

fn writeAll(io: std.Io, stream: Stream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try stream.write(io, &.{bytes[offset..]});
        if (written == 0) return error.BrokenPipe;
        offset += written;
    }
}

fn mapReadError(err: anyerror) Stream.ReadError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.ConnectionReset, error.ConnectionResetByPeer => error.ConnectionReset,
        error.EndOfStream,
        error.ProtocolViolation,
        error.InvalidDomain,
        error.NoSpace,
        => error.ProtocolViolation,
        else => error.Unexpected,
    };
}

test "canonical UUID parsing" {
    const uuid = try parseUuid("00112233-4455-6677-8899-aabbccddeeff");
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        },
        &uuid,
    );
    const compact = try parseUuid("00112233445566778899aabbccddeeff");
    try std.testing.expectEqualSlices(u8, &uuid, &compact);
}

test "invalid UUID is rejected" {
    try std.testing.expectError(error.InvalidUuid, parseUuid(""));
    try std.testing.expectError(
        error.InvalidUuid,
        parseUuid("00112233445566778899aabbccddeef"),
    );
    try std.testing.expectError(
        error.InvalidUuid,
        parseUuid("00112233-4455-6677-8899-aabbccddeefg"),
    );
    try std.testing.expectError(
        error.InvalidUuid,
        parseUuid("00112233_4455_6677_8899_aabbccddeeff"),
    );
}

test "IPv4 request header encoding" {
    const uuid = try parseUuid("00112233-4455-6677-8899-aabbccddeeff");
    var buffer: [request_header_max]u8 = undefined;
    const target = try Endpoint.parse("1.2.3.4:443");
    const len = try encodeRequest(&buffer, &uuid, target);

    const expected = [_]u8{
        0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x01,
        0x01, 0x02, 0x03, 0x04,
    };
    try std.testing.expectEqual(@as(usize, expected.len), len);
    try std.testing.expectEqualSlices(u8, &expected, buffer[0..len]);
}

test "domain request header encoding" {
    const uuid = try parseUuid("00112233445566778899aabbccddeeff");
    var buffer: [request_header_max]u8 = undefined;
    const target = try Endpoint.parse("example.com:80");
    const len = try encodeRequest(&buffer, &uuid, target);

    try std.testing.expectEqual(@as(u8, 0x00), buffer[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[17]);
    try std.testing.expectEqual(@as(u8, 0x01), buffer[18]);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[19]);
    try std.testing.expectEqual(@as(u8, 0x50), buffer[20]);
    try std.testing.expectEqual(@as(u8, 0x02), buffer[21]);
    try std.testing.expectEqual(@as(u8, 11), buffer[22]);
    try std.testing.expectEqualStrings("example.com", buffer[23..34]);
    try std.testing.expectEqual(@as(usize, 34), len);
}

test "IPv6 request header encoding" {
    const uuid = try parseUuid("00112233445566778899aabbccddeeff");
    var buffer: [request_header_max]u8 = undefined;
    const target = try Endpoint.parse("[::1]:443");
    const len = try encodeRequest(&buffer, &uuid, target);

    try std.testing.expectEqual(@as(u8, 0x03), buffer[21]);
    try std.testing.expectEqual(@as(u8, 1), buffer[22 + 15]);
    try std.testing.expectEqual(@as(usize, 22 + 16), len);
}

test "request header rejects a tiny buffer" {
    const uuid = try parseUuid("00112233445566778899aabbccddeeff");
    const target = try Endpoint.parse("example.com:80");
    var buffer: [8]u8 = undefined;
    try std.testing.expectError(
        error.NoSpace,
        encodeRequest(&buffer, &uuid, target),
    );
}
