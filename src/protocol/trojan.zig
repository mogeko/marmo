//! Trojan client and inbound codec (TCP and UDP association).

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Stream = @import("../transport/stream.zig").Stream;

pub const password_hash_len: usize = 56;
pub const auth_prefix_len: usize = password_hash_len + 2;
pub const command_connect: u8 = 1;
pub const command_udp_associate: u8 = 3;
pub const address_ipv4: u8 = 1;
pub const address_domain: u8 = 3;
pub const address_ipv6: u8 = 4;
pub const max_domain_len: usize = 255;
pub const max_udp_payload: usize = 65535;
pub const crlf = "\r\n";

/// Maximum bytes in `hex(SHA224(password)) | CRLF | request | CRLF`.
pub const request_header_max: usize =
    auth_prefix_len + 1 + 1 + 1 + max_domain_len + 2 + 2;
pub const udp_header_max: usize = 1 + 1 + max_domain_len + 2 + 2 + 2;

comptime {
    // Authentication line, command, address type, domain length, port, CRLF.
    std.debug.assert(request_header_max == 320);
    std.debug.assert(udp_header_max == 263);
}

pub const PasswordHash = [password_hash_len]u8;

/// Hashes a password the way Trojan expects: lower-case hex SHA-224.
pub fn hashPassword(password: []const u8) PasswordHash {
    var digest: [28]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    std.crypto.hash.sha2.Sha224.hash(password, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Encodes the address type, address, and port.
pub fn encodeAddress(out: []u8, endpoint: Endpoint) !usize {
    switch (endpoint) {
        .ip => |ip| switch (ip) {
            .ip4 => |ip4| {
                if (out.len < 7) return error.NoSpace;
                out[0] = address_ipv4;
                @memcpy(out[1..5], &ip4.bytes);
                std.mem.writeInt(u16, out[5..7], ip4.port, .big);
                return 7;
            },
            .ip6 => |ip6| {
                if (out.len < 19) return error.NoSpace;
                out[0] = address_ipv6;
                @memcpy(out[1..17], &ip6.bytes);
                std.mem.writeInt(u16, out[17..19], ip6.port, .big);
                return 19;
            },
        },
        .domain => |domain| {
            if (domain.name.len == 0 or domain.name.len > max_domain_len) {
                return error.InvalidDomain;
            }
            const total = 1 + 1 + domain.name.len + 2;
            if (out.len < total) return error.NoSpace;
            out[0] = address_domain;
            out[1] = @intCast(domain.name.len);
            @memcpy(out[2 .. 2 + domain.name.len], domain.name);
            std.mem.writeInt(
                u16,
                out[2 + domain.name.len ..][0..2],
                domain.port,
                .big,
            );
            return total;
        },
    }
}

/// Encodes `CMD | ATYP | DST.ADDR | DST.PORT`.
pub fn encodeRequest(out: []u8, target: Endpoint, command: u8) !usize {
    if (command != command_connect and command != command_udp_associate) {
        return error.CommandUnsupported;
    }
    if (out.len < 2) return error.NoSpace;
    out[0] = command;
    return 1 + try encodeAddress(out[1..], target);
}

/// Encodes the complete request header, including the authentication line and
/// the closing CRLF.
pub fn encodeRequestHeader(
    out: []u8,
    hash: *const PasswordHash,
    target: Endpoint,
    command: u8,
) !usize {
    if (out.len < auth_prefix_len + 2) return error.NoSpace;
    @memcpy(out[0..password_hash_len], hash);
    @memcpy(out[password_hash_len..auth_prefix_len], crlf);
    const request_len = try encodeRequest(
        out[auth_prefix_len..],
        target,
        command,
    );
    const closing = auth_prefix_len + request_len;
    if (out.len < closing + 2) return error.NoSpace;
    @memcpy(out[closing..][0..2], crlf);
    return closing + 2;
}

pub fn writeRequestHeader(
    io: std.Io,
    stream: Stream,
    hash: *const PasswordHash,
    target: Endpoint,
    command: u8,
) !void {
    var buffer: [request_header_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const length = try encodeRequestHeader(&buffer, hash, target, command);
    try writeAll(io, stream, buffer[0..length]);
}

pub const Auth = struct {
    matched: bool,
    len: usize,
};

/// Reads the 56-byte hash and its CRLF. A short read is not an error so the
/// caller can replay the partial prefix to a fallback service.
pub fn readAuthPrefix(
    io: std.Io,
    stream: Stream,
    expected: *const PasswordHash,
    prefix: *[auth_prefix_len]u8,
) Stream.ReadError!Auth {
    var offset: usize = 0;
    while (offset < prefix.len) {
        const before = offset;
        var buffers = [_][]u8{prefix[offset..]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) break;
        offset += read_len;

        // A non-hex byte cannot belong to `hex(SHA224(password))`, and the
        // two bytes after the hash must be CRLF. Stop as soon as the prefix is
        // known not to match so a short probe does not wait for 58 bytes; the
        // caller replays every byte actually consumed.
        var index = before;
        while (index < offset) : (index += 1) {
            if (index < password_hash_len) {
                if (!isLowerHex(prefix[index])) {
                    return .{ .matched = false, .len = offset };
                }
            } else if (prefix[index] != crlf[index - password_hash_len]) {
                return .{ .matched = false, .len = offset };
            }
        }
    }
    if (offset < auth_prefix_len) return .{ .matched = false, .len = offset };
    if (prefix[password_hash_len] != crlf[0] or
        prefix[password_hash_len + 1] != crlf[1])
    {
        return .{ .matched = false, .len = auth_prefix_len };
    }
    const received: PasswordHash = prefix[0..password_hash_len].*;
    return .{
        .matched = std.crypto.timing_safe.eql(PasswordHash, expected.*, received),
        .len = auth_prefix_len,
    };
}

fn isLowerHex(byte: u8) bool {
    return (byte >= '0' and byte <= '9') or
        (byte >= 'a' and byte <= 'f');
}

pub const Request = struct {
    command: u8,
    target: Endpoint,
};

/// Reads the request after the authentication line. Domain names are copied
/// into `domain_buffer`, which the caller must keep alive.
pub fn readRequestHeader(
    io: std.Io,
    stream: Stream,
    domain_buffer: *[max_domain_len]u8,
) !Request {
    var fixed: [2]u8 = undefined;
    try readExact(io, stream, &fixed);
    const command = fixed[0];
    if (command != command_connect and command != command_udp_associate) {
        return error.CommandUnsupported;
    }

    const target = try readAddress(io, stream, fixed[1], domain_buffer);
    var closing: [2]u8 = undefined;
    try readExact(io, stream, &closing);
    if (closing[0] != crlf[0] or closing[1] != crlf[1]) {
        return error.Malformed;
    }
    return .{ .command = command, .target = target };
}

pub const UdpPacket = struct {
    /// The destination for client-to-server frames, or the source for
    /// server-to-client frames.
    endpoint: Endpoint,
    data_len: usize,
};

/// Encodes the UDP frame header. The payload follows the CRLF.
pub fn encodeUdpHeader(
    out: []u8,
    endpoint: Endpoint,
    payload_len: usize,
) !usize {
    if (payload_len > max_udp_payload) return error.MessageTooBig;
    const address_len = try encodeAddress(out, endpoint);
    const offset = address_len;
    if (out.len < offset + 4) return error.NoSpace;
    std.mem.writeInt(u16, out[offset..][0..2], @intCast(payload_len), .big);
    @memcpy(out[offset + 2 ..][0..2], crlf);
    return offset + 4;
}

pub fn writeUdpPacket(
    io: std.Io,
    stream: Stream,
    endpoint: Endpoint,
    payload: []const u8,
) !void {
    if (payload.len > max_udp_payload) return error.MessageTooBig;
    var header: [udp_header_max]u8 = undefined;
    const header_len = try encodeUdpHeader(&header, endpoint, payload.len);
    const written = try stream.write(io, &.{ header[0..header_len], payload });
    if (written != header_len + payload.len) return error.BrokenPipe;
}

/// Reads one UDP frame into `buffer`. The returned endpoint borrows
/// `domain_buffer` when the wire address is a domain.
pub fn readUdpPacket(
    io: std.Io,
    stream: Stream,
    buffer: []u8,
    domain_buffer: *[max_domain_len]u8,
) !UdpPacket {
    var address_type: [1]u8 = undefined;
    try readExact(io, stream, &address_type);
    const endpoint = try readAddress(io, stream, address_type[0], domain_buffer);

    var length: [2]u8 = undefined;
    try readExact(io, stream, &length);
    const payload_len: usize = std.mem.readInt(u16, &length, .big);
    if (payload_len > buffer.len) return error.MessageTooBig;

    var closing: [2]u8 = undefined;
    try readExact(io, stream, &closing);
    if (closing[0] != crlf[0] or closing[1] != crlf[1]) {
        return error.Malformed;
    }
    try readExact(io, stream, buffer[0..payload_len]);
    return .{ .endpoint = endpoint, .data_len = payload_len };
}

fn readAddress(
    io: std.Io,
    stream: Stream,
    address_type: u8,
    domain_buffer: *[max_domain_len]u8,
) !Endpoint {
    switch (address_type) {
        address_ipv4 => {
            var bytes: [4]u8 = undefined;
            try readExact(io, stream, &bytes);
            var port_bytes: [2]u8 = undefined;
            try readExact(io, stream, &port_bytes);
            return .{ .ip = .{ .ip4 = .{
                .bytes = bytes,
                .port = std.mem.readInt(u16, &port_bytes, .big),
            } } };
        },
        address_domain => {
            var length: [1]u8 = undefined;
            try readExact(io, stream, &length);
            if (length[0] == 0) return error.InvalidDomain;
            const name_len: usize = length[0];
            try readExact(io, stream, domain_buffer[0..name_len]);
            var port_bytes: [2]u8 = undefined;
            try readExact(io, stream, &port_bytes);
            return .{ .domain = .{
                .name = domain_buffer[0..name_len],
                .port = std.mem.readInt(u16, &port_bytes, .big),
            } };
        },
        address_ipv6 => {
            var bytes: [16]u8 = undefined;
            try readExact(io, stream, &bytes);
            var port_bytes: [2]u8 = undefined;
            try readExact(io, stream, &port_bytes);
            return .{ .ip = .{ .ip6 = .{
                .bytes = bytes,
                .port = std.mem.readInt(u16, &port_bytes, .big),
            } } };
        },
        else => return error.UnsupportedAddress,
    }
}

/// A stream that writes the Trojan request header before the first payload.
/// The header is coalesced with a single-buffer first write where possible.
pub const ClientStream = struct {
    gpa: std.mem.Allocator,
    inner: Stream,
    local_endpoint: Endpoint,
    remote_endpoint: Endpoint,
    header: [request_header_max]u8 = undefined,
    header_len: usize,
    header_sent: std.atomic.Value(bool) = .init(false),
    header_lock: std.Io.Mutex = .init,
    closed: std.atomic.Value(bool) = .init(false),

    /// Takes ownership of `inner` on success; the caller closes it on error.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        hash: *const PasswordHash,
        target: Endpoint,
        local_endpoint: Endpoint,
        command: u8,
    ) !*ClientStream {
        _ = io;
        const self = try gpa.create(ClientStream);
        errdefer {
            std.crypto.secureZero(u8, std.mem.asBytes(&self.header));
            gpa.destroy(self);
        }

        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .local_endpoint = local_endpoint,
            .remote_endpoint = target,
            .header_len = 0,
        };
        self.header_len = try encodeRequestHeader(
            &self.header,
            hash,
            target,
            command,
        );
        return self;
    }

    pub fn stream(self: *ClientStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn ensureHeader(self: *ClientStream, io: std.Io) Stream.WriteError!void {
        if (self.header_sent.load(.acquire)) return;
        self.header_lock.lock(io) catch return error.Canceled;
        defer self.header_lock.unlock(io);
        if (self.header_sent.load(.acquire)) return;
        try writeAll(io, self.inner, self.header[0..self.header_len]);
        self.header_sent.store(true, .release);
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        self.ensureHeader(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Unexpected => return error.Unexpected,
            else => return error.ProtocolViolation,
        };
        return self.inner.read(io, buffers);
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        if (!self.header_sent.load(.acquire)) {
            self.header_lock.lock(io) catch return error.Canceled;
            if (!self.header_sent.load(.acquire) and buffers.len == 1) {
                const written = self.inner.write(io, &.{
                    self.header[0..self.header_len],
                    buffers[0],
                }) catch |err| {
                    self.header_lock.unlock(io);
                    return err;
                };
                self.header_sent.store(true, .release);
                self.header_lock.unlock(io);
                if (written != self.header_len + buffers[0].len) {
                    return error.BrokenPipe;
                }
                return buffers[0].len;
            }
            if (!self.header_sent.load(.acquire)) {
                writeAll(io, self.inner, self.header[0..self.header_len]) catch |err| {
                    self.header_lock.unlock(io);
                    return err;
                };
                self.header_sent.store(true, .release);
            }
            self.header_lock.unlock(io);
        }
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
        std.crypto.secureZero(u8, std.mem.asBytes(&self.header));
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

fn writeAll(io: std.Io, stream: Stream, bytes: []const u8) Stream.WriteError!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = try stream.write(io, &.{bytes[offset..]});
        if (written == 0) return error.BrokenPipe;
        offset += written;
    }
}

const TestStream = struct {
    input: []const u8,
    position: usize = 0,
    output: [512]u8 = undefined,
    output_len: usize = 0,

    fn stream(self: *TestStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        _ = io;
        const self: *TestStream = @ptrCast(@alignCast(ctx));
        if (self.position == self.input.len) return 0;
        const available = self.input[self.position..];
        var total: usize = 0;
        for (buffers) |buffer| {
            if (total == available.len) break;
            const count = @min(buffer.len, available.len - total);
            @memcpy(buffer[0..count], available[total..][0..count]);
            total += count;
        }
        self.position += total;
        return total;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        _ = io;
        const self: *TestStream = @ptrCast(@alignCast(ctx));
        var total: usize = 0;
        for (buffers) |buffer| {
            if (self.output_len + buffer.len > self.output.len) {
                return error.BrokenPipe;
            }
            @memcpy(self.output[self.output_len..][0..buffer.len], buffer);
            self.output_len += buffer.len;
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

    fn local(ctx: *anyopaque) Endpoint {
        _ = ctx;
        return .{ .ip = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } } };
    }

    fn remote(ctx: *anyopaque) Endpoint {
        _ = ctx;
        return .{ .ip = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 2 } } };
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

test "SHA-224 password hashing matches the protocol vector" {
    const empty = hashPassword("");
    try std.testing.expectEqualStrings(
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        &empty,
    );
    const password = hashPassword("password");
    try std.testing.expectEqualStrings(
        "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01",
        &password,
    );
}

test "IPv4 request header encoding" {
    const hash = hashPassword("password");
    var buffer: [request_header_max]u8 = undefined;
    const target = try Endpoint.parse("1.2.3.4:443");
    const len = try encodeRequestHeader(
        &buffer,
        &hash,
        target,
        command_connect,
    );
    try std.testing.expectEqual(@as(usize, 58 + 1 + 1 + 4 + 2 + 2), len);
    try std.testing.expectEqualStrings(
        "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01",
        buffer[0..56],
    );
    try std.testing.expectEqualSlices(u8, "\r\n", buffer[56..58]);
    try std.testing.expectEqual(@as(u8, command_connect), buffer[58]);
    try std.testing.expectEqual(@as(u8, address_ipv4), buffer[59]);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, buffer[60..64]);
    try std.testing.expectEqual(@as(u8, 0x01), buffer[64]);
    try std.testing.expectEqual(@as(u8, 0xbb), buffer[65]);
    try std.testing.expectEqualSlices(u8, "\r\n", buffer[66..68]);
}

test "domain and IPv6 request headers roundtrip" {
    const hash = hashPassword("password");
    var buffer: [request_header_max]u8 = undefined;
    const domain = try Endpoint.parse("example.com:80");
    const domain_len = try encodeRequestHeader(
        &buffer,
        &hash,
        domain,
        command_udp_associate,
    );
    var test_stream: TestStream = .{ .input = buffer[auth_prefix_len..domain_len] };
    var domain_buffer: [max_domain_len]u8 = undefined;
    const request = try readRequestHeader(
        ioForTest(),
        test_stream.stream(),
        &domain_buffer,
    );
    try std.testing.expectEqual(command_udp_associate, request.command);
    try std.testing.expectEqualStrings("example.com", request.target.domain.name);
    try std.testing.expectEqual(@as(u16, 80), request.target.port());

    const ipv6 = try Endpoint.parse("[::1]:443");
    const ipv6_len = try encodeRequestHeader(
        &buffer,
        &hash,
        ipv6,
        command_connect,
    );
    var ipv6_stream: TestStream = .{ .input = buffer[auth_prefix_len..ipv6_len] };
    const ipv6_request = try readRequestHeader(
        ioForTest(),
        ipv6_stream.stream(),
        &domain_buffer,
    );
    try std.testing.expectEqual(@as(u16, 443), ipv6_request.target.port());
}

test "request header rejects truncation at every prefix" {
    const hash = hashPassword("password");
    var buffer: [request_header_max]u8 = undefined;
    const target = try Endpoint.parse("example.com:443");
    const len = try encodeRequestHeader(
        &buffer,
        &hash,
        target,
        command_connect,
    );
    const request = buffer[auth_prefix_len..len];

    var index: usize = 0;
    while (index < request.len) : (index += 1) {
        var test_stream: TestStream = .{ .input = request[0..index] };
        var domain_buffer: [max_domain_len]u8 = undefined;
        _ = readRequestHeader(
            ioForTest(),
            test_stream.stream(),
            &domain_buffer,
        ) catch continue;
        return error.TestUnexpectedResult;
    }
}

test "authentication prefix distinguishes a match and a mismatch" {
    const hash = hashPassword("password");
    const wrong = hashPassword("not-password");
    var expected: [auth_prefix_len]u8 = undefined;
    @memcpy(expected[0..56], &hash);
    @memcpy(expected[56..58], crlf);

    var prefix: [auth_prefix_len]u8 = undefined;
    var test_stream: TestStream = .{ .input = &expected };
    const matched = try readAuthPrefix(
        ioForTest(),
        test_stream.stream(),
        &hash,
        &prefix,
    );
    try std.testing.expect(matched.matched);
    try std.testing.expectEqual(auth_prefix_len, matched.len);

    var wrong_prefix: [auth_prefix_len]u8 = undefined;
    @memcpy(wrong_prefix[0..56], &wrong);
    @memcpy(wrong_prefix[56..58], crlf);
    var wrong_stream: TestStream = .{ .input = &wrong_prefix };
    const mismatch = try readAuthPrefix(
        ioForTest(),
        wrong_stream.stream(),
        &hash,
        &prefix,
    );
    try std.testing.expect(!mismatch.matched);
    try std.testing.expectEqual(auth_prefix_len, mismatch.len);

    var partial: TestStream = .{ .input = expected[0..10] };
    const short = try readAuthPrefix(
        ioForTest(),
        partial.stream(),
        &hash,
        &prefix,
    );
    try std.testing.expect(!short.matched);
    try std.testing.expectEqual(@as(usize, 10), short.len);

    const http_probe = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var probe_stream: TestStream = .{ .input = http_probe };
    const probe = try readAuthPrefix(
        ioForTest(),
        probe_stream.stream(),
        &hash,
        &prefix,
    );
    try std.testing.expect(!probe.matched);
    try std.testing.expectEqual(http_probe.len, probe.len);
}

test "UDP frames roundtrip with domain and IPv4 addresses" {
    var test_stream: TestStream = .{ .input = "" };
    const target = try Endpoint.parse("example.com:53");
    try writeUdpPacket(
        ioForTest(),
        test_stream.stream(),
        target,
        "hello",
    );
    try std.testing.expectEqual(@as(usize, 1 + 1 + 11 + 2 + 2 + 2 + 5), test_stream.output_len);

    var read_stream: TestStream = .{ .input = test_stream.output[0..test_stream.output_len] };
    var buffer: [64]u8 = undefined;
    var domain_buffer: [max_domain_len]u8 = undefined;
    const packet = try readUdpPacket(
        ioForTest(),
        read_stream.stream(),
        &buffer,
        &domain_buffer,
    );
    try std.testing.expectEqual(@as(usize, 5), packet.data_len);
    try std.testing.expectEqualStrings("hello", buffer[0..5]);
    try std.testing.expectEqualStrings("example.com", packet.endpoint.domain.name);

    var ipv4_stream: TestStream = .{ .input = "" };
    const ipv4 = try Endpoint.parse("127.0.0.1:9");
    try writeUdpPacket(ioForTest(), ipv4_stream.stream(), ipv4, "x");
    var ipv4_read: TestStream = .{ .input = ipv4_stream.output[0..ipv4_stream.output_len] };
    const ipv4_packet = try readUdpPacket(
        ioForTest(),
        ipv4_read.stream(),
        &buffer,
        &domain_buffer,
    );
    try std.testing.expectEqual(@as(u16, 9), ipv4_packet.endpoint.port());
}

test "UDP frame rejects an oversized payload" {
    var header: [udp_header_max]u8 = undefined;
    const target = try Endpoint.parse("127.0.0.1:9");
    try std.testing.expectError(
        error.MessageTooBig,
        encodeUdpHeader(&header, target, max_udp_payload + 1),
    );
}

test "client stream sends the header before its first write" {
    const hash = hashPassword("password");
    var stream_state: TestStream = .{ .input = "" };
    const target = try Endpoint.parse("127.0.0.1:443");
    const client = try ClientStream.create(
        ioForTest(),
        std.testing.allocator,
        stream_state.stream(),
        &hash,
        target,
        target,
        command_connect,
    );
    defer client.stream().close(ioForTest());

    const written = try client.stream().write(ioForTest(), &.{"hello"});
    try std.testing.expectEqual(@as(usize, 5), written);
    try std.testing.expectEqual(@as(usize, 58 + 1 + 1 + 4 + 2 + 2 + 5), stream_state.output_len);
    try std.testing.expectEqualStrings(
        "hello",
        stream_state.output[stream_state.output_len - 5 .. stream_state.output_len],
    );
}

fn ioForTest() std.Io {
    return std.testing.io;
}
