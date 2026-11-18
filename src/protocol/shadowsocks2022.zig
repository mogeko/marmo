//! Shadowsocks 2022 (SIP022): key derivation, framing, and TCP streams.
//!
//! Only the required AES-GCM methods are implemented:
//! `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const PacketConn = @import("../transport/packet.zig").PacketConn;
const Stream = @import("../transport/stream.zig").Stream;

pub const tag_length = 16;
pub const nonce_length = 12;
pub const max_payload = 65535;
pub const timestamp_window_s = 30;
pub const salt_window_s = 60;
pub const replay_capacity = 4096;
pub const max_padding = 900;

const subkey_context = "shadowsocks 2022 session subkey";

pub const Method = enum {
    aes_128_gcm,
    aes_256_gcm,

    pub fn parse(text: []const u8) ?Method {
        if (std.mem.eql(u8, text, "2022-blake3-aes-128-gcm")) return .aes_128_gcm;
        if (std.mem.eql(u8, text, "2022-blake3-aes-256-gcm")) return .aes_256_gcm;
        return null;
    }

    pub fn keyLength(self: Method) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
        };
    }

    pub fn saltLength(self: Method) usize {
        return self.keyLength();
    }
};

pub const Key = struct {
    bytes: [32]u8 = @splat(0),
    len: u8 = 0,

    pub const ParseError = error{InvalidKey};

    pub fn parse(method: Method, password: []const u8) ParseError!Key {
        const expected_len = method.keyLength();
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(password) catch
            return error.InvalidKey;
        if (decoded_len != expected_len) return error.InvalidKey;

        var key: Key = .{ .len = @intCast(decoded_len) };
        std.base64.standard.Decoder.decode(
            key.bytes[0..decoded_len],
            password,
        ) catch return error.InvalidKey;
        return key;
    }

    pub fn slice(self: *const Key) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn deinit(self: *Key) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.len = 0;
    }
};

pub fn deriveSubkey(
    method: Method,
    psk: []const u8,
    salt: []const u8,
    out: []u8,
) void {
    var hasher = std.crypto.hash.Blake3.initKdf(subkey_context, .{});
    hasher.update(psk);
    hasher.update(salt);
    hasher.final(out[0..method.keyLength()]);
}

pub fn seal(
    method: Method,
    key: []const u8,
    nonce: [nonce_length]u8,
    plaintext: []const u8,
    out: []u8,
) void {
    std.debug.assert(out.len >= plaintext.len + tag_length);
    var tag: [tag_length]u8 = undefined;
    switch (method) {
        .aes_128_gcm => {
            var key_fixed: [16]u8 = undefined;
            @memcpy(&key_fixed, key[0..16]);
            std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                out[0..plaintext.len],
                &tag,
                plaintext,
                &.{},
                nonce,
                key_fixed,
            );
        },
        .aes_256_gcm => {
            var key_fixed: [32]u8 = undefined;
            @memcpy(&key_fixed, key[0..32]);
            std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                out[0..plaintext.len],
                &tag,
                plaintext,
                &.{},
                nonce,
                key_fixed,
            );
        },
    }
    @memcpy(out[plaintext.len..][0..tag_length], &tag);
}

pub fn open(
    method: Method,
    key: []const u8,
    nonce: [nonce_length]u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    if (ciphertext.len < tag_length) return error.AuthenticationFailed;
    const plaintext_len = ciphertext.len - tag_length;
    if (out.len < plaintext_len) return error.NoSpace;

    const tag: [tag_length]u8 = ciphertext[plaintext_len..][0..tag_length].*;
    switch (method) {
        .aes_128_gcm => {
            var key_fixed: [16]u8 = undefined;
            @memcpy(&key_fixed, key[0..16]);
            std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                out[0..plaintext_len],
                ciphertext[0..plaintext_len],
                tag,
                &.{},
                nonce,
                key_fixed,
            ) catch return error.AuthenticationFailed;
        },
        .aes_256_gcm => {
            var key_fixed: [32]u8 = undefined;
            @memcpy(&key_fixed, key[0..32]);
            std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                out[0..plaintext_len],
                ciphertext[0..plaintext_len],
                tag,
                &.{},
                nonce,
                key_fixed,
            ) catch return error.AuthenticationFailed;
        },
    }
    return plaintext_len;
}

pub fn nonceFromCounter(counter: u64) [nonce_length]u8 {
    var nonce: [nonce_length]u8 = @splat(0);
    std.mem.writeInt(u64, nonce[0..8], counter, .little);
    return nonce;
}

pub fn nextCounter(counter: *u64) !u64 {
    if (counter.* == std.math.maxInt(u64)) return error.CounterExhausted;
    const value = counter.*;
    counter.* += 1;
    return value;
}

pub const DecodedAddress = struct {
    endpoint: Endpoint,
    next: usize,
};

pub fn decodeAddress(bytes: []const u8, start: usize) !DecodedAddress {
    if (start >= bytes.len) return error.MalformedAddress;
    var offset = start;
    const address_type = bytes[offset];
    offset += 1;

    switch (address_type) {
        0x01 => {
            if (offset + 6 > bytes.len) return error.MalformedAddress;
            const address_bytes = bytes[offset..][0..4].*;
            const port = portFromBytes(bytes[offset + 4 ..][0..2]);
            offset += 6;
            return .{
                .endpoint = .{ .ip = .{ .ip4 = .{
                    .bytes = address_bytes,
                    .port = port,
                } } },
                .next = offset,
            };
        },
        0x03 => {
            if (offset + 1 > bytes.len) return error.MalformedAddress;
            const name_len = bytes[offset];
            offset += 1;
            if (name_len == 0 or offset + name_len + 2 > bytes.len) {
                return error.MalformedAddress;
            }
            const name = bytes[offset .. offset + name_len];
            offset += name_len;
            const port = portFromBytes(bytes[offset..][0..2]);
            offset += 2;
            return .{
                .endpoint = .{ .domain = .{ .name = name, .port = port } },
                .next = offset,
            };
        },
        0x04 => {
            if (offset + 18 > bytes.len) return error.MalformedAddress;
            const address_bytes = bytes[offset..][0..16].*;
            const port = portFromBytes(bytes[offset + 16 ..][0..2]);
            offset += 18;
            return .{
                .endpoint = .{ .ip = .{ .ip6 = .{
                    .bytes = address_bytes,
                    .port = port,
                } } },
                .next = offset,
            };
        },
        else => return error.UnsupportedAddress,
    }
}

pub fn encodeAddress(endpoint: Endpoint, out: []u8) !usize {
    switch (endpoint) {
        .ip => |ip| switch (ip) {
            .ip4 => |ip4| {
                if (out.len < 7) return error.NoSpace;
                out[0] = 0x01;
                @memcpy(out[1..5], &ip4.bytes);
                out[5] = @intCast(ip4.port >> 8);
                out[6] = @intCast(ip4.port & 0xff);
                return 7;
            },
            .ip6 => |ip6| {
                if (out.len < 19) return error.NoSpace;
                out[0] = 0x04;
                @memcpy(out[1..17], &ip6.bytes);
                out[17] = @intCast(ip6.port >> 8);
                out[18] = @intCast(ip6.port & 0xff);
                return 19;
            },
        },
        .domain => |domain| {
            if (domain.name.len == 0 or domain.name.len > 255) {
                return error.InvalidDomain;
            }
            const needed = 1 + 1 + domain.name.len + 2;
            if (out.len < needed) return error.NoSpace;
            out[0] = 0x03;
            out[1] = @intCast(domain.name.len);
            @memcpy(out[2 .. 2 + domain.name.len], domain.name);
            const port_offset = 2 + domain.name.len;
            out[port_offset] = @intCast(domain.port >> 8);
            out[port_offset + 1] = @intCast(domain.port & 0xff);
            return needed;
        },
    }
}

fn portFromBytes(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

pub const ReplayCache = struct {
    entries: [replay_capacity]Entry = @splat(Entry{}),
    next: usize = 0,
    mutex: std.Io.Mutex = .init,

    const Entry = struct {
        salt: [32]u8 = @splat(0),
        len: u8 = 0,
        expires_at_s: i64 = 0,
    };

    pub const Error = error{
        Canceled,
        Replay,
        CacheFull,
    };

    pub fn checkAndAdd(
        self: *ReplayCache,
        io: std.Io,
        salt: []const u8,
        now_s: i64,
    ) Error!void {
        if (salt.len == 0 or salt.len > 32) return error.Replay;
        self.mutex.lock(io) catch return error.Canceled;
        defer self.mutex.unlock(io);

        for (&self.entries) |*entry| {
            if (entry.len == 0) continue;
            if (entry.expires_at_s <= now_s) {
                entry.len = 0;
                continue;
            }
            if (entry.len == salt.len and
                std.mem.eql(u8, entry.salt[0..entry.len], salt))
            {
                return error.Replay;
            }
        }

        var index: usize = self.next;
        var attempts: usize = 0;
        while (attempts < replay_capacity) : (attempts += 1) {
            const entry = &self.entries[index];
            if (entry.len == 0) {
                @memcpy(entry.salt[0..salt.len], salt);
                entry.len = @intCast(salt.len);
                entry.expires_at_s = now_s + salt_window_s;
                self.next = (index + 1) % replay_capacity;
                return;
            }
            index = (index + 1) % replay_capacity;
        }
        return error.CacheFull;
    }
};

pub fn nowSeconds(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .real).toSeconds();
}

pub fn timestampNow(io: std.Io) !u64 {
    const seconds = nowSeconds(io);
    if (seconds < 0) return error.InvalidTimestamp;
    return @intCast(seconds);
}

fn validateTimestamp(io: std.Io, raw: u64) !void {
    const seconds = std.math.cast(i64, raw) orelse return error.InvalidTimestamp;
    const now = nowSeconds(io);
    const difference = if (now > seconds) now - seconds else seconds - now;
    if (difference > timestamp_window_s) return error.StaleTimestamp;
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

fn writeAll(io: std.Io, stream: Stream, buffers: []const []const u8) !void {
    _ = try stream.write(io, buffers);
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

fn writeU16(bytes: []u8, value: u16) void {
    bytes[0] = @intCast(value >> 8);
    bytes[1] = @intCast(value & 0xff);
}

pub const UdpDirection = enum { client_to_server, server_to_client };

pub const Window = struct {
    initialized: bool = false,
    max_id: u64 = 0,
    bitmap: u64 = 0,

    /// Returns false for duplicates and packets older than the window.
    pub fn accept(self: *Window, packet_id: u64) bool {
        if (!self.initialized) {
            self.initialized = true;
            self.max_id = packet_id;
            self.bitmap = 1;
            return true;
        }
        if (packet_id == self.max_id) return false;
        if (packet_id > self.max_id) {
            const shift = packet_id - self.max_id;
            self.bitmap = if (shift >= 64) 1 else (self.bitmap << @intCast(shift)) | 1;
            self.max_id = packet_id;
            return true;
        }

        const delta = self.max_id - packet_id;
        if (delta >= 64) return false;
        const bit = @as(u64, 1) << @intCast(delta);
        if (self.bitmap & bit != 0) return false;
        self.bitmap |= bit;
        return true;
    }
};

pub const UdpDecoded = struct {
    session_id: [8]u8,
    packet_id: u64,
    client_session_id: ?[8]u8,
    source: Endpoint,
    payload: []const u8,
};

pub fn encodeUdpPacketWithTime(
    method: Method,
    psk: []const u8,
    session_id: [8]u8,
    packet_id: u64,
    direction: UdpDirection,
    client_session_id: ?[8]u8,
    destination: Endpoint,
    payload: []const u8,
    padding_len: u16,
    timestamp_s: u64,
    out: []u8,
) !usize {
    var body: [max_payload]u8 = undefined;
    var offset: usize = 0;

    body[offset] = switch (direction) {
        .client_to_server => 0,
        .server_to_client => 1,
    };
    offset += 1;
    std.mem.writeInt(u64, body[offset..][0..8], timestamp_s, .big);
    offset += 8;

    if (direction == .server_to_client) {
        const id = client_session_id orelse return error.MissingClientSession;
        @memcpy(body[offset..][0..8], &id);
        offset += 8;
    }

    writeU16(body[offset..], padding_len);
    offset += 2;
    if (offset + padding_len > body.len) return error.NoSpace;
    @memset(body[offset .. offset + padding_len], 0);
    offset += padding_len;

    offset += try encodeAddress(destination, body[offset..]);
    if (payload.len > body.len - offset) return error.NoSpace;
    @memcpy(body[offset .. offset + payload.len], payload);
    offset += payload.len;

    if (out.len < 16 + offset + tag_length) return error.NoSpace;

    var separate_plain: [16]u8 = undefined;
    @memcpy(separate_plain[0..8], &session_id);
    std.mem.writeInt(u64, separate_plain[8..16], packet_id, .big);
    aesBlockEncrypt(method, psk, &separate_plain, out[0..16]);

    var subkey: [32]u8 = @splat(0);
    deriveSubkey(method, psk, &session_id, &subkey);
    const nonce: [nonce_length]u8 = separate_plain[4..16].*;
    seal(method, &subkey, nonce, body[0..offset], out[16..]);
    std.crypto.secureZero(u8, &subkey);
    return 16 + offset + tag_length;
}

pub fn decodeUdpPacket(
    io: std.Io,
    method: Method,
    psk: []const u8,
    packet: []const u8,
    expected_direction: UdpDirection,
    expected_client_session: ?[8]u8,
    plaintext: []u8,
) !UdpDecoded {
    if (packet.len < 16 + tag_length + 3) return error.MalformedPacket;

    var separate_plain: [16]u8 = undefined;
    aesBlockDecrypt(method, psk, packet[0..16], &separate_plain);

    const session_id: [8]u8 = separate_plain[0..8].*;
    const packet_id = std.mem.readInt(u64, separate_plain[8..16], .big);

    var subkey: [32]u8 = @splat(0);
    deriveSubkey(method, psk, &session_id, &subkey);
    const nonce: [nonce_length]u8 = separate_plain[4..16].*;
    const body_len = open(
        method,
        &subkey,
        nonce,
        packet[16..],
        plaintext,
    ) catch {
        std.crypto.secureZero(u8, &subkey);
        return error.AuthenticationFailed;
    };
    std.crypto.secureZero(u8, &subkey);

    var offset: usize = 0;
    if (body_len < 11) return error.MalformedPacket;

    const expected_type: u8 = switch (expected_direction) {
        .client_to_server => 0,
        .server_to_client => 1,
    };
    if (plaintext[0] != expected_type) return error.ProtocolViolation;
    offset += 1;

    try validateTimestamp(io, std.mem.readInt(u64, plaintext[offset..][0..8], .big));
    offset += 8;

    var client_session_id: ?[8]u8 = null;
    if (expected_direction == .server_to_client) {
        if (offset + 8 > body_len) return error.MalformedPacket;
        client_session_id = plaintext[offset..][0..8].*;
        offset += 8;
        if (expected_client_session) |expected| {
            if (!std.mem.eql(u8, &client_session_id.?, &expected)) {
                return error.ProtocolViolation;
            }
        }
    }

    if (offset + 2 > body_len) return error.MalformedPacket;
    const padding_len = readU16(plaintext[offset..][0..2]);
    offset += 2;
    if (offset + padding_len > body_len) return error.MalformedPacket;
    offset += padding_len;

    const decoded = try decodeAddress(plaintext[0..body_len], offset);
    return .{
        .session_id = session_id,
        .packet_id = packet_id,
        .client_session_id = client_session_id,
        .source = decoded.endpoint,
        .payload = plaintext[decoded.next..body_len],
    };
}

fn aesBlockEncrypt(method: Method, psk: []const u8, input: *const [16]u8, out: *[16]u8) void {
    switch (method) {
        .aes_128_gcm => {
            var key: [16]u8 = undefined;
            @memcpy(&key, psk[0..16]);
            var context = std.crypto.core.aes.Aes128.initEnc(key);
            context.encrypt(out, input);
        },
        .aes_256_gcm => {
            var key: [32]u8 = undefined;
            @memcpy(&key, psk[0..32]);
            var context = std.crypto.core.aes.Aes256.initEnc(key);
            context.encrypt(out, input);
        },
    }
}

fn aesBlockDecrypt(method: Method, psk: []const u8, input: []const u8, out: *[16]u8) void {
    var input_block: [16]u8 = undefined;
    @memcpy(&input_block, input[0..16]);
    switch (method) {
        .aes_128_gcm => {
            var key: [16]u8 = undefined;
            @memcpy(&key, psk[0..16]);
            var context = std.crypto.core.aes.Aes128.initDec(key);
            context.decrypt(out, &input_block);
        },
        .aes_256_gcm => {
            var key: [32]u8 = undefined;
            @memcpy(&key, psk[0..32]);
            var context = std.crypto.core.aes.Aes256.initDec(key);
            context.decrypt(out, &input_block);
        },
    }
}

pub const UdpClient = struct {
    gpa: std.mem.Allocator,
    inner: PacketConn,
    server: Endpoint,
    method: Method,
    psk: Key,
    session_id: [8]u8 = @splat(0),
    packet_counter: u64 = 0,
    server_session_id: ?[8]u8 = null,
    window: Window = .{},
    closed: std.atomic.Value(bool) = .init(false),

    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: PacketConn,
        method: Method,
        psk: *const Key,
        server: Endpoint,
    ) !*UdpClient {
        const self = try gpa.create(UdpClient);
        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .server = server,
            .method = method,
            .psk = psk.*,
        };
        std.Io.randomSecure(io, &self.session_id) catch {
            gpa.destroy(self);
            return error.RandomFailed;
        };
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
        const inner_max = self.inner.max_datagram_size();
        const max_size = if (inner_max > 128) inner_max - 128 else 0;
        if (data.len > max_size) return error.MessageTooBig;

        const packet_id = nextCounter(&self.packet_counter) catch
            return error.ProtocolViolation;
        const timestamp = timestampNow(io) catch return error.ProtocolViolation;
        var packet: [max_payload]u8 = undefined;
        const packet_len = encodeUdpPacketWithTime(
            self.method,
            self.psk.slice(),
            self.session_id,
            packet_id,
            .client_to_server,
            null,
            destination,
            data,
            0,
            timestamp,
            &packet,
        ) catch |err| switch (err) {
            error.NoSpace => return error.MessageTooBig,
            else => return error.ProtocolViolation,
        };
        self.inner.send_to(io, self.server, packet[0..packet_len]) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.MessageTooBig => return error.MessageTooBig,
            error.ProtocolViolation => return error.ProtocolViolation,
            else => return error.Unexpected,
        };
    }

    fn receive(
        ctx: *anyopaque,
        io: std.Io,
        buffer: []u8,
    ) PacketConn.ReceiveError!PacketConn.Received {
        const self: *UdpClient = @ptrCast(@alignCast(ctx));
        var attempts: usize = 0;
        while (attempts < 8) : (attempts += 1) {
            var packet: [max_payload]u8 = undefined;
            const message = self.inner.receive(io, &packet) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.MessageTooBig => return error.MessageTooBig,
                error.ProtocolViolation => return error.ProtocolViolation,
                else => return error.Unexpected,
            };

            var plaintext: [max_payload]u8 = undefined;
            const decoded = decodeUdpPacket(
                io,
                self.method,
                self.psk.slice(),
                packet[0..message.data_len],
                .server_to_client,
                self.session_id,
                &plaintext,
            ) catch |err| switch (err) {
                else => continue,
            };

            if (self.server_session_id) |server_session| {
                if (!std.mem.eql(u8, &server_session, &decoded.session_id)) {
                    self.server_session_id = decoded.session_id;
                    self.window = .{};
                }
            } else {
                self.server_session_id = decoded.session_id;
            }

            if (!self.window.accept(decoded.packet_id)) continue;
            if (decoded.payload.len > buffer.len) return error.MessageTooBig;
            @memcpy(buffer[0..decoded.payload.len], decoded.payload);
            return .{
                .data_len = decoded.payload.len,
                .source = decoded.source,
            };
        }
        return error.ProtocolViolation;
    }

    fn maxDatagramSize(ctx: *anyopaque) usize {
        const self: *UdpClient = @ptrCast(@alignCast(ctx));
        const inner_max = self.inner.max_datagram_size();
        return if (inner_max > 128) inner_max - 128 else 0;
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *UdpClient = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        self.inner.close(io);
        std.crypto.secureZero(u8, &self.session_id);
        self.psk.deinit();
        self.gpa.destroy(self);
    }

    const vtable: PacketConn.VTable = .{
        .send_to = sendTo,
        .receive = receive,
        .max_datagram_size = maxDatagramSize,
        .close = close,
    };
};

pub const ClientStream = struct {
    gpa: std.mem.Allocator,
    inner: Stream,
    local_endpoint: Endpoint,
    remote_endpoint: Endpoint,
    method: Method,
    psk: Key,
    request_salt: [32]u8 = @splat(0),
    request_salt_len: u8 = 0,
    send_key: [32]u8 = @splat(0),
    send_counter: u64 = 2,
    recv_key: [32]u8 = @splat(0),
    recv_counter: u64 = 0,
    response_started: bool = false,
    read_buffer: [max_payload]u8 = undefined,
    read_len: usize = 0,
    read_offset: usize = 0,
    closed: std.atomic.Value(bool) = .init(false),

    /// Takes ownership of `inner`.
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        inner: Stream,
        method: Method,
        psk: *const Key,
        target: Endpoint,
        local_endpoint: Endpoint,
    ) !*ClientStream {
        const self = try gpa.create(ClientStream);
        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .local_endpoint = local_endpoint,
            .remote_endpoint = target,
            .method = method,
            .psk = psk.*,
        };
        errdefer {
            self.psk.deinit();
            gpa.destroy(self);
        }

        const salt_len = method.saltLength();
        std.Io.randomSecure(io, self.request_salt[0..salt_len]) catch
            return error.RandomFailed;
        self.request_salt_len = @intCast(salt_len);
        deriveSubkey(method, psk.slice(), self.request_salt[0..salt_len], &self.send_key);
        try self.sendRequestHeader(io, target);
        return self;
    }

    pub fn stream(self: *ClientStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn sendRequestHeader(self: *ClientStream, io: std.Io, target: Endpoint) !void {
        var variable: [max_padding + 262]u8 = undefined;
        var offset: usize = 0;
        offset += try encodeAddress(target, variable[offset..]);

        var random_byte: [1]u8 = undefined;
        std.Io.randomSecure(io, &random_byte) catch return error.RandomFailed;
        const padding_len: u16 = 1 + (random_byte[0] % 64);
        writeU16(variable[offset..], padding_len);
        offset += 2;
        std.Io.randomSecure(io, variable[offset .. offset + padding_len]) catch
            return error.RandomFailed;
        offset += padding_len;

        var fixed_plain: [11]u8 = undefined;
        fixed_plain[0] = 0;
        std.mem.writeInt(u64, fixed_plain[1..9], try timestampNow(io), .big);
        writeU16(fixed_plain[9..], @intCast(offset));

        var fixed_cipher: [11 + tag_length]u8 = undefined;
        seal(
            self.method,
            &self.send_key,
            nonceFromCounter(0),
            &fixed_plain,
            &fixed_cipher,
        );

        var variable_cipher: [max_padding + 262 + tag_length]u8 = undefined;
        seal(
            self.method,
            &self.send_key,
            nonceFromCounter(1),
            variable[0..offset],
            &variable_cipher,
        );

        try writeAll(io, self.inner, &.{
            self.request_salt[0..self.request_salt_len],
            &fixed_cipher,
            variable_cipher[0 .. offset + tag_length],
        });
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        if (self.read_offset == self.read_len) {
            self.fill(io) catch |err| return mapReadError(err);
        }

        var copied: usize = 0;
        for (buffers) |buffer| {
            const remaining = self.read_len - self.read_offset;
            if (remaining == 0) break;
            const copy_len = @min(buffer.len, remaining);
            @memcpy(buffer[0..copy_len], self.read_buffer[self.read_offset..][0..copy_len]);
            self.read_offset += copy_len;
            copied += copy_len;
        }
        return copied;
    }

    fn fill(self: *ClientStream, io: std.Io) !void {
        if (!self.response_started) {
            try self.readResponseHeader(io);
            self.response_started = true;
            return;
        }

        var length_cipher: [2 + tag_length]u8 = undefined;
        try readExact(io, self.inner, &length_cipher);
        var length_plain: [2]u8 = undefined;
        const nonce = nonceFromCounter(try nextCounter(&self.recv_counter));
        _ = try open(
            self.method,
            &self.recv_key,
            nonce,
            &length_cipher,
            &length_plain,
        );

        const payload_len = readU16(&length_plain);
        if (payload_len == 0) return error.ProtocolViolation;
        var payload_cipher: [max_payload + tag_length]u8 = undefined;
        try readExact(io, self.inner, payload_cipher[0 .. payload_len + tag_length]);
        const payload_nonce = nonceFromCounter(try nextCounter(&self.recv_counter));
        const plain_len = try open(
            self.method,
            &self.recv_key,
            payload_nonce,
            payload_cipher[0 .. payload_len + tag_length],
            &self.read_buffer,
        );
        if (plain_len != payload_len) return error.ProtocolViolation;
        self.read_len = plain_len;
        self.read_offset = 0;
    }

    fn readResponseHeader(self: *ClientStream, io: std.Io) !void {
        const salt_len = self.method.saltLength();
        var salt: [32]u8 = undefined;
        try readExact(io, self.inner, salt[0..salt_len]);
        deriveSubkey(self.method, self.psk.slice(), salt[0..salt_len], &self.recv_key);

        const header_len = 11 + salt_len;
        var header_cipher: [11 + 32 + tag_length]u8 = undefined;
        try readExact(io, self.inner, header_cipher[0 .. header_len + tag_length]);

        var header_plain: [43]u8 = undefined;
        const nonce = nonceFromCounter(try nextCounter(&self.recv_counter));
        _ = try open(
            self.method,
            &self.recv_key,
            nonce,
            header_cipher[0 .. header_len + tag_length],
            header_plain[0..header_len],
        );
        if (header_plain[0] != 1) return error.ProtocolViolation;
        try validateTimestamp(io, std.mem.readInt(u64, header_plain[1..9], .big));
        if (!std.mem.eql(
            u8,
            header_plain[9 .. 9 + salt_len],
            self.request_salt[0..salt_len],
        )) return error.ProtocolViolation;

        const payload_len = readU16(header_plain[9 + salt_len ..][0..2]);
        if (payload_len == 0) return error.ProtocolViolation;

        var payload_cipher: [max_payload + tag_length]u8 = undefined;
        try readExact(io, self.inner, payload_cipher[0 .. payload_len + tag_length]);
        const payload_nonce = nonceFromCounter(try nextCounter(&self.recv_counter));
        const plain_len = try open(
            self.method,
            &self.recv_key,
            payload_nonce,
            payload_cipher[0 .. payload_len + tag_length],
            &self.read_buffer,
        );
        if (plain_len != payload_len) return error.ProtocolViolation;
        self.read_len = plain_len;
        self.read_offset = 0;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *ClientStream = @ptrCast(@alignCast(ctx));
        var total: usize = 0;
        for (buffers) |buffer| {
            var offset: usize = 0;
            while (offset < buffer.len) {
                const chunk_len = @min(buffer.len - offset, max_payload);
                self.writeChunk(io, buffer[offset .. offset + chunk_len]) catch |err|
                    return mapWriteError(err);
                offset += chunk_len;
                total += chunk_len;
            }
        }
        return total;
    }

    fn writeChunk(self: *ClientStream, io: std.Io, chunk: []const u8) !void {
        var length_plain: [2]u8 = undefined;
        writeU16(&length_plain, @intCast(chunk.len));
        var length_cipher: [2 + tag_length]u8 = undefined;
        const length_nonce = nonceFromCounter(try nextCounter(&self.send_counter));
        seal(
            self.method,
            &self.send_key,
            length_nonce,
            &length_plain,
            &length_cipher,
        );

        var payload_cipher: [max_payload + tag_length]u8 = undefined;
        const payload_nonce = nonceFromCounter(try nextCounter(&self.send_counter));
        seal(
            self.method,
            &self.send_key,
            payload_nonce,
            chunk,
            payload_cipher[0 .. chunk.len + tag_length],
        );
        try writeAll(io, self.inner, &.{
            &length_cipher,
            payload_cipher[0 .. chunk.len + tag_length],
        });
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
        std.crypto.secureZero(u8, &self.send_key);
        std.crypto.secureZero(u8, &self.recv_key);
        std.crypto.secureZero(u8, &self.request_salt);
        self.psk.deinit();
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

pub const ClientRequest = struct {
    salt: [32]u8,
    salt_len: u8,
    recv_key: [32]u8,
    target: Endpoint,
    initial_payload: []const u8,
};

/// Parse and authenticate a client request stream.
///
/// `plaintext` must hold `max_payload` bytes; the returned initial payload
/// points into it.
pub fn readClientRequest(
    io: std.Io,
    stream: Stream,
    method: Method,
    psk: *const Key,
    replay: *ReplayCache,
    plaintext: []u8,
) !ClientRequest {
    if (plaintext.len < max_payload) return error.NoSpace;

    const salt_len = method.saltLength();
    var salt: [32]u8 = @splat(0);
    try readExact(io, stream, salt[0..salt_len]);

    var recv_key: [32]u8 = @splat(0);
    deriveSubkey(method, psk.slice(), salt[0..salt_len], &recv_key);

    const fixed_len = 11;
    var fixed_cipher: [11 + tag_length]u8 = undefined;
    try readExact(io, stream, &fixed_cipher);

    var fixed_plain: [11]u8 = undefined;
    const nonce0 = nonceFromCounter(0);
    const fixed_plain_len = try open(
        method,
        &recv_key,
        nonce0,
        &fixed_cipher,
        &fixed_plain,
    );
    if (fixed_plain_len != fixed_len) return error.ProtocolViolation;
    if (fixed_plain[0] != 0) return error.ProtocolViolation;

    try validateTimestamp(io, std.mem.readInt(u64, fixed_plain[1..9], .big));
    const now = nowSeconds(io);
    replay.checkAndAdd(io, salt[0..salt_len], now) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Replay => return error.Replay,
        error.CacheFull => return error.ReplayCacheFull,
    };

    const variable_len = readU16(fixed_plain[9..][0..2]);
    if (variable_len == 0) return error.ProtocolViolation;

    var variable_cipher: [max_payload + tag_length]u8 = undefined;
    try readExact(io, stream, variable_cipher[0 .. variable_len + tag_length]);
    const nonce1 = nonceFromCounter(1);
    const plain_len = try open(
        method,
        &recv_key,
        nonce1,
        variable_cipher[0 .. variable_len + tag_length],
        plaintext[0..variable_len],
    );
    if (plain_len != variable_len) return error.ProtocolViolation;

    const decoded = try decodeAddress(plaintext[0..variable_len], 0);
    var offset = decoded.next;
    if (offset + 2 > variable_len) return error.ProtocolViolation;
    const padding_len = readU16(plaintext[offset..][0..2]);
    offset += 2;
    if (padding_len > max_padding) return error.ProtocolViolation;
    if (offset + padding_len > variable_len) return error.ProtocolViolation;
    offset += padding_len;

    const initial_payload = plaintext[offset..variable_len];
    if (initial_payload.len == 0 and padding_len == 0) {
        return error.ProtocolViolation;
    }

    return .{
        .salt = salt,
        .salt_len = @intCast(salt_len),
        .recv_key = recv_key,
        .target = decoded.endpoint,
        .initial_payload = initial_payload,
    };
}

pub const ServerStream = struct {
    gpa: std.mem.Allocator,
    inner: Stream,
    local_endpoint: Endpoint,
    remote_endpoint: Endpoint,
    method: Method,
    psk: Key,
    request_salt: [32]u8 = @splat(0),
    request_salt_len: u8 = 0,
    recv_key: [32]u8 = @splat(0),
    recv_counter: u64 = 2,
    send_key: [32]u8 = @splat(0),
    send_counter: u64 = 0,
    send_started: bool = false,
    read_buffer: [max_payload]u8 = undefined,
    read_len: usize = 0,
    read_offset: usize = 0,
    closed: std.atomic.Value(bool) = .init(false),

    /// Takes ownership of `inner`.
    pub fn create(
        gpa: std.mem.Allocator,
        inner: Stream,
        method: Method,
        psk: *const Key,
        request_salt: []const u8,
        recv_key: *const [32]u8,
        initial_payload: []const u8,
        local_endpoint: Endpoint,
        remote_endpoint: Endpoint,
    ) !*ServerStream {
        if (request_salt.len == 0 or request_salt.len > 32) return error.InvalidSalt;
        if (initial_payload.len > max_payload) return error.TooLarge;

        const self = try gpa.create(ServerStream);
        self.* = .{
            .gpa = gpa,
            .inner = inner,
            .local_endpoint = local_endpoint,
            .remote_endpoint = remote_endpoint,
            .method = method,
            .psk = psk.*,
        };
        errdefer {
            self.psk.deinit();
            gpa.destroy(self);
        }

        @memcpy(self.request_salt[0..request_salt.len], request_salt);
        self.request_salt_len = @intCast(request_salt.len);
        @memcpy(self.recv_key[0..method.keyLength()], recv_key[0..method.keyLength()]);
        @memcpy(self.read_buffer[0..initial_payload.len], initial_payload);
        self.read_len = initial_payload.len;
        return self;
    }

    pub fn stream(self: *ServerStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn destroy(self: *ServerStream, io: std.Io) void {
        close(@ptrCast(self), io);
    }

    fn read(ctx: *anyopaque, io: std.Io, buffers: [][]u8) Stream.ReadError!usize {
        const self: *ServerStream = @ptrCast(@alignCast(ctx));
        if (self.read_offset == self.read_len) {
            self.fill(io) catch |err| return mapReadError(err);
        }

        var copied: usize = 0;
        for (buffers) |buffer| {
            const remaining = self.read_len - self.read_offset;
            if (remaining == 0) break;
            const copy_len = @min(buffer.len, remaining);
            @memcpy(buffer[0..copy_len], self.read_buffer[self.read_offset..][0..copy_len]);
            self.read_offset += copy_len;
            copied += copy_len;
        }
        return copied;
    }

    fn fill(self: *ServerStream, io: std.Io) !void {
        var length_cipher: [2 + tag_length]u8 = undefined;
        try readExact(io, self.inner, &length_cipher);
        var length_plain: [2]u8 = undefined;
        const length_nonce = nonceFromCounter(try nextCounter(&self.recv_counter));
        _ = try open(
            self.method,
            &self.recv_key,
            length_nonce,
            &length_cipher,
            &length_plain,
        );

        const payload_len = readU16(&length_plain);
        if (payload_len == 0) return error.ProtocolViolation;
        var payload_cipher: [max_payload + tag_length]u8 = undefined;
        try readExact(io, self.inner, payload_cipher[0 .. payload_len + tag_length]);
        const payload_nonce = nonceFromCounter(try nextCounter(&self.recv_counter));
        const plain_len = try open(
            self.method,
            &self.recv_key,
            payload_nonce,
            payload_cipher[0 .. payload_len + tag_length],
            &self.read_buffer,
        );
        if (plain_len != payload_len) return error.ProtocolViolation;
        self.read_len = plain_len;
        self.read_offset = 0;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        const self: *ServerStream = @ptrCast(@alignCast(ctx));
        var total: usize = 0;
        for (buffers) |buffer| {
            var offset: usize = 0;
            while (offset < buffer.len) {
                const chunk_len = @min(buffer.len - offset, max_payload);
                const chunk = buffer[offset .. offset + chunk_len];
                if (!self.send_started) {
                    self.writeFirstChunk(io, chunk) catch |err|
                        return mapWriteError(err);
                    self.send_started = true;
                } else {
                    self.writeChunk(io, chunk) catch |err|
                        return mapWriteError(err);
                }
                offset += chunk_len;
                total += chunk_len;
            }
        }
        return total;
    }

    fn writeFirstChunk(self: *ServerStream, io: std.Io, chunk: []const u8) !void {
        const salt_len = self.method.saltLength();
        var salt: [32]u8 = undefined;
        std.Io.randomSecure(io, salt[0..salt_len]) catch return error.RandomFailed;
        deriveSubkey(self.method, self.psk.slice(), salt[0..salt_len], &self.send_key);

        const header_len = 11 + salt_len;
        var header_plain: [43]u8 = undefined;
        header_plain[0] = 1;
        std.mem.writeInt(u64, header_plain[1..9], try timestampNow(io), .big);
        @memcpy(header_plain[9 .. 9 + salt_len], self.request_salt[0..salt_len]);
        writeU16(header_plain[9 + salt_len ..], @intCast(chunk.len));

        var header_cipher: [43 + tag_length]u8 = undefined;
        seal(
            self.method,
            &self.send_key,
            nonceFromCounter(0),
            header_plain[0..header_len],
            header_cipher[0 .. header_len + tag_length],
        );

        var payload_cipher: [max_payload + tag_length]u8 = undefined;
        seal(
            self.method,
            &self.send_key,
            nonceFromCounter(1),
            chunk,
            payload_cipher[0 .. chunk.len + tag_length],
        );

        try writeAll(io, self.inner, &.{
            salt[0..salt_len],
            header_cipher[0 .. header_len + tag_length],
            payload_cipher[0 .. chunk.len + tag_length],
        });
        self.send_counter = 2;
    }

    fn writeChunk(self: *ServerStream, io: std.Io, chunk: []const u8) !void {
        var length_plain: [2]u8 = undefined;
        writeU16(&length_plain, @intCast(chunk.len));
        var length_cipher: [2 + tag_length]u8 = undefined;
        const length_nonce = nonceFromCounter(try nextCounter(&self.send_counter));
        seal(
            self.method,
            &self.send_key,
            length_nonce,
            &length_plain,
            &length_cipher,
        );

        var payload_cipher: [max_payload + tag_length]u8 = undefined;
        const payload_nonce = nonceFromCounter(try nextCounter(&self.send_counter));
        seal(
            self.method,
            &self.send_key,
            payload_nonce,
            chunk,
            payload_cipher[0 .. chunk.len + tag_length],
        );
        try writeAll(io, self.inner, &.{
            &length_cipher,
            payload_cipher[0 .. chunk.len + tag_length],
        });
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        const self: *ServerStream = @ptrCast(@alignCast(ctx));
        return self.inner.shutdown(io, how);
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        const self: *ServerStream = @ptrCast(@alignCast(ctx));
        if (self.closed.swap(true, .acq_rel)) return;
        _ = io;
        std.crypto.secureZero(u8, &self.send_key);
        std.crypto.secureZero(u8, &self.recv_key);
        std.crypto.secureZero(u8, &self.request_salt);
        self.psk.deinit();
        self.gpa.destroy(self);
    }

    fn local(ctx: *anyopaque) Endpoint {
        const self: *ServerStream = @ptrCast(@alignCast(ctx));
        return self.local_endpoint;
    }

    fn remote(ctx: *anyopaque) Endpoint {
        const self: *ServerStream = @ptrCast(@alignCast(ctx));
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

fn mapReadError(err: anyerror) Stream.ReadError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.ConnectionReset, error.ConnectionResetByPeer => error.ConnectionReset,
        error.ProtocolViolation,
        error.AuthenticationFailed,
        error.InvalidTimestamp,
        error.StaleTimestamp,
        error.EndOfStream,
        error.MalformedAddress,
        error.UnsupportedAddress,
        error.InvalidDomain,
        error.NoSpace,
        error.CounterExhausted,
        error.Replay,
        error.ReplayCacheFull,
        => error.ProtocolViolation,
        else => error.Unexpected,
    };
}

fn mapWriteError(err: anyerror) Stream.WriteError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.BrokenPipe => error.BrokenPipe,
        error.ProtocolViolation, error.CounterExhausted => error.ProtocolViolation,
        else => error.Unexpected,
    };
}

test "method parsing and key lengths" {
    try std.testing.expectEqual(Method.aes_128_gcm, Method.parse("2022-blake3-aes-128-gcm").?);
    try std.testing.expectEqual(@as(usize, 16), Method.aes_128_gcm.keyLength());
    try std.testing.expectEqual(@as(usize, 32), Method.aes_256_gcm.keyLength());
    try std.testing.expect(Method.parse("2022-blake3-chacha20-poly1305") == null);
}

test "base64 PSK parsing" {
    const key16 = try Key.parse(Method.aes_128_gcm, "MDEyMzQ1Njc4OWFiY2RlZg==");
    try std.testing.expectEqual(@as(u8, 16), key16.len);
    try std.testing.expectEqualStrings("0123456789abcdef", key16.slice());

    const key32 = try Key.parse(
        Method.aes_256_gcm,
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    );
    try std.testing.expectEqual(@as(u8, 32), key32.len);
}

test "address roundtrip" {
    var buffer: [256]u8 = undefined;
    const endpoint = try Endpoint.parse("example.com:443");
    const len = try encodeAddress(endpoint, &buffer);
    const decoded = try decodeAddress(buffer[0..len], 0);
    try std.testing.expect(Endpoint.eql(endpoint, decoded.endpoint));
}

test "AEAD chunk roundtrip and nonce order" {
    const psk: [32]u8 = @splat(0x42);
    var key: [32]u8 = undefined;
    const salt: [32]u8 = @splat(0x01);
    deriveSubkey(Method.aes_256_gcm, &psk, &salt, &key);

    var ciphertext: [64]u8 = undefined;
    const plaintext = "hello shadowsocks 2022";
    const nonce0 = nonceFromCounter(0);
    seal(Method.aes_256_gcm, &key, nonce0, plaintext, &ciphertext);

    var decrypted: [64]u8 = undefined;
    const len = try open(
        Method.aes_256_gcm,
        &key,
        nonce0,
        ciphertext[0 .. plaintext.len + tag_length],
        &decrypted,
    );
    try std.testing.expectEqualStrings(plaintext, decrypted[0..len]);
}

test "TCP nonce is a 12-byte little-endian integer" {
    const one = nonceFromCounter(1);
    try std.testing.expectEqual(@as(u8, 1), one[0]);
    for (one[1..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    const value = nonceFromCounter(0x0102030405060708);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0 },
        &value,
    );
}

test "sliding window rejects duplicates and old packets" {
    var window: Window = .{};
    try std.testing.expect(window.accept(5));
    try std.testing.expect(!window.accept(5));
    try std.testing.expect(window.accept(8));
    try std.testing.expect(window.accept(6));
    try std.testing.expect(!window.accept(6));
    try std.testing.expect(window.accept(0));
    try std.testing.expect(!window.accept(0));
    try std.testing.expect(window.accept(100));
    try std.testing.expect(!window.accept(5));
    try std.testing.expect(window.accept(99));
}
