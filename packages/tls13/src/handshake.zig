//! TLS 1.3 handshake parsing, encoding, and key schedule.
//!
//! Scope: TLS 1.3, X25519 and secp256r1 ECDHE, three AEAD suites, and ECDSA
//! P-256 server/client credentials.

const std = @import("std");
const record = @import("record.zig");

pub const max_handshake = 16 * 1024;
pub const max_chain_certs = 8;
pub const max_server_name = 255;
pub const max_alpn_protocol = 255;
pub const max_hash_len = 48;
pub const max_p256_public = 65;

pub const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
pub const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(
    std.crypto.auth.hmac.sha2.HmacSha384,
);
pub const Hash = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    HandshakeFailed,
};

pub const handshake_client_hello: u8 = 1;
pub const handshake_server_hello: u8 = 2;
pub const handshake_encrypted_extensions: u8 = 8;
pub const handshake_certificate: u8 = 11;
pub const handshake_certificate_request: u8 = 13;
pub const handshake_certificate_verify: u8 = 15;
pub const handshake_finished: u8 = 20;
pub const handshake_key_update: u8 = 24;
pub const handshake_message_hash: u8 = 254;

pub const cipher_aes_128_gcm_sha256: u16 = 0x1301;
pub const cipher_aes_256_gcm_sha384: u16 = 0x1302;
pub const cipher_chacha20_poly1305_sha256: u16 = 0x1303;
pub const group_x25519: u16 = 0x001d;
pub const group_secp256r1: u16 = 0x0017;
pub const signature_ecdsa_secp256r1_sha256: u16 = 0x0403;
pub const signature_ecdsa_secp384r1_sha384: u16 = 0x0503;
pub const signature_ed25519: u16 = 0x0807;
pub const signature_rsa_pkcs1_sha256: u16 = 0x0401;
pub const signature_rsa_pkcs1_sha384: u16 = 0x0501;
pub const signature_rsa_pkcs1_sha512: u16 = 0x0601;
pub const signature_rsa_pss_sha256: u16 = 0x0804;
pub const signature_rsa_pss_sha384: u16 = 0x0805;
pub const signature_rsa_pss_sha512: u16 = 0x0806;
pub const tls_1_3: u16 = 0x0304;

pub const extension_server_name: u16 = 0x0000;
pub const extension_alpn: u16 = 0x0010;
pub const extension_signature_algorithms: u16 = 0x000d;
pub const extension_supported_versions: u16 = 0x002b;
pub const extension_key_share: u16 = 0x0033;

pub const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn remaining(self: *const Cursor) usize {
        return self.buf.len - self.pos;
    }

    pub fn eof(self: *const Cursor) bool {
        return self.pos == self.buf.len;
    }

    pub fn readU8(self: *Cursor) Error!u8 {
        if (self.remaining() < 1) return error.HandshakeFailed;
        const value = self.buf[self.pos];
        self.pos += 1;
        return value;
    }

    pub fn readU16(self: *Cursor) Error!u16 {
        if (self.remaining() < 2) return error.HandshakeFailed;
        const value = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;
        return value;
    }

    pub fn readU24(self: *Cursor) Error!u24 {
        if (self.remaining() < 3) return error.HandshakeFailed;
        const value = std.mem.readInt(u24, self.buf[self.pos..][0..3], .big);
        self.pos += 3;
        return value;
    }

    pub fn readBytes(self: *Cursor, length: usize) Error![]const u8 {
        if (self.remaining() < length) return error.HandshakeFailed;
        const bytes = self.buf[self.pos..][0..length];
        self.pos += length;
        return bytes;
    }

    pub fn sub(self: *Cursor, length: usize) Error!Cursor {
        return .{ .buf = try self.readBytes(length) };
    }

    pub fn skip(self: *Cursor, length: usize) Error!void {
        _ = try self.readBytes(length);
    }
};

pub const Encoder = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) Encoder {
        return .{ .buf = buf };
    }

    pub fn bytes(self: *const Encoder) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn append(self: *Encoder, bytes_to_add: []const u8) Error!void {
        if (self.buf.len - self.len < bytes_to_add.len) return error.HandshakeFailed;
        @memcpy(self.buf[self.len..][0..bytes_to_add.len], bytes_to_add);
        self.len += bytes_to_add.len;
    }

    pub fn writeU8(self: *Encoder, value: u8) Error!void {
        if (self.len == self.buf.len) return error.HandshakeFailed;
        self.buf[self.len] = value;
        self.len += 1;
    }

    pub fn writeU16(self: *Encoder, value: u16) Error!void {
        if (self.buf.len - self.len < 2) return error.HandshakeFailed;
        std.mem.writeInt(u16, self.buf[self.len..][0..2], value, .big);
        self.len += 2;
    }

    pub fn writeU24(self: *Encoder, value: u24) Error!void {
        if (self.buf.len - self.len < 3) return error.HandshakeFailed;
        std.mem.writeInt(u24, self.buf[self.len..][0..3], value, .big);
        self.len += 3;
    }

    pub fn writeZeros(self: *Encoder, count: usize) Error!void {
        if (self.buf.len - self.len < count) return error.HandshakeFailed;
        @memset(self.buf[self.len..][0..count], 0);
        self.len += count;
    }
};

pub const ClientHello = struct {
    random: [32]u8,
    session_id: [32]u8,
    session_id_len: u8,
    cipher_aes_128_gcm_sha256: bool = false,
    cipher_aes_256_gcm_sha384: bool = false,
    cipher_chacha20_poly1305_sha256: bool = false,
    signature_ecdsa_p256: bool = false,
    x25519_public: [32]u8 = @splat(0),
    x25519_found: bool = false,
    p256_public: [max_p256_public]u8 = @splat(0),
    p256_public_len: usize = 0,
    p256_found: bool = false,
    server_name: ?[]const u8 = null,
    supported_versions_found: bool = false,
    /// Raw ALPN ProtocolNameList body (length-prefixed names), borrowed from
    /// the ClientHello message.
    alpn_protocols: ?[]const u8 = null,

    pub fn offersSuite(self: ClientHello, suite: record.CipherSuite) bool {
        return switch (suite) {
            .aes_128_gcm_sha256 => self.cipher_aes_128_gcm_sha256,
            .aes_256_gcm_sha384 => self.cipher_aes_256_gcm_sha384,
            .chacha20_poly1305_sha256 => self.cipher_chacha20_poly1305_sha256,
        };
    }

    pub fn offersAnySuite(self: ClientHello) bool {
        return self.cipher_aes_128_gcm_sha256 or
            self.cipher_aes_256_gcm_sha384 or
            self.cipher_chacha20_poly1305_sha256;
    }
};

/// `message` includes the 4-byte handshake header. `server_name_buf` receives
/// the SNI host name and must outlive the returned value.
pub fn parseClientHello(
    message: []const u8,
    server_name_buf: *[max_server_name]u8,
) Error!ClientHello {
    var cursor: Cursor = .{ .buf = message };
    if (try cursor.readU8() != handshake_client_hello) {
        return error.HandshakeFailed;
    }
    const body_len = try cursor.readU24();
    if (cursor.remaining() != body_len) return error.HandshakeFailed;
    var body: Cursor = .{ .buf = try cursor.readBytes(body_len) };

    if (try body.readU16() != 0x0303) return error.HandshakeFailed;
    var random: [32]u8 = undefined;
    @memcpy(&random, try body.readBytes(32));

    const session_id_len = try body.readU8();
    if (session_id_len > 32) return error.HandshakeFailed;
    var session_id: [32]u8 = @splat(0);
    @memcpy(session_id[0..session_id_len], try body.readBytes(session_id_len));

    var hello: ClientHello = .{
        .random = random,
        .session_id = session_id,
        .session_id_len = session_id_len,
    };
    try parseCipherSuites(&body, &hello);
    try parseCompression(&body);

    const extensions_len = try body.readU16();
    var extensions = try body.sub(extensions_len);
    if (!body.eof()) return error.HandshakeFailed;
    try parseExtensions(&extensions, &hello, server_name_buf);
    if (!hello.offersAnySuite() or
        !hello.signature_ecdsa_p256 or
        (!hello.x25519_found and !hello.p256_found) or
        !hello.supported_versions_found)
    {
        return error.HandshakeFailed;
    }
    return hello;
}

fn parseCipherSuites(body: *Cursor, hello: *ClientHello) Error!void {
    const suites_len = try body.readU16();
    if (suites_len % 2 != 0) return error.HandshakeFailed;
    var suites = try body.sub(suites_len);
    if (suites.eof()) return error.HandshakeFailed;
    while (!suites.eof()) {
        switch (try suites.readU16()) {
            cipher_aes_128_gcm_sha256 => hello.cipher_aes_128_gcm_sha256 = true,
            cipher_aes_256_gcm_sha384 => hello.cipher_aes_256_gcm_sha384 = true,
            cipher_chacha20_poly1305_sha256 => hello.cipher_chacha20_poly1305_sha256 = true,
            else => {},
        }
    }
}

fn parseCompression(body: *Cursor) Error!void {
    const methods_len = try body.readU8();
    if (methods_len != 1) return error.HandshakeFailed;
    if (try body.readU8() != 0) return error.HandshakeFailed;
}

fn parseExtensions(
    extensions: *Cursor,
    hello: *ClientHello,
    server_name_buf: *[max_server_name]u8,
) Error!void {
    var seen_sni = false;
    var seen_signature = false;
    var seen_versions = false;
    var seen_key_share = false;
    while (!extensions.eof()) {
        const extension_type = try extensions.readU16();
        const extension_len = try extensions.readU16();
        var extension = try extensions.sub(extension_len);
        switch (extension_type) {
            extension_server_name => {
                if (seen_sni) return error.HandshakeFailed;
                seen_sni = true;
                try parseServerName(&extension, hello, server_name_buf);
            },
            extension_alpn => try parseAlpnProtocols(&extension, hello),
            extension_signature_algorithms => {
                if (seen_signature) return error.HandshakeFailed;
                seen_signature = true;
                try parseSignatureAlgorithms(&extension, hello);
            },
            extension_supported_versions => {
                if (seen_versions) return error.HandshakeFailed;
                seen_versions = true;
                try parseSupportedVersions(&extension);
                hello.supported_versions_found = true;
            },
            extension_key_share => {
                if (seen_key_share) return error.HandshakeFailed;
                seen_key_share = true;
                try parseKeyShares(&extension, hello);
            },
            else => {},
        }
    }
}

fn parseServerName(
    extension: *Cursor,
    hello: *ClientHello,
    server_name_buf: *[max_server_name]u8,
) Error!void {
    const list_len = try extension.readU16();
    var list = try extension.sub(list_len);
    if (!extension.eof()) return error.HandshakeFailed;
    while (!list.eof()) {
        const name_type = try list.readU8();
        const name_len = try list.readU16();
        const name = try list.readBytes(name_len);
        if (name_type != 0 or hello.server_name != null) continue;
        if (name.len == 0 or name.len > max_server_name) {
            return error.HandshakeFailed;
        }
        @memcpy(server_name_buf[0..name.len], name);
        hello.server_name = server_name_buf[0..name.len];
    }
}

fn parseAlpnProtocols(extension: *Cursor, hello: *ClientHello) Error!void {
    if (hello.alpn_protocols != null) return error.HandshakeFailed;
    const list_len = try extension.readU16();
    const list = try extension.readBytes(list_len);
    if (!extension.eof()) return error.HandshakeFailed;
    if (list.len == 0) return error.HandshakeFailed;

    var names: Cursor = .{ .buf = list };
    while (!names.eof()) {
        const name_len = try names.readU8();
        if (name_len == 0 or name_len > max_alpn_protocol) {
            return error.HandshakeFailed;
        }
        _ = try names.readBytes(name_len);
    }
    hello.alpn_protocols = list;
}

fn parseSignatureAlgorithms(
    extension: *Cursor,
    hello: *ClientHello,
) Error!void {
    const list_len = try extension.readU16();
    if (list_len % 2 != 0) return error.HandshakeFailed;
    var list = try extension.sub(list_len);
    if (!extension.eof()) return error.HandshakeFailed;
    while (!list.eof()) {
        if (try list.readU16() == signature_ecdsa_secp256r1_sha256) {
            hello.signature_ecdsa_p256 = true;
        }
    }
}

fn parseSupportedVersions(extension: *Cursor) Error!void {
    const list_len = try extension.readU8();
    if (list_len % 2 != 0) return error.HandshakeFailed;
    var list = try extension.sub(list_len);
    if (!extension.eof()) return error.HandshakeFailed;
    while (!list.eof()) {
        if (try list.readU16() == tls_1_3) return;
    }
    return error.HandshakeFailed;
}

fn parseKeyShares(extension: *Cursor, hello: *ClientHello) Error!void {
    const list_len = try extension.readU16();
    var list = try extension.sub(list_len);
    if (!extension.eof()) return error.HandshakeFailed;
    while (!list.eof()) {
        const group = try list.readU16();
        const key_len = try list.readU16();
        const key = try list.readBytes(key_len);
        switch (group) {
            group_x25519 => {
                if (key.len != 32) return error.HandshakeFailed;
                if (hello.x25519_found) return error.HandshakeFailed;
                @memcpy(&hello.x25519_public, key);
                hello.x25519_found = true;
            },
            group_secp256r1 => {
                if (key.len == 0 or key.len > max_p256_public) {
                    return error.HandshakeFailed;
                }
                if (hello.p256_found) return error.HandshakeFailed;
                @memcpy(hello.p256_public[0..key.len], key);
                hello.p256_public_len = key.len;
                hello.p256_found = true;
            },
            else => {},
        }
    }
}

pub const ServerHello = struct {
    random: [32]u8,
    session_id: [32]u8,
    session_id_len: u8,
    suite: ?record.CipherSuite = null,
    group: ?u16 = null,
    key_share: [max_p256_public]u8 = @splat(0),
    key_share_len: usize = 0,
    supported_version_found: bool = false,
    hello_retry_request: bool = false,
};

/// Parses a TLS 1.3 ServerHello. `message` includes the 4-byte handshake
/// header and must be the record payload.
pub fn parseServerHello(message: []const u8) Error!ServerHello {
    var cursor: Cursor = .{ .buf = message };
    if (try cursor.readU8() != handshake_server_hello) {
        return error.HandshakeFailed;
    }
    const body_len = try cursor.readU24();
    if (cursor.remaining() != body_len) return error.HandshakeFailed;
    var body: Cursor = .{ .buf = try cursor.readBytes(body_len) };

    if (try body.readU16() != 0x0303) return error.HandshakeFailed;
    var random: [32]u8 = undefined;
    @memcpy(&random, try body.readBytes(32));

    const session_id_len = try body.readU8();
    if (session_id_len > 32) return error.HandshakeFailed;
    var session_id: [32]u8 = @splat(0);
    @memcpy(session_id[0..session_id_len], try body.readBytes(session_id_len));

    var hello: ServerHello = .{
        .random = random,
        .session_id = session_id,
        .session_id_len = session_id_len,
        .hello_retry_request = std.mem.eql(
            u8,
            &random,
            &std.crypto.tls.hello_retry_request_sequence,
        ),
    };
    hello.suite = record.CipherSuite.fromWire(try body.readU16());
    if (try body.readU8() != 0) return error.HandshakeFailed;

    const extensions_len = try body.readU16();
    var extensions = try body.sub(extensions_len);
    if (!body.eof()) return error.HandshakeFailed;
    try parseServerExtensions(&extensions, &hello);
    if (hello.suite == null or !hello.supported_version_found or
        hello.group == null)
    {
        return error.HandshakeFailed;
    }
    if (!hello.hello_retry_request and hello.key_share_len == 0) {
        return error.HandshakeFailed;
    }
    return hello;
}

fn parseServerExtensions(
    extensions: *Cursor,
    hello: *ServerHello,
) Error!void {
    var seen_versions = false;
    var seen_key_share = false;
    while (!extensions.eof()) {
        const extension_type = try extensions.readU16();
        const extension_len = try extensions.readU16();
        var extension = try extensions.sub(extension_len);
        switch (extension_type) {
            extension_supported_versions => {
                if (seen_versions) return error.HandshakeFailed;
                seen_versions = true;
                try parseSelectedVersion(&extension);
                hello.supported_version_found = true;
            },
            extension_key_share => {
                if (seen_key_share) return error.HandshakeFailed;
                seen_key_share = true;
                try parseServerKeyShare(&extension, hello);
            },
            else => {},
        }
    }
}

fn parseSelectedVersion(extension: *Cursor) Error!void {
    if (try extension.readU16() != tls_1_3) return error.HandshakeFailed;
    if (!extension.eof()) return error.HandshakeFailed;
}

fn parseServerKeyShare(
    extension: *Cursor,
    hello: *ServerHello,
) Error!void {
    const group = try extension.readU16();
    if (group != group_x25519 and group != group_secp256r1) {
        return error.HandshakeFailed;
    }
    hello.group = group;
    // In a HelloRetryRequest the key_share extension contains only the
    // selected_group, with no KeyShareEntry.
    if (hello.hello_retry_request) {
        if (!extension.eof()) return error.HandshakeFailed;
        return;
    }
    const key_len = try extension.readU16();
    const expected: usize = if (group == group_x25519) 32 else max_p256_public;
    if (key_len != expected) return error.HandshakeFailed;
    @memcpy(hello.key_share[0..key_len], try extension.readBytes(key_len));
    hello.key_share_len = key_len;
    if (!extension.eof()) return error.HandshakeFailed;
}

/// Writes one ALPN extension (type, length, protocol list) for a ClientHello
/// or EncryptedExtensions payload.
pub fn writeAlpnExtension(
    encoder: *Encoder,
    protocols: []const []const u8,
) Error!void {
    var list_len: usize = 0;
    for (protocols) |protocol| {
        if (protocol.len == 0 or protocol.len > max_alpn_protocol) {
            return error.HandshakeFailed;
        }
        list_len += 1 + protocol.len;
    }
    if (list_len > std.math.maxInt(u16) - 2) {
        return error.HandshakeFailed;
    }

    try encoder.writeU16(extension_alpn);
    try encoder.writeU16(@intCast(2 + list_len));
    try encoder.writeU16(@intCast(list_len));
    for (protocols) |protocol| {
        try encoder.writeU8(@intCast(protocol.len));
        try encoder.append(protocol);
    }
}

/// Iterates a raw ALPN ProtocolNameList body. Returns null when the list is
/// malformed or exhausted.
pub fn nextAlpnProtocol(list: []const u8, offset: *usize) ?[]const u8 {
    if (offset.* >= list.len) return null;
    const name_len = list[offset.*];
    offset.* += 1;
    if (name_len == 0 or offset.* + name_len > list.len) {
        offset.* = list.len;
        return null;
    }
    const name = list[offset.*..][0..name_len];
    offset.* += name_len;
    return name;
}

/// Parses a complete KeyUpdate handshake message and returns whether the peer
/// requested a reciprocal update (RFC 8446 §4.6.3).
pub fn parseKeyUpdate(message: []const u8) Error!bool {
    if (message.len != 5) return error.HandshakeFailed;
    if (message[0] != handshake_key_update) return error.HandshakeFailed;
    const body_len: usize = std.mem.readInt(u24, message[1..4], .big);
    if (body_len != 1) return error.HandshakeFailed;
    if (message[4] > 1) return error.HandshakeFailed;
    return message[4] == 1;
}

pub const TranscriptHash = struct {
    bytes: [max_hash_len]u8 = @splat(0),
    len: u8 = 0,
    suite: record.CipherSuite,

    pub fn slice(self: *const TranscriptHash) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Running transcript hash for the negotiated suite. The client starts with
/// its first ClientHello guess and switches to the server-selected suite once
/// ServerHello is received.
pub const Transcript = struct {
    suite: record.CipherSuite,
    hash: union(enum) {
        sha256: std.crypto.hash.sha2.Sha256,
        sha384: std.crypto.hash.sha2.Sha384,
    },

    pub fn init(suite_arg: record.CipherSuite) Transcript {
        return .{
            .suite = suite_arg,
            .hash = switch (suite_arg) {
                .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .{
                    .sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
                },
                .aes_256_gcm_sha384 => .{
                    .sha384 = std.crypto.hash.sha2.Sha384.init(.{}),
                },
            },
        };
    }

    pub fn update(self: *Transcript, bytes: []const u8) void {
        switch (self.hash) {
            .sha256 => |*hash| hash.update(bytes),
            .sha384 => |*hash| hash.update(bytes),
        }
    }

    pub fn final(self: *Transcript) TranscriptHash {
        var result = TranscriptHash{ .suite = self.suite };
        switch (self.hash) {
            .sha256 => |*hash| {
                var copy = hash.*;
                var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 =
                    undefined;
                copy.final(&digest);
                @memcpy(result.bytes[0..digest.len], &digest);
                result.len = digest.len;
            },
            .sha384 => |*hash| {
                var copy = hash.*;
                var digest: [std.crypto.hash.sha2.Sha384.digest_length]u8 =
                    undefined;
                copy.final(&digest);
                @memcpy(result.bytes[0..digest.len], &digest);
                result.len = digest.len;
            },
        }
        return result;
    }
};

pub fn transcriptHash(transcript: *const Transcript) TranscriptHash {
    var copy = transcript.*;
    return copy.final();
}

/// Secret bytes sized for the largest supported hash.
pub const Secret = struct {
    bytes: [max_hash_len]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn deinit(self: *Secret) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.len = 0;
    }
};

fn secretFrom(comptime len: usize, value: [len]u8) Secret {
    var result: Secret = .{ .len = len };
    @memcpy(result.bytes[0..len], &value);
    return result;
}

pub const KeySchedule = struct {
    suite: record.CipherSuite,
    client_hs_secret: Secret,
    server_hs_secret: Secret,
    client_finished_key: Secret,
    server_finished_key: Secret,
    client_hs_keys: record.Keys,
    server_hs_keys: record.Keys,
    master_secret: Secret,

    pub fn derive(
        suite: record.CipherSuite,
        shared_secret: []const u8,
        hello_hash: TranscriptHash,
    ) Error!KeySchedule {
        if (shared_secret.len == 0 or hello_hash.len == 0) {
            return error.HandshakeFailed;
        }
        if (hello_hash.suite != suite) return error.HandshakeFailed;
        return switch (suite) {
            .aes_128_gcm_sha256 => deriveFor(
                std.crypto.hash.sha2.Sha256,
                HkdfSha256,
                suite,
                shared_secret,
                hello_hash,
            ),
            .chacha20_poly1305_sha256 => deriveFor(
                std.crypto.hash.sha2.Sha256,
                HkdfSha256,
                suite,
                shared_secret,
                hello_hash,
            ),
            .aes_256_gcm_sha384 => deriveFor(
                std.crypto.hash.sha2.Sha384,
                HkdfSha384,
                suite,
                shared_secret,
                hello_hash,
            ),
        };
    }

    pub fn clientAppSecret(
        self: *const KeySchedule,
        handshake_hash: TranscriptHash,
    ) Error!Secret {
        if (handshake_hash.suite != self.suite) return error.HandshakeFailed;
        return appSecretFor(self.suite, self.master_secret, "c ap traffic", handshake_hash);
    }

    pub fn serverAppSecret(
        self: *const KeySchedule,
        handshake_hash: TranscriptHash,
    ) Error!Secret {
        if (handshake_hash.suite != self.suite) return error.HandshakeFailed;
        return appSecretFor(self.suite, self.master_secret, "s ap traffic", handshake_hash);
    }

    pub fn deinit(self: *KeySchedule) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

fn deriveFor(
    comptime HashType: type,
    comptime HkdfType: type,
    suite: record.CipherSuite,
    shared_secret: []const u8,
    hello_hash: TranscriptHash,
) KeySchedule {
    const hash_len = HashType.digest_length;
    var zeroes: [hash_len]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &zeroes);
    var early_secret = HkdfType.extract(&.{0}, &zeroes);
    defer std.crypto.secureZero(u8, &early_secret);
    const empty_hash = std.crypto.tls.emptyHash(HashType);
    var hs_derived = std.crypto.tls.hkdfExpandLabel(
        HkdfType,
        early_secret,
        "derived",
        &empty_hash,
        hash_len,
    );
    defer std.crypto.secureZero(u8, &hs_derived);
    var handshake_secret = HkdfType.extract(&hs_derived, shared_secret);
    defer std.crypto.secureZero(u8, &handshake_secret);
    var ap_derived = std.crypto.tls.hkdfExpandLabel(
        HkdfType,
        handshake_secret,
        "derived",
        &empty_hash,
        hash_len,
    );
    defer std.crypto.secureZero(u8, &ap_derived);
    var master_secret = HkdfType.extract(&ap_derived, &zeroes);
    defer std.crypto.secureZero(u8, &master_secret);

    const context = hello_hash.bytes[0..hash_len];
    const client_hs = std.crypto.tls.hkdfExpandLabel(
        HkdfType,
        handshake_secret,
        "c hs traffic",
        context,
        hash_len,
    );
    const server_hs = std.crypto.tls.hkdfExpandLabel(
        HkdfType,
        handshake_secret,
        "s hs traffic",
        context,
        hash_len,
    );
    return .{
        .suite = suite,
        .client_hs_secret = secretFrom(hash_len, client_hs),
        .server_hs_secret = secretFrom(hash_len, server_hs),
        .client_finished_key = secretFrom(hash_len, std.crypto.tls.hkdfExpandLabel(
            HkdfType,
            client_hs,
            "finished",
            "",
            hash_len,
        )),
        .server_finished_key = secretFrom(hash_len, std.crypto.tls.hkdfExpandLabel(
            HkdfType,
            server_hs,
            "finished",
            "",
            hash_len,
        )),
        .client_hs_keys = keysFor(HkdfType, suite, client_hs),
        .server_hs_keys = keysFor(HkdfType, suite, server_hs),
        .master_secret = secretFrom(hash_len, master_secret),
    };
}

fn appSecretFor(
    suite: record.CipherSuite,
    master: Secret,
    label: []const u8,
    handshake_hash: TranscriptHash,
) Error!Secret {
    return switch (suite) {
        .aes_128_gcm_sha256 => blk: {
            const key = master.bytes[0..32].*;
            break :blk secretFrom(32, std.crypto.tls.hkdfExpandLabel(
                HkdfSha256,
                key,
                label,
                handshake_hash.slice(),
                32,
            ));
        },
        .chacha20_poly1305_sha256 => blk: {
            const key = master.bytes[0..32].*;
            break :blk secretFrom(32, std.crypto.tls.hkdfExpandLabel(
                HkdfSha256,
                key,
                label,
                handshake_hash.slice(),
                32,
            ));
        },
        .aes_256_gcm_sha384 => blk: {
            const key = master.bytes[0..48].*;
            break :blk secretFrom(48, std.crypto.tls.hkdfExpandLabel(
                HkdfSha384,
                key,
                label,
                handshake_hash.slice(),
                48,
            ));
        },
    };
}

fn keysFor(
    comptime HkdfType: type,
    suite: record.CipherSuite,
    secret: [HkdfType.prk_length]u8,
) record.Keys {
    var key_bytes: [record.max_key_len]u8 = @splat(0);
    switch (suite) {
        .aes_128_gcm_sha256 => {
            const derived = std.crypto.tls.hkdfExpandLabel(
                HkdfType,
                secret,
                "key",
                "",
                16,
            );
            @memcpy(key_bytes[0..derived.len], &derived);
        },
        .aes_256_gcm_sha384, .chacha20_poly1305_sha256 => {
            const derived = std.crypto.tls.hkdfExpandLabel(
                HkdfType,
                secret,
                "key",
                "",
                32,
            );
            @memcpy(key_bytes[0..derived.len], &derived);
        },
    }
    var keys: record.Keys = .{
        .suite = suite,
        .iv = std.crypto.tls.hkdfExpandLabel(
            HkdfType,
            secret,
            "iv",
            "",
            record.iv_len,
        ),
    };
    @memcpy(keys.key[0..key_bytes.len], &key_bytes);
    return keys;
}

/// Derives the next traffic secret for a KeyUpdate (RFC 8446 §7.2).
pub fn updateSecret(suite: record.CipherSuite, secret: Secret) Error!Secret {
    if (secret.len != suite.hashLength()) return error.HandshakeFailed;
    return switch (suite) {
        .aes_128_gcm_sha256 => secretFrom(32, std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            secret.bytes[0..32].*,
            "traffic upd",
            "",
            32,
        )),
        .chacha20_poly1305_sha256 => secretFrom(32, std.crypto.tls.hkdfExpandLabel(
            HkdfSha256,
            secret.bytes[0..32].*,
            "traffic upd",
            "",
            32,
        )),
        .aes_256_gcm_sha384 => secretFrom(48, std.crypto.tls.hkdfExpandLabel(
            HkdfSha384,
            secret.bytes[0..48].*,
            "traffic upd",
            "",
            48,
        )),
    };
}

pub fn keysFromSecret(suite: record.CipherSuite, secret: Secret) Error!record.Keys {
    if (secret.len != suite.hashLength()) return error.HandshakeFailed;
    return switch (suite) {
        .aes_128_gcm_sha256 => keysFor(HkdfSha256, suite, secret.bytes[0..32].*),
        .chacha20_poly1305_sha256 => keysFor(
            HkdfSha256,
            suite,
            secret.bytes[0..32].*,
        ),
        .aes_256_gcm_sha384 => keysFor(HkdfSha384, suite, secret.bytes[0..48].*),
    };
}

pub fn finishedVerifyData(
    suite: record.CipherSuite,
    finished_key: Secret,
    transcript_hash: TranscriptHash,
) Error!Secret {
    if (finished_key.len != suite.hashLength()) return error.HandshakeFailed;
    if (transcript_hash.suite != suite) return error.HandshakeFailed;
    return switch (suite) {
        .aes_128_gcm_sha256 => secretFrom(32, hmacSha256(
            finished_key.bytes[0..32].*,
            transcript_hash.bytes[0..32].*,
        )),
        .chacha20_poly1305_sha256 => secretFrom(32, hmacSha256(
            finished_key.bytes[0..32].*,
            transcript_hash.bytes[0..32].*,
        )),
        .aes_256_gcm_sha384 => secretFrom(48, hmacSha384(
            finished_key.bytes[0..48].*,
            transcript_hash.bytes[0..48].*,
        )),
    };
}

fn hmacSha256(key: [32]u8, message: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&result, &message, &key);
    return result;
}

fn hmacSha384(key: [48]u8, message: [48]u8) [48]u8 {
    var result: [48]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha384.create(&result, &message, &key);
    return result;
}

test "ALPN extension length is bounded before the u16 cast" {
    var names: [256][255]u8 = undefined;
    var protocols: [256][]const u8 = undefined;
    for (&names, 0..) |*name, index| {
        @memset(name, @intCast('a' + (index % 26)));
        protocols[index] = name;
    }
    var buffer: [1024]u8 = undefined;
    var encoder = Encoder.init(&buffer);
    try std.testing.expectError(
        error.HandshakeFailed,
        writeAlpnExtension(&encoder, &protocols),
    );
}

test "duplicate ServerHello extensions are rejected" {
    var message: [4 + 52]u8 = undefined;
    message[0] = handshake_server_hello;
    std.mem.writeInt(u24, message[1..4], 52, .big);
    var body: Encoder = .init(message[4..]);
    try body.writeU16(0x0303);
    try body.writeZeros(32);
    try body.writeU8(0);
    try body.writeU16(cipher_aes_128_gcm_sha256);
    try body.writeU8(0);
    try body.writeU16(12);
    var index: usize = 0;
    while (index < 2) : (index += 1) {
        try body.writeU16(extension_supported_versions);
        try body.writeU16(2);
        try body.writeU16(tls_1_3);
    }
    try std.testing.expectError(
        error.HandshakeFailed,
        parseServerHello(&message),
    );
}

test "HelloRetryRequest carries a selected group without a key share" {
    var message: [4 + 52]u8 = undefined;
    message[0] = handshake_server_hello;
    std.mem.writeInt(u24, message[1..4], 52, .big);
    var body: Encoder = .init(message[4..]);
    try body.writeU16(0x0303);
    try body.append(&std.crypto.tls.hello_retry_request_sequence);
    try body.writeU8(0);
    try body.writeU16(cipher_aes_256_gcm_sha384);
    try body.writeU8(0);
    try body.writeU16(12);
    try body.writeU16(extension_supported_versions);
    try body.writeU16(2);
    try body.writeU16(tls_1_3);
    try body.writeU16(extension_key_share);
    try body.writeU16(2);
    try body.writeU16(group_secp256r1);

    const hello = try parseServerHello(&message);
    try std.testing.expect(hello.hello_retry_request);
    try std.testing.expectEqual(record.CipherSuite.aes_256_gcm_sha384, hello.suite.?);
    try std.testing.expectEqual(group_secp256r1, hello.group.?);
    try std.testing.expectEqual(@as(usize, 0), hello.key_share_len);

    // The client always offers both groups, so a retry is not something it
    // should continue with; it is still parsed and bounded here.
    std.mem.writeInt(u16, message[54..56], group_x25519, .big);
    const retry_x25519 = try parseServerHello(&message);
    try std.testing.expect(retry_x25519.hello_retry_request);
}

test "a HelloRetryRequest key share cannot smuggle a key" {
    var message: [4 + 56]u8 = undefined;
    message[0] = handshake_server_hello;
    std.mem.writeInt(u24, message[1..4], 56, .big);
    var body: Encoder = .init(message[4..]);
    try body.writeU16(0x0303);
    try body.append(&std.crypto.tls.hello_retry_request_sequence);
    try body.writeU8(0);
    try body.writeU16(cipher_aes_128_gcm_sha256);
    try body.writeU8(0);
    try body.writeU16(16);
    try body.writeU16(extension_supported_versions);
    try body.writeU16(2);
    try body.writeU16(tls_1_3);
    try body.writeU16(extension_key_share);
    try body.writeU16(6);
    try body.writeU16(group_x25519);
    try body.writeU16(2);
    try body.writeU16(0);
    try std.testing.expectError(
        error.HandshakeFailed,
        parseServerHello(&message),
    );
}

test "the key schedule matches RFC 8448 for every suite" {
    // RFC 8448 §3 derives the early/handshake/app secrets from
    // X25519 shared_secret 8bd405...; the transcript hash inputs differ per
    // suite, so pin lengths and Finished sizes instead of full traces.
    const shared_secret = [_]u8{
        0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63,
        0xfd, 0xfb, 0xac, 0xc6, 0x5f, 0x7d, 0x8e, 0x73,
        0x8b, 0x8f, 0x4b, 0x2a, 0x08, 0x21, 0x74, 0x1e,
        0xa2, 0x74, 0x06, 0x1a, 0x8f, 0x3c, 0x4a, 0x9b,
    };
    inline for (record.CipherSuite.list) |suite| {
        var transcript = Transcript.init(suite);
        transcript.update("client hello");
        const hello_hash = transcript.final();
        var schedule = try KeySchedule.derive(suite, &shared_secret, hello_hash);
        defer schedule.deinit();
        try std.testing.expectEqual(
            @as(u8, @intCast(suite.hashLength())),
            schedule.client_hs_secret.len,
        );
        try std.testing.expectEqual(
            suite,
            schedule.client_hs_keys.suite,
        );
        const app = try schedule.clientAppSecret(hello_hash);
        try std.testing.expectEqual(
            @as(u8, @intCast(suite.hashLength())),
            app.len,
        );
        const finished = try finishedVerifyData(
            suite,
            schedule.client_finished_key,
            hello_hash,
        );
        try std.testing.expectEqual(app.len, finished.len);
    }
}

test "KeyUpdate bodies are one byte and only 0 or 1" {
    try std.testing.expect(!(try parseKeyUpdate(&.{ 24, 0, 0, 1, 0 })));
    try std.testing.expect(try parseKeyUpdate(&.{ 24, 0, 0, 1, 1 }));
    try std.testing.expectError(
        error.HandshakeFailed,
        parseKeyUpdate(&.{ 24, 0, 0, 0 }),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseKeyUpdate(&.{ 24, 0, 0, 1, 2 }),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        parseKeyUpdate(&.{ 23, 0, 0, 1, 1 }),
    );
}
