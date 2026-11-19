//! TLS 1.3 server handshake parsing, encoding, and key schedule.
//!
//! Scope is deliberately narrow: TLS 1.3, X25519, AES-128-GCM/SHA-256, and
//! ECDSA P-256 server certificates.

const std = @import("std");
const record = @import("record.zig");

pub const max_handshake = 16 * 1024;
pub const max_chain_certs = 8;
pub const max_server_name = 255;

pub const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
pub const Hash = std.crypto.hash.sha2.Sha256;
pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Error = error{
    HandshakeFailed,
};

pub const handshake_client_hello: u8 = 1;
pub const handshake_server_hello: u8 = 2;
pub const handshake_encrypted_extensions: u8 = 8;
pub const handshake_certificate: u8 = 11;
pub const handshake_certificate_verify: u8 = 15;
pub const handshake_finished: u8 = 20;

pub const cipher_aes_128_gcm_sha256: u16 = 0x1301;
pub const group_x25519: u16 = 0x001d;
pub const signature_ecdsa_secp256r1_sha256: u16 = 0x0403;
pub const tls_1_3: u16 = 0x0304;

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
    cipher_aes_128_gcm_sha256: bool,
    signature_ecdsa_p256: bool,
    x25519_public: [32]u8,
    x25519_found: bool,
    server_name: ?[]const u8,
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

    _ = try body.readU16(); // legacy_version
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
        .cipher_aes_128_gcm_sha256 = false,
        .signature_ecdsa_p256 = false,
        .x25519_public = @splat(0),
        .x25519_found = false,
        .server_name = null,
    };
    try parseCipherSuites(&body, &hello);
    try parseCompression(&body);

    const extensions_len = try body.readU16();
    var extensions = try body.sub(extensions_len);
    if (!body.eof()) return error.HandshakeFailed;
    try parseExtensions(&extensions, &hello, server_name_buf);
    if (!hello.cipher_aes_128_gcm_sha256 or
        !hello.signature_ecdsa_p256 or
        !hello.x25519_found)
    {
        return error.HandshakeFailed;
    }
    return hello;
}

fn parseCipherSuites(body: *Cursor, hello: *ClientHello) Error!void {
    const suites_len = try body.readU16();
    if (suites_len % 2 != 0) return error.HandshakeFailed;
    var suites = try body.sub(suites_len);
    while (!suites.eof()) {
        if (try suites.readU16() == cipher_aes_128_gcm_sha256) {
            hello.cipher_aes_128_gcm_sha256 = true;
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
    while (!extensions.eof()) {
        const extension_type = try extensions.readU16();
        const extension_len = try extensions.readU16();
        var extension = try extensions.sub(extension_len);
        switch (extension_type) {
            0x0000 => try parseServerName(&extension, hello, server_name_buf),
            0x000d => try parseSignatureAlgorithms(&extension, hello),
            0x002b => try parseSupportedVersions(&extension),
            0x0033 => try parseKeyShares(&extension, hello),
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
        if (group != group_x25519 or key.len != 32) continue;
        @memcpy(&hello.x25519_public, key);
        hello.x25519_found = true;
    }
}

pub const KeySchedule = struct {
    client_hs_secret: [32]u8,
    server_hs_secret: [32]u8,
    client_finished_key: [32]u8,
    server_finished_key: [32]u8,
    client_hs_keys: record.Keys,
    server_hs_keys: record.Keys,
    master_secret: [32]u8,

    pub fn derive(shared_secret: [32]u8, hello_hash: [32]u8) KeySchedule {
        const zeroes: [32]u8 = @splat(0);
        const early_secret = Hkdf.extract(&.{0}, &zeroes);
        const empty_hash = std.crypto.tls.emptyHash(Hash);
        const hs_derived = std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            early_secret,
            "derived",
            &empty_hash,
            32,
        );
        const handshake_secret = Hkdf.extract(&hs_derived, &shared_secret);
        const ap_derived = std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            handshake_secret,
            "derived",
            &empty_hash,
            32,
        );
        const master_secret = Hkdf.extract(&ap_derived, &zeroes);
        const client_hs_secret = std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            handshake_secret,
            "c hs traffic",
            &hello_hash,
            32,
        );
        const server_hs_secret = std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            handshake_secret,
            "s hs traffic",
            &hello_hash,
            32,
        );
        return .{
            .client_hs_secret = client_hs_secret,
            .server_hs_secret = server_hs_secret,
            .client_finished_key = std.crypto.tls.hkdfExpandLabel(
                Hkdf,
                client_hs_secret,
                "finished",
                "",
                32,
            ),
            .server_finished_key = std.crypto.tls.hkdfExpandLabel(
                Hkdf,
                server_hs_secret,
                "finished",
                "",
                32,
            ),
            .client_hs_keys = keysFromSecret(client_hs_secret),
            .server_hs_keys = keysFromSecret(server_hs_secret),
            .master_secret = master_secret,
        };
    }

    pub fn clientAppSecret(self: *const KeySchedule, handshake_hash: [32]u8) [32]u8 {
        return std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            self.master_secret,
            "c ap traffic",
            &handshake_hash,
            32,
        );
    }

    pub fn serverAppSecret(self: *const KeySchedule, handshake_hash: [32]u8) [32]u8 {
        return std.crypto.tls.hkdfExpandLabel(
            Hkdf,
            self.master_secret,
            "s ap traffic",
            &handshake_hash,
            32,
        );
    }
};

pub fn keysFromSecret(secret: [32]u8) record.Keys {
    return .{
        .key = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "key", "", record.key_len),
        .iv = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "iv", "", record.iv_len),
    };
}

pub fn finishedVerifyData(
    finished_key: [32]u8,
    transcript_hash: [32]u8,
) [32]u8 {
    var result: [32]u8 = undefined;
    Hmac.create(&result, &transcript_hash, &finished_key);
    return result;
}

pub fn transcriptHash(transcript: *const Hash) [32]u8 {
    var copy = transcript.*;
    return copy.finalResult();
}
