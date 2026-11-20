//! TLS 1.3 record protection for the client and server.
//!
//! The suite is carried in `Keys` so one connection can switch between the
//! AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 record layers without a
//! generic type in the public API.

const std = @import("std");

pub const content_type_change_cipher_spec: u8 = 20;
pub const content_type_alert: u8 = 21;
pub const content_type_handshake: u8 = 22;
pub const content_type_application_data: u8 = 23;

pub const record_header_len = 5;
pub const max_plaintext = 16 * 1024;
pub const max_ciphertext = max_plaintext + 256;
pub const max_record = record_header_len + max_ciphertext;

pub const max_key_len = 32;
/// Historical name for the AES-128 key length. Kept exported because the
/// package README and out-of-tree callers used it.
pub const key_len = 16;
pub const iv_len = 12;
pub const tag_len = 16;

/// TLS 1.3 cipher suites implemented by this package.
pub const CipherSuite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,

    pub const list = [_]CipherSuite{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };

    pub fn wireId(self: CipherSuite) u16 {
        return switch (self) {
            .aes_128_gcm_sha256 => 0x1301,
            .aes_256_gcm_sha384 => 0x1302,
            .chacha20_poly1305_sha256 => 0x1303,
        };
    }

    pub fn fromWire(id: u16) ?CipherSuite {
        return switch (id) {
            0x1301 => .aes_128_gcm_sha256,
            0x1302 => .aes_256_gcm_sha384,
            0x1303 => .chacha20_poly1305_sha256,
            else => null,
        };
    }

    pub fn keyLength(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .aes_256_gcm_sha384, .chacha20_poly1305_sha256 => 32,
        };
    }

    pub fn hashLength(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => 32,
            .aes_256_gcm_sha384 => 48,
        };
    }
};

pub const ReadError = error{
    Canceled,
    EndOfStream,
    ProtocolViolation,
    Unexpected,
};

pub const SealError = error{
    CounterExhausted,
    NoSpace,
};

pub const OpenError = error{
    BadRecord,
    CounterExhausted,
    ProtocolViolation,
};

pub const Keys = struct {
    suite: CipherSuite = .aes_128_gcm_sha256,
    /// Only the first `suite.keyLength()` bytes are used.
    key: [max_key_len]u8 = @splat(0),
    iv: [iv_len]u8 = @splat(0),
    seq: u64 = 0,

    pub fn reset(self: *Keys) void {
        self.seq = 0;
    }
};

/// Reads one full TLS record into `buffer`.
pub fn readRecord(
    input: *std.Io.Reader,
    buffer: []u8,
) ReadError![]u8 {
    if (buffer.len < record_header_len) return error.ProtocolViolation;
    var header: [record_header_len]u8 = undefined;
    readExact(input, &header) catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        else => return error.Unexpected,
    };

    const length = std.mem.readInt(u16, header[3..5], .big);
    if (length > max_ciphertext) return error.ProtocolViolation;
    const total = record_header_len + length;
    if (buffer.len < total) return error.ProtocolViolation;
    @memcpy(buffer[0..record_header_len], &header);
    readExact(input, buffer[record_header_len..total]) catch |err| switch (err) {
        error.EndOfStream => return error.ProtocolViolation,
        else => return error.Unexpected,
    };
    return buffer[0..total];
}

pub fn writePlain(
    output: *std.Io.Writer,
    content_type: u8,
    payload: []const u8,
) std.Io.Writer.Error!void {
    if (payload.len > max_plaintext) return error.WriteFailed;
    var header: [record_header_len]u8 = .{
        content_type,
        0x03,
        0x03,
        0,
        0,
    };
    std.mem.writeInt(u16, header[3..5], @intCast(payload.len), .big);
    try output.writeAll(&header);
    try output.writeAll(payload);
}

/// Encrypts one TLS 1.3 record. `out` must hold `5 + plaintext + 1 + tag`.
pub fn seal(
    keys: *Keys,
    inner_type: u8,
    plaintext: []const u8,
    out: []u8,
) SealError![]u8 {
    const total = record_header_len + plaintext.len + 1 + tag_len;
    if (out.len < total) return error.NoSpace;
    if (plaintext.len > max_plaintext) return error.NoSpace;

    out[0] = content_type_application_data;
    out[1] = 0x03;
    out[2] = 0x03;
    std.mem.writeInt(
        u16,
        out[3..5],
        @intCast(plaintext.len + 1 + tag_len),
        .big,
    );
    @memcpy(out[record_header_len..][0..plaintext.len], plaintext);
    const inner_index = record_header_len + plaintext.len;
    out[inner_index] = inner_type;

    const nonce = makeNonce(keys.iv, keys.seq);
    const header = out[0..record_header_len];
    const ciphertext = out[record_header_len..][0 .. plaintext.len + 1];
    const tag = out[inner_index + 1 ..][0..tag_len];
    encrypt(keys.suite, ciphertext, tag, ciphertext, header, nonce, keys.key);

    keys.seq = std.math.add(u64, keys.seq, 1) catch
        return error.CounterExhausted;
    return out[0..total];
}

pub const Opened = struct {
    content_type: u8,
    content: []u8,
};

/// Decrypts one full TLS record into `out`, returning the inner content.
pub fn open(keys: *Keys, record: []const u8, out: []u8) OpenError!Opened {
    if (record.len < record_header_len) return error.BadRecord;
    if (record[0] != content_type_application_data) return error.BadRecord;
    if (record[1] != 0x03) return error.BadRecord;
    // Encrypted TLS 1.3 records always carry legacy_record_version 0x0303.
    if (record[2] != 0x03) return error.BadRecord;

    const ciphertext_len = std.mem.readInt(u16, record[3..5], .big);
    if (ciphertext_len < tag_len + 1) return error.BadRecord;
    if (record.len != record_header_len + ciphertext_len) return error.BadRecord;

    const ciphertext = record[record_header_len..][0 .. ciphertext_len - tag_len];
    const tag = record[record.len - tag_len ..][0..tag_len];
    if (ciphertext.len > max_plaintext + 1) return error.ProtocolViolation;
    if (out.len < ciphertext.len) return error.ProtocolViolation;

    const nonce = makeNonce(keys.iv, keys.seq);
    decrypt(
        keys.suite,
        out[0..ciphertext.len],
        ciphertext,
        tag,
        record[0..record_header_len],
        nonce,
        keys.key,
    ) catch return error.BadRecord;

    keys.seq = std.math.add(u64, keys.seq, 1) catch
        return error.CounterExhausted;

    const plain = out[0..ciphertext.len];
    const inner_index = std.mem.lastIndexOfNone(u8, plain, &.{0}) orelse
        return error.BadRecord;
    return .{
        .content_type = plain[inner_index],
        .content = plain[0..inner_index],
    };
}

fn encrypt(
    suite: CipherSuite,
    ciphertext: []u8,
    tag: []u8,
    plaintext: []const u8,
    ad: []const u8,
    nonce: [iv_len]u8,
    key: [max_key_len]u8,
) void {
    switch (suite) {
        .aes_128_gcm_sha256 => {
            const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
            var tag_array: [tag_len]u8 = undefined;
            Aead.encrypt(
                ciphertext,
                &tag_array,
                plaintext,
                ad,
                nonce,
                key[0..Aead.key_length].*,
            );
            @memcpy(tag, &tag_array);
        },
        .aes_256_gcm_sha384 => {
            const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;
            var tag_array: [tag_len]u8 = undefined;
            Aead.encrypt(
                ciphertext,
                &tag_array,
                plaintext,
                ad,
                nonce,
                key[0..Aead.key_length].*,
            );
            @memcpy(tag, &tag_array);
        },
        .chacha20_poly1305_sha256 => {
            const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            var tag_array: [tag_len]u8 = undefined;
            Aead.encrypt(
                ciphertext,
                &tag_array,
                plaintext,
                ad,
                nonce,
                key[0..Aead.key_length].*,
            );
            @memcpy(tag, &tag_array);
        },
    }
}

fn decrypt(
    suite: CipherSuite,
    plaintext: []u8,
    ciphertext: []const u8,
    tag: []const u8,
    ad: []const u8,
    nonce: [iv_len]u8,
    key: [max_key_len]u8,
) !void {
    switch (suite) {
        .aes_128_gcm_sha256 => {
            const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
            try Aead.decrypt(
                plaintext,
                ciphertext,
                tag[0..tag_len].*,
                ad,
                nonce,
                key[0..Aead.key_length].*,
            );
        },
        .aes_256_gcm_sha384 => {
            const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;
            try Aead.decrypt(
                plaintext,
                ciphertext,
                tag[0..tag_len].*,
                ad,
                nonce,
                key[0..Aead.key_length].*,
            );
        },
        .chacha20_poly1305_sha256 => {
            const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            try Aead.decrypt(
                plaintext,
                ciphertext,
                tag[0..tag_len].*,
                ad,
                nonce,
                key[0..Aead.key_length].*,
            );
        },
    }
}

fn makeNonce(iv: [iv_len]u8, seq: u64) [iv_len]u8 {
    var nonce = iv;
    var sequence: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence, seq, .big);
    for (sequence, 0..) |byte, index| {
        nonce[iv_len - 8 + index] ^= byte;
    }
    return nonce;
}

fn readExact(input: *std.Io.Reader, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const read_len = try input.readSliceShort(buffer[offset..]);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
}

test "encrypted records reject a non-0x0303 legacy version" {
    var keys: Keys = .{};
    var out: [32]u8 = undefined;
    const record = [_]u8{ content_type_application_data, 0x03, 0x02, 0, tag_len + 1 };
    try std.testing.expectError(error.BadRecord, open(&keys, &record, &out));
}

test "every suite seals and opens an application-data record" {
    var keys_aes128: Keys = .{ .suite = .aes_128_gcm_sha256 };
    var keys_aes256: Keys = .{ .suite = .aes_256_gcm_sha384 };
    var keys_chacha: Keys = .{ .suite = .chacha20_poly1305_sha256 };
    @memset(&keys_aes128.key, 0x11);
    @memset(&keys_aes256.key, 0x22);
    @memset(&keys_chacha.key, 0x33);
    @memset(&keys_aes128.iv, 0x44);
    @memset(&keys_aes256.iv, 0x55);
    @memset(&keys_chacha.iv, 0x66);

    const plaintext = "suite round trip";
    inline for (.{ &keys_aes128, &keys_aes256, &keys_chacha }) |keys| {
        var sealed_buffer: [record_header_len + max_plaintext + 1 + tag_len]u8 =
            undefined;
        const sealed = try seal(
            keys,
            content_type_application_data,
            plaintext,
            &sealed_buffer,
        );
        var open_keys = keys.*;
        open_keys.seq = 0;
        var opened_buffer: [max_plaintext + 1]u8 = undefined;
        const opened = try open(&open_keys, sealed, &opened_buffer);
        try std.testing.expectEqual(
            content_type_application_data,
            opened.content_type,
        );
        try std.testing.expectEqualStrings(plaintext, opened.content);
    }
}
