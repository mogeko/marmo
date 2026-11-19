//! TLS 1.3 record protection for the server implementation.
//!
//! Only the initial cipher suite set is wired: AES-128-GCM with SHA-256.

const std = @import("std");

pub const content_type_change_cipher_spec: u8 = 20;
pub const content_type_alert: u8 = 21;
pub const content_type_handshake: u8 = 22;
pub const content_type_application_data: u8 = 23;

pub const record_header_len = 5;
pub const max_plaintext = 16 * 1024;
pub const max_ciphertext = max_plaintext + 256;
pub const max_record = record_header_len + max_ciphertext;

pub const key_len = 16;
pub const iv_len = 12;
pub const tag_len = 16;

const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;

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
    key: [key_len]u8 = @splat(0),
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
    Aead.encrypt(ciphertext, tag, ciphertext, header, nonce, keys.key);

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
    Aead.decrypt(
        out[0..ciphertext.len],
        ciphertext,
        tag.*,
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
