//! Loads TLS server credentials from PEM or DER files.
//!
//! Supported input: DER certificate chain or PEM `CERTIFICATE` blocks, and an
//! ECDSA P-256 private key in PKCS#8 or SEC1 (`EC PRIVATE KEY`) form.

const std = @import("std");
const tls13 = @import("tls13");
const tls_server = @import("tls_server.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const max_file_len = 64 * 1024;
const max_certs = 8;

pub const LoadError = error{
    OutOfMemory,
    InvalidCredentials,
};

pub fn loadOptions(
    allocator: std.mem.Allocator,
    io: std.Io,
    certificate_path: []const u8,
    private_key_path: []const u8,
) LoadError!tls_server.Options {
    const certificate_text = readFile(
        allocator,
        io,
        certificate_path,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidCredentials,
    };
    defer allocator.free(certificate_text);
    const private_key_text = readFile(
        allocator,
        io,
        private_key_path,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidCredentials,
    };
    defer {
        std.crypto.secureZero(u8, private_key_text);
        allocator.free(private_key_text);
    }

    const chain = try parseCertificateChain(allocator, certificate_text);
    errdefer freeCertificateChain(allocator, chain);
    var key = try parsePrivateKey(allocator, private_key_text);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));

    tls13.validateCredentials(chain, key) catch
        return error.InvalidCredentials;
    const options: tls_server.Options = .{
        .certificate_chain = chain,
        .private_key = key,
    };
    return options;
}

/// Frees a chain returned by `parseCertificateChain`. Every certificate slice
/// is allocator-owned, including the DER passthrough case.
pub fn freeCertificateChain(
    allocator: std.mem.Allocator,
    chain: []const []const u8,
) void {
    for (chain) |certificate| allocator.free(certificate);
    allocator.free(chain);
}

fn readFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_file_len),
    );
}

/// Parses a DER chain or PEM `CERTIFICATE` blocks. Every returned certificate
/// is allocator-owned; use `freeCertificateChain` when done.
pub fn parseCertificateChain(
    allocator: std.mem.Allocator,
    text: []const u8,
) LoadError![]const []const u8 {
    if (std.mem.find(u8, text, "-----BEGIN") == null) {
        if (text.len == 0) return error.InvalidCredentials;
        const chain = try allocator.alloc([]const u8, 1);
        errdefer allocator.free(chain);
        chain[0] = try allocator.dupe(u8, text);
        return chain;
    }

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    var chain: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (chain.items) |certificate| allocator.free(certificate);
        chain.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const begin_relative = std.mem.find(
            u8,
            text[offset..],
            begin_marker,
        ) orelse break;
        const begin = offset + begin_relative + begin_marker.len;
        const end_relative = std.mem.find(u8, text[begin..], end_marker) orelse
            return error.InvalidCredentials;
        const body = text[begin..][0..end_relative];
        const der = try decodeBase64(allocator, body);
        chain.append(allocator, der) catch |err| {
            allocator.free(der);
            return err;
        };
        if (chain.items.len > max_certs) return error.InvalidCredentials;
        offset = begin + end_relative + end_marker.len;
    }

    if (chain.items.len == 0) return error.InvalidCredentials;
    return chain.toOwnedSlice(allocator);
}

/// Parses an ECDSA P-256 key from PKCS#8/SEC1 DER or PEM.
pub fn parsePrivateKey(
    allocator: std.mem.Allocator,
    text: []const u8,
) LoadError!Ecdsa.KeyPair {
    if (std.mem.find(u8, text, "-----BEGIN") == null) {
        return parsePrivateKeyDer(text);
    }

    if (pemBody(text, "PRIVATE KEY")) |body| {
        const der = try decodeBase64(allocator, body);
        defer std.crypto.secureZero(u8, der);
        return parsePrivateKeyDer(der);
    }
    if (pemBody(text, "EC PRIVATE KEY")) |body| {
        const der = try decodeBase64(allocator, body);
        defer std.crypto.secureZero(u8, der);
        return parsePrivateKeyDer(der);
    }
    return error.InvalidCredentials;
}

fn pemBody(text: []const u8, label: []const u8) ?[]const u8 {
    var begin_buffer: [64]u8 = undefined;
    var end_buffer: [64]u8 = undefined;
    const begin = std.fmt.bufPrint(
        &begin_buffer,
        "-----BEGIN {s}-----",
        .{label},
    ) catch return null;
    const end = std.fmt.bufPrint(
        &end_buffer,
        "-----END {s}-----",
        .{label},
    ) catch return null;

    const begin_index = std.mem.find(u8, text, begin) orelse return null;
    const body_start = begin_index + begin.len;
    const end_index = std.mem.find(u8, text[body_start..], end) orelse
        return null;
    return text[body_start..][0..end_index];
}

fn decodeBase64(
    allocator: std.mem.Allocator,
    text: []const u8,
) LoadError![]u8 {
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const decoded = try allocator.alloc(
        u8,
        decoder.calcSizeUpperBound(text.len),
    );
    errdefer allocator.free(decoded);
    const written = decoder.decode(decoded, text) catch
        return error.InvalidCredentials;
    if (written == decoded.len) return decoded;
    return allocator.realloc(decoded, written) catch error.OutOfMemory;
}

const Element = struct {
    tag: u8,
    content: []const u8,
};

fn parsePrivateKeyDer(der: []const u8) LoadError!Ecdsa.KeyPair {
    var position: usize = 0;
    const outer = try readElement(der, &position);
    if (outer.tag != 0x30) return error.InvalidCredentials;

    var inner_position: usize = 0;
    const version = try readElement(outer.content, &inner_position);
    if (version.tag != 0x02) return error.InvalidCredentials;
    const second = try readElement(outer.content, &inner_position);

    if (second.tag == 0x30) {
        const third = try readElement(outer.content, &inner_position);
        if (third.tag != 0x04) return error.InvalidCredentials;
        return parseEcPrivateKey(third.content);
    }
    if (second.tag == 0x04) {
        return keyFromScalar(second.content);
    }
    return error.InvalidCredentials;
}

fn parseEcPrivateKey(der: []const u8) LoadError!Ecdsa.KeyPair {
    var position: usize = 0;
    const outer = try readElement(der, &position);
    if (outer.tag != 0x30) return error.InvalidCredentials;

    var inner_position: usize = 0;
    const version = try readElement(outer.content, &inner_position);
    if (version.tag != 0x02) return error.InvalidCredentials;
    const scalar = try readElement(outer.content, &inner_position);
    if (scalar.tag != 0x04) return error.InvalidCredentials;
    return keyFromScalar(scalar.content);
}

fn keyFromScalar(scalar: []const u8) LoadError!Ecdsa.KeyPair {
    if (scalar.len == 0 or scalar.len > Ecdsa.SecretKey.encoded_length) {
        return error.InvalidCredentials;
    }
    var bytes: [Ecdsa.SecretKey.encoded_length]u8 = @splat(0);
    @memcpy(bytes[bytes.len - scalar.len ..], scalar);
    defer std.crypto.secureZero(u8, &bytes);
    var secret = Ecdsa.SecretKey.fromBytes(bytes) catch
        return error.InvalidCredentials;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
    return Ecdsa.KeyPair.fromSecretKey(secret) catch
        return error.InvalidCredentials;
}

fn readElement(
    buffer: []const u8,
    position: *usize,
) LoadError!Element {
    if (position.* >= buffer.len) return error.InvalidCredentials;
    const tag = buffer[position.*];
    position.* += 1;
    if (position.* >= buffer.len) return error.InvalidCredentials;

    const first = buffer[position.*];
    position.* += 1;
    var length: usize = undefined;
    if (first < 0x80) {
        length = first;
    } else {
        const length_bytes = first & 0x7f;
        if (length_bytes == 0 or length_bytes > 3) {
            return error.InvalidCredentials;
        }
        if (buffer.len - position.* < length_bytes) {
            return error.InvalidCredentials;
        }
        length = 0;
        for (0..length_bytes) |_| {
            length = (length << 8) | buffer[position.*];
            position.* += 1;
        }
    }
    if (buffer.len - position.* < length) return error.InvalidCredentials;
    const content = buffer[position.*..][0..length];
    position.* += length;
    return .{ .tag = tag, .content = content };
}
