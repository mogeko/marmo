//! Credential validation shared by the TLS client and server.
//!
//! The in-tree handshake only signs with ECDSA P-256, so both server and
//! client credentials must use a P-256 leaf key that matches the configured
//! key pair. Chain encoding and handshake bounds are checked here so a
//! listener or dialer can reject bad configuration before a peer appears.

const std = @import("std");
const handshake = @import("handshake.zig");
const cert_path = @import("cert_path.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{HandshakeFailed};

/// Checks chain bounds, the leaf key algorithm, and that the key pair matches
/// the leaf certificate.
pub fn validateCredentials(
    certificate_chain: []const []const u8,
    private_key: Ecdsa.KeyPair,
) Error!void {
    try validateChain(certificate_chain);
    const leaf: std.crypto.Certificate = .{
        .buffer = certificate_chain[0],
        .index = 0,
    };
    const parsed = leaf.parse() catch return error.HandshakeFailed;
    const is_p256 = switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| curve == .X9_62_prime256v1,
        else => false,
    };
    if (!is_p256) return error.HandshakeFailed;
    const expected = private_key.public_key.toUncompressedSec1();
    if (!std.mem.eql(u8, parsed.pubKey(), &expected)) {
        return error.HandshakeFailed;
    }
}

/// Checks that a certificate list fits the Certificate message and that every
/// DER element is structurally valid.
pub fn validateChain(certificate_chain: []const []const u8) Error!void {
    if (certificate_chain.len == 0 or
        certificate_chain.len > handshake.max_chain_certs)
    {
        return error.HandshakeFailed;
    }
    var total: usize = 1 + 3;
    for (certificate_chain) |cert| {
        if (cert.len == 0) return error.HandshakeFailed;
        total += 3 + cert.len + 2;
    }
    if (total + 4 > handshake.max_handshake) return error.HandshakeFailed;
    for (certificate_chain) |certificate| {
        cert_path.validateCertificateDer(certificate) catch
            return error.HandshakeFailed;
    }
}

/// Parses a Certificate message's certificate_list body into borrowed DER
/// slices. The list cursor must contain only complete CertificateEntry values.
pub fn readCertificateList(
    chain: *[handshake.max_chain_certs][]const u8,
    list: *handshake.Cursor,
) !usize {
    var chain_len: usize = 0;
    while (!list.eof()) {
        if (chain_len == chain.len) return error.HandshakeFailed;
        const cert_len = try list.readU24();
        const der = try list.readBytes(cert_len);
        const extensions_len = try list.readU16();
        _ = try list.readBytes(extensions_len);
        if (der.len == 0) return error.HandshakeFailed;
        chain[chain_len] = der;
        chain_len += 1;
    }
    return chain_len;
}

test "credential validation rejects a key that does not match the leaf" {
    const other = Ecdsa.KeyPair.generate(std.testing.io);
    const tiny = [_]u8{0x30};
    try std.testing.expectError(
        error.HandshakeFailed,
        validateCredentials(&.{&tiny}, other),
    );
}
