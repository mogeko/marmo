//! CertificateVerify signature verification shared by both TLS roles.
//!
//! The certificate chain parser supplies the leaf public key and its
//! algorithm; this module only checks the signature over the RFC 8446
//! CertificateVerify context string.

const std = @import("std");
const handshake = @import("handshake.zig");
const Certificate = std.crypto.Certificate;
const Ecdsa = std.crypto.sign.ecdsa;

pub const max_pubkey = 1024;

pub fn verify(
    scheme: u16,
    signature: []const u8,
    message: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    pub_key: []const u8,
) !void {
    switch (scheme) {
        handshake.signature_ecdsa_secp256r1_sha256 => {
            const Signature = Ecdsa.EcdsaP256Sha256.Signature;
            const PublicKey = Ecdsa.EcdsaP256Sha256.PublicKey;
            const sig = try Signature.fromDer(signature);
            const key = try PublicKey.fromSec1(pub_key);
            try sig.verify(message, key);
        },
        handshake.signature_ecdsa_secp384r1_sha384 => {
            const Signature = Ecdsa.EcdsaP384Sha384.Signature;
            const PublicKey = Ecdsa.EcdsaP384Sha384.PublicKey;
            const sig = try Signature.fromDer(signature);
            const key = try PublicKey.fromSec1(pub_key);
            try sig.verify(message, key);
        },
        handshake.signature_ed25519 => {
            const Ed25519 = std.crypto.sign.Ed25519;
            if (signature.len != Ed25519.Signature.encoded_length) {
                return error.InvalidSignature;
            }
            if (pub_key.len != Ed25519.PublicKey.encoded_length) {
                return error.InvalidSignature;
            }
            const sig = Ed25519.Signature.fromBytes(
                signature[0..Ed25519.Signature.encoded_length].*,
            );
            const key = try Ed25519.PublicKey.fromBytes(
                pub_key[0..Ed25519.PublicKey.encoded_length].*,
            );
            try sig.verify(message, key);
        },
        handshake.signature_rsa_pss_sha256,
        handshake.signature_rsa_pss_sha384,
        handshake.signature_rsa_pss_sha512,
        => try verifyRsa(scheme, signature, message, pub_key_algo, pub_key),
        else => return error.HandshakeFailed,
    }
}

fn verifyRsa(
    scheme: u16,
    signature: []const u8,
    message: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    pub_key: []const u8,
) !void {
    if (pub_key_algo != .rsaEncryption and pub_key_algo != .rsassa_pss) {
        return error.HandshakeFailed;
    }
    const components = try Certificate.rsa.PublicKey.parseDer(pub_key);
    const key = try Certificate.rsa.PublicKey.fromBytes(
        components.exponent,
        components.modulus,
    );
    // RFC 8446 §4.4.3: the signature is a fixed-size RSA result, so its
    // length must equal the certificate modulus. A mismatch would otherwise
    // trip an assertion inside the PSS verifier.
    if (signature.len != components.modulus.len) {
        return error.HandshakeFailed;
    }
    // The std PSS verifier derives the encoded-message length from the
    // modulus bit length and asserts that it equals the byte length. Keys
    // whose modulus is more than six bits short of a whole byte (for example
    // 2041-bit) would abort, so reject them before reaching the assertion.
    if (components.modulus.len == 0) return error.HandshakeFailed;
    const leading_zeros = @as(usize, @clz(components.modulus[0]));
    const modulus_bits = components.modulus.len * 8 - leading_zeros;
    if (modulus_bits + 6 < components.modulus.len * 8) {
        return error.HandshakeFailed;
    }
    switch (signature.len) {
        inline 256, 384, 512 => |modulus_len| {
            const sig: *const [modulus_len]u8 = signature[0..modulus_len];
            switch (scheme) {
                handshake.signature_rsa_pkcs1_sha256 => try Certificate.rsa
                    .PKCS1v1_5Signature.verify(
                    modulus_len,
                    sig,
                    message,
                    key,
                    std.crypto.hash.sha2.Sha256,
                ),
                handshake.signature_rsa_pkcs1_sha384 => try Certificate.rsa
                    .PKCS1v1_5Signature.verify(
                    modulus_len,
                    sig,
                    message,
                    key,
                    std.crypto.hash.sha2.Sha384,
                ),
                handshake.signature_rsa_pkcs1_sha512 => try Certificate.rsa
                    .PKCS1v1_5Signature.verify(
                    modulus_len,
                    sig,
                    message,
                    key,
                    std.crypto.hash.sha2.Sha512,
                ),
                handshake.signature_rsa_pss_sha256 => try Certificate.rsa
                    .PSSSignature.verify(
                    modulus_len,
                    sig,
                    message,
                    key,
                    std.crypto.hash.sha2.Sha256,
                ),
                handshake.signature_rsa_pss_sha384 => try Certificate.rsa
                    .PSSSignature.verify(
                    modulus_len,
                    sig,
                    message,
                    key,
                    std.crypto.hash.sha2.Sha384,
                ),
                handshake.signature_rsa_pss_sha512 => try Certificate.rsa
                    .PSSSignature.verify(
                    modulus_len,
                    sig,
                    message,
                    key,
                    std.crypto.hash.sha2.Sha512,
                ),
                else => return error.HandshakeFailed,
            }
        },
        else => return error.HandshakeFailed,
    }
}

test "RSA-PSS signature length must match the certificate modulus" {
    const allocator = std.testing.allocator;
    var key: std.ArrayList(u8) = .empty;
    defer key.deinit(allocator);
    try key.append(allocator, 0x30);
    try key.append(allocator, 0x81);
    try key.append(allocator, 0x86);
    try key.append(allocator, 0x02);
    try key.append(allocator, 0x81);
    try key.append(allocator, 0x80);
    try key.appendNTimes(allocator, 0x81, 128);
    try key.appendSlice(allocator, &.{ 0x02, 0x01, 0x03 });

    var signature: [256]u8 = undefined;
    @memset(&signature, 1);
    try std.testing.expectError(
        error.HandshakeFailed,
        verifyRsa(
            handshake.signature_rsa_pss_sha256,
            &signature,
            "message",
            .rsaEncryption,
            key.items,
        ),
    );
}

test "RSA moduli with non-byte-aligned bit lengths are rejected" {
    const allocator = std.testing.allocator;
    var key: std.ArrayList(u8) = .empty;
    defer key.deinit(allocator);
    try key.append(allocator, 0x30);
    try key.append(allocator, 0x81);
    try key.append(allocator, 0x86);
    try key.append(allocator, 0x02);
    try key.append(allocator, 0x81);
    try key.append(allocator, 0x80);
    try key.append(allocator, 0x01);
    try key.appendNTimes(allocator, 0x00, 126);
    try key.append(allocator, 0x01);
    try key.appendSlice(allocator, &.{ 0x02, 0x01, 0x03 });

    var signature: [256]u8 = undefined;
    @memset(&signature, 0);
    signature[255] = 1;
    try std.testing.expectError(
        error.HandshakeFailed,
        verifyRsa(
            handshake.signature_rsa_pss_sha256,
            &signature,
            "message",
            .rsaEncryption,
            key.items,
        ),
    );
}
