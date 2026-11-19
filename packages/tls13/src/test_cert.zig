//! Test-only self-signed ECDSA P-256 certificate builder.
//!
//! No private key is committed; tests generate a fresh key and certificate at
//! runtime. This file is only referenced by test declarations.

const std = @import("std");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Certificate = struct {
    der: []u8,
    key_pair: Ecdsa.KeyPair,

    pub fn deinit(self: *Certificate, gpa: std.mem.Allocator) void {
        gpa.free(self.der);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_pair));
        self.* = undefined;
    }
};

pub fn generate(
    gpa: std.mem.Allocator,
    io: std.Io,
) !Certificate {
    const key_pair = Ecdsa.KeyPair.generate(io);

    const sig_alg = try buildSignatureAlgorithm(gpa);
    defer gpa.free(sig_alg);
    const name = try buildName(gpa);
    defer gpa.free(name);
    const validity = try buildValidity(gpa);
    defer gpa.free(validity);
    const spki = try buildSpki(gpa, key_pair);
    defer gpa.free(spki);
    const extensions = try buildExtensions(gpa);
    defer gpa.free(extensions);

    const version_inner = try tlv(gpa, 0x02, &.{2});
    defer gpa.free(version_inner);
    const version = try tlv(gpa, 0xa0, version_inner);
    defer gpa.free(version);
    const serial = try tlv(gpa, 0x02, &.{1});
    defer gpa.free(serial);

    const tbs_content = try concat(gpa, &.{
        version,
        serial,
        sig_alg,
        name,
        validity,
        name,
        spki,
        extensions,
    });
    defer gpa.free(tbs_content);
    const tbs = try tlv(gpa, 0x30, tbs_content);
    defer gpa.free(tbs);

    const signature_value = try buildSignatureValue(gpa, key_pair, tbs);
    defer gpa.free(signature_value);

    const certificate_content = try concat(gpa, &.{
        tbs,
        sig_alg,
        signature_value,
    });
    defer gpa.free(certificate_content);
    const der = try tlv(gpa, 0x30, certificate_content);

    return .{ .der = der, .key_pair = key_pair };
}

fn buildSignatureAlgorithm(gpa: std.mem.Allocator) ![]u8 {
    const oid = try tlv(
        gpa,
        0x06,
        &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 },
    );
    defer gpa.free(oid);
    return tlv(gpa, 0x30, oid);
}

fn buildName(gpa: std.mem.Allocator) ![]u8 {
    const cn_oid = try tlv(gpa, 0x06, &.{ 0x55, 0x04, 0x03 });
    defer gpa.free(cn_oid);
    const cn_value = try tlv(gpa, 0x0c, "localhost");
    defer gpa.free(cn_value);
    const atv = try concat(gpa, &.{ cn_oid, cn_value });
    defer gpa.free(atv);
    const atv_seq = try tlv(gpa, 0x30, atv);
    defer gpa.free(atv_seq);
    const rdn = try tlv(gpa, 0x31, atv_seq);
    defer gpa.free(rdn);
    return tlv(gpa, 0x30, rdn);
}

fn buildValidity(gpa: std.mem.Allocator) ![]u8 {
    const not_before = try tlv(gpa, 0x17, "260101000000Z");
    defer gpa.free(not_before);
    const not_after = try tlv(gpa, 0x17, "360101000000Z");
    defer gpa.free(not_after);
    const content = try concat(gpa, &.{ not_before, not_after });
    defer gpa.free(content);
    return tlv(gpa, 0x30, content);
}

fn buildSpki(
    gpa: std.mem.Allocator,
    key_pair: Ecdsa.KeyPair,
) ![]u8 {
    const ec_oid = try tlv(
        gpa,
        0x06,
        &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 },
    );
    defer gpa.free(ec_oid);
    const p256_oid = try tlv(
        gpa,
        0x06,
        &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 },
    );
    defer gpa.free(p256_oid);
    const alg_content = try concat(gpa, &.{ ec_oid, p256_oid });
    defer gpa.free(alg_content);
    const alg = try tlv(gpa, 0x30, alg_content);
    defer gpa.free(alg);

    const public_key = key_pair.public_key.toUncompressedSec1();
    var bit_string_content: [1 + @sizeOf(@TypeOf(public_key))]u8 = undefined;
    bit_string_content[0] = 0;
    @memcpy(bit_string_content[1..], &public_key);
    const bit_string = try tlv(gpa, 0x03, &bit_string_content);
    defer gpa.free(bit_string);

    const content = try concat(gpa, &.{ alg, bit_string });
    defer gpa.free(content);
    return tlv(gpa, 0x30, content);
}

fn buildExtensions(gpa: std.mem.Allocator) ![]u8 {
    const san_oid = try tlv(gpa, 0x06, &.{ 0x55, 0x1d, 0x11 });
    defer gpa.free(san_oid);
    const dns_name = try tlv(gpa, 0x82, "localhost");
    defer gpa.free(dns_name);
    const general_names = try tlv(gpa, 0x30, dns_name);
    defer gpa.free(general_names);
    const extn_value = try tlv(gpa, 0x04, general_names);
    defer gpa.free(extn_value);
    const extension_content = try concat(gpa, &.{ san_oid, extn_value });
    defer gpa.free(extension_content);
    const extension = try tlv(gpa, 0x30, extension_content);
    defer gpa.free(extension);
    const extensions_content = try tlv(gpa, 0x30, extension);
    defer gpa.free(extensions_content);
    return tlv(gpa, 0xa3, extensions_content);
}

fn buildSignatureValue(
    gpa: std.mem.Allocator,
    key_pair: Ecdsa.KeyPair,
    tbs: []const u8,
) ![]u8 {
    const signature = try key_pair.sign(tbs, null);
    var der_buffer: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der_signature = signature.toDer(&der_buffer);
    var content: [1 + Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    content[0] = 0;
    @memcpy(content[1..][0..der_signature.len], der_signature);
    return tlv(gpa, 0x03, content[0 .. 1 + der_signature.len]);
}

fn tlv(
    gpa: std.mem.Allocator,
    tag: u8,
    content: []const u8,
) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try list.append(gpa, tag);
    try writeLength(gpa, &list, content.len);
    try list.appendSlice(gpa, content);
    return list.toOwnedSlice(gpa);
}

fn writeLength(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    length: usize,
) !void {
    if (length < 0x80) {
        try list.append(gpa, @intCast(length));
        return;
    }
    if (length <= 0xff) {
        try list.append(gpa, 0x81);
        try list.append(gpa, @intCast(length));
        return;
    }
    if (length <= 0xffff) {
        try list.append(gpa, 0x82);
        try list.append(gpa, @intCast(length >> 8));
        try list.append(gpa, @intCast(length & 0xff));
        return;
    }
    return error.CertificateTooLarge;
}

fn concat(
    gpa: std.mem.Allocator,
    parts: []const []const u8,
) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    for (parts) |part| {
        try list.appendSlice(gpa, part);
    }
    return list.toOwnedSlice(gpa);
}

/// PEM-encoded DER certificate chain (one certificate).
pub fn certificatePem(gpa: std.mem.Allocator, der: []const u8) ![]u8 {
    return pemEncode(gpa, "CERTIFICATE", der);
}

/// PEM-encoded PKCS#8 ECDSA P-256 private key.
pub fn privateKeyPem(
    gpa: std.mem.Allocator,
    key_pair: Ecdsa.KeyPair,
) ![]u8 {
    const der = try buildPkcs8(gpa, key_pair);
    defer gpa.free(der);
    return pemEncode(gpa, "PRIVATE KEY", der);
}

fn buildPkcs8(
    gpa: std.mem.Allocator,
    key_pair: Ecdsa.KeyPair,
) ![]u8 {
    const version = try tlv(gpa, 0x02, &.{0});
    defer gpa.free(version);
    const ec_oid = try tlv(
        gpa,
        0x06,
        &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 },
    );
    defer gpa.free(ec_oid);
    const p256_oid = try tlv(
        gpa,
        0x06,
        &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 },
    );
    defer gpa.free(p256_oid);
    const alg_content = try concat(gpa, &.{ ec_oid, p256_oid });
    defer gpa.free(alg_content);
    const alg = try tlv(gpa, 0x30, alg_content);
    defer gpa.free(alg);

    const ec_version = try tlv(gpa, 0x02, &.{1});
    defer gpa.free(ec_version);
    const scalar = key_pair.secret_key.toBytes();
    const scalar_octet = try tlv(gpa, 0x04, &scalar);
    defer gpa.free(scalar_octet);
    const ec_content = try concat(gpa, &.{ ec_version, scalar_octet });
    defer gpa.free(ec_content);
    const ec = try tlv(gpa, 0x30, ec_content);
    defer gpa.free(ec);
    const private_key_octet = try tlv(gpa, 0x04, ec);
    defer gpa.free(private_key_octet);

    const pki_content = try concat(gpa, &.{ version, alg, private_key_octet });
    defer gpa.free(pki_content);
    return tlv(gpa, 0x30, pki_content);
}

fn pemEncode(
    gpa: std.mem.Allocator,
    label: []const u8,
    der: []const u8,
) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try list.appendSlice(gpa, "-----BEGIN ");
    try list.appendSlice(gpa, label);
    try list.appendSlice(gpa, "-----\n");

    const encoded_len = std.base64.standard.Encoder.calcSize(der.len);
    const encoded = try gpa.alloc(u8, encoded_len);
    defer gpa.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, der);
    var offset: usize = 0;
    while (offset < encoded.len) {
        const count = @min(64, encoded.len - offset);
        try list.appendSlice(gpa, encoded[offset..][0..count]);
        try list.append(gpa, '\n');
        offset += count;
    }

    try list.appendSlice(gpa, "-----END ");
    try list.appendSlice(gpa, label);
    try list.appendSlice(gpa, "-----\n");
    return list.toOwnedSlice(gpa);
}
