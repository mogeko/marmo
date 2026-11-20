//! RFC 5280 server-certificate path checks for the TLS client.
//!
//! Zig 0.17.1 `std.crypto.Certificate.Parsed` verifies signatures but does
//! not expose `basicConstraints` or `keyUsage`. A TLS client cannot safely
//! trust a chain without checking that each issuer is actually a CA, so this
//! module parses the few extensions that matter for the transport path.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;

pub const Error = error{CertificateRejected};

pub const max_chain = 8;
pub const max_pubkey = 1024;

pub const Leaf = struct {
    pubkey: [max_pubkey]u8 = undefined,
    len: usize = 0,
    algo: Certificate.Parsed.PubKeyAlgo = .rsaEncryption,
};

pub const Purpose = enum { server, client };

pub const Parameters = struct {
    host: ?[]const u8,
    verify_chain: bool,
    now_sec: i64,
    bundle: ?*const Certificate.Bundle,
    purpose: Purpose = .server,
};

pub fn verifyServerChain(
    chain: []const []const u8,
    params: Parameters,
    leaf: *Leaf,
) Error!void {
    return verifyChain(chain, params, leaf);
}

/// Client certificates carry no host name; the leaf and every CA still need
/// the clientAuth EKU when the extension is present (RFC 5280 §4.2.1.12).
pub fn verifyClientChain(
    chain: []const []const u8,
    params: Parameters,
    leaf: *Leaf,
) Error!void {
    return verifyChain(chain, params, leaf);
}

fn verifyChain(
    chain: []const []const u8,
    params: Parameters,
    leaf: *Leaf,
) Error!void {
    if (chain.len == 0 or chain.len > max_chain) return error.CertificateRejected;

    const leaf_cert = parse(chain[0]) catch return error.CertificateRejected;
    try rejectWeakSignature(leaf_cert);
    _ = try parseExtensions(chain[0], .leaf, params.purpose);
    try copyLeaf(leaf_cert, leaf);
    if (params.host) |host| {
        leaf_cert.verifyHostName(host) catch return error.CertificateRejected;
    }
    if (!params.verify_chain) return;

    var previous = leaf_cert;
    var trusted = false;
    if (params.bundle) |bundle| {
        trusted = try bundleTrusts(
            bundle,
            leaf_cert,
            params.now_sec,
            params.host,
            params.purpose,
        );
    }
    if (trusted) return;

    var index: usize = 1;
    while (index < chain.len) : (index += 1) {
        try checkIssuer(
            chain[index],
            params.host,
            index - 1,
            params.purpose,
        );
        const subject = parse(chain[index]) catch
            return error.CertificateRejected;
        try rejectWeakSignature(subject);
        previous.verify(subject, params.now_sec) catch
            return error.CertificateRejected;
        if (params.bundle) |bundle| {
            if (try bundleTrusts(
                bundle,
                subject,
                params.now_sec,
                params.host,
                params.purpose,
            )) {
                trusted = true;
                break;
            }
        }
        previous = subject;
    }
    if (!trusted) return error.CertificateRejected;
}

fn parse(bytes: []const u8) !Certificate.Parsed {
    try validateCertificateDer(bytes);
    const certificate: Certificate = .{ .buffer = bytes, .index = 0 };
    return certificate.parse();
}

/// Validates every DER TLV boundary before handing the certificate to
/// `std.crypto.Certificate`, whose parser assumes a well-formed buffer.
pub fn validateCertificateDer(bytes: []const u8) Error!void {
    if (bytes.len < 2) return error.CertificateRejected;
    const top = try readTlv(bytes, 0);
    if (top.tag != 0x30) return error.CertificateRejected;
    if (top.content_end != bytes.len) return error.CertificateRejected;

    var stack: [64]usize = undefined;
    var depth: usize = 0;
    stack[0] = top.content_end;
    depth = 1;
    var cursor = top.content_start;
    while (depth != 0) {
        const end = stack[depth - 1];
        if (cursor == end) {
            depth -= 1;
            continue;
        }
        if (cursor > end) return error.CertificateRejected;
        const tlv = try readTlv(bytes, cursor);
        if (tlv.content_end > end) return error.CertificateRejected;
        if (tlv.tag & 0x20 != 0) {
            if (depth == stack.len) return error.CertificateRejected;
            stack[depth] = tlv.content_end;
            depth += 1;
            cursor = tlv.content_start;
        } else {
            if (tlv.tag == 0x03) {
                // `std.crypto.Certificate` indexes the first BIT STRING byte
                // (the unused-bit count) without a length check.
                if (tlv.content_end == tlv.content_start) {
                    return error.CertificateRejected;
                }
                if (bytes[tlv.content_start] > 7) {
                    return error.CertificateRejected;
                }
            }
            cursor = tlv.content_end;
        }
    }
    try validateCertificateShape(bytes);
}

/// Mirrors the field accesses performed by `Certificate.parse` so every
/// offset it dereferences is backed by a complete DER element. A purely
/// generic TLV walk is not enough: the std parser also indexes empty
/// sequences, zero-length BIT STRINGs, and malformed SAN payloads.
fn validateCertificateShape(bytes: []const u8) Error!void {
    const certificate = try readTlv(bytes, 0);
    if (certificate.tag != 0x30) return error.CertificateRejected;
    if (certificate.content_end != bytes.len) {
        return error.CertificateRejected;
    }
    var cursor = certificate.content_start;
    const tbs = try childTlv(bytes, &cursor, certificate.content_end);
    if (tbs.tag != 0x30) return error.CertificateRejected;
    try validateTbsCertificate(bytes, tbs);

    cursor = tbs.next;
    try validateAlgorithmIdentifier(bytes, &cursor, certificate.content_end);
    const signature = try childTlv(bytes, &cursor, certificate.content_end);
    if (signature.tag != 0x03) return error.CertificateRejected;
    if (cursor != certificate.content_end) {
        return error.CertificateRejected;
    }
}

fn validateTbsCertificate(bytes: []const u8, tbs: Tlv) Error!void {
    var cursor = tbs.content_start;
    var version_value: u8 = 0;
    var has_version = false;
    var field = try childTlv(bytes, &cursor, tbs.content_end);
    if (field.tag == 0xa0) {
        var version_cursor = field.content_start;
        const version = try childTlv(bytes, &version_cursor, field.content_end);
        if (version.tag != 0x02) return error.CertificateRejected;
        if (version_cursor != field.content_end) {
            return error.CertificateRejected;
        }
        const version_bytes = bytes[version.content_start..version.content_end];
        if (!std.mem.eql(u8, version_bytes, &.{0}) and
            !std.mem.eql(u8, version_bytes, &.{1}) and
            !std.mem.eql(u8, version_bytes, &.{2}))
        {
            return error.CertificateRejected;
        }
        version_value = version_bytes[0];
        has_version = true;
        field = try childTlv(bytes, &cursor, tbs.content_end);
    }
    // serialNumber
    if (field.tag != 0x02) return error.CertificateRejected;
    if (field.content_end == field.content_start) {
        return error.CertificateRejected;
    }
    // signature AlgorithmIdentifier, issuer, validity, subject, SPKI
    try validateAlgorithmIdentifier(bytes, &cursor, tbs.content_end);
    try validateName(bytes, &cursor, tbs.content_end);
    try validateValidity(bytes, &cursor, tbs.content_end);
    try validateName(bytes, &cursor, tbs.content_end);
    try validateSubjectPublicKeyInfo(bytes, &cursor, tbs.content_end);

    var has_extensions = false;
    while (cursor < tbs.content_end) {
        const optional = try childTlv(bytes, &cursor, tbs.content_end);
        const low_bits = optional.tag & 0x1f;
        // RFC 5280 §4.1.2.8: conforming CAs MUST NOT generate unique
        // identifiers, and std stops looking for extensions when it meets
        // one. Reject them instead of letting SAN and CN checks diverge.
        if (low_bits == 0x01 or low_bits == 0x02) {
            return error.CertificateRejected;
        }
        // std compares only the low five tag bits, so a non-canonical
        // wrapper for [3] still reaches its extension parser.
        if (low_bits != 0x03) return error.CertificateRejected;
        has_extensions = true;
        try validateExtensions(bytes, optional);
    }
    // Extensions are a v3 feature. A v1/v2 certificate carrying them makes
    // std skip them entirely and fall back to the common name.
    if (has_extensions and (!has_version or version_value != 2)) {
        return error.CertificateRejected;
    }
}

fn validateAlgorithmIdentifier(
    bytes: []const u8,
    cursor: *usize,
    limit: usize,
) Error!void {
    const algorithm = try childTlv(bytes, cursor, limit);
    if (algorithm.tag != 0x30) return error.CertificateRejected;
    var inner = algorithm.content_start;
    const oid = try childTlv(bytes, &inner, algorithm.content_end);
    if (oid.tag != 0x06 or oid.content_end == oid.content_start) {
        return error.CertificateRejected;
    }
    // At most one parameters element, and it must fit the sequence.
    if (inner != algorithm.content_end) {
        _ = try childTlv(bytes, &inner, algorithm.content_end);
        if (inner != algorithm.content_end) {
            return error.CertificateRejected;
        }
    }
}

fn validateName(bytes: []const u8, cursor: *usize, limit: usize) Error!void {
    const name = try childTlv(bytes, cursor, limit);
    if (name.tag != 0x30) return error.CertificateRejected;
    var rdn_cursor = name.content_start;
    while (rdn_cursor < name.content_end) {
        const rdn = try childTlv(bytes, &rdn_cursor, name.content_end);
        if (rdn.tag != 0x31) return error.CertificateRejected;
        var atav_cursor = rdn.content_start;
        while (atav_cursor < rdn.content_end) {
            const atav = try childTlv(bytes, &atav_cursor, rdn.content_end);
            if (atav.tag != 0x30) return error.CertificateRejected;
            var value_cursor = atav.content_start;
            const attribute = try childTlv(bytes, &value_cursor, atav.content_end);
            if (attribute.tag != 0x06 or
                attribute.content_end == attribute.content_start)
            {
                return error.CertificateRejected;
            }
            _ = try childTlv(bytes, &value_cursor, atav.content_end);
            if (value_cursor != atav.content_end) {
                return error.CertificateRejected;
            }
        }
    }
}

fn validateValidity(bytes: []const u8, cursor: *usize, limit: usize) Error!void {
    const validity = try childTlv(bytes, cursor, limit);
    if (validity.tag != 0x30) return error.CertificateRejected;
    var time_cursor = validity.content_start;
    const not_before = try childTlv(bytes, &time_cursor, validity.content_end);
    try validateTime(bytes, not_before);
    const not_after = try childTlv(bytes, &time_cursor, validity.content_end);
    try validateTime(bytes, not_after);
    if (time_cursor != validity.content_end) {
        return error.CertificateRejected;
    }
}

fn validateTime(_: []const u8, time: Tlv) Error!void {
    switch (time.tag) {
        0x17 => if (time.content_end - time.content_start != 13) {
            return error.CertificateRejected;
        },
        0x18 => if (time.content_end - time.content_start < 15) {
            return error.CertificateRejected;
        },
        else => return error.CertificateRejected,
    }
}

fn validateSubjectPublicKeyInfo(
    bytes: []const u8,
    cursor: *usize,
    limit: usize,
) Error!void {
    const info = try childTlv(bytes, cursor, limit);
    if (info.tag != 0x30) return error.CertificateRejected;
    var inner = info.content_start;
    try validateAlgorithmIdentifier(bytes, &inner, info.content_end);
    const bit_string = try childTlv(bytes, &inner, info.content_end);
    if (bit_string.tag != 0x03) return error.CertificateRejected;
    // One unused-bit byte plus at least one key byte.
    if (bit_string.content_end - bit_string.content_start < 2) {
        return error.CertificateRejected;
    }
    if (bytes[bit_string.content_start] != 0) {
        return error.CertificateRejected;
    }
    if (inner != info.content_end) return error.CertificateRejected;

    const key = bytes[bit_string.content_start + 1 .. bit_string.content_end];
    if (isRsaAlgorithmIdentifier(bytes, info.content_start, info.content_end)) {
        try validateRsaPublicKey(key);
    }
}

fn isRsaAlgorithmIdentifier(
    bytes: []const u8,
    start: usize,
    end: usize,
) bool {
    const algorithm = readTlv(bytes, start) catch return false;
    if (algorithm.tag != 0x30 or algorithm.content_end > end) return false;
    const oid = readTlv(bytes, algorithm.content_start) catch return false;
    if (oid.tag != 0x06) return false;
    const value = bytes[oid.content_start..oid.content_end];
    return std.mem.eql(u8, value, &oid_rsa_encryption) or
        std.mem.eql(u8, value, &oid_rsassa_pss);
}

fn validateRsaPublicKey(key: []const u8) Error!void {
    const sequence = readTlv(key, 0) catch return error.CertificateRejected;
    if (sequence.tag != 0x30) return error.CertificateRejected;
    if (sequence.content_end != key.len) return error.CertificateRejected;
    var cursor = sequence.content_start;
    const modulus = try childTlv(key, &cursor, sequence.content_end);
    if (modulus.tag != 0x02 or modulus.content_end == modulus.content_start) {
        return error.CertificateRejected;
    }
    const exponent = try childTlv(key, &cursor, sequence.content_end);
    if (exponent.tag != 0x02 or exponent.content_end == exponent.content_start) {
        return error.CertificateRejected;
    }
    if (cursor != sequence.content_end) return error.CertificateRejected;
}

fn validateExtensions(bytes: []const u8, outer: Tlv) Error!void {
    if (outer.content_end == outer.content_start) {
        return error.CertificateRejected;
    }
    var cursor = outer.content_start;
    const list = try childTlv(bytes, &cursor, outer.content_end);
    if (list.tag != 0x30) return error.CertificateRejected;
    if (cursor != outer.content_end) return error.CertificateRejected;
    var extension_cursor = list.content_start;
    while (extension_cursor < list.content_end) {
        const extension = try childTlv(bytes, &extension_cursor, list.content_end);
        if (extension.tag != 0x30) return error.CertificateRejected;
        var field_cursor = extension.content_start;
        const oid = try childTlv(bytes, &field_cursor, extension.content_end);
        if (oid.tag != 0x06 or oid.content_end == oid.content_start) {
            return error.CertificateRejected;
        }
        var value = try childTlv(bytes, &field_cursor, extension.content_end);
        if (value.tag == 0x01) {
            if (value.content_end != value.content_start + 1) {
                return error.CertificateRejected;
            }
            value = try childTlv(bytes, &field_cursor, extension.content_end);
        }
        if (value.tag != 0x04) return error.CertificateRejected;
        if (field_cursor != extension.content_end) {
            return error.CertificateRejected;
        }
    }
}

/// Bounds every GeneralName before `std.crypto.Certificate.verifyHostName`
/// walks the same structure without length checks.
fn validateGeneralNames(value: []const u8) Error!void {
    const sequence = readTlv(value, 0) catch return error.CertificateRejected;
    if (sequence.tag != 0x30) return error.CertificateRejected;
    if (sequence.content_end != value.len) return error.CertificateRejected;
    var cursor = sequence.content_start;
    while (cursor < sequence.content_end) {
        const name = readTlv(value, cursor) catch return error.CertificateRejected;
        if (name.content_end > sequence.content_end) {
            return error.CertificateRejected;
        }
        cursor = name.next;
    }
}

fn childTlv(bytes: []const u8, cursor: *usize, limit: usize) Error!Tlv {
    if (cursor.* >= limit) return error.CertificateRejected;
    const tlv = try readTlv(bytes, cursor.*);
    if (tlv.content_end > limit) return error.CertificateRejected;
    cursor.* = tlv.next;
    return tlv;
}

const Tlv = struct {
    tag: u8,
    content_start: usize,
    content_end: usize,
    next: usize,
};

fn readTlv(bytes: []const u8, index: usize) Error!Tlv {
    if (index + 2 > bytes.len) return error.CertificateRejected;
    const tag = bytes[index];
    const size_byte = bytes[index + 1];
    var cursor = index + 2;
    var length: usize = 0;
    if (size_byte & 0x80 == 0) {
        length = size_byte;
    } else {
        const count = size_byte & 0x7f;
        if (count == 0 or count > 4) return error.CertificateRejected;
        if (cursor + count > bytes.len) return error.CertificateRejected;
        for (bytes[cursor..][0..count]) |byte| {
            length = std.math.mul(usize, length, 256) catch
                return error.CertificateRejected;
            length = std.math.add(usize, length, byte) catch
                return error.CertificateRejected;
        }
        cursor += count;
    }
    const end = std.math.add(usize, cursor, length) catch
        return error.CertificateRejected;
    if (end > bytes.len) return error.CertificateRejected;
    return .{
        .tag = tag,
        .content_start = cursor,
        .content_end = end,
        .next = end,
    };
}

fn copyLeaf(subject: Certificate.Parsed, leaf: *Leaf) Error!void {
    const key = subject.pubKey();
    if (key.len == 0 or key.len > leaf.pubkey.len) {
        return error.CertificateRejected;
    }
    @memcpy(leaf.pubkey[0..key.len], key);
    leaf.len = key.len;
    leaf.algo = subject.pub_key_algo;
}

fn bundleTrusts(
    bundle: *const Certificate.Bundle,
    subject: Certificate.Parsed,
    now_sec: i64,
    host: ?[]const u8,
    purpose: Purpose,
) Error!bool {
    bundle.verify(subject, now_sec) catch |err| switch (err) {
        error.CertificateIssuerNotFound => return false,
        else => return error.CertificateRejected,
    };
    // Apply trust-anchor constraints found in the bundle. A trust anchor is
    // still allowed to omit basicConstraints for legacy compatibility.
    if (bundle.find(subject.issuer())) |index| {
        const anchor: Certificate = .{
            .buffer = bundle.bytes.items,
            .index = index,
        };
        const parsed = anchor.parse() catch return error.CertificateRejected;
        // Bundle.verify checks the subject's validity but not the trust
        // anchor's; an expired or not-yet-valid root must not anchor a chain.
        const not_before = std.math.cast(i64, parsed.validity.not_before) orelse
            return error.CertificateRejected;
        const not_after = std.math.cast(i64, parsed.validity.not_after) orelse
            return error.CertificateRejected;
        if (now_sec < not_before or now_sec > not_after) {
            return error.CertificateRejected;
        }
        const extensions = parseExtensions(
            bundle.bytes.items[index..],
            .issuer,
            purpose,
        ) catch return error.CertificateRejected;
        if (extensions.name_constraints) |constraints| {
            if (host) |name| try checkNameConstraints(constraints, name);
        }
        if (extensions.eku_allows_purpose) |allowed| {
            if (!allowed) return error.CertificateRejected;
        }
    }
    return true;
}

fn rejectWeakSignature(subject: Certificate.Parsed) Error!void {
    switch (subject.signature_algorithm) {
        .md2WithRSAEncryption,
        .md5WithRSAEncryption,
        .sha1WithRSAEncryption,
        .sha224WithRSAEncryption,
        .ecdsa_with_SHA224,
        => return error.CertificateRejected,
        else => {},
    }
}

fn checkIssuer(
    der_bytes: []const u8,
    host: ?[]const u8,
    ca_below: usize,
    purpose: Purpose,
) Error!void {
    const extensions = parseExtensions(der_bytes, .issuer, purpose) catch
        return error.CertificateRejected;
    if (!extensions.ca) return error.CertificateRejected;
    if (extensions.key_cert_sign) |allowed| {
        if (!allowed) return error.CertificateRejected;
    }
    if (extensions.path_len) |limit| {
        if (limit < ca_below) return error.CertificateRejected;
    }
    if (extensions.eku_allows_purpose) |allowed| {
        if (!allowed) return error.CertificateRejected;
    }
    if (extensions.name_constraints) |constraints| {
        if (host) |name| try checkNameConstraints(constraints, name);
    }
}

fn checkNameConstraints(value: []const u8, host: []const u8) Error!void {
    const host_ip = std.Io.net.IpAddress.parse(host, 0) catch null;
    const host_dns: ?[]const u8 = if (host_ip == null) host else null;

    const sequence = elementAt(value, 0) orelse
        return error.CertificateRejected;
    if (sequence.identifier.tag != .sequence) {
        return error.CertificateRejected;
    }
    var permitted_present = false;
    var permitted_match = false;
    var cursor = sequence.slice.start;
    while (cursor < sequence.slice.end) {
        const subtree = elementAt(value, cursor) orelse
            return error.CertificateRejected;
        cursor = subtree.slice.end;
        const kind = identifier(subtree);
        if (kind != 0xa0 and kind != 0xa1) continue;
        if (kind == 0xa0) permitted_present = true;

        var entry_cursor = subtree.slice.start;
        while (entry_cursor < subtree.slice.end) {
            const entry = elementAt(value, entry_cursor) orelse
                return error.CertificateRejected;
            entry_cursor = entry.slice.end;
            if (entry.identifier.tag != .sequence) continue;
            const base = elementAt(value, entry.slice.start) orelse
                return error.CertificateRejected;
            const name = value[base.slice.start..base.slice.end];
            const matches = switch (identifier(base)) {
                0x82 => if (host_dns) |dns| dnsMatches(dns, name) else false,
                0x87 => if (host_ip) |ip| ipMatches(ip, name) else false,
                else => false,
            };
            if (kind == 0xa1) {
                if (matches) return error.CertificateRejected;
            } else if (matches) {
                permitted_match = true;
            }
        }
    }
    if (permitted_present and !permitted_match) {
        return error.CertificateRejected;
    }
}

fn ipMatches(ip: std.Io.net.IpAddress, constraint: []const u8) bool {
    return switch (ip) {
        .ip4 => |address| blk: {
            if (constraint.len != 8) break :blk false;
            for (0..4) |index| {
                const mask = constraint[4 + index];
                if ((address.bytes[index] & mask) !=
                    (constraint[index] & mask))
                {
                    break :blk false;
                }
            }
            break :blk true;
        },
        .ip6 => |address| blk: {
            if (constraint.len != 32) break :blk false;
            for (0..16) |index| {
                const mask = constraint[16 + index];
                if ((address.bytes[index] & mask) !=
                    (constraint[index] & mask))
                {
                    break :blk false;
                }
            }
            break :blk true;
        },
    };
}

fn dnsMatches(host: []const u8, constraint: []const u8) bool {
    if (constraint.len == 0) return false;
    if (constraint[0] == '.') {
        return host.len > constraint.len and
            std.ascii.endsWithIgnoreCase(host, constraint);
    }
    if (std.ascii.eqlIgnoreCase(host, constraint)) return true;
    return host.len > constraint.len and
        host[host.len - constraint.len - 1] == '.' and
        std.ascii.endsWithIgnoreCase(host, constraint);
}

const ExtensionKind = enum { leaf, issuer };

const Extensions = struct {
    ca: bool = false,
    key_cert_sign: ?bool = null,
    path_len: ?u16 = null,
    name_constraints: ?[]const u8 = null,
    eku_allows_purpose: ?bool = null,
};

fn parseExtensions(
    bytes: []const u8,
    kind: ExtensionKind,
    purpose: Purpose,
) Error!Extensions {
    const certificate = elementAt(bytes, 0) orelse
        return error.CertificateRejected;
    if (certificate.identifier.tag != .sequence) {
        return error.CertificateRejected;
    }
    const tbs = elementAt(bytes, certificate.slice.start) orelse
        return error.CertificateRejected;
    if (tbs.identifier.tag != .sequence) return error.CertificateRejected;

    var cursor = tbs.slice.start;
    const version = elementAt(bytes, cursor) orelse
        return error.CertificateRejected;
    var version_value: u8 = 0;
    if (identifier(version) == 0xa0) {
        const inner = elementAt(bytes, version.slice.start) orelse
            return error.CertificateRejected;
        if (inner.identifier.tag != .integer or
            inner.slice.end != version.slice.end or
            inner.slice.end - inner.slice.start != 1)
        {
            return error.CertificateRejected;
        }
        version_value = bytes[inner.slice.start];
        if (version_value > 2) return error.CertificateRejected;
        cursor = version.slice.end;
    }

    const skippable = [_]der.Tag{
        .integer,
        .sequence,
        .sequence,
        .sequence,
        .sequence,
        .sequence,
    };
    for (skippable) |tag| {
        const field = elementAt(bytes, cursor) orelse
            return error.CertificateRejected;
        if (field.identifier.tag != tag) return error.CertificateRejected;
        cursor = field.slice.end;
    }

    var extensions: Extensions = .{};
    var found_extensions = false;
    while (cursor < tbs.slice.end) {
        const field = elementAt(bytes, cursor) orelse
            return error.CertificateRejected;
        cursor = field.slice.end;
        // std compares only the low five tag bits when it recognizes the
        // extensions wrapper, so non-canonical [3] encodings (0x43/0x83/0xc3)
        // must still be parsed here or their SAN payload would escape
        // validation while std happily reads it.
        const low_bits = identifier(field) & 0x1f;
        if (low_bits == 0x01 or low_bits == 0x02) {
            return error.CertificateRejected;
        }
        if (low_bits != 0x03) continue;
        if (found_extensions) return error.CertificateRejected;
        if (version_value != 2) return error.CertificateRejected;
        found_extensions = true;
        try parseExtensionList(bytes, field, kind, purpose, &extensions);
    }
    return extensions;
}

fn parseExtensionList(
    bytes: []const u8,
    outer: der.Element,
    kind: ExtensionKind,
    purpose: Purpose,
    extensions: *Extensions,
) Error!void {
    const list = elementAt(bytes, outer.slice.start) orelse
        return error.CertificateRejected;
    if (list.identifier.tag != .sequence) return error.CertificateRejected;
    var cursor = list.slice.start;
    while (cursor < list.slice.end) {
        const extension = elementAt(bytes, cursor) orelse
            return error.CertificateRejected;
        cursor = extension.slice.end;
        if (extension.identifier.tag != .sequence) {
            return error.CertificateRejected;
        }
        const oid_elem = elementAt(bytes, extension.slice.start) orelse
            return error.CertificateRejected;
        if (oid_elem.identifier.tag != .object_identifier) {
            return error.CertificateRejected;
        }
        const oid = bytes[oid_elem.slice.start..oid_elem.slice.end];
        var value_elem = elementAt(bytes, oid_elem.slice.end) orelse
            return error.CertificateRejected;
        var critical = false;
        if (value_elem.identifier.tag == .boolean) {
            if (value_elem.slice.end != value_elem.slice.start + 1) {
                return error.CertificateRejected;
            }
            critical = bytes[value_elem.slice.start] != 0;
            value_elem = elementAt(bytes, value_elem.slice.end) orelse
                return error.CertificateRejected;
        }
        if (value_elem.identifier.tag != .octetstring) {
            return error.CertificateRejected;
        }
        const value = bytes[value_elem.slice.start..value_elem.slice.end];
        if (std.mem.eql(u8, oid, &oid_basic_constraints)) {
            const basic = try parseBasicConstraints(value);
            extensions.ca = basic.ca;
            extensions.path_len = basic.path_len;
        } else if (std.mem.eql(u8, oid, &oid_key_usage)) {
            extensions.key_cert_sign = try parseKeyUsage(value);
        } else if (std.mem.eql(u8, oid, &oid_ext_key_usage)) {
            const allowed = try hasEku(value, purpose);
            extensions.eku_allows_purpose = allowed;
            if (kind == .leaf and !allowed) {
                return error.CertificateRejected;
            }
        } else if (std.mem.eql(u8, oid, &oid_subject_alt_name_legacy)) {
            // Zig std also treats 2.5.29.7 as a subjectAltName alias, but
            // OpenSSL ignores it. Reject it so its payload cannot bypass
            // `validateGeneralNames` and reach std's unbounded parser.
            return error.CertificateRejected;
        } else if (std.mem.eql(u8, oid, &oid_subject_alt_name)) {
            // `Certificate.Parsed.verifyHostName` reparses this value with an
            // unbounded DER parser, so bound it here first.
            try validateGeneralNames(value);
        } else if (std.mem.eql(u8, oid, &oid_name_constraints)) {
            extensions.name_constraints = value;
        } else if (critical) {
            return error.CertificateRejected;
        }
    }
}

const BasicConstraints = struct {
    ca: bool = false,
    path_len: ?u16 = null,
};

fn parseBasicConstraints(value: []const u8) Error!BasicConstraints {
    const sequence = elementAt(value, 0) orelse
        return error.CertificateRejected;
    if (sequence.identifier.tag != .sequence) {
        return error.CertificateRejected;
    }
    var result: BasicConstraints = .{};
    var cursor = sequence.slice.start;
    if (cursor >= sequence.slice.end) return result;
    const boolean = elementAt(value, cursor) orelse
        return error.CertificateRejected;
    if (boolean.identifier.tag == .boolean) {
        if (boolean.slice.end != boolean.slice.start + 1) {
            return error.CertificateRejected;
        }
        result.ca = value[boolean.slice.start] != 0;
        cursor = boolean.slice.end;
    }
    if (cursor < sequence.slice.end) {
        const integer = elementAt(value, cursor) orelse
            return error.CertificateRejected;
        if (integer.identifier.tag != .integer) {
            return error.CertificateRejected;
        }
        const bytes = value[integer.slice.start..integer.slice.end];
        if (bytes.len == 0 or bytes.len > 2) {
            return error.CertificateRejected;
        }
        if (bytes[0] & 0x80 != 0) return error.CertificateRejected;
        if (bytes.len == 2 and bytes[0] == 0 and bytes[1] < 0x80) {
            return error.CertificateRejected; // non-minimal DER
        }
        var path_len: u16 = 0;
        for (bytes) |byte| {
            path_len = std.math.mul(u16, path_len, 256) catch
                return error.CertificateRejected;
            path_len = std.math.add(u16, path_len, byte) catch
                return error.CertificateRejected;
        }
        result.path_len = path_len;
    }
    return result;
}

fn parseKeyUsage(value: []const u8) Error!bool {
    const bit_string = elementAt(value, 0) orelse
        return error.CertificateRejected;
    if (bit_string.identifier.tag != .bitstring) {
        return error.CertificateRejected;
    }
    const bytes = value[bit_string.slice.start..bit_string.slice.end];
    if (bytes.len < 1 or bytes.len > 3) return error.CertificateRejected;
    if (bytes[0] > 7) return error.CertificateRejected;
    if (bytes.len < 2) return false;
    return bytes[1] & 0x04 != 0;
}

fn hasEku(value: []const u8, purpose: Purpose) Error!bool {
    const required = switch (purpose) {
        .server => &oid_server_auth,
        .client => &oid_client_auth,
    };
    const sequence = elementAt(value, 0) orelse
        return error.CertificateRejected;
    if (sequence.identifier.tag != .sequence) {
        return error.CertificateRejected;
    }
    var cursor = sequence.slice.start;
    while (cursor < sequence.slice.end) {
        const oid_elem = elementAt(value, cursor) orelse
            return error.CertificateRejected;
        cursor = oid_elem.slice.end;
        if (oid_elem.identifier.tag != .object_identifier) {
            return error.CertificateRejected;
        }
        const oid = value[oid_elem.slice.start..oid_elem.slice.end];
        if (std.mem.eql(u8, oid, required) or
            std.mem.eql(u8, oid, &oid_any_ext_key_usage))
        {
            return true;
        }
    }
    return false;
}

fn elementAt(bytes: []const u8, index: usize) ?der.Element {
    if (index + 2 > bytes.len) return null;
    const size_byte = bytes[index + 1];
    var header_len: usize = 2;
    if (size_byte & 0x80 != 0) {
        const length_bytes = size_byte & 0x7f;
        if (length_bytes == 0 or length_bytes > 4) return null;
        header_len += length_bytes;
        if (index + header_len > bytes.len) return null;
    }
    const element = der.Element.parse(bytes, @intCast(index)) catch return null;
    if (element.slice.end > bytes.len) return null;
    if (element.slice.start > element.slice.end) return null;
    return element;
}

fn identifier(element: der.Element) u8 {
    return @bitCast(element.identifier);
}

const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f };
const oid_ext_key_usage = [_]u8{ 0x55, 0x1d, 0x25 };
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 };
const oid_subject_alt_name_legacy = [_]u8{ 0x55, 0x1d, 0x07 };
const oid_name_constraints = [_]u8{ 0x55, 0x1d, 0x1e };
const oid_rsa_encryption = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
};
const oid_rsassa_pss = [_]u8{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
};
const oid_server_auth = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
};
const oid_client_auth = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
};
const oid_any_ext_key_usage = [_]u8{ 0x55, 0x1d, 0x25, 0x00 };

test "basicConstraints and keyUsage are parsed" {
    const ca = [_]u8{
        0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00,
    };
    try std.testing.expect((try parseBasicConstraints(&ca)).ca);

    const not_ca = [_]u8{ 0x30, 0x00 };
    try std.testing.expect(!(try parseBasicConstraints(&not_ca)).ca);

    const usage = [_]u8{ 0x03, 0x02, 0x02, 0x04 };
    try std.testing.expect(try parseKeyUsage(&usage));
}

test "name constraints permit and exclude DNS subtrees" {
    const permitted = [_]u8{
        0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 0x82, 0x0b,
        'e',  'x',  'a',  'm',  'p',  'l',  'e',  '.',
        'c',  'o',  'm',
    };
    try checkNameConstraints(&permitted, "proxy.example.com");
    try checkNameConstraints(&permitted, "example.com");
    try std.testing.expectError(
        error.CertificateRejected,
        checkNameConstraints(&permitted, "other.test"),
    );

    const excluded = [_]u8{
        0x30, 0x11, 0xa1, 0x0f, 0x30, 0x0d, 0x82, 0x0b,
        'e',  'x',  'a',  'm',  'p',  'l',  'e',  '.',
        'c',  'o',  'm',
    };
    try checkNameConstraints(&excluded, "other.test");
    try std.testing.expectError(
        error.CertificateRejected,
        checkNameConstraints(&excluded, "proxy.example.com"),
    );
}

test "malformed DER is rejected before std parse" {
    const cases = [_][]const u8{
        &.{},
        &.{0x30},
        &.{ 0x30, 0x01, 0x00 },
        &.{ 0x30, 0x82, 0xff, 0xff },
        &.{ 0x31, 0x00 },
    };
    for (cases) |bytes| {
        try std.testing.expectError(
            error.CertificateRejected,
            validateCertificateDer(bytes),
        );
    }
}

test "negative and non-minimal pathLen are rejected" {
    const negative = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0xff };
    try std.testing.expectError(
        error.CertificateRejected,
        parseBasicConstraints(&negative),
    );
    const non_minimal = [_]u8{ 0x30, 0x04, 0x02, 0x02, 0x00, 0x01 };
    try std.testing.expectError(
        error.CertificateRejected,
        parseBasicConstraints(&non_minimal),
    );
}

test "IP name constraints match address and mask" {
    const permitted = [_]u8{
        0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a, 0x87, 0x08,
        10,   0,    0,    0,    255,  0,    0,    0,
    };
    try checkNameConstraints(&permitted, "10.1.2.3");
    try std.testing.expectError(
        error.CertificateRejected,
        checkNameConstraints(&permitted, "11.1.2.3"),
    );
}
