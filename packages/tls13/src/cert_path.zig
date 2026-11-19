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

pub const Parameters = struct {
    host: ?[]const u8,
    verify_chain: bool,
    now_sec: i64,
    bundle: ?*const Certificate.Bundle,
};

pub fn verifyServerChain(
    chain: []const []const u8,
    params: Parameters,
    leaf: *Leaf,
) Error!void {
    if (chain.len == 0 or chain.len > max_chain) return error.CertificateRejected;

    const leaf_cert = parse(chain[0]) catch return error.CertificateRejected;
    try rejectWeakSignature(leaf_cert);
    _ = try parseExtensions(chain[0], .leaf);
    try copyLeaf(leaf_cert, leaf);
    if (params.host) |host| {
        leaf_cert.verifyHostName(host) catch return error.CertificateRejected;
    }
    if (!params.verify_chain) return;

    var previous = leaf_cert;
    var trusted = false;
    if (params.bundle) |bundle| {
        trusted = try bundleTrusts(bundle, leaf_cert, params.now_sec);
    }
    if (trusted) return;

    var index: usize = 1;
    while (index < chain.len) : (index += 1) {
        try checkIssuer(chain[index]);
        const subject = parse(chain[index]) catch
            return error.CertificateRejected;
        try rejectWeakSignature(subject);
        previous.verify(subject, params.now_sec) catch
            return error.CertificateRejected;
        if (params.bundle) |bundle| {
            if (try bundleTrusts(bundle, subject, params.now_sec)) {
                trusted = true;
                break;
            }
        }
        previous = subject;
    }
    if (!trusted) return error.CertificateRejected;
}

fn parse(bytes: []const u8) !Certificate.Parsed {
    const certificate: Certificate = .{ .buffer = bytes, .index = 0 };
    return certificate.parse();
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
) Error!bool {
    bundle.verify(subject, now_sec) catch |err| switch (err) {
        error.CertificateIssuerNotFound => return false,
        else => return error.CertificateRejected,
    };
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

fn checkIssuer(der_bytes: []const u8) Error!void {
    const extensions = parseExtensions(der_bytes, .issuer) catch
        return error.CertificateRejected;
    if (!extensions.ca) return error.CertificateRejected;
    if (extensions.key_cert_sign) |allowed| {
        if (!allowed) return error.CertificateRejected;
    }
}

const ExtensionKind = enum { leaf, issuer };

const Extensions = struct {
    ca: bool = false,
    key_cert_sign: ?bool = null,
};

fn parseExtensions(
    bytes: []const u8,
    kind: ExtensionKind,
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
    if (identifier(version) == 0xa0) cursor = version.slice.end;

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
        if (identifier(field) != 0xa3) continue;
        if (found_extensions) return error.CertificateRejected;
        found_extensions = true;
        try parseExtensionList(bytes, field, kind, &extensions);
    }
    return extensions;
}

fn parseExtensionList(
    bytes: []const u8,
    outer: der.Element,
    kind: ExtensionKind,
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
            extensions.ca = try parseBasicConstraints(value);
        } else if (std.mem.eql(u8, oid, &oid_key_usage)) {
            extensions.key_cert_sign = try parseKeyUsage(value);
        } else if (std.mem.eql(u8, oid, &oid_ext_key_usage)) {
            if (kind == .leaf and !try hasServerAuth(value)) {
                return error.CertificateRejected;
            }
        } else if (std.mem.eql(u8, oid, &oid_subject_alt_name)) {
            // Host-name validation is already handled by Certificate.Parsed.
        } else if (critical) {
            return error.CertificateRejected;
        }
    }
}

fn parseBasicConstraints(value: []const u8) Error!bool {
    const sequence = elementAt(value, 0) orelse
        return error.CertificateRejected;
    if (sequence.identifier.tag != .sequence) {
        return error.CertificateRejected;
    }
    const cursor = sequence.slice.start;
    if (cursor >= sequence.slice.end) return false;
    const boolean = elementAt(value, cursor) orelse
        return error.CertificateRejected;
    if (boolean.identifier.tag != .boolean) return false;
    if (boolean.slice.end != boolean.slice.start + 1) {
        return error.CertificateRejected;
    }
    return value[boolean.slice.start] != 0;
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

fn hasServerAuth(value: []const u8) Error!bool {
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
        if (std.mem.eql(u8, oid, &oid_server_auth)) return true;
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
const oid_server_auth = [_]u8{
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
};

test "basicConstraints and keyUsage are parsed" {
    const ca = [_]u8{
        0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00,
    };
    try std.testing.expect(try parseBasicConstraints(&ca));

    const not_ca = [_]u8{ 0x30, 0x00 };
    try std.testing.expect(!try parseBasicConstraints(&not_ca));

    const usage = [_]u8{ 0x03, 0x02, 0x02, 0x04 };
    try std.testing.expect(try parseKeyUsage(&usage));
}
