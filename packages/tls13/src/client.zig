//! TLS 1.3 client session over a `std.Io.Reader`/`Writer` pair.
//!
//! Scope matches the in-tree server: X25519 and secp256r1 ECDHE, AES-128-GCM,
//! AES-256-GCM, and ChaCha20-Poly1305, server certificates (ECDSA, Ed25519,
//! RSA) with optional chain/host verification, optional client
//! authentication, ALPN, and key updates. There is no PSK, ticket, or 0-RTT.

const std = @import("std");
const Ca = @import("ca.zig").Ca;
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const cert_path = @import("cert_path.zig");
const credentials = @import("credentials.zig");
const signature = @import("signature.zig");
const Certificate = std.crypto.Certificate;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P256 = std.crypto.ecc.P256;

pub const min_buffer_len = std.crypto.tls.Client.min_buffer_len;

pub const Options = struct {
    /// Server name for SNI and certificate host verification. Required when
    /// `verify` is true.
    server_name: ?[]const u8,
    /// Verify the certificate chain against `ca`.
    verify: bool = true,
    /// System CA bundle. Required when `verify` is true.
    ca: ?*Ca = null,
    /// ALPN protocols in preference order. Empty disables the extension.
    alpn_protocols: []const []const u8 = &.{},
    /// If set, the handshake fails unless the server selects this protocol.
    required_alpn: ?[]const u8 = null,
    /// Offered cipher suites in preference order. Must be non-empty.
    cipher_suites: []const record.CipherSuite = &record.CipherSuite.list,
    /// Client certificate chain, leaf first. Empty disables client auth.
    client_certificate_chain: []const []const u8 = &.{},
    /// Client ECDSA P-256 key matching the first certificate.
    client_private_key: ?Ecdsa.KeyPair = null,
    /// Plaintext reader buffer. Must be non-empty.
    read_buffer: []u8,
    /// Plaintext writer buffer. Must be non-empty.
    write_buffer: []u8,
    /// Treat a missing `close_notify` as EOF. Byte-stream protocols without
    /// their own truncation check normally want this.
    allow_truncation_attacks: bool = true,
};

pub const InitError = error{
    Canceled,
    Closed,
    HandshakeFailed,
    Truncated,
};

const max_pubkey = signature.max_pubkey;
const max_alpn_list = 1024;

pub const Client = struct {
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    transcript: handshake.Transcript,
    key_schedule: handshake.KeySchedule,
    client_app_secret: handshake.Secret = .{},
    server_app_secret: handshake.Secret = .{},
    read_keys: record.Keys = .{},
    write_keys: record.Keys = .{},
    reader_interface: std.Io.Reader,
    writer_interface: std.Io.Writer,
    pubkey: [max_pubkey]u8 = undefined,
    pubkey_len: usize = 0,
    pubkey_algo: Certificate.Parsed.PubKeyAlgo = .rsaEncryption,
    alpn_buf: [handshake.max_alpn_protocol]u8 = undefined,
    alpn_len: u8 = 0,
    pending: [record.max_ciphertext]u8 = undefined,
    pending_len: usize = 0,
    pending_offset: usize = 0,
    record_read: [record.max_record]u8 = undefined,
    record_write: [record.max_record]u8 = undefined,
    handshake_buffer: [handshake.max_handshake]u8 = undefined,
    handshake_len: usize = 0,
    handshake_offset: usize = 0,
    client_hello: [handshake.max_handshake]u8 = undefined,
    client_hello_len: usize = 0,
    post_handshake: [handshake.max_handshake]u8 = undefined,
    post_handshake_len: usize = 0,
    client_certificate_chain: []const []const u8 = &.{},
    client_private_key: ?Ecdsa.KeyPair = null,
    certificate_requested: bool = false,
    pending_key_update_response: std.atomic.Value(bool) = .init(false),
    allow_truncation_attacks: bool = false,
    closed: bool = false,
    eof_received: bool = false,
    read_error: ?InitError = null,
    write_error: ?InitError = null,

    pub fn init(
        io: std.Io,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        options: Options,
    ) InitError!Client {
        try validateOptions(options);
        if (options.verify) {
            options.ca.?.ensure(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.LoadFailed => return error.HandshakeFailed,
            };
        }
        if (input.buffer.len < min_buffer_len or
            output.buffer.len < min_buffer_len)
        {
            return error.HandshakeFailed;
        }

        var self: Client = .{
            .io = io,
            .input = input,
            .output = output,
            .transcript = undefined,
            .key_schedule = undefined,
            .reader_interface = .{
                .vtable = &.{ .stream = readerStream },
                .buffer = options.read_buffer,
                .seek = 0,
                .end = 0,
            },
            .writer_interface = .{
                .vtable = &.{ .drain = writerDrain },
                .buffer = options.write_buffer,
            },
            .client_certificate_chain = options.client_certificate_chain,
            .client_private_key = options.client_private_key,
            .allow_truncation_attacks = options.allow_truncation_attacks,
        };
        try self.runHandshake(options);
        return self;
    }

    pub fn reader(self: *Client) *std.Io.Reader {
        return &self.reader_interface;
    }

    pub fn writer(self: *Client) *std.Io.Writer {
        return &self.writer_interface;
    }

    pub fn negotiatedProtocol(self: *const Client) ?[]const u8 {
        if (self.alpn_len == 0) return null;
        return self.alpn_buf[0..self.alpn_len];
    }

    pub fn negotiatedCipherSuite(self: *const Client) record.CipherSuite {
        return self.write_keys.suite;
    }

    pub fn readError(self: *const Client) ?InitError {
        return self.read_error;
    }

    pub fn writeError(self: *const Client) ?InitError {
        return self.write_error;
    }

    /// Sends a KeyUpdate and switches the sending keys (RFC 8446 §4.6.3).
    /// The caller must serialize writes with any other writer task.
    pub fn keyUpdate(self: *Client, request_update: bool) InitError!void {
        try self.sendKeyUpdate(request_update);
        self.output.flush() catch return error.HandshakeFailed;
    }

    pub fn end(self: *Client) std.Io.Writer.Error!void {
        if (self.closed) return;
        self.writer_interface.flush() catch return error.WriteFailed;

        const alert = [2]u8{ 1, 0 };
        const sealed = record.seal(
            &self.write_keys,
            record.content_type_alert,
            &alert,
            &self.record_write,
        ) catch return error.WriteFailed;
        self.output.writeAll(sealed) catch return error.WriteFailed;
        self.output.flush() catch return error.WriteFailed;
        self.closed = true;
    }

    pub fn eof(self: Client) bool {
        return self.eof_received;
    }

    /// Zeroizes the session state; the caller still owns the buffers.
    pub fn deinit(self: *Client) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    fn runHandshake(self: *Client, options: Options) InitError!void {
        errdefer std.crypto.secureZero(u8, std.mem.asBytes(self));
        try self.beginHandshake(options);
        try self.finishHandshake(options);
    }

    fn beginHandshake(self: *Client, options: Options) InitError!void {
        var session_id: [32]u8 = undefined;
        var random: [32]u8 = undefined;
        std.Io.randomSecure(self.io, &random) catch return self.randomError();
        std.Io.randomSecure(self.io, &session_id) catch return self.randomError();

        var x25519 = std.crypto.dh.X25519.KeyPair.generate(self.io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&x25519.secret_key));
        var p256_scalar = P256.scalar.random(self.io, .big);
        defer std.crypto.secureZero(u8, &p256_scalar);
        var p256_public = P256.basePoint.mul(p256_scalar, .big) catch
            return error.HandshakeFailed;

        const client_hello = try self.buildClientHello(
            options,
            random,
            session_id,
            x25519.public_key,
            p256_public.toUncompressedSec1(),
        );
        record.writePlain(
            self.output,
            record.content_type_handshake,
            client_hello,
        ) catch return error.HandshakeFailed;
        self.output.flush() catch return error.HandshakeFailed;

        const server_hello_message = try self.readHandshakeMessage(null);
        const server_hello = handshake.parseServerHello(server_hello_message) catch
            return error.HandshakeFailed;
        if (server_hello.hello_retry_request) {
            // This client always sends an X25519 and a P-256 share, so a
            // conforming server never needs HelloRetryRequest. A retry for a
            // group we already offered is a protocol violation.
            return error.HandshakeFailed;
        }
        if (server_hello.session_id_len != session_id.len or
            !std.mem.eql(u8, &server_hello.session_id, &session_id))
        {
            return error.HandshakeFailed;
        }
        const suite = server_hello.suite orelse return error.HandshakeFailed;
        if (!containsSuite(options.cipher_suites, suite)) {
            return error.HandshakeFailed;
        }

        self.transcript = handshake.Transcript.init(suite);
        self.transcript.update(self.client_hello[0..self.client_hello_len]);
        self.transcript.update(server_hello_message);

        var shared_secret: [32]u8 = switch (server_hello.group.?) {
            handshake.group_x25519 => std.crypto.dh.X25519.scalarmult(
                x25519.secret_key,
                server_hello.key_share[0..32].*,
            ) catch return error.HandshakeFailed,
            handshake.group_secp256r1 => p256SharedSecret(
                p256_scalar,
                server_hello.key_share[0..server_hello.key_share_len],
            ) catch return error.HandshakeFailed,
            else => return error.HandshakeFailed,
        };
        defer std.crypto.secureZero(u8, &shared_secret);
        const hello_hash = handshake.transcriptHash(&self.transcript);
        self.key_schedule = handshake.KeySchedule.derive(
            suite,
            &shared_secret,
            hello_hash,
        ) catch return error.HandshakeFailed;
    }

    fn finishHandshake(self: *Client, options: Options) InitError!void {
        try self.readServerFlight(options, &self.key_schedule.server_hs_keys);

        const handshake_hash = handshake.transcriptHash(&self.transcript);
        self.client_app_secret = self.key_schedule.clientAppSecret(
            handshake_hash,
        ) catch return error.HandshakeFailed;
        self.server_app_secret = self.key_schedule.serverAppSecret(
            handshake_hash,
        ) catch return error.HandshakeFailed;

        try self.sendClientAuthentication(&self.key_schedule.client_hs_keys);
        try self.sendClientFinished(
            &self.key_schedule.client_hs_keys,
            self.key_schedule.client_finished_key,
        );
        const suite = self.key_schedule.suite;
        self.read_keys = handshake.keysFromSecret(
            suite,
            self.server_app_secret,
        ) catch return error.HandshakeFailed;
        self.write_keys = handshake.keysFromSecret(
            suite,
            self.client_app_secret,
        ) catch return error.HandshakeFailed;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_schedule));
        if (options.required_alpn) |required| {
            const selected = self.negotiatedProtocol() orelse
                return error.HandshakeFailed;
            if (!std.mem.eql(u8, selected, required)) {
                return error.HandshakeFailed;
            }
        }
    }

    fn buildClientHello(
        self: *Client,
        options: Options,
        random: [32]u8,
        session_id: [32]u8,
        x25519_public: [32]u8,
        p256_public: [65]u8,
    ) InitError![]const u8 {
        var extension_buffer: [max_alpn_list + 512]u8 = undefined;
        var extensions = handshake.Encoder.init(&extension_buffer);
        try writeExtensions(
            &extensions,
            options,
            x25519_public,
            p256_public,
        );

        var body = handshake.Encoder.init(self.client_hello[4..]);
        try body.writeU16(0x0303);
        try body.append(&random);
        try body.writeU8(32);
        try body.append(&session_id);
        try body.writeU16(@intCast(options.cipher_suites.len * 2));
        for (options.cipher_suites) |suite| {
            try body.writeU16(suite.wireId());
        }
        try body.writeU8(1);
        try body.writeU8(0);
        try body.writeU16(@intCast(extensions.len));
        try body.append(extensions.bytes());
        self.client_hello[0] = handshake.handshake_client_hello;
        std.mem.writeInt(u24, self.client_hello[1..4], @intCast(body.len), .big);
        self.client_hello_len = 4 + body.len;
        return self.client_hello[0..self.client_hello_len];
    }

    fn readServerFlight(
        self: *Client,
        options: Options,
        keys: *record.Keys,
    ) InitError!void {
        const encrypted_extensions = try self.readHandshakeMessage(keys);
        try self.parseEncryptedExtensions(options, encrypted_extensions);
        self.transcript.update(encrypted_extensions);

        var message = try self.readHandshakeMessage(keys);
        if (message.len >= 1 and
            message[0] == handshake.handshake_certificate_request)
        {
            try self.parseCertificateRequest(message);
            self.transcript.update(message);
            self.certificate_requested = true;
            message = try self.readHandshakeMessage(keys);
        }

        self.parseCertificate(options, message) catch
            return error.HandshakeFailed;
        self.transcript.update(message);

        const verify_message = try self.readHandshakeMessage(keys);
        self.verifyCertificateVerify(verify_message) catch
            return error.HandshakeFailed;
        self.transcript.update(verify_message);

        const finished_message = try self.readHandshakeMessage(keys);
        try self.verifyServerFinished(finished_message);
        self.transcript.update(finished_message);
    }

    fn parseEncryptedExtensions(
        self: *Client,
        options: Options,
        message: []const u8,
    ) InitError!void {
        if (message.len < 4 or message[0] != handshake.handshake_encrypted_extensions) {
            return error.HandshakeFailed;
        }
        var cursor: handshake.Cursor = .{ .buf = message[4..] };
        const extensions_len = cursor.readU16() catch return error.HandshakeFailed;
        var extensions = cursor.sub(extensions_len) catch return error.HandshakeFailed;
        if (!cursor.eof()) return error.HandshakeFailed;

        var selected: ?[]const u8 = null;
        while (!extensions.eof()) {
            const extension_type = extensions.readU16() catch
                return error.HandshakeFailed;
            const extension_len = extensions.readU16() catch
                return error.HandshakeFailed;
            var extension = extensions.sub(extension_len) catch
                return error.HandshakeFailed;
            if (extension_type != handshake.extension_alpn) continue;
            if (selected != null or options.alpn_protocols.len == 0) {
                return error.HandshakeFailed;
            }
            selected = try parseSelectedAlpn(&extension);
        }
        if (selected) |protocol| {
            if (!containsProtocol(options.alpn_protocols, protocol)) {
                return error.HandshakeFailed;
            }
            @memcpy(self.alpn_buf[0..protocol.len], protocol);
            self.alpn_len = @intCast(protocol.len);
        }
    }

    fn parseCertificateRequest(self: *Client, message: []const u8) InitError!void {
        _ = self;
        if (message.len < 4 or
            message[0] != handshake.handshake_certificate_request)
        {
            return error.HandshakeFailed;
        }
        var cursor: handshake.Cursor = .{ .buf = message[4..] };
        const context_len = cursor.readU8() catch return error.HandshakeFailed;
        cursor.skip(context_len) catch return error.HandshakeFailed;
        const extensions_len = cursor.readU16() catch
            return error.HandshakeFailed;
        var extensions = cursor.sub(extensions_len) catch
            return error.HandshakeFailed;
        if (!cursor.eof()) return error.HandshakeFailed;

        var seen_signature = false;
        var has_p256 = false;
        while (!extensions.eof()) {
            const extension_type = extensions.readU16() catch
                return error.HandshakeFailed;
            const extension_len = extensions.readU16() catch
                return error.HandshakeFailed;
            var extension = extensions.sub(extension_len) catch
                return error.HandshakeFailed;
            if (extension_type != handshake.extension_signature_algorithms) {
                continue;
            }
            if (seen_signature) return error.HandshakeFailed;
            seen_signature = true;
            const list_len = extension.readU16() catch
                return error.HandshakeFailed;
            if (list_len % 2 != 0) return error.HandshakeFailed;
            var list = extension.sub(list_len) catch
                return error.HandshakeFailed;
            if (!extension.eof()) return error.HandshakeFailed;
            while (!list.eof()) {
                const scheme = list.readU16() catch
                    return error.HandshakeFailed;
                if (scheme == handshake.signature_ecdsa_secp256r1_sha256) {
                    has_p256 = true;
                }
            }
        }
        if (!has_p256) return error.HandshakeFailed;
    }

    fn parseCertificate(
        self: *Client,
        options: Options,
        message: []const u8,
    ) InitError!void {
        if (message.len < 4 or message[0] != handshake.handshake_certificate) {
            return error.HandshakeFailed;
        }
        var cursor: handshake.Cursor = .{ .buf = message[4..] };
        const context_len = cursor.readU8() catch return error.HandshakeFailed;
        _ = cursor.readBytes(context_len) catch return error.HandshakeFailed;
        const list_len = cursor.readU24() catch return error.HandshakeFailed;
        var list = cursor.sub(list_len) catch return error.HandshakeFailed;
        if (!cursor.eof()) return error.HandshakeFailed;

        var chain: [cert_path.max_chain][]const u8 = undefined;
        const chain_len = credentials.readCertificateList(&chain, &list) catch
            return error.HandshakeFailed;
        if (chain_len == 0) return error.HandshakeFailed;

        const now_sec = std.Io.Timestamp.now(self.io, .real).toSeconds();
        var leaf: cert_path.Leaf = .{};
        if (options.verify) {
            const ca = options.ca orelse return error.HandshakeFailed;
            ca.lock.lockShared(self.io) catch return error.Canceled;
            defer ca.lock.unlockShared(self.io);
            cert_path.verifyServerChain(chain[0..chain_len], .{
                .host = options.server_name,
                .verify_chain = true,
                .now_sec = now_sec,
                .bundle = &ca.bundle,
            }, &leaf) catch return error.HandshakeFailed;
        } else {
            cert_path.verifyServerChain(chain[0..chain_len], .{
                .host = options.server_name,
                .verify_chain = false,
                .now_sec = now_sec,
                .bundle = null,
            }, &leaf) catch return error.HandshakeFailed;
        }
        if (leaf.len == 0 or leaf.len > self.pubkey.len) {
            return error.HandshakeFailed;
        }
        @memcpy(self.pubkey[0..leaf.len], leaf.pubkey[0..leaf.len]);
        self.pubkey_len = leaf.len;
        self.pubkey_algo = leaf.algo;
    }

    fn verifyCertificateVerify(
        self: *Client,
        message: []const u8,
    ) InitError!void {
        if (message.len < 4 or message[0] != handshake.handshake_certificate_verify) {
            return error.HandshakeFailed;
        }
        var cursor: handshake.Cursor = .{ .buf = message[4..] };
        const scheme = cursor.readU16() catch return error.HandshakeFailed;
        const signature_len = cursor.readU16() catch return error.HandshakeFailed;
        const signature_value = cursor.readBytes(signature_len) catch
            return error.HandshakeFailed;
        if (!cursor.eof()) return error.HandshakeFailed;

        var signed = certificateVerifyInput(
            "TLS 1.3, server CertificateVerify",
            handshake.transcriptHash(&self.transcript),
        );
        signature.verify(
            scheme,
            signature_value,
            signed.slice(),
            self.pubkey_algo,
            self.pubkey[0..self.pubkey_len],
        ) catch return error.HandshakeFailed;
    }

    fn verifyServerFinished(
        self: *Client,
        message: []const u8,
    ) InitError!void {
        if (message.len != 4 + self.key_schedule.suite.hashLength() or
            message[0] != handshake.handshake_finished)
        {
            return error.HandshakeFailed;
        }
        const transcript_hash = handshake.transcriptHash(&self.transcript);
        const expected = handshake.finishedVerifyData(
            self.key_schedule.suite,
            self.key_schedule.server_finished_key,
            transcript_hash,
        ) catch return error.HandshakeFailed;
        const actual = message[4..][0..expected.len];
        if (!constantTimeEqual(expected, actual)) {
            return error.HandshakeFailed;
        }
    }

    fn sendClientAuthentication(
        self: *Client,
        keys: *record.Keys,
    ) InitError!void {
        if (!self.certificate_requested) return;
        self.sendClientCertificate(keys) catch return error.HandshakeFailed;
        if (self.client_certificate_chain.len == 0) return;
        self.sendClientCertificateVerify(keys) catch return error.HandshakeFailed;
    }

    fn sendClientCertificate(
        self: *Client,
        keys: *record.Keys,
    ) InitError!void {
        var body = handshake.Encoder.init(self.handshake_buffer[4..]);
        try body.writeU8(0); // certificate_request_context
        var list_len: usize = 0;
        for (self.client_certificate_chain) |cert| {
            list_len += 3 + cert.len + 2;
        }
        try body.writeU24(@intCast(list_len));
        for (self.client_certificate_chain) |cert| {
            try body.writeU24(@intCast(cert.len));
            try body.append(cert);
            try body.writeU16(0);
        }
        const message = self.finishMessage(
            handshake.handshake_certificate,
            body.len,
        ) catch return error.HandshakeFailed;
        try self.sendEncryptedHandshake(keys, message);
    }

    fn sendClientCertificateVerify(
        self: *Client,
        keys: *record.Keys,
    ) InitError!void {
        const key_pair = self.client_private_key orelse
            return error.HandshakeFailed;
        var signed = certificateVerifyInput(
            "TLS 1.3, client CertificateVerify",
            handshake.transcriptHash(&self.transcript),
        );
        const signature_value = key_pair.sign(signed.bytes[0..signed.len], null) catch
            return error.HandshakeFailed;
        var der_buffer: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = signature_value.toDer(&der_buffer);

        var body = handshake.Encoder.init(self.handshake_buffer[4..]);
        try body.writeU16(handshake.signature_ecdsa_secp256r1_sha256);
        try body.writeU16(@intCast(der.len));
        try body.append(der);
        const message = self.finishMessage(
            handshake.handshake_certificate_verify,
            body.len,
        ) catch return error.HandshakeFailed;
        try self.sendEncryptedHandshake(keys, message);
    }

    fn sendClientFinished(
        self: *Client,
        keys: *record.Keys,
        finished_key: handshake.Secret,
    ) InitError!void {
        const transcript_hash = handshake.transcriptHash(&self.transcript);
        const verify_data = handshake.finishedVerifyData(
            self.key_schedule.suite,
            finished_key,
            transcript_hash,
        ) catch return error.HandshakeFailed;
        var body = handshake.Encoder.init(self.handshake_buffer[4..]);
        body.append(verify_data.slice()) catch return error.HandshakeFailed;
        const message = self.finishMessage(
            handshake.handshake_finished,
            body.len,
        ) catch return error.HandshakeFailed;

        self.write_keys = keys.*;
        const sealed = record.seal(
            &self.write_keys,
            record.content_type_handshake,
            message,
            &self.record_write,
        ) catch return error.HandshakeFailed;
        self.output.writeAll(sealed) catch return error.HandshakeFailed;
        self.output.flush() catch return error.HandshakeFailed;
    }

    fn sendEncryptedHandshake(
        self: *Client,
        keys: *record.Keys,
        message: []const u8,
    ) InitError!void {
        self.transcript.update(message);
        const sealed = record.seal(
            keys,
            record.content_type_handshake,
            message,
            &self.record_write,
        ) catch |err| switch (err) {
            error.CounterExhausted => return error.Closed,
            error.NoSpace => return error.HandshakeFailed,
        };
        self.output.writeAll(sealed) catch return error.HandshakeFailed;
    }

    fn finishMessage(
        self: *Client,
        msg_type: u8,
        body_len: usize,
    ) InitError![]const u8 {
        if (body_len > handshake.max_handshake - 4) {
            return error.HandshakeFailed;
        }
        self.handshake_buffer[0] = msg_type;
        std.mem.writeInt(
            u24,
            self.handshake_buffer[1..4],
            @intCast(body_len),
            .big,
        );
        return self.handshake_buffer[0 .. 4 + body_len];
    }

    fn readHandshakeMessage(
        self: *Client,
        keys: ?*record.Keys,
    ) InitError![]const u8 {
        while (true) {
            if (self.handshakeLen() >= 4) {
                const pending = self.handshake_buffer[self.handshake_offset..self.handshake_len];
                const body_len: usize = std.mem.readInt(
                    u24,
                    pending[1..4],
                    .big,
                );
                if (body_len > handshake.max_handshake - 4) {
                    return error.HandshakeFailed;
                }
                const total = 4 + body_len;
                if (pending.len >= total) {
                    const message = pending[0..total];
                    self.handshake_offset += total;
                    if (self.handshake_offset == self.handshake_len) {
                        self.handshake_len = 0;
                        self.handshake_offset = 0;
                    }
                    return message;
                }
            }
            self.compactHandshake();
            const fragment = try self.readHandshakeFragment(keys);
            try self.appendHandshake(fragment);
        }
    }

    fn handshakeLen(self: *const Client) usize {
        return self.handshake_len - self.handshake_offset;
    }

    fn compactHandshake(self: *Client) void {
        if (self.handshake_offset == 0) return;
        const remaining = self.handshakeLen();
        if (remaining != 0) {
            std.mem.copyForwards(
                u8,
                self.handshake_buffer[0..remaining],
                self.handshake_buffer[self.handshake_offset..self.handshake_len],
            );
        }
        self.handshake_len = remaining;
        self.handshake_offset = 0;
    }

    fn appendHandshake(self: *Client, fragment: []const u8) InitError!void {
        if (self.handshake_buffer.len - self.handshake_len < fragment.len) {
            return error.HandshakeFailed;
        }
        @memcpy(
            self.handshake_buffer[self.handshake_len..][0..fragment.len],
            fragment,
        );
        self.handshake_len += fragment.len;
    }

    fn readHandshakeFragment(
        self: *Client,
        keys: ?*record.Keys,
    ) InitError![]const u8 {
        while (true) {
            const rec = record.readRecord(
                self.input,
                &self.record_read,
            ) catch return mapRecordError();
            if (rec[0] == record.content_type_change_cipher_spec) {
                if (rec.len != 6 or rec[5] != 1) return error.HandshakeFailed;
                continue;
            }
            if (rec[0] == record.content_type_alert) {
                return error.HandshakeFailed;
            }
            if (keys) |key_state| {
                if (rec[0] != record.content_type_application_data) {
                    return error.HandshakeFailed;
                }
                const opened = record.open(key_state, rec, &self.pending) catch
                    return error.HandshakeFailed;
                if (opened.content_type == record.content_type_alert) {
                    return error.HandshakeFailed;
                }
                if (opened.content_type != record.content_type_handshake) {
                    return error.HandshakeFailed;
                }
                return opened.content;
            }
            if (rec[0] != record.content_type_handshake) {
                return error.HandshakeFailed;
            }
            return rec[record.record_header_len..];
        }
    }

    fn readPlaintext(self: *Client, dest: []u8) InitError!usize {
        if (self.eof_received) return error.Closed;
        if (self.pending_offset < self.pending_len) {
            return self.copyPending(dest);
        }

        while (true) {
            const rec = record.readRecord(
                self.input,
                &self.record_read,
            ) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.EndOfStream => {
                    if (self.allow_truncation_attacks) {
                        self.eof_received = true;
                        return error.Closed;
                    }
                    return error.Truncated;
                },
                else => return error.HandshakeFailed,
            };
            if (rec[0] == record.content_type_change_cipher_spec) {
                return error.HandshakeFailed;
            }
            // RFC 8446 §5.1: after the handshake every alert must be
            // protected by the current write keys.
            if (rec[0] != record.content_type_application_data) {
                return error.HandshakeFailed;
            }

            const opened = record.open(
                &self.read_keys,
                rec,
                &self.pending,
            ) catch return error.HandshakeFailed;
            switch (opened.content_type) {
                record.content_type_application_data => {
                    if (opened.content.len == 0) continue;
                    self.pending_len = opened.content.len;
                    self.pending_offset = 0;
                    return self.copyPending(dest);
                },
                record.content_type_alert => return self.handleAlert(opened.content),
                record.content_type_handshake => {
                    try self.handlePostHandshake(opened.content);
                    continue;
                },
                else => return error.HandshakeFailed,
            }
        }
    }

    fn handlePostHandshake(self: *Client, content: []const u8) InitError!void {
        if (self.post_handshake.len - self.post_handshake_len < content.len) {
            return error.HandshakeFailed;
        }
        @memcpy(
            self.post_handshake[self.post_handshake_len..][0..content.len],
            content,
        );
        self.post_handshake_len += content.len;

        var offset: usize = 0;
        while (self.post_handshake_len - offset >= 4) {
            const body_len: usize = std.mem.readInt(
                u24,
                self.post_handshake[offset + 1 ..][0..3],
                .big,
            );
            if (body_len > handshake.max_handshake - 4) {
                return error.HandshakeFailed;
            }
            const total = 4 + body_len;
            if (self.post_handshake_len - offset < total) break;
            try self.handlePostHandshakeMessage(
                self.post_handshake[offset..][0..total],
            );
            offset += total;
        }
        if (offset == 0) return;
        const remaining = self.post_handshake_len - offset;
        if (remaining != 0) {
            std.mem.copyForwards(
                u8,
                self.post_handshake[0..remaining],
                self.post_handshake[offset..self.post_handshake_len],
            );
        }
        self.post_handshake_len = remaining;
    }

    fn handlePostHandshakeMessage(
        self: *Client,
        message: []const u8,
    ) InitError!void {
        switch (message[0]) {
            // NewSessionTicket is ignored: this client has no PSK or tickets.
            4 => {},
            handshake.handshake_key_update => {
                const request_update = handshake.parseKeyUpdate(message) catch
                    return error.HandshakeFailed;
                self.server_app_secret = handshake.updateSecret(
                    self.write_keys.suite,
                    self.server_app_secret,
                ) catch return error.HandshakeFailed;
                self.read_keys = handshake.keysFromSecret(
                    self.write_keys.suite,
                    self.server_app_secret,
                ) catch return error.HandshakeFailed;
                if (request_update) {
                    self.pending_key_update_response.store(true, .release);
                }
            },
            else => return error.HandshakeFailed,
        }
    }

    fn sendKeyUpdate(self: *Client, request_update: bool) InitError!void {
        var body = handshake.Encoder.init(self.handshake_buffer[4..]);
        body.writeU8(@intFromBool(request_update)) catch
            return error.HandshakeFailed;
        const message = self.finishMessage(
            handshake.handshake_key_update,
            body.len,
        ) catch return error.HandshakeFailed;

        // RFC 8446 §4.6.3: the KeyUpdate itself uses the old sending keys;
        // the new keys apply to records after it.
        const sealed = record.seal(
            &self.write_keys,
            record.content_type_handshake,
            message,
            &self.record_write,
        ) catch |err| switch (err) {
            error.CounterExhausted => return error.Closed,
            error.NoSpace => return error.HandshakeFailed,
        };
        self.output.writeAll(sealed) catch return error.HandshakeFailed;
        self.client_app_secret = handshake.updateSecret(
            self.write_keys.suite,
            self.client_app_secret,
        ) catch return error.HandshakeFailed;
        self.write_keys = handshake.keysFromSecret(
            self.write_keys.suite,
            self.client_app_secret,
        ) catch return error.HandshakeFailed;
    }

    fn copyPending(self: *Client, dest: []u8) usize {
        const available = self.pending_len - self.pending_offset;
        const count = @min(dest.len, available);
        @memcpy(
            dest[0..count],
            self.pending[self.pending_offset..][0..count],
        );
        self.pending_offset += count;
        return count;
    }

    fn handleAlert(self: *Client, alert: []const u8) InitError {
        if (alert.len != 2) return error.HandshakeFailed;
        if (alert[1] == 0) {
            self.eof_received = true;
            return error.Closed;
        }
        return error.HandshakeFailed;
    }

    fn writeAppData(self: *Client, bytes: []const u8) InitError!void {
        if (self.pending_key_update_response.swap(false, .acquire)) {
            try self.sendKeyUpdate(false);
        }
        var offset: usize = 0;
        while (offset < bytes.len) {
            const chunk_len = @min(bytes.len - offset, record.max_plaintext);
            const chunk = bytes[offset..][0..chunk_len];
            const sealed = record.seal(
                &self.write_keys,
                record.content_type_application_data,
                chunk,
                &self.record_write,
            ) catch |err| switch (err) {
                error.CounterExhausted => return error.Closed,
                error.NoSpace => return error.HandshakeFailed,
            };
            self.output.writeAll(sealed) catch return error.HandshakeFailed;
            offset += chunk_len;
        }
    }

    fn randomError(self: *Client) InitError {
        _ = self;
        return error.HandshakeFailed;
    }
};

pub const CertificateVerifyInput = struct {
    bytes: [64 + 33 + 1 + handshake.max_hash_len]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const CertificateVerifyInput) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn certificateVerifyInput(
    context: []const u8,
    transcript_hash: handshake.TranscriptHash,
) CertificateVerifyInput {
    var result: CertificateVerifyInput = .{};
    @memset(result.bytes[0..64], 0x20);
    @memcpy(result.bytes[64..][0..context.len], context);
    result.bytes[64 + context.len] = 0;
    @memcpy(
        result.bytes[64 + context.len + 1 ..][0..transcript_hash.len],
        transcript_hash.slice(),
    );
    result.len = 64 + context.len + 1 + transcript_hash.len;
    return result;
}

/// Constant-time comparison of a Finished or KeyUpdate-sized value.
fn constantTimeEqual(
    expected: handshake.Secret,
    actual: []const u8,
) bool {
    if (actual.len != expected.len) return false;
    var padded: [handshake.max_hash_len]u8 = @splat(0);
    @memcpy(padded[0..actual.len], actual);
    return std.crypto.timing_safe.eql(
        [handshake.max_hash_len]u8,
        expected.bytes,
        padded,
    );
}

fn p256SharedSecret(scalar: [32]u8, peer: []const u8) ![32]u8 {
    const point = try P256.fromSec1(peer);
    const shared = try point.mul(scalar, .big);
    return shared.affineCoordinates().x.toBytes(.big);
}

fn containsSuite(
    suites: []const record.CipherSuite,
    suite: record.CipherSuite,
) bool {
    for (suites) |candidate| {
        if (candidate == suite) return true;
    }
    return false;
}

fn validateOptions(options: Options) InitError!void {
    if (options.read_buffer.len == 0 or options.write_buffer.len == 0) {
        return error.HandshakeFailed;
    }
    if (options.verify and
        (options.server_name == null or options.ca == null))
    {
        return error.HandshakeFailed;
    }
    if (options.cipher_suites.len == 0) return error.HandshakeFailed;
    for (options.cipher_suites, 0..) |suite, index| {
        for (options.cipher_suites[0..index]) |previous| {
            if (previous == suite) return error.HandshakeFailed;
        }
    }
    if ((options.client_certificate_chain.len == 0) !=
        (options.client_private_key == null))
    {
        return error.HandshakeFailed;
    }
    if (options.client_certificate_chain.len != 0) {
        credentials.validateCredentials(
            options.client_certificate_chain,
            options.client_private_key.?,
        ) catch return error.HandshakeFailed;
    }
    var alpn_len: usize = 0;
    for (options.alpn_protocols) |protocol| {
        if (protocol.len == 0 or
            protocol.len > handshake.max_alpn_protocol)
        {
            return error.HandshakeFailed;
        }
        alpn_len += 1 + protocol.len;
    }
    if (alpn_len > max_alpn_list) return error.HandshakeFailed;
}

fn writeExtensions(
    extensions: *handshake.Encoder,
    options: Options,
    x25519_public: [32]u8,
    p256_public: [65]u8,
) InitError!void {
    try writeServerName(extensions, options.server_name);
    try extensions.writeU16(handshake.extension_supported_versions);
    try extensions.writeU16(3);
    try extensions.writeU8(2);
    try extensions.writeU16(handshake.tls_1_3);
    try writeSignatureAlgorithms(extensions);
    try extensions.writeU16(0x000a); // supported_groups
    try extensions.writeU16(6);
    try extensions.writeU16(4);
    try extensions.writeU16(handshake.group_x25519);
    try extensions.writeU16(handshake.group_secp256r1);
    try extensions.writeU16(handshake.extension_key_share);
    try extensions.writeU16(107);
    try extensions.writeU16(105);
    try extensions.writeU16(handshake.group_x25519);
    try extensions.writeU16(32);
    try extensions.append(&x25519_public);
    try extensions.writeU16(handshake.group_secp256r1);
    try extensions.writeU16(65);
    try extensions.append(&p256_public);
    if (options.alpn_protocols.len != 0) {
        handshake.writeAlpnExtension(extensions, options.alpn_protocols) catch
            return error.HandshakeFailed;
    }
}

fn writeServerName(
    extensions: *handshake.Encoder,
    server_name: ?[]const u8,
) InitError!void {
    const name = server_name orelse return;
    if (name.len == 0 or name.len > handshake.max_server_name) {
        return error.HandshakeFailed;
    }
    try extensions.writeU16(handshake.extension_server_name);
    try extensions.writeU16(@intCast(2 + 1 + 2 + name.len));
    try extensions.writeU16(@intCast(1 + 2 + name.len));
    try extensions.writeU8(0);
    try extensions.writeU16(@intCast(name.len));
    try extensions.append(name);
}

fn writeSignatureAlgorithms(extensions: *handshake.Encoder) InitError!void {
    const schemes = [_]u16{
        handshake.signature_ecdsa_secp256r1_sha256,
        handshake.signature_ecdsa_secp384r1_sha384,
        handshake.signature_ed25519,
        handshake.signature_rsa_pss_sha256,
        handshake.signature_rsa_pss_sha384,
        handshake.signature_rsa_pss_sha512,
    };
    try extensions.writeU16(handshake.extension_signature_algorithms);
    try extensions.writeU16(2 + schemes.len * 2);
    try extensions.writeU16(@intCast(schemes.len * 2));
    for (schemes) |scheme| try extensions.writeU16(scheme);
}

fn parseSelectedAlpn(extension: *handshake.Cursor) InitError![]const u8 {
    const list_len = extension.readU16() catch return error.HandshakeFailed;
    var list = extension.sub(list_len) catch return error.HandshakeFailed;
    if (!extension.eof()) return error.HandshakeFailed;
    const name_len = list.readU8() catch return error.HandshakeFailed;
    if (name_len == 0) return error.HandshakeFailed;
    const name = list.readBytes(name_len) catch return error.HandshakeFailed;
    if (!list.eof()) return error.HandshakeFailed;
    return name;
}

fn containsProtocol(protocols: []const []const u8, protocol: []const u8) bool {
    for (protocols) |candidate| {
        if (std.mem.eql(u8, candidate, protocol)) return true;
    }
    return false;
}

fn readerStream(
    io_r: *std.Io.Reader,
    io_w: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    const self: *Client = @alignCast(@fieldParentPtr("reader_interface", io_r));
    const dest = limit.slice(io_w.writableSliceGreedy(1) catch
        return error.WriteFailed);
    if (dest.len == 0) return 0;

    const read_len = self.readPlaintext(dest) catch |err| {
        self.read_error = err;
        return switch (err) {
            error.Closed => error.EndOfStream,
            else => error.ReadFailed,
        };
    };
    io_w.advance(read_len);
    return read_len;
}

fn writerDrain(
    io_w: *std.Io.Writer,
    data: []const []const u8,
    splat: usize,
) std.Io.Writer.Error!usize {
    const self: *Client = @alignCast(@fieldParentPtr("writer_interface", io_w));
    if (io_w.end != 0) {
        self.writeAppData(io_w.buffer[0..io_w.end]) catch |err| {
            self.write_error = err;
            return error.WriteFailed;
        };
        io_w.end = 0;
    }

    var consumed: usize = 0;
    for (data, 0..) |slice, index| {
        const repeat = if (index + 1 == data.len) splat else 1;
        var i: usize = 0;
        while (i < repeat) : (i += 1) {
            self.writeAppData(slice) catch |err| {
                self.write_error = err;
                return error.WriteFailed;
            };
            consumed += slice.len;
        }
    }
    return consumed;
}

fn mapRecordError() InitError {
    return error.HandshakeFailed;
}

test "a peer close during the handshake fails the handshake" {
    var input_buffer: [min_buffer_len]u8 = undefined;
    var input: std.Io.Reader = .{
        .vtable = &.{ .stream = failingStream },
        .buffer = &input_buffer,
        .seek = 0,
        .end = 0,
    };
    var output_buffer: [min_buffer_len]u8 = undefined;
    var output: std.Io.Writer = .{
        .vtable = &.{ .drain = discardDrain },
        .buffer = &output_buffer,
    };
    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;

    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = "localhost",
            .verify = false,
            .read_buffer = &read_buffer,
            .write_buffer = &write_buffer,
        }),
    );
}

test "verification requires a server name and a CA" {
    var input: std.Io.Reader = .failing;
    var output: std.Io.Writer = .failing;
    var dummy: [1]u8 = undefined;
    var ca = Ca.init(std.testing.allocator);
    defer ca.deinit();

    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = "localhost",
            .verify = true,
            .ca = null,
            .read_buffer = &dummy,
            .write_buffer = &dummy,
        }),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = null,
            .verify = true,
            .ca = &ca,
            .read_buffer = &dummy,
            .write_buffer = &dummy,
        }),
    );
}

test "ALPN protocol names are bounded" {
    var input: std.Io.Reader = .failing;
    var output: std.Io.Writer = .failing;
    var dummy: [1]u8 = undefined;
    const too_long: [256]u8 = @splat('x');
    const protocols = [_][]const u8{&too_long};

    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = "localhost",
            .verify = false,
            .alpn_protocols = &protocols,
            .read_buffer = &dummy,
            .write_buffer = &dummy,
        }),
    );
}

test "cipher suite list must be non-empty and unique" {
    var input: std.Io.Reader = .failing;
    var output: std.Io.Writer = .failing;
    var dummy: [1]u8 = undefined;
    const duplicate = [_]record.CipherSuite{
        .aes_128_gcm_sha256,
        .aes_128_gcm_sha256,
    };
    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = "localhost",
            .verify = false,
            .cipher_suites = &.{},
            .read_buffer = &dummy,
            .write_buffer = &dummy,
        }),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = "localhost",
            .verify = false,
            .cipher_suites = &duplicate,
            .read_buffer = &dummy,
            .write_buffer = &dummy,
        }),
    );
}

fn failingStream(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    _ = reader;
    _ = writer;
    _ = limit;
    return error.EndOfStream;
}

fn discardDrain(
    writer: *std.Io.Writer,
    data: []const []const u8,
    splat: usize,
) std.Io.Writer.Error!usize {
    writer.end = 0;
    var total: usize = 0;
    for (data, 0..) |slice, index| {
        const repeat = if (index + 1 == data.len) splat else 1;
        total += slice.len * repeat;
    }
    return total;
}

test "plaintext close_notify is rejected after the handshake" {
    const alert = [_]u8{ record.content_type_alert, 0x03, 0x03, 0, 2, 1, 0 };
    var input_buffer: [16]u8 = undefined;
    var calls = [_]std.testing.Reader.Call{.{ .buffer = &alert }};
    var reader = std.testing.Reader.init(&input_buffer, &calls);

    var client: Client = undefined;
    client.input = &reader.interface;
    client.eof_received = false;
    client.allow_truncation_attacks = false;
    client.pending_len = 0;
    client.pending_offset = 0;
    client.read_keys = .{};

    var dest: [16]u8 = undefined;
    try std.testing.expectError(
        error.HandshakeFailed,
        client.readPlaintext(&dest),
    );
    try std.testing.expect(!client.eof_received);
}

test "missing close_notify is a truncation unless explicitly allowed" {
    var input_buffer: [16]u8 = undefined;
    var calls = [_]std.testing.Reader.Call{};
    var reader = std.testing.Reader.init(&input_buffer, &calls);
    var client: Client = undefined;
    client.input = &reader.interface;
    client.eof_received = false;
    client.allow_truncation_attacks = false;
    client.pending_len = 0;
    client.pending_offset = 0;
    client.read_keys = .{};
    var dest: [16]u8 = undefined;
    try std.testing.expectError(
        error.Truncated,
        client.readPlaintext(&dest),
    );

    client.eof_received = false;
    client.allow_truncation_attacks = true;
    try std.testing.expectError(
        error.Closed,
        client.readPlaintext(&dest),
    );
    try std.testing.expect(client.eof_received);
}
