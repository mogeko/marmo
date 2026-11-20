//! TLS 1.3 server.
//!
//! Scope: X25519 and secp256r1 ECDHE, AES-128-GCM, AES-256-GCM, and
//! ChaCha20-Poly1305, ECDSA P-256 certificates, optional/required client
//! authentication, and key updates. No PSK/session tickets, HelloRetryRequest,
//! or 0-RTT. The API operates on `std.Io.Reader`/`Writer` so the server has no
//! dependency on marmo.

const std = @import("std");
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const client = @import("client.zig");
const cert_path = @import("cert_path.zig");
const credentials = @import("credentials.zig");
const signature = @import("signature.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P256 = std.crypto.ecc.P256;
const test_cert = @import("test_cert.zig");

pub const Error = error{
    Canceled,
    HandshakeFailed,
    ProtocolViolation,
    Closed,
    Truncated,
    OutOfMemory,
};

/// Server-side client-certificate policy.
pub const ClientAuth = enum { none, optional, required };

pub const ServerOptions = struct {
    /// DER certificates, leaf first.
    certificate_chain: []const []const u8,
    private_key: Ecdsa.KeyPair,
    /// ALPN protocols in server preference order. Empty disables selection.
    alpn_protocols: []const []const u8 = &.{},
    /// Cipher suites in server preference order. Must be non-empty.
    cipher_suites: []const record.CipherSuite = &record.CipherSuite.list,
    /// Preferred key exchange group. Null prefers X25519 when offered.
    key_exchange_group: ?u16 = null,
    /// Whether to request and verify a client certificate.
    client_auth: ClientAuth = .none,
    /// Trust anchors for client certificates. Required when `client_auth` is
    /// not `.none`.
    client_ca: ?*const std.crypto.Certificate.Bundle = null,
    /// Treat a missing client close_notify as EOF. The root adapters default
    /// to strict truncation handling.
    allow_truncation_attacks: bool = false,
    /// Plaintext reader buffer; the caller keeps ownership.
    read_buffer: []u8,
    /// Plaintext writer buffer; the caller keeps ownership.
    write_buffer: []u8,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
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
    server_name_buf: [handshake.max_server_name]u8 = undefined,
    server_name_len: u8 = 0,
    alpn_buf: [handshake.max_alpn_protocol]u8 = undefined,
    alpn_len: u8 = 0,
    group: u16 = 0,
    peer_pubkey: [signature.max_pubkey]u8 = undefined,
    peer_pubkey_len: usize = 0,
    peer_pubkey_algo: std.crypto.Certificate.Parsed.PubKeyAlgo = .rsaEncryption,
    pending: [record.max_ciphertext]u8 = undefined,
    pending_len: usize = 0,
    pending_offset: usize = 0,
    record_read: [record.max_record]u8 = undefined,
    record_write: [record.max_record]u8 = undefined,
    handshake_buffer: [handshake.max_handshake]u8 = undefined,
    message_buffer: [handshake.max_handshake]u8 = undefined,
    post_handshake: [handshake.max_handshake]u8 = undefined,
    post_handshake_len: usize = 0,
    pending_key_update_response: std.atomic.Value(bool) = .init(false),
    negotiated_suite: record.CipherSuite = .aes_128_gcm_sha256,
    allow_truncation_attacks: bool = false,
    closed: bool = false,
    eof: bool = false,
    read_error: ?Error = null,
    write_error: ?Error = null,

    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        options: ServerOptions,
    ) Error!*Server {
        try validateOptions(&options);
        var owned_options = options;
        defer std.crypto.secureZero(
            u8,
            std.mem.asBytes(&owned_options.private_key),
        );

        const self = try gpa.create(Server);
        errdefer {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
            gpa.destroy(self);
        }
        self.* = .{
            .gpa = gpa,
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
            .allow_truncation_attacks = options.allow_truncation_attacks,
        };
        try self.runHandshake(io, &owned_options);
        return self;
    }

    pub fn reader(self: *Server) *std.Io.Reader {
        return &self.reader_interface;
    }

    pub fn writer(self: *Server) *std.Io.Writer {
        return &self.writer_interface;
    }

    pub fn serverName(self: *const Server) ?[]const u8 {
        if (self.server_name_len == 0) return null;
        return self.server_name_buf[0..self.server_name_len];
    }

    pub fn negotiatedProtocol(self: *const Server) ?[]const u8 {
        if (self.alpn_len == 0) return null;
        return self.alpn_buf[0..self.alpn_len];
    }

    pub fn negotiatedCipherSuite(self: *const Server) record.CipherSuite {
        return self.negotiated_suite;
    }

    pub fn negotiatedGroup(self: *const Server) u16 {
        return self.group;
    }

    pub fn readError(self: *const Server) ?Error {
        return self.read_error;
    }

    pub fn writeError(self: *const Server) ?Error {
        return self.write_error;
    }

    /// Sends a KeyUpdate and switches the sending keys (RFC 8446 §4.6.3).
    /// The caller must serialize writes with any other writer task.
    pub fn keyUpdate(self: *Server, request_update: bool) Error!void {
        try self.sendKeyUpdate(request_update);
        self.output.flush() catch return error.ProtocolViolation;
    }

    pub fn flush(self: *Server) Error!void {
        self.writer_interface.flush() catch return self.writeError() orelse error.ProtocolViolation;
        self.output.flush() catch return error.ProtocolViolation;
    }

    pub fn end(self: *Server) Error!void {
        if (self.closed) return;
        try self.flush();

        const alert = [2]u8{ 1, 0 };
        const sealed = record.seal(
            &self.write_keys,
            record.content_type_alert,
            &alert,
            &self.record_write,
        ) catch return error.ProtocolViolation;
        self.output.writeAll(sealed) catch return error.ProtocolViolation;
        self.output.flush() catch return error.ProtocolViolation;
        self.closed = true;
    }

    pub fn deinit(self: *Server) void {
        const gpa = self.gpa;
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        gpa.destroy(self);
    }

    fn runHandshake(
        self: *Server,
        io: std.Io,
        options: *const ServerOptions,
    ) Error!void {
        const client_hello_message = try self.readHandshake(null);
        const client_hello = handshake.parseClientHello(
            client_hello_message,
            &self.server_name_buf,
        ) catch return error.HandshakeFailed;
        if (client_hello.server_name) |name| {
            self.server_name_len = @intCast(name.len);
        }
        selectAlpn(
            client_hello.alpn_protocols,
            options.alpn_protocols,
            &self.alpn_buf,
            &self.alpn_len,
        ) catch |err| {
            record.writePlain(
                self.output,
                record.content_type_alert,
                &.{ 2, 120 },
            ) catch {};
            self.output.flush() catch {};
            return err;
        };
        const suite = selectCipherSuite(client_hello, options.cipher_suites) catch
            return error.HandshakeFailed;
        const group = selectGroup(
            client_hello,
            options.key_exchange_group,
        ) catch return error.HandshakeFailed;
        self.group = group;
        self.transcript = handshake.Transcript.init(suite);
        self.transcript.update(client_hello_message);

        var key_exchange = try computeKeyExchange(io, client_hello, group);
        defer key_exchange.deinit();

        try self.sendServerHello(
            io,
            client_hello,
            suite,
            group,
            key_exchange.public[0..key_exchange.public_len],
        );
        const hello_hash = handshake.transcriptHash(&self.transcript);
        self.key_schedule = handshake.KeySchedule.derive(
            suite,
            &key_exchange.secret,
            hello_hash,
        ) catch return error.HandshakeFailed;
        self.write_keys = self.key_schedule.server_hs_keys;
        self.write_keys.seq = 0;
        try self.sendServerFlight(
            options.certificate_chain,
            &options.private_key,
            options.client_auth != .none,
        );
        self.output.flush() catch return error.HandshakeFailed;
        try self.finishHandshake(options);
    }

    fn finishHandshake(
        self: *Server,
        options: *const ServerOptions,
    ) Error!void {
        const handshake_hash = handshake.transcriptHash(&self.transcript);
        self.client_app_secret = self.key_schedule.clientAppSecret(
            handshake_hash,
        ) catch return error.HandshakeFailed;
        self.server_app_secret = self.key_schedule.serverAppSecret(
            handshake_hash,
        ) catch return error.HandshakeFailed;

        const suite = self.key_schedule.suite;
        self.write_keys = handshake.keysFromSecret(
            suite,
            self.server_app_secret,
        ) catch return error.HandshakeFailed;
        try self.readClientAuthentication(options, &self.key_schedule.client_hs_keys);
        try self.readClientFinished(
            &self.key_schedule.client_hs_keys,
            self.key_schedule.client_finished_key,
        );
        self.read_keys = handshake.keysFromSecret(
            suite,
            self.client_app_secret,
        ) catch return error.HandshakeFailed;
        self.negotiated_suite = suite;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_schedule));
    }

    fn sendServerHello(
        self: *Server,
        io: std.Io,
        client_hello: handshake.ClientHello,
        suite: record.CipherSuite,
        group: u16,
        public_key: []const u8,
    ) Error!void {
        var random: [32]u8 = undefined;
        std.Io.randomSecure(io, &random) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.HandshakeFailed,
        };

        var extension_buf: [80]u8 = undefined;
        var extensions = handshake.Encoder.init(&extension_buf);
        try extensions.writeU16(handshake.extension_supported_versions);
        try extensions.writeU16(2);
        try extensions.writeU16(handshake.tls_1_3);
        try extensions.writeU16(handshake.extension_key_share);
        try extensions.writeU16(@intCast(2 + 2 + public_key.len));
        try extensions.writeU16(group);
        try extensions.writeU16(@intCast(public_key.len));
        try extensions.append(public_key);

        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.writeU16(0x0303); // legacy_version
        try body.append(&random);
        try body.writeU8(client_hello.session_id_len);
        try body.append(client_hello.session_id[0..client_hello.session_id_len]);
        try body.writeU16(suite.wireId());
        try body.writeU8(0); // legacy_compression_method
        try body.writeU16(@intCast(extensions.len));
        try body.append(extensions.bytes());

        const message = try self.finishMessage(
            handshake.handshake_server_hello,
            body.len,
        );
        self.transcript.update(message);
        record.writePlain(
            self.output,
            record.content_type_handshake,
            message,
        ) catch return error.HandshakeFailed;
        // Middlebox-compatibility CCS: it is not part of the transcript.
        record.writePlain(
            self.output,
            record.content_type_change_cipher_spec,
            &.{1},
        ) catch return error.HandshakeFailed;
        self.output.flush() catch return error.HandshakeFailed;
    }

    fn sendServerFlight(
        self: *Server,
        chain: []const []const u8,
        private_key: *const Ecdsa.KeyPair,
        request_client_auth: bool,
    ) Error!void {
        try self.sendEncryptedExtensions();
        if (request_client_auth) try self.sendCertificateRequest();
        try self.sendCertificate(chain);
        try self.sendCertificateVerify(private_key);
        try self.sendFinished();
    }

    fn sendEncryptedExtensions(self: *Server) Error!void {
        var extension_buffer: [512]u8 = undefined;
        var extensions = handshake.Encoder.init(&extension_buffer);
        if (self.negotiatedProtocol()) |protocol| {
            try handshake.writeAlpnExtension(&extensions, &.{protocol});
        }

        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.writeU16(@intCast(extensions.len));
        try body.append(extensions.bytes());
        const message = try self.finishMessage(
            handshake.handshake_encrypted_extensions,
            body.len,
        );
        try self.sendEncryptedHandshake(message);
    }

    fn sendCertificateRequest(self: *Server) Error!void {
        const schemes = [_]u16{
            handshake.signature_ecdsa_secp256r1_sha256,
            handshake.signature_ecdsa_secp384r1_sha384,
            handshake.signature_ed25519,
            handshake.signature_rsa_pss_sha256,
            handshake.signature_rsa_pss_sha384,
            handshake.signature_rsa_pss_sha512,
        };
        var extension_buffer: [32]u8 = undefined;
        var extensions = handshake.Encoder.init(&extension_buffer);
        try extensions.writeU16(handshake.extension_signature_algorithms);
        try extensions.writeU16(2 + schemes.len * 2);
        try extensions.writeU16(schemes.len * 2);
        for (schemes) |scheme| try extensions.writeU16(scheme);

        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.writeU8(0); // certificate_request_context
        try body.writeU16(@intCast(extensions.len));
        try body.append(extensions.bytes());
        const message = try self.finishMessage(
            handshake.handshake_certificate_request,
            body.len,
        );
        try self.sendEncryptedHandshake(message);
    }

    fn sendCertificate(self: *Server, chain: []const []const u8) Error!void {
        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.writeU8(0); // certificate_request_context

        var list_len: usize = 0;
        for (chain) |cert| {
            list_len += 3 + cert.len + 2;
        }
        try body.writeU24(@intCast(list_len));
        for (chain) |cert| {
            try body.writeU24(@intCast(cert.len));
            try body.append(cert);
            try body.writeU16(0); // per-certificate extensions
        }

        const message = try self.finishMessage(
            handshake.handshake_certificate,
            body.len,
        );
        try self.sendEncryptedHandshake(message);
    }

    fn sendCertificateVerify(
        self: *Server,
        private_key: *const Ecdsa.KeyPair,
    ) Error!void {
        const transcript_hash = handshake.transcriptHash(&self.transcript);
        var context: [64 + 33 + 1 + handshake.max_hash_len]u8 = @splat(0);
        const label = "TLS 1.3, server CertificateVerify";
        @memset(context[0..64], 0x20);
        @memcpy(context[64..][0..label.len], label);
        context[64 + label.len] = 0;
        @memcpy(
            context[64 + label.len + 1 ..][0..transcript_hash.len],
            transcript_hash.slice(),
        );
        const signed_len = 64 + label.len + 1 + transcript_hash.len;

        const signature_value = private_key.sign(context[0..signed_len], null) catch
            return error.HandshakeFailed;
        var der_buffer: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = signature_value.toDer(&der_buffer);

        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.writeU16(handshake.signature_ecdsa_secp256r1_sha256);
        try body.writeU16(@intCast(der.len));
        try body.append(der);

        const message = try self.finishMessage(
            handshake.handshake_certificate_verify,
            body.len,
        );
        try self.sendEncryptedHandshake(message);
    }

    fn sendFinished(self: *Server) Error!void {
        const transcript_hash = handshake.transcriptHash(&self.transcript);
        const verify_data = handshake.finishedVerifyData(
            self.key_schedule.suite,
            self.key_schedule.server_finished_key,
            transcript_hash,
        ) catch return error.HandshakeFailed;

        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.append(verify_data.slice());
        const message = try self.finishMessage(
            handshake.handshake_finished,
            body.len,
        );
        try self.sendEncryptedHandshake(message);
    }

    fn finishMessage(
        self: *Server,
        msg_type: u8,
        body_len: usize,
    ) Error![]const u8 {
        if (body_len > handshake.max_handshake - 4) {
            return error.HandshakeFailed;
        }
        self.message_buffer[0] = msg_type;
        std.mem.writeInt(u24, self.message_buffer[1..4], @intCast(body_len), .big);
        return self.message_buffer[0 .. 4 + body_len];
    }

    fn sendEncryptedHandshake(self: *Server, message: []const u8) Error!void {
        self.transcript.update(message);
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
    }

    fn readClientAuthentication(
        self: *Server,
        options: *const ServerOptions,
        keys: *record.Keys,
    ) Error!void {
        if (options.client_auth == .none) return;
        const message = try self.readHandshake(keys);
        if (message.len < 1 or message[0] != handshake.handshake_certificate) {
            return error.HandshakeFailed;
        }
        const chain_len = try self.parseClientCertificate(options, message);
        if (chain_len == 0) {
            if (options.client_auth == .required) {
                return error.HandshakeFailed;
            }
            self.transcript.update(message);
            return;
        }
        self.transcript.update(message);
        const verify_message = try self.readHandshake(keys);
        try self.verifyClientCertificateVerify(verify_message);
        self.transcript.update(verify_message);
    }

    fn parseClientCertificate(
        self: *Server,
        options: *const ServerOptions,
        message: []const u8,
    ) Error!usize {
        var cursor: handshake.Cursor = .{ .buf = message[4..] };
        const context_len = cursor.readU8() catch return error.HandshakeFailed;
        if (context_len != 0) return error.HandshakeFailed;
        _ = cursor.readBytes(context_len) catch return error.HandshakeFailed;
        const list_len = cursor.readU24() catch return error.HandshakeFailed;
        var list = cursor.sub(list_len) catch return error.HandshakeFailed;
        if (!cursor.eof()) return error.HandshakeFailed;

        var chain: [cert_path.max_chain][]const u8 = undefined;
        const chain_len = credentials.readCertificateList(&chain, &list) catch
            return error.HandshakeFailed;
        if (chain_len == 0) return 0;

        const bundle = options.client_ca orelse return error.HandshakeFailed;
        const now_sec = std.Io.Timestamp.now(self.io, .real).toSeconds();
        var leaf: cert_path.Leaf = .{};
        cert_path.verifyClientChain(chain[0..chain_len], .{
            .host = null,
            .verify_chain = true,
            .now_sec = now_sec,
            .bundle = bundle,
            .purpose = .client,
        }, &leaf) catch return error.HandshakeFailed;
        if (leaf.len == 0 or leaf.len > self.peer_pubkey.len) {
            return error.HandshakeFailed;
        }
        @memcpy(self.peer_pubkey[0..leaf.len], leaf.pubkey[0..leaf.len]);
        self.peer_pubkey_len = leaf.len;
        self.peer_pubkey_algo = leaf.algo;
        return chain_len;
    }

    fn verifyClientCertificateVerify(
        self: *Server,
        message: []const u8,
    ) Error!void {
        if (message.len < 4 or
            message[0] != handshake.handshake_certificate_verify)
        {
            return error.HandshakeFailed;
        }
        var cursor: handshake.Cursor = .{ .buf = message[4..] };
        const scheme = cursor.readU16() catch return error.HandshakeFailed;
        const signature_len = cursor.readU16() catch
            return error.HandshakeFailed;
        const signature_value = cursor.readBytes(signature_len) catch
            return error.HandshakeFailed;
        if (!cursor.eof()) return error.HandshakeFailed;

        const transcript_hash = handshake.transcriptHash(&self.transcript);
        var signed: [64 + 33 + 1 + handshake.max_hash_len]u8 = @splat(0);
        const label = "TLS 1.3, client CertificateVerify";
        @memset(signed[0..64], 0x20);
        @memcpy(signed[64..][0..label.len], label);
        signed[64 + label.len] = 0;
        @memcpy(
            signed[64 + label.len + 1 ..][0..transcript_hash.len],
            transcript_hash.slice(),
        );
        const signed_len = 64 + label.len + 1 + transcript_hash.len;

        signature.verify(
            scheme,
            signature_value,
            signed[0..signed_len],
            self.peer_pubkey_algo,
            self.peer_pubkey[0..self.peer_pubkey_len],
        ) catch return error.HandshakeFailed;
    }

    fn readClientFinished(
        self: *Server,
        keys: *record.Keys,
        finished_key: handshake.Secret,
    ) Error!void {
        const message = try self.readHandshake(keys);
        const digest_len = self.key_schedule.suite.hashLength();
        if (message.len != 4 + digest_len) return error.HandshakeFailed;
        if (message[0] != handshake.handshake_finished) {
            return error.HandshakeFailed;
        }
        const body_len: usize = std.mem.readInt(u24, message[1..4], .big);
        if (body_len != digest_len) return error.HandshakeFailed;

        const transcript_hash = handshake.transcriptHash(&self.transcript);
        const expected = handshake.finishedVerifyData(
            self.key_schedule.suite,
            finished_key,
            transcript_hash,
        ) catch return error.HandshakeFailed;
        var padded: [handshake.max_hash_len]u8 = @splat(0);
        @memcpy(padded[0..expected.len], message[4..][0..expected.len]);
        if (!std.crypto.timing_safe.eql(
            [handshake.max_hash_len]u8,
            expected.bytes,
            padded,
        )) {
            return error.HandshakeFailed;
        }
    }

    fn readHandshake(
        self: *Server,
        keys: ?*record.Keys,
    ) Error![]const u8 {
        var handshake_len: usize = 0;
        while (true) {
            const rec = record.readRecord(
                self.input,
                &self.record_read,
            ) catch |err| return mapHandshakeReadError(err);

            if (rec[0] == record.content_type_change_cipher_spec) {
                if (rec.len != 6 or rec[5] != 1) return error.HandshakeFailed;
                continue;
            }
            if (rec[0] == record.content_type_alert) {
                return error.HandshakeFailed;
            }

            const fragment = if (keys) |key_state| blk: {
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
                break :blk opened.content;
            } else blk: {
                if (rec[0] != record.content_type_handshake) {
                    return error.HandshakeFailed;
                }
                break :blk rec[record.record_header_len..];
            };

            if (self.handshake_buffer.len - handshake_len < fragment.len) {
                return error.HandshakeFailed;
            }
            @memcpy(self.handshake_buffer[handshake_len..][0..fragment.len], fragment);
            handshake_len += fragment.len;
            if (handshake_len < 4) continue;

            const body_len: usize = std.mem.readInt(
                u24,
                self.handshake_buffer[1..4],
                .big,
            );
            if (body_len > handshake.max_handshake - 4) {
                return error.HandshakeFailed;
            }
            const total = 4 + body_len;
            if (handshake_len < total) continue;
            if (handshake_len != total) return error.HandshakeFailed;
            return self.handshake_buffer[0..total];
        }
    }

    fn readPlaintext(self: *Server, dest: []u8) Error!usize {
        if (self.eof) return error.Closed;
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
                        self.eof = true;
                        return error.Closed;
                    }
                    return error.Truncated;
                },
                else => return error.ProtocolViolation,
            };

            // RFC 8446 §5: a change_cipher_spec record after the handshake is
            // a protocol error, not a record to ignore.
            if (rec[0] == record.content_type_change_cipher_spec) {
                return error.ProtocolViolation;
            }
            // RFC 8446 §5.1: every post-handshake alert is encrypted.
            if (rec[0] != record.content_type_application_data) {
                return error.ProtocolViolation;
            }

            const opened = record.open(
                &self.read_keys,
                rec,
                &self.pending,
            ) catch return error.ProtocolViolation;
            switch (opened.content_type) {
                record.content_type_application_data => {
                    if (opened.content.len == 0) continue;
                    self.pending_len = opened.content.len;
                    self.pending_offset = 0;
                    return self.copyPending(dest);
                },
                record.content_type_alert => return self.handleAppAlert(opened.content),
                record.content_type_handshake => {
                    try self.handlePostHandshake(opened.content);
                    continue;
                },
                else => return error.ProtocolViolation,
            }
        }
    }

    fn handlePostHandshake(self: *Server, content: []const u8) Error!void {
        if (self.post_handshake.len - self.post_handshake_len < content.len) {
            return error.ProtocolViolation;
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
                return error.ProtocolViolation;
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
        self: *Server,
        message: []const u8,
    ) Error!void {
        switch (message[0]) {
            4 => {},
            handshake.handshake_key_update => {
                const request_update = handshake.parseKeyUpdate(message) catch
                    return error.ProtocolViolation;
                self.client_app_secret = handshake.updateSecret(
                    self.negotiated_suite,
                    self.client_app_secret,
                ) catch return error.ProtocolViolation;
                self.read_keys = handshake.keysFromSecret(
                    self.negotiated_suite,
                    self.client_app_secret,
                ) catch return error.ProtocolViolation;
                if (request_update) {
                    self.pending_key_update_response.store(true, .release);
                }
            },
            else => return error.ProtocolViolation,
        }
    }

    fn sendKeyUpdate(self: *Server, request_update: bool) Error!void {
        var body = handshake.Encoder.init(self.message_buffer[4..]);
        body.writeU8(@intFromBool(request_update)) catch
            return error.HandshakeFailed;
        const message = try self.finishMessage(
            handshake.handshake_key_update,
            body.len,
        );

        const sealed = record.seal(
            &self.write_keys,
            record.content_type_handshake,
            message,
            &self.record_write,
        ) catch |err| switch (err) {
            error.CounterExhausted => return error.Closed,
            error.NoSpace => return error.ProtocolViolation,
        };
        self.output.writeAll(sealed) catch return error.ProtocolViolation;
        self.server_app_secret = handshake.updateSecret(
            self.negotiated_suite,
            self.server_app_secret,
        ) catch return error.ProtocolViolation;
        self.write_keys = handshake.keysFromSecret(
            self.negotiated_suite,
            self.server_app_secret,
        ) catch return error.ProtocolViolation;
    }

    fn copyPending(self: *Server, dest: []u8) usize {
        const available = self.pending_len - self.pending_offset;
        const count = @min(dest.len, available);
        @memcpy(
            dest[0..count],
            self.pending[self.pending_offset..][0..count],
        );
        self.pending_offset += count;
        return count;
    }

    fn handleAppAlert(self: *Server, alert: []const u8) Error {
        if (alert.len != 2) return error.ProtocolViolation;
        if (alert[1] == 0) {
            self.eof = true;
            return error.Closed;
        }
        return error.ProtocolViolation;
    }

    fn writeAppData(self: *Server, bytes: []const u8) Error!void {
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
                error.NoSpace => return error.ProtocolViolation,
            };
            self.output.writeAll(sealed) catch return error.ProtocolViolation;
            offset += chunk_len;
        }
    }
};

pub const validateCredentials = credentials.validateCredentials;

const KeyExchange = struct {
    secret: [32]u8,
    public: [65]u8,
    public_len: usize,

    fn deinit(self: *KeyExchange) void {
        std.crypto.secureZero(u8, &self.secret);
    }
};

fn computeKeyExchange(
    io: std.Io,
    client_hello: handshake.ClientHello,
    group: u16,
) Error!KeyExchange {
    var result: KeyExchange = .{
        .secret = @splat(0),
        .public = @splat(0),
        .public_len = 0,
    };
    errdefer result.deinit();
    switch (group) {
        handshake.group_x25519 => {
            var key_pair = std.crypto.dh.X25519.KeyPair.generate(io);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
            result.secret = key_pair.secret_key;
            result.public[0..32].* = key_pair.public_key;
            result.public_len = 32;
            result.secret = std.crypto.dh.X25519.scalarmult(
                key_pair.secret_key,
                client_hello.x25519_public,
            ) catch return error.HandshakeFailed;
        },
        handshake.group_secp256r1 => {
            var scalar = P256.scalar.random(io, .big);
            defer std.crypto.secureZero(u8, &scalar);
            const point = P256.basePoint.mul(scalar, .big) catch
                return error.HandshakeFailed;
            const encoded = point.toUncompressedSec1();
            @memcpy(result.public[0..encoded.len], &encoded);
            result.public_len = encoded.len;
            result.secret = p256SharedSecret(
                scalar,
                client_hello.p256_public[0..client_hello.p256_public_len],
            ) catch return error.HandshakeFailed;
        },
        else => return error.HandshakeFailed,
    }
    return result;
}

fn selectCipherSuite(
    client_hello: handshake.ClientHello,
    server_suites: []const record.CipherSuite,
) Error!record.CipherSuite {
    for (server_suites) |suite| {
        if (client_hello.offersSuite(suite)) return suite;
    }
    return error.HandshakeFailed;
}

fn selectGroup(
    client_hello: handshake.ClientHello,
    preferred: ?u16,
) Error!u16 {
    if (preferred) |group| {
        return switch (group) {
            handshake.group_x25519 => if (client_hello.x25519_found)
                group
            else
                error.HandshakeFailed,
            handshake.group_secp256r1 => if (client_hello.p256_found)
                group
            else
                error.HandshakeFailed,
            else => error.HandshakeFailed,
        };
    }
    if (client_hello.x25519_found) return handshake.group_x25519;
    if (client_hello.p256_found) return handshake.group_secp256r1;
    return error.HandshakeFailed;
}

fn p256SharedSecret(scalar: [32]u8, peer: []const u8) ![32]u8 {
    const point = try P256.fromSec1(peer);
    const shared = try point.mul(scalar, .big);
    return shared.affineCoordinates().x.toBytes(.big);
}

fn selectAlpn(
    client_list: ?[]const u8,
    server_protocols: []const []const u8,
    selected_buf: *[handshake.max_alpn_protocol]u8,
    selected_len: *u8,
) Error!void {
    if (server_protocols.len == 0) return;
    const list = client_list orelse return error.HandshakeFailed;
    for (server_protocols) |server_protocol| {
        if (server_protocol.len == 0 or
            server_protocol.len > handshake.max_alpn_protocol)
        {
            return error.HandshakeFailed;
        }
        var offset: usize = 0;
        while (handshake.nextAlpnProtocol(list, &offset)) |client_protocol| {
            if (!std.mem.eql(u8, server_protocol, client_protocol)) continue;
            @memcpy(
                selected_buf[0..server_protocol.len],
                server_protocol,
            );
            selected_len.* = @intCast(server_protocol.len);
            return;
        }
    }
    return error.HandshakeFailed;
}

fn validateOptions(options: *const ServerOptions) Error!void {
    for (options.alpn_protocols) |protocol| {
        if (protocol.len == 0 or
            protocol.len > handshake.max_alpn_protocol)
        {
            return error.HandshakeFailed;
        }
    }
    if (options.read_buffer.len == 0 or options.write_buffer.len == 0) {
        return error.HandshakeFailed;
    }
    if (options.cipher_suites.len == 0) return error.HandshakeFailed;
    for (options.cipher_suites, 0..) |suite, index| {
        for (options.cipher_suites[0..index]) |previous| {
            if (previous == suite) return error.HandshakeFailed;
        }
    }
    if (options.client_auth != .none and options.client_ca == null) {
        return error.HandshakeFailed;
    }
    try validateCredentials(options.certificate_chain, options.private_key);
}

fn readerStream(
    io_r: *std.Io.Reader,
    io_w: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    const self: *Server = @alignCast(@fieldParentPtr("reader_interface", io_r));
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
    const self: *Server = @alignCast(@fieldParentPtr("writer_interface", io_w));
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

fn mapHandshakeReadError(err: record.ReadError) Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.EndOfStream,
        error.ProtocolViolation,
        error.Unexpected,
        => error.HandshakeFailed,
    };
}

const TestContext = struct {
    listener: *std.Io.net.Server,
    cert: *test_cert.Certificate,
    server_name: [64]u8 = undefined,
    server_name_len: usize = 0,
    alpn: [16]u8 = undefined,
    alpn_len: usize = 0,
    error_code: ?anyerror = null,
};

fn testServer(io: std.Io, context: *TestContext) void {
    testServerRun(io, context) catch |err| {
        context.error_code = err;
    };
}

fn testServerRun(io: std.Io, context: *TestContext) !void {
    const stream = try context.listener.accept(io);
    defer stream.close(io);

    var socket_read: [client.min_buffer_len]u8 = undefined;
    var socket_write: [client.min_buffer_len]u8 = undefined;
    var net_reader = stream.reader(io, &socket_read);
    var net_writer = stream.writer(io, &socket_write);
    var plain_read: [4096]u8 = undefined;
    var plain_write: [4096]u8 = undefined;

    var tls_server = try Server.create(
        io,
        std.testing.allocator,
        &net_reader.interface,
        &net_writer.interface,
        .{
            .certificate_chain = &.{context.cert.der},
            .private_key = context.cert.key_pair,
            .alpn_protocols = &.{"h2"},
            .read_buffer = &plain_read,
            .write_buffer = &plain_write,
        },
    );
    defer {
        tls_server.end() catch {};
        tls_server.deinit();
    }

    if (tls_server.serverName()) |name| {
        @memcpy(context.server_name[0..name.len], name);
        context.server_name_len = name.len;
    }
    if (tls_server.negotiatedProtocol()) |protocol| {
        @memcpy(context.alpn[0..protocol.len], protocol);
        context.alpn_len = protocol.len;
    }

    var buffer: [128]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    while (true) {
        const read_len = @import("reader.zig").readSome(
            tls_server.reader(),
            &buffers,
        ) catch |err| return err;
        if (read_len == 0) break;
        try tls_server.writer().writeAll(buffer[0..read_len]);
        try tls_server.flush();
    }
}

test "post-handshake change_cipher_spec is a protocol error" {
    const ccs = [_]u8{ record.content_type_change_cipher_spec, 0x03, 0x03, 0, 1, 1 };
    var input_buffer: [16]u8 = undefined;
    var calls = [_]std.testing.Reader.Call{.{ .buffer = &ccs }};
    var reader = std.testing.Reader.init(&input_buffer, &calls);

    var server: Server = undefined;
    server.input = &reader.interface;
    server.eof = false;
    server.pending_len = 0;
    server.pending_offset = 0;
    server.read_keys = .{};

    var dest: [16]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        server.readPlaintext(&dest),
    );
}

test "plaintext close_notify is a protocol error" {
    const alert = [_]u8{ record.content_type_alert, 0x03, 0x03, 0, 2, 1, 0 };
    var input_buffer: [16]u8 = undefined;
    var calls = [_]std.testing.Reader.Call{.{ .buffer = &alert }};
    var reader = std.testing.Reader.init(&input_buffer, &calls);

    var server: Server = undefined;
    server.input = &reader.interface;
    server.eof = false;
    server.pending_len = 0;
    server.pending_offset = 0;
    server.read_keys = .{};

    var dest: [16]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        server.readPlaintext(&dest),
    );
    try std.testing.expect(!server.eof);
}

test "TLS 1.3 server and client exchange application data" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try test_cert.generate(allocator, io);
    defer cert.deinit(allocator);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var context: TestContext = .{
        .listener = &listener,
        .cert = &cert,
    };
    var server_future = io.async(testServer, .{ io, &context });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer stream.close(io);

    var socket_read: [client.min_buffer_len]u8 = undefined;
    var socket_write: [client.min_buffer_len]u8 = undefined;
    var net_reader = stream.reader(io, &socket_read);
    var net_writer = stream.writer(io, &socket_write);
    var plain_read: [4096]u8 = undefined;
    var plain_write: [4096]u8 = undefined;

    var tls_client = try client.Client.init(
        io,
        &net_reader.interface,
        &net_writer.interface,
        .{
            .server_name = "localhost",
            .verify = false,
            .alpn_protocols = &.{ "http/1.1", "h2" },
            .required_alpn = "h2",
            .read_buffer = &plain_read,
            .write_buffer = &plain_write,
        },
    );
    defer tls_client.deinit();
    try std.testing.expectEqualStrings(
        "h2",
        tls_client.negotiatedProtocol() orelse "",
    );

    try tls_client.writer().writeAll("hello");
    try tls_client.writer().flush();
    try net_writer.interface.flush();

    var response: [5]u8 = undefined;
    var offset: usize = 0;
    while (offset < response.len) {
        const read_len = try tls_client.reader().readSliceShort(response[offset..]);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
    try std.testing.expectEqualStrings("hello", &response);

    try tls_client.end();
    try net_writer.interface.flush();

    _ = server_future.await(io);
    try std.testing.expectEqualStrings(
        "localhost",
        context.server_name[0..context.server_name_len],
    );
    try std.testing.expectEqualStrings(
        "h2",
        context.alpn[0..context.alpn_len],
    );
    if (context.error_code) |err| return err;
}

test "the server picks its preferred suite the client offered" {
    const hello: handshake.ClientHello = .{
        .random = @splat(0),
        .session_id = @splat(0),
        .session_id_len = 0,
        .cipher_aes_128_gcm_sha256 = true,
        .cipher_chacha20_poly1305_sha256 = true,
    };
    try std.testing.expectEqual(
        record.CipherSuite.chacha20_poly1305_sha256,
        try selectCipherSuite(hello, &.{
            .chacha20_poly1305_sha256,
            .aes_128_gcm_sha256,
        }),
    );
    try std.testing.expectEqual(
        record.CipherSuite.aes_128_gcm_sha256,
        try selectCipherSuite(hello, &.{ .aes_256_gcm_sha384, .aes_128_gcm_sha256 }),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        selectCipherSuite(hello, &.{.aes_256_gcm_sha384}),
    );
}

test "ALPN selects the first server protocol offered" {
    const client_list = [_]u8{
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2',
    };
    var selected: [handshake.max_alpn_protocol]u8 = undefined;
    var selected_len: u8 = 0;
    try selectAlpn(&client_list, &.{ "h2", "http/1.1" }, &selected, &selected_len);
    try std.testing.expectEqualStrings("h2", selected[0..selected_len]);

    try std.testing.expectError(
        error.HandshakeFailed,
        selectAlpn(&client_list, &.{"acme-tls/1"}, &selected, &selected_len),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        selectAlpn(null, &.{"h2"}, &selected, &selected_len),
    );
}

test "ALPN with no server preference leaves the protocol unset" {
    var selected: [handshake.max_alpn_protocol]u8 = undefined;
    var selected_len: u8 = 99;
    try selectAlpn(&.{ 2, 'h', '2' }, &.{}, &selected, &selected_len);
    try std.testing.expectEqual(@as(u8, 99), selected_len);
}

test "certificate path rejects a non-CA intermediate" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var root = try test_cert.generateCa(allocator, io, "marmo test root");
    defer root.deinit(allocator);
    var legit = try test_cert.generateParams(allocator, io, .{
        .common_name = "attacker-owned.example",
        .issuer_name = "marmo test root",
        .issuer_key = root.key_pair,
        .san = "attacker-owned.example",
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_server_auth = true,
    });
    defer legit.deinit(allocator);
    var fake = try test_cert.generateParams(allocator, io, .{
        .common_name = "victim.test",
        .issuer_name = "attacker-owned.example",
        .issuer_key = legit.key_pair,
        .san = "victim.test",
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_server_auth = true,
    });
    defer fake.deinit(allocator);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, root.der, now);

    var leaf: cert_path.Leaf = .{};
    const bad_chain = [_][]const u8{ fake.der, legit.der };
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&bad_chain, .{
            .host = "victim.test",
            .verify_chain = true,
            .now_sec = now,
            .bundle = &bundle,
        }, &leaf),
    );
}

test "certificate path accepts a CA:TRUE intermediate" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var root = try test_cert.generateCa(allocator, io, "marmo test root");
    defer root.deinit(allocator);
    var intermediate = try test_cert.generateParams(allocator, io, .{
        .common_name = "marmo test intermediate",
        .issuer_name = "marmo test root",
        .issuer_key = root.key_pair,
        .san = null,
        .ca = true,
        .include_basic_constraints = true,
        .include_key_usage = true,
    });
    defer intermediate.deinit(allocator);
    var leaf_cert = try test_cert.generateParams(allocator, io, .{
        .common_name = "proxy.test",
        .issuer_name = "marmo test intermediate",
        .issuer_key = intermediate.key_pair,
        .san = "proxy.test",
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_server_auth = true,
    });
    defer leaf_cert.deinit(allocator);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, root.der, now);

    var leaf: cert_path.Leaf = .{};
    const chain = [_][]const u8{ leaf_cert.der, intermediate.der };
    try cert_path.verifyServerChain(&chain, .{
        .host = "proxy.test",
        .verify_chain = true,
        .now_sec = now,
        .bundle = &bundle,
    }, &leaf);

    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&chain, .{
            .host = "wrong.test",
            .verify_chain = false,
            .now_sec = now,
            .bundle = null,
        }, &leaf),
    );
}

test "certificate path enforces pathLenConstraint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var root = try test_cert.generateCa(allocator, io, "marmo pathlen root");
    defer root.deinit(allocator);
    var inter1 = try test_cert.generateParams(allocator, io, .{
        .common_name = "marmo pathlen intermediate",
        .issuer_name = "marmo pathlen root",
        .issuer_key = root.key_pair,
        .san = null,
        .ca = true,
        .path_len = 0,
        .include_basic_constraints = true,
        .include_key_usage = true,
    });
    defer inter1.deinit(allocator);
    var inter2 = try test_cert.generateParams(allocator, io, .{
        .common_name = "marmo pathlen second",
        .issuer_name = "marmo pathlen intermediate",
        .issuer_key = inter1.key_pair,
        .san = null,
        .ca = true,
        .include_basic_constraints = true,
        .include_key_usage = true,
    });
    defer inter2.deinit(allocator);
    var leaf_cert = try test_cert.generateParams(allocator, io, .{
        .common_name = "proxy.test",
        .issuer_name = "marmo pathlen second",
        .issuer_key = inter2.key_pair,
        .san = "proxy.test",
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_server_auth = true,
    });
    defer leaf_cert.deinit(allocator);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, root.der, now);

    var leaf: cert_path.Leaf = .{};
    const chain = [_][]const u8{ leaf_cert.der, inter2.der, inter1.der };
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&chain, .{
            .host = "proxy.test",
            .verify_chain = true,
            .now_sec = now,
            .bundle = &bundle,
        }, &leaf),
    );
}

test "validateCredentials rejects malformed DER without panicking" {
    const key_pair = Ecdsa.KeyPair.generate(std.testing.io);
    const tiny = [_]u8{0x30};
    try std.testing.expectError(
        error.HandshakeFailed,
        validateCredentials(&.{&tiny}, key_pair),
    );
}

test "malformed SAN DER is rejected before host-name verification" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A one-byte extnValue makes std's unbounded DER parse read past the end.
    var cert = try test_cert.generateParams(allocator, io, .{
        .san_der = &.{0x82},
        .eku_server_auth = true,
    });
    defer cert.deinit(allocator);
    var leaf: cert_path.Leaf = .{};
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&.{cert.der}, .{
            .host = "localhost",
            .verify_chain = false,
            .now_sec = 0,
            .bundle = null,
        }, &leaf),
    );
}

test "zero-length signature BIT STRING is rejected" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try test_cert.generateParams(allocator, io, .{
        .empty_signature = true,
        .eku_server_auth = true,
    });
    defer cert.deinit(allocator);
    var leaf: cert_path.Leaf = .{};
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&.{cert.der}, .{
            .host = "localhost",
            .verify_chain = false,
            .now_sec = 0,
            .bundle = null,
        }, &leaf),
    );
}

test "non-canonical extension wrapper must not bypass SAN validation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // std compares only the low five tag bits, so 0x83 still reaches its
    // extension parser. The SAN payload below declares a dNSName longer than
    // the enclosing GeneralNames sequence.
    var cert = try test_cert.generateParams(allocator, io, .{
        .extensions_tag = 0x83,
        .san_der = &.{ 0x30, 0x03, 0x82, 0x05, 'a' },
        .eku_server_auth = true,
    });
    defer cert.deinit(allocator);
    var leaf: cert_path.Leaf = .{};
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&.{cert.der}, .{
            .host = "localhost",
            .verify_chain = false,
            .now_sec = 0,
            .bundle = null,
        }, &leaf),
    );
}

test "v1 certificates with extensions are rejected" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try test_cert.generateParams(allocator, io, .{
        .omit_version = true,
        .eku_server_auth = true,
    });
    defer cert.deinit(allocator);
    var leaf: cert_path.Leaf = .{};
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&.{cert.der}, .{
            .host = "localhost",
            .verify_chain = false,
            .now_sec = 0,
            .bundle = null,
        }, &leaf),
    );
}

test "unique identifiers before extensions are rejected" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try test_cert.generateParams(allocator, io, .{
        .unique_id = true,
        .eku_server_auth = true,
    });
    defer cert.deinit(allocator);
    var leaf: cert_path.Leaf = .{};
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&.{cert.der}, .{
            .host = "localhost",
            .verify_chain = false,
            .now_sec = 0,
            .bundle = null,
        }, &leaf),
    );
}

test "the legacy SAN OID is rejected before std parses it" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try test_cert.generateParams(allocator, io, .{
        .san_oid = &.{ 0x55, 0x1d, 0x07 },
        .san_der = &.{0x82},
        .eku_server_auth = true,
    });
    defer cert.deinit(allocator);
    var leaf: cert_path.Leaf = .{};
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&.{cert.der}, .{
            .host = "localhost",
            .verify_chain = false,
            .now_sec = 0,
            .bundle = null,
        }, &leaf),
    );
}

test "an expired trust anchor is rejected" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var root = try test_cert.generateParams(allocator, io, .{
        .common_name = "marmo expired root",
        .san = null,
        .ca = true,
        .include_basic_constraints = true,
        .include_key_usage = true,
        .expired = true,
    });
    defer root.deinit(allocator);
    var leaf_cert = try test_cert.generateParams(allocator, io, .{
        .common_name = "proxy.test",
        .issuer_name = "marmo expired root",
        .issuer_key = root.key_pair,
        .san = "proxy.test",
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_server_auth = true,
    });
    defer leaf_cert.deinit(allocator);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try test_cert.addTrustedDer(&bundle, allocator, root.der, 946684800); // 2000-01-01

    var leaf: cert_path.Leaf = .{};
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyServerChain(&.{leaf_cert.der}, .{
            .host = "proxy.test",
            .verify_chain = true,
            .now_sec = now,
            .bundle = &bundle,
        }, &leaf),
    );
}

test "client certificate name constraints are enforced" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var root = try test_cert.generateParams(allocator, io, .{
        .common_name = "marmo nc root",
        .san = null,
        .ca = true,
        .include_basic_constraints = true,
        .include_key_usage = true,
        .name_constraints_dns = ".corp.example",
    });
    defer root.deinit(allocator);
    var client_cert = try test_cert.generateParams(allocator, io, .{
        .common_name = "client",
        .issuer_name = "marmo nc root",
        .issuer_key = root.key_pair,
        .san = "evil.test",
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_client_auth = true,
    });
    defer client_cert.deinit(allocator);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, root.der, now);

    var leaf: cert_path.Leaf = .{};
    try std.testing.expectError(
        error.CertificateRejected,
        cert_path.verifyClientChain(&.{client_cert.der}, .{
            .host = null,
            .verify_chain = true,
            .now_sec = now,
            .bundle = &bundle,
            .purpose = .client,
        }, &leaf),
    );
}
