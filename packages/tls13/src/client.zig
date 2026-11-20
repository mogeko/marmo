//! TLS 1.3 client session over a `std.Io.Reader`/`Writer` pair.
//!
//! Scope matches the in-tree server: X25519, AES-128-GCM/SHA-256, server
//! certificates (ECDSA, Ed25519, RSA) with optional chain/host verification,
//! and ALPN. There is no client authentication, PSK, ticket, KeyUpdate, or
//! 0-RTT.

const std = @import("std");
const Ca = @import("ca.zig").Ca;
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const cert_path = @import("cert_path.zig");
const Certificate = std.crypto.Certificate;
const Ecdsa = std.crypto.sign.ecdsa;

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

const max_pubkey = 1024;
const max_alpn_list = 1024;

pub const Client = struct {
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    transcript: handshake.Hash,
    key_schedule: handshake.KeySchedule,
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
            .transcript = handshake.Hash.init(.{}),
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

    pub fn readError(self: *const Client) ?InitError {
        return self.read_error;
    }

    pub fn writeError(self: *const Client) ?InitError {
        return self.write_error;
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
        var session_id: [32]u8 = undefined;
        var random: [32]u8 = undefined;
        std.Io.randomSecure(self.io, &random) catch return self.randomError();
        std.Io.randomSecure(self.io, &session_id) catch return self.randomError();

        var key_pair = std.crypto.dh.X25519.KeyPair.generate(self.io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key));

        const client_hello = try self.buildClientHello(
            options,
            random,
            session_id,
            key_pair.public_key,
        );
        self.transcript.update(client_hello);
        record.writePlain(
            self.output,
            record.content_type_handshake,
            client_hello,
        ) catch return error.HandshakeFailed;
        self.output.flush() catch return error.HandshakeFailed;

        const server_hello_message = try self.readHandshakeMessage(null);
        const server_hello = handshake.parseServerHello(server_hello_message) catch
            return error.HandshakeFailed;
        if (server_hello.hello_retry_request) return error.HandshakeFailed;
        if (server_hello.session_id_len != session_id.len) {
            return error.HandshakeFailed;
        }
        if (!std.mem.eql(u8, &server_hello.session_id, &session_id)) {
            return error.HandshakeFailed;
        }
        self.transcript.update(server_hello_message);

        var shared_secret = std.crypto.dh.X25519.scalarmult(
            key_pair.secret_key,
            server_hello.x25519_public,
        ) catch return error.HandshakeFailed;
        defer std.crypto.secureZero(u8, &shared_secret);
        const hello_hash = handshake.transcriptHash(&self.transcript);
        self.key_schedule = handshake.KeySchedule.derive(
            shared_secret,
            hello_hash,
        );

        try self.readServerFlight(options, &self.key_schedule.server_hs_keys);

        const handshake_hash = handshake.transcriptHash(&self.transcript);
        var client_app_secret = self.key_schedule.clientAppSecret(handshake_hash);
        var server_app_secret = self.key_schedule.serverAppSecret(handshake_hash);
        defer std.crypto.secureZero(u8, &client_app_secret);
        defer std.crypto.secureZero(u8, &server_app_secret);

        try self.sendClientFinished(
            &self.key_schedule.client_hs_keys,
            self.key_schedule.client_finished_key,
            handshake_hash,
        );
        self.read_keys = handshake.keysFromSecret(server_app_secret);
        self.write_keys = handshake.keysFromSecret(client_app_secret);
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
        public_key: [32]u8,
    ) InitError![]const u8 {
        var extension_buffer: [max_alpn_list + 512]u8 = undefined;
        var extensions = handshake.Encoder.init(&extension_buffer);
        try writeExtensions(&extensions, options, public_key);

        var body = handshake.Encoder.init(self.handshake_buffer[4..]);
        try body.writeU16(0x0303);
        try body.append(&random);
        try body.writeU8(32);
        try body.append(&session_id);
        try body.writeU16(2);
        try body.writeU16(handshake.cipher_aes_128_gcm_sha256);
        try body.writeU8(1);
        try body.writeU8(0);
        try body.writeU16(@intCast(extensions.len));
        try body.append(extensions.bytes());
        return self.finishMessage(handshake.handshake_client_hello, body.len) catch
            return error.HandshakeFailed;
    }

    fn readServerFlight(
        self: *Client,
        options: Options,
        keys: *record.Keys,
    ) InitError!void {
        const encrypted_extensions = try self.readHandshakeMessage(keys);
        try self.parseEncryptedExtensions(options, encrypted_extensions);
        self.transcript.update(encrypted_extensions);

        const certificate_message = try self.readHandshakeMessage(keys);
        self.parseCertificate(options, certificate_message) catch
            return error.HandshakeFailed;
        self.transcript.update(certificate_message);

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
        var chain_len: usize = 0;
        while (!list.eof()) {
            if (chain_len == chain.len) return error.HandshakeFailed;
            const cert_len = list.readU24() catch return error.HandshakeFailed;
            const der = list.readBytes(cert_len) catch return error.HandshakeFailed;
            const extensions_len = list.readU16() catch
                return error.HandshakeFailed;
            _ = list.readBytes(extensions_len) catch return error.HandshakeFailed;
            chain[chain_len] = der;
            chain_len += 1;
        }

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
        const signature = cursor.readBytes(signature_len) catch
            return error.HandshakeFailed;
        if (!cursor.eof()) return error.HandshakeFailed;

        const transcript_hash = handshake.transcriptHash(&self.transcript);
        const context = "TLS 1.3, server CertificateVerify";
        var signed: [64 + context.len + 1 + 32]u8 = undefined;
        @memset(signed[0..64], 0x20);
        @memcpy(signed[64..][0..context.len], context);
        signed[64 + context.len] = 0;
        @memcpy(signed[64 + context.len + 1 ..][0..32], &transcript_hash);

        verifyServerSignature(
            scheme,
            signature,
            &signed,
            self.pubkey_algo,
            self.pubkey[0..self.pubkey_len],
        ) catch return error.HandshakeFailed;
    }

    fn verifyServerFinished(
        self: *Client,
        message: []const u8,
    ) InitError!void {
        if (message.len != 4 + 32 or
            message[0] != handshake.handshake_finished)
        {
            return error.HandshakeFailed;
        }
        const transcript_hash = handshake.transcriptHash(&self.transcript);
        const expected = handshake.finishedVerifyData(
            self.key_schedule.server_finished_key,
            transcript_hash,
        );
        const actual: [32]u8 = message[4..36].*;
        if (!std.crypto.timing_safe.eql([32]u8, expected, actual)) {
            return error.HandshakeFailed;
        }
    }

    fn sendClientFinished(
        self: *Client,
        keys: *record.Keys,
        finished_key: [32]u8,
        transcript_hash: [32]u8,
    ) InitError!void {
        const verify_data = handshake.finishedVerifyData(
            finished_key,
            transcript_hash,
        );
        var body = handshake.Encoder.init(self.handshake_buffer[4..]);
        body.append(&verify_data) catch return error.HandshakeFailed;
        const message = self.finishMessage(
            handshake.handshake_finished,
            body.len,
        ) catch return error.HandshakeFailed;

        self.write_keys = keys.*;
        self.write_keys.seq = 0;
        const sealed = record.seal(
            &self.write_keys,
            record.content_type_handshake,
            message,
            &self.record_write,
        ) catch return error.HandshakeFailed;
        self.output.writeAll(sealed) catch return error.HandshakeFailed;
        self.output.flush() catch return error.HandshakeFailed;
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
                    try rejectKeyUpdate(opened.content);
                    continue;
                },
                else => return error.HandshakeFailed,
            }
        }
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
        var offset: usize = 0;
        while (offset < bytes.len) {
            const chunk_len = @min(bytes.len - offset, record.max_plaintext);
            const chunk = bytes[offset..][0..chunk_len];
            const sealed = record.seal(
                &self.write_keys,
                record.content_type_application_data,
                chunk,
                &self.record_write,
            ) catch return error.HandshakeFailed;
            self.output.writeAll(sealed) catch return error.HandshakeFailed;
            offset += chunk_len;
        }
    }

    fn randomError(self: *Client) InitError {
        _ = self;
        return error.HandshakeFailed;
    }
};

fn validateOptions(options: Options) InitError!void {
    if (options.read_buffer.len == 0 or options.write_buffer.len == 0) {
        return error.HandshakeFailed;
    }
    if (options.verify and
        (options.server_name == null or options.ca == null))
    {
        return error.HandshakeFailed;
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
    public_key: [32]u8,
) InitError!void {
    try writeServerName(extensions, options.server_name);
    try extensions.writeU16(handshake.extension_supported_versions);
    try extensions.writeU16(3);
    try extensions.writeU8(2);
    try extensions.writeU16(handshake.tls_1_3);
    try writeSignatureAlgorithms(extensions);
    try extensions.writeU16(0x000a); // supported_groups
    try extensions.writeU16(4);
    try extensions.writeU16(2);
    try extensions.writeU16(handshake.group_x25519);
    try extensions.writeU16(handshake.extension_key_share);
    try extensions.writeU16(38);
    try extensions.writeU16(36);
    try extensions.writeU16(handshake.group_x25519);
    try extensions.writeU16(32);
    try extensions.append(&public_key);
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

fn verifyServerSignature(
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

fn rejectKeyUpdate(content: []const u8) InitError!void {
    var offset: usize = 0;
    while (offset < content.len) {
        if (content.len - offset < 4) return error.HandshakeFailed;
        const body_len: usize = std.mem.readInt(
            u24,
            content[offset + 1 ..][0..3],
            .big,
        );
        if (body_len > content.len - offset - 4) {
            return error.HandshakeFailed;
        }
        if (content[offset] == 24) return error.HandshakeFailed;
        offset += 4 + body_len;
    }
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

test "post-handshake KeyUpdate is rejected even after a ticket" {
    const content = [_]u8{
        4, 0, 0, 0, // NewSessionTicket header, empty body
        24, 0, 0, 0, // KeyUpdate header, empty body
    };
    try std.testing.expectError(
        error.HandshakeFailed,
        rejectKeyUpdate(&content),
    );
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
