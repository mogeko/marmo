//! TLS 1.3 server.
//!
//! Scope: X25519, AES-128-GCM/SHA-256, ECDSA P-256 certificates, no client auth,
//! no PSK/session tickets, no HelloRetryRequest, no 0-RTT. The API operates on
//! `std.Io.Reader`/`Writer` so the server has no dependency on marmo.

const std = @import("std");
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const client = @import("client.zig");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const test_cert = @import("test_cert.zig");

pub const Error = error{
    Canceled,
    HandshakeFailed,
    ProtocolViolation,
    Closed,
    OutOfMemory,
};

pub const ServerOptions = struct {
    /// DER certificates, leaf first.
    certificate_chain: []const []const u8,
    private_key: Ecdsa.KeyPair,
    /// ALPN protocols in server preference order. Empty disables selection.
    alpn_protocols: []const []const u8 = &.{},
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
    transcript: handshake.Hash,
    key_schedule: handshake.KeySchedule,
    read_keys: record.Keys = .{},
    write_keys: record.Keys = .{},
    reader_interface: std.Io.Reader,
    writer_interface: std.Io.Writer,
    server_name_buf: [handshake.max_server_name]u8 = undefined,
    server_name_len: u8 = 0,
    alpn_buf: [handshake.max_alpn_protocol]u8 = undefined,
    alpn_len: u8 = 0,
    pending: [record.max_ciphertext]u8 = undefined,
    pending_len: usize = 0,
    pending_offset: usize = 0,
    record_read: [record.max_record]u8 = undefined,
    record_write: [record.max_record]u8 = undefined,
    handshake_buffer: [handshake.max_handshake]u8 = undefined,
    message_buffer: [handshake.max_handshake]u8 = undefined,
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
        try validateOptions(options);

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
        };
        try self.runHandshake(io, options);
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

    pub fn readError(self: *const Server) ?Error {
        return self.read_error;
    }

    pub fn writeError(self: *const Server) ?Error {
        return self.write_error;
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

    fn runHandshake(self: *Server, io: std.Io, options: ServerOptions) Error!void {
        const client_hello_message = try self.readHandshake(null);
        const client_hello = handshake.parseClientHello(
            client_hello_message,
            &self.server_name_buf,
        ) catch return error.HandshakeFailed;
        if (client_hello.server_name) |name| {
            self.server_name_len = @intCast(name.len);
        }
        try selectAlpn(
            client_hello.alpn_protocols,
            options.alpn_protocols,
            &self.alpn_buf,
            &self.alpn_len,
        );
        self.transcript.update(client_hello_message);

        var key_pair = std.crypto.dh.X25519.KeyPair.generate(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key));
        var shared_secret = std.crypto.dh.X25519.scalarmult(
            key_pair.secret_key,
            client_hello.x25519_public,
        ) catch return error.HandshakeFailed;
        defer std.crypto.secureZero(u8, &shared_secret);

        try self.sendServerHello(io, client_hello, key_pair.public_key);
        const hello_hash = handshake.transcriptHash(&self.transcript);
        self.key_schedule = handshake.KeySchedule.derive(
            shared_secret,
            hello_hash,
        );
        self.write_keys = self.key_schedule.server_hs_keys;
        try self.sendServerFlight(options.certificate_chain, options.private_key);
        self.output.flush() catch return error.HandshakeFailed;

        const handshake_hash = handshake.transcriptHash(&self.transcript);
        var client_app_secret = self.key_schedule.clientAppSecret(handshake_hash);
        var server_app_secret = self.key_schedule.serverAppSecret(handshake_hash);
        defer std.crypto.secureZero(u8, &client_app_secret);
        defer std.crypto.secureZero(u8, &server_app_secret);

        self.write_keys = handshake.keysFromSecret(server_app_secret);
        try self.readClientFinished(
            &self.key_schedule.client_hs_keys,
            self.key_schedule.client_finished_key,
            handshake_hash,
        );
        self.read_keys = handshake.keysFromSecret(client_app_secret);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key_schedule));
    }

    fn sendServerHello(
        self: *Server,
        io: std.Io,
        client_hello: handshake.ClientHello,
        public_key: [32]u8,
    ) Error!void {
        var random: [32]u8 = undefined;
        std.Io.randomSecure(io, &random) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.HandshakeFailed,
        };

        var extension_buf: [64]u8 = undefined;
        var extensions = handshake.Encoder.init(&extension_buf);
        try extensions.writeU16(0x002b); // supported_versions
        try extensions.writeU16(2);
        try extensions.writeU16(handshake.tls_1_3);
        try extensions.writeU16(0x0033); // key_share
        try extensions.writeU16(36);
        try extensions.writeU16(handshake.group_x25519);
        try extensions.writeU16(32);
        try extensions.append(&public_key);

        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.writeU16(0x0303); // legacy_version
        try body.append(&random);
        try body.writeU8(client_hello.session_id_len);
        try body.append(client_hello.session_id[0..client_hello.session_id_len]);
        try body.writeU16(handshake.cipher_aes_128_gcm_sha256);
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
        // Middlebox-compatibility CCS: it is not part of the transcript, but
        // the std client switches its read cipher state on it.
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
        private_key: Ecdsa.KeyPair,
    ) Error!void {
        try self.sendEncryptedExtensions();
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
        private_key: Ecdsa.KeyPair,
    ) Error!void {
        const transcript_hash = handshake.transcriptHash(&self.transcript);
        const context = "TLS 1.3, server CertificateVerify";
        var signed: [64 + context.len + 1 + 32]u8 = undefined;
        @memset(signed[0..64], 0x20);
        @memcpy(signed[64..][0..context.len], context);
        signed[64 + context.len] = 0;
        @memcpy(signed[64 + context.len + 1 ..][0..32], &transcript_hash);

        const signature = private_key.sign(&signed, null) catch
            return error.HandshakeFailed;
        var der_buffer: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = signature.toDer(&der_buffer);

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
            self.key_schedule.server_finished_key,
            transcript_hash,
        );

        var body = handshake.Encoder.init(self.message_buffer[4..]);
        try body.append(&verify_data);
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

    fn readClientFinished(
        self: *Server,
        keys: *record.Keys,
        finished_key: [32]u8,
        handshake_hash: [32]u8,
    ) Error!void {
        const message = try self.readHandshake(keys);
        if (message.len != 4 + 32) return error.HandshakeFailed;
        if (message[0] != handshake.handshake_finished) {
            return error.HandshakeFailed;
        }
        const body_len: usize = std.mem.readInt(u24, message[1..4], .big);
        if (body_len != 32) return error.HandshakeFailed;

        const expected = handshake.finishedVerifyData(
            finished_key,
            handshake_hash,
        );
        const actual: [32]u8 = message[4..36].*;
        if (!std.crypto.timing_safe.eql([32]u8, expected, actual)) {
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
            ) catch |err| return mapAppReadError(err);

            // RFC 8446 §5: a change_cipher_spec record after the handshake is
            // a protocol error, not a record to ignore.
            if (rec[0] == record.content_type_change_cipher_spec) {
                return error.ProtocolViolation;
            }
            if (rec[0] == record.content_type_alert) {
                return self.handleAppAlert(rec[record.record_header_len..]);
            }
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
                else => return error.ProtocolViolation,
            }
        }
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

/// Checks chain bounds, the leaf key algorithm, and that the key pair matches
/// the leaf certificate. Useful for config validation before a listener starts.
pub fn validateCredentials(
    certificate_chain: []const []const u8,
    private_key: Ecdsa.KeyPair,
) Error!void {
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

fn validateOptions(options: ServerOptions) Error!void {
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

fn mapAppReadError(err: record.ReadError) Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.EndOfStream => error.Closed,
        error.ProtocolViolation,
        error.Unexpected,
        => error.ProtocolViolation,
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

test "plaintext close_notify is reported as clean EOF" {
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
    try std.testing.expectError(error.Closed, server.readPlaintext(&dest));
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
