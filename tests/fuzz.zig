//! Bounded fuzz targets for every wire decoder and handshake parser.
//!
//! The same target functions run three ways:
//!   * as deterministic corpus smoke tests in `zig build test`;
//!   * under Zig's built-in fuzzer via `zig build test --fuzz`;
//!   * from `zig build fuzz`, which drives fixed seeds and iteration counts.
//!
//! Targets never perform network I/O. Inputs are bounded stack buffers and any
//! allocator use is either per-iteration or explicitly freed, so a hostile
//! input cannot grow memory without bound.

const std = @import("std");
const marmo = @import("marmo");
const tls13 = @import("tls13");
const http2 = @import("http2");
const ws = @import("ws");
const Cidr = marmo.Cidr;
const Endpoint = marmo.Endpoint;
const config = marmo.internal.config;
const trojan = marmo.internal.trojan;
const vless = marmo.internal.vless;
const xudp = marmo.internal.xudp;
const s2022 = marmo.internal.shadowsocks2022;
const tls_credentials = marmo.internal.tls_credentials;
const socks5 = marmo.internal.socks5;
const http_inbound = marmo.internal.http;
const Action = marmo.Action;
const Dialer = marmo.Dialer;
const Dispatch = marmo.internal.dispatch.Dispatch;
const Metadata = marmo.Metadata;
const Metrics = marmo.Metrics;
const PacketConn = marmo.PacketConn;
const Stream = marmo.Stream;

const max_input = 128 * 1024;
const http_headers_max = 8192;
const http_head_max = http_headers_max + 1024;

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    cert: ?*tls13.test_cert.Certificate = null,
};

pub const Target = struct {
    name: []const u8,
    max_input: usize,
    run: *const fn (Context, *std.testing.Smith) anyerror!void,
};

/// A trivially deterministic in-memory `Stream`. Reads never block; the input
/// is the fuzz bytes and the output is discarded (or bounded by the caller).
const MemoryStream = struct {
    input: []const u8,
    read_offset: usize = 0,
    output: []u8,
    output_len: usize = 0,

    fn stream(self: *MemoryStream) Stream {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn read(
        ctx: *anyopaque,
        io: std.Io,
        buffers: [][]u8,
    ) Stream.ReadError!usize {
        _ = io;
        const self: *MemoryStream = @ptrCast(@alignCast(ctx));
        var copied: usize = 0;
        for (buffers) |buffer| {
            const remaining = self.input.len - self.read_offset - copied;
            const count = @min(buffer.len, remaining);
            @memcpy(buffer[0..count], self.input[self.read_offset + copied ..][0..count]);
            copied += count;
            if (self.read_offset + copied == self.input.len) break;
        }
        self.read_offset += copied;
        return copied;
    }

    fn write(
        ctx: *anyopaque,
        io: std.Io,
        buffers: []const []const u8,
    ) Stream.WriteError!usize {
        _ = io;
        const self: *MemoryStream = @ptrCast(@alignCast(ctx));
        var total: usize = 0;
        for (buffers) |buffer| {
            if (buffer.len > self.output.len - self.output_len) {
                return error.BrokenPipe;
            }
            @memcpy(self.output[self.output_len..][0..buffer.len], buffer);
            self.output_len += buffer.len;
            total += buffer.len;
        }
        return total;
    }

    fn shutdown(
        ctx: *anyopaque,
        io: std.Io,
        how: Stream.ShutdownHow,
    ) Stream.ShutdownError!void {
        _ = ctx;
        _ = io;
        _ = how;
    }

    fn close(ctx: *anyopaque, io: std.Io) void {
        _ = ctx;
        _ = io;
    }

    fn endpoint(ctx: *anyopaque) Endpoint {
        _ = ctx;
        return .{ .ip = .{ .ip4 = .loopback(1) } };
    }

    const vtable: Stream.VTable = .{
        .read = read,
        .write = write,
        .shutdown = shutdown,
        .close = close,
        .local = endpoint,
        .remote = endpoint,
    };
};

const FakeDispatch = struct {
    metrics: Metrics = .{},

    fn dispatch(self: *FakeDispatch) Dispatch {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn route(ctx: *anyopaque, metadata: *const Metadata) Action {
        _ = ctx;
        _ = metadata;
        return .{ .reject = .rule };
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        tag: []const u8,
        target: Endpoint,
    ) Dialer.ConnectError!Stream {
        _ = ctx;
        _ = io;
        _ = tag;
        _ = target;
        return error.Unsupported;
    }

    fn connectPacket(
        ctx: *anyopaque,
        io: std.Io,
        tag: []const u8,
        target: Endpoint,
    ) Dialer.ConnectError!PacketConn {
        _ = ctx;
        _ = io;
        _ = tag;
        _ = target;
        return error.Unsupported;
    }

    fn metricsOf(ctx: *anyopaque) *Metrics {
        const self: *FakeDispatch = @ptrCast(@alignCast(ctx));
        return &self.metrics;
    }

    const vtable: Dispatch.VTable = .{
        .route = route,
        .connect = connect,
        .connect_packet = connectPacket,
        .metrics = metricsOf,
    };
};

fn fuzzWsFrame(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [ws.max_frame_payload]u8 = undefined;
    const len = smith.slice(&input);
    var reader = std.Io.Reader.fixed(input[0..len]);
    var payload: [ws.max_frame_payload]u8 = undefined;
    _ = ws.frame.read(&reader, .server, &payload) catch |err| switch (err) {
        error.Canceled,
        error.EndOfStream,
        error.ProtocolViolation,
        error.Unexpected,
        => return,
    };
}

fn fuzzWsHandshake(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [ws.max_handshake]u8 = undefined;
    const len = smith.slice(&input);
    var reader = std.Io.Reader.fixed(input[0..len]);
    var head: ws.handshake.Head = .{};
    ws.handshake.readHead(&reader, &head) catch return;
    _ = ws.handshake.headerValue(head.bytes(), "sec-websocket-key");
    _ = ws.handshake.headerValue(head.bytes(), "upgrade");
}

fn fuzzHttp2Frame(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [http2.max_frame_size + http2.frame.header_len]u8 = undefined;
    const len = smith.slice(&input);
    var reader = std.Io.Reader.fixed(input[0..len]);
    var payload: [http2.max_frame_size]u8 = undefined;
    _ = http2.frame.read(&reader, &payload) catch |err| switch (err) {
        error.Canceled,
        error.EndOfStream,
        error.ProtocolViolation,
        error.Unexpected,
        => return,
    };
}

fn fuzzHttp2Hpack(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [http2.max_header_block]u8 = undefined;
    const len = smith.slice(&input);
    var decoder = http2.hpack.Decoder.init();
    var storage: [http2.max_header_block]u8 = undefined;
    var headers: [http2.hpack.max_headers]http2.Header = undefined;
    _ = decoder.decode(input[0..len], &storage, &headers) catch |err| switch (err) {
        error.Malformed, error.OutOfMemory => return,
    };
}

fn fuzzTlsClientHello(_: Context, smith: *std.testing.Smith) anyerror!void {
    var buffer: [tls13.handshake.max_handshake]u8 = undefined;
    const len = smith.slice(&buffer);
    var server_name: [tls13.handshake.max_server_name]u8 = undefined;
    _ = tls13.handshake.parseClientHello(
        buffer[0..len],
        &server_name,
    ) catch |err| switch (err) {
        error.HandshakeFailed => return,
    };
}

fn mutate(
    input: []const u8,
    smith: *std.testing.Smith,
    out: []u8,
) []const u8 {
    @memcpy(out[0..input.len], input);
    const mutations = smith.valueRangeAtMost(u8, 1, 8);
    var index: u8 = 0;
    while (index < mutations) : (index += 1) {
        const at = smith.index(out[0..input.len].len);
        out[at] = smith.value(u8);
    }
    return out[0..input.len];
}

fn fuzzTlsClientHelloMutated(_: Context, smith: *std.testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const input = mutate(tls_client_hello_fixture, smith, &buffer);
    var server_name: [tls13.handshake.max_server_name]u8 = undefined;
    _ = tls13.handshake.parseClientHello(input, &server_name) catch |err| switch (err) {
        error.HandshakeFailed => return,
    };
}

fn fuzzTlsRecordRead(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [tls13.record.max_record]u8 = undefined;
    const len = smith.slice(&input);
    var calls = [_]std.testing.Reader.Call{.{ .buffer = input[0..len] }};
    var reader_buffer: [256]u8 = undefined;
    var reader = std.testing.Reader.init(&reader_buffer, &calls);

    var record_buffer: [tls13.record.max_record]u8 = undefined;
    const rec = tls13.record.readRecord(
        &reader.interface,
        &record_buffer,
    ) catch |err| switch (err) {
        error.Canceled, error.EndOfStream, error.ProtocolViolation, error.Unexpected => return,
    };
    if (rec.len > record_buffer.len) return error.FuzzInvariant;
}

fn fuzzTlsRecordOpen(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [tls13.record.max_record]u8 = undefined;
    const len = smith.slice(&input);
    var keys: tls13.record.Keys = .{ .seq = smith.value(u64) };
    smith.bytes(&keys.key);
    smith.bytes(&keys.iv);

    var out: [tls13.record.max_ciphertext]u8 = undefined;
    _ = tls13.record.open(
        &keys,
        input[0..len],
        &out,
    ) catch |err| switch (err) {
        error.BadRecord, error.CounterExhausted, error.ProtocolViolation => return,
    };
}

fn fuzzTlsRecordOpenValid(_: Context, smith: *std.testing.Smith) anyerror!void {
    var plain: [tls13.record.max_plaintext]u8 = undefined;
    const len = smith.slice(&plain);
    var keys: tls13.record.Keys = .{
        .seq = smith.valueRangeAtMost(u64, 0, std.math.maxInt(u64) - 2),
    };
    smith.bytes(&keys.key);
    smith.bytes(&keys.iv);
    const inner_type = smith.valueRangeAtMost(u8, 20, 23);

    var sealed_buffer: [tls13.record.max_record]u8 = undefined;
    const sealed = tls13.record.seal(
        &keys,
        inner_type,
        plain[0..len],
        &sealed_buffer,
    ) catch return;

    var open_keys = keys;
    open_keys.seq = keys.seq - 1;
    var opened_buffer: [tls13.record.max_ciphertext]u8 = undefined;
    const opened = tls13.record.open(
        &open_keys,
        sealed,
        &opened_buffer,
    ) catch return;
    if (opened.content_type != inner_type) return error.FuzzInvariant;
    if (!std.mem.eql(u8, opened.content, plain[0..len])) return error.FuzzInvariant;

    var exhausted: tls13.record.Keys = .{ .seq = std.math.maxInt(u64) };
    _ = tls13.record.seal(
        &exhausted,
        23,
        "",
        &sealed_buffer,
    ) catch |err| switch (err) {
        error.CounterExhausted => return,
        error.NoSpace => return error.FuzzInvariant,
    };
    return error.FuzzInvariant;
}

fn fuzzTlsRecordSeal(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [tls13.record.max_plaintext]u8 = undefined;
    const len = smith.slice(&input);
    var keys: tls13.record.Keys = .{ .seq = smith.value(u64) };
    smith.bytes(&keys.key);
    smith.bytes(&keys.iv);

    var out: [tls13.record.max_record]u8 = undefined;
    const sealed = tls13.record.seal(
        &keys,
        smith.value(u8),
        input[0..len],
        &out,
    ) catch |err| switch (err) {
        error.CounterExhausted, error.NoSpace => return,
    };
    if (sealed.len != tls13.record.record_header_len + len + 1 + tls13.record.tag_len) {
        return error.FuzzInvariant;
    }
}

fn runTlsServerHandshake(ctx: Context, input: []const u8) anyerror!void {
    const cert = ctx.cert orelse return error.FuzzMissingCertificate;
    var calls = [_]std.testing.Reader.Call{.{ .buffer = input }};
    var reader_buffer: [256]u8 = undefined;
    var reader = std.testing.Reader.init(&reader_buffer, &calls);

    var output_buffer: [32 * 1024]u8 = undefined;
    var output = std.Io.Writer.fixed(&output_buffer);
    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;

    const result = tls13.Server.create(
        ctx.io,
        ctx.allocator,
        &reader.interface,
        &output,
        .{
            .certificate_chain = &.{cert.der},
            .private_key = cert.key_pair,
            .read_buffer = &read_buffer,
            .write_buffer = &write_buffer,
        },
    );
    if (result) |server| {
        var value = server;
        value.end() catch {};
        value.deinit();
    } else |err| switch (err) {
        error.Canceled,
        error.HandshakeFailed,
        error.ProtocolViolation,
        error.Closed,
        error.OutOfMemory,
        => return,
    }
}

fn fuzzTlsServerHandshake(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [tls13.handshake.max_handshake]u8 = undefined;
    const len = smith.slice(&input);
    return runTlsServerHandshake(ctx, input[0..len]);
}

fn fuzzTlsServerHandshakeMutated(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const input = mutate(tls_client_hello_record, smith, &buffer);
    return runTlsServerHandshake(ctx, input);
}

fn fuzzTlsCredentials(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var buffer: [4096]u8 = undefined;
    const len = smith.slice(&buffer);
    const split = if (len == 0) 0 else smith.index(len);

    const chain = tls_credentials.parseCertificateChain(
        ctx.allocator,
        buffer[0..split],
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.InvalidCredentials => return,
    };
    defer tls_credentials.freeCertificateChain(ctx.allocator, chain);

    var key = tls_credentials.parsePrivateKey(
        ctx.allocator,
        buffer[split..len],
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.InvalidCredentials => return,
    };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));

    if (ctx.cert) |cert| {
        tls13.validateCredentials(chain, cert.key_pair) catch return;
    }

    // Treat the whole input as an untrusted DER chain for chain validation.
    const untrusted = [_][]const u8{buffer[0..len]};
    if (ctx.cert) |cert| {
        tls13.validateCredentials(&untrusted, cert.key_pair) catch return;
    }
}

fn fuzzTlsKeySchedule(_: Context, smith: *std.testing.Smith) anyerror!void {
    var shared_secret: [32]u8 = undefined;
    var hello_hash: [32]u8 = undefined;
    smith.bytes(&shared_secret);
    smith.bytes(&hello_hash);
    const schedule = tls13.handshake.KeySchedule.derive(shared_secret, hello_hash);
    _ = tls13.handshake.finishedVerifyData(
        schedule.server_finished_key,
        hello_hash,
    );
    _ = schedule.clientAppSecret(hello_hash);
    _ = schedule.serverAppSecret(hello_hash);
}

fn fuzzTrojanAuth(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [trojan.auth_prefix_len]u8 = undefined;
    const len = smith.slice(&input);
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    const hash = trojan.hashPassword("password");
    var prefix: [trojan.auth_prefix_len]u8 = undefined;
    _ = trojan.readAuthPrefix(
        ctx.io,
        memory.stream(),
        &hash,
        &prefix,
    ) catch return;
}

fn fuzzTrojanRequest(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const len = smith.slice(&input);
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    var domain: [trojan.max_domain_len]u8 = undefined;
    _ = trojan.readRequestHeader(
        ctx.io,
        memory.stream(),
        &domain,
    ) catch return;
}

fn fuzzTrojanUdpFrame(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [trojan.max_udp_payload]u8 = undefined;
    const len = smith.slice(&input);
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    var buffer: [trojan.max_udp_payload]u8 = undefined;
    var domain: [trojan.max_domain_len]u8 = undefined;
    _ = trojan.readUdpPacket(
        ctx.io,
        memory.stream(),
        &buffer,
        &domain,
    ) catch return;
}

fn fuzzVlessRequest(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const len = smith.slice(&input);
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    const uuid = try vless.parseUuid("00112233-4455-6677-8899-aabbccddeeff");
    var domain: [vless.max_domain_len]u8 = undefined;
    _ = vless.readRequestHeader(
        ctx.io,
        memory.stream(),
        &uuid,
        &domain,
    ) catch return;

    var memory2: MemoryStream = .{ .input = input[0..len], .output = &output };
    var addons: [vless.addon_len_max]u8 = undefined;
    vless.readResponseHeader(ctx.io, memory2.stream(), &addons) catch return;
}

fn fuzzXudpFrame(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [xudp.max_meta_len + xudp.max_data_len + 16]u8 = undefined;
    const len = smith.slice(&input);
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    var meta: [xudp.max_meta_len]u8 = undefined;
    var data: [xudp.max_data_len]u8 = undefined;
    _ = xudp.readFrame(ctx.io, memory.stream(), &meta, &data) catch return;
}

fn fuzzSs2022Request(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [s2022.max_payload]u8 = undefined;
    const len = smith.slice(&input);
    const method = if (smith.value(bool)) s2022.Method.aes_128_gcm else s2022.Method.aes_256_gcm;
    var key = testKey(method);
    defer key.deinit();
    const replay = try ctx.allocator.create(s2022.ReplayCache);
    defer ctx.allocator.destroy(replay);
    replay.* = .{};
    var plaintext: [s2022.max_payload]u8 = undefined;
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    _ = s2022.readClientRequest(
        ctx.io,
        memory.stream(),
        method,
        &key,
        replay,
        &plaintext,
    ) catch return;
}

/// Builds an authenticated SS2022 TCP request around arbitrary variable-header
/// bytes, so hostile address/padding layouts reach the parser after AEAD.
fn fuzzSs2022RequestLayout(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var variable: [s2022.max_payload]u8 = undefined;
    const variable_len = smith.slice(&variable);
    if (variable_len == 0) return;
    const method = if (smith.value(bool)) s2022.Method.aes_128_gcm else s2022.Method.aes_256_gcm;
    var key = testKey(method);
    defer key.deinit();

    var salt: [32]u8 = @splat(0x42);
    const salt_len = method.saltLength();
    var recv_key: [32]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &recv_key);
    s2022.deriveSubkey(method, key.slice(), salt[0..salt_len], &recv_key);

    var stream_bytes: [s2022.max_payload + 128]u8 = undefined;
    @memcpy(stream_bytes[0..salt_len], salt[0..salt_len]);
    var offset: usize = salt_len;

    var fixed: [11]u8 = undefined;
    fixed[0] = 0;
    std.mem.writeInt(u64, fixed[1..9], try s2022.timestampNow(ctx.io), .big);
    std.mem.writeInt(u16, fixed[9..11], @intCast(variable_len), .big);
    s2022.seal(
        method,
        &recv_key,
        s2022.nonceFromCounter(0),
        &fixed,
        stream_bytes[offset..],
    );
    offset += fixed.len + s2022.tag_length;

    s2022.seal(
        method,
        &recv_key,
        s2022.nonceFromCounter(1),
        variable[0..variable_len],
        stream_bytes[offset..],
    );
    offset += variable_len + s2022.tag_length;

    const replay = try ctx.allocator.create(s2022.ReplayCache);
    defer ctx.allocator.destroy(replay);
    replay.* = .{};
    var plaintext: [s2022.max_payload]u8 = undefined;
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = stream_bytes[0..offset], .output = &output };
    _ = s2022.readClientRequest(
        ctx.io,
        memory.stream(),
        method,
        &key,
        replay,
        &plaintext,
    ) catch return;
}

fn fuzzSs2022Chunks(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    const method = if (smith.value(bool)) s2022.Method.aes_128_gcm else s2022.Method.aes_256_gcm;
    var key = testKey(method);
    defer key.deinit();

    var salt: [32]u8 = @splat(0x24);
    const salt_len = method.saltLength();
    var recv_key: [32]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &recv_key);
    s2022.deriveSubkey(method, key.slice(), salt[0..salt_len], &recv_key);

    var length_plain: [2]u8 = undefined;
    smith.bytes(&length_plain);
    const payload_len: usize = std.mem.readInt(u16, &length_plain, .big);
    var payload: [s2022.max_payload]u8 = undefined;
    smith.bytes(payload[0..payload_len]);

    var stream_bytes: [s2022.max_payload + 64]u8 = undefined;
    var offset: usize = 0;
    s2022.seal(
        method,
        &recv_key,
        s2022.nonceFromCounter(2),
        &length_plain,
        stream_bytes[offset..],
    );
    offset += length_plain.len + s2022.tag_length;
    s2022.seal(
        method,
        &recv_key,
        s2022.nonceFromCounter(3),
        payload[0..payload_len],
        stream_bytes[offset..],
    );
    offset += payload_len + s2022.tag_length;

    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = stream_bytes[0..offset], .output = &output };
    const server = try s2022.ServerStream.create(
        ctx.allocator,
        memory.stream(),
        method,
        &key,
        salt[0..salt_len],
        &recv_key,
        &.{},
        .{ .ip = .{ .ip4 = .loopback(1) } },
        .{ .ip = .{ .ip4 = .loopback(2) } },
    );
    defer server.destroy(ctx.io);
    var buffer: [1024]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    _ = server.stream().read(ctx.io, &buffers) catch return;
}

fn fuzzSs2022UdpRaw(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [s2022.max_payload]u8 = undefined;
    const len = smith.slice(&input);
    const method = if (smith.value(bool)) s2022.Method.aes_128_gcm else s2022.Method.aes_256_gcm;
    var key = testKey(method);
    defer key.deinit();
    var plaintext: [s2022.max_payload]u8 = undefined;
    _ = s2022.decodeUdpPacket(
        ctx.io,
        method,
        key.slice(),
        input[0..len],
        .client_to_server,
        null,
        &plaintext,
    ) catch return;
}

fn fuzzSs2022UdpLayout(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    const method = if (smith.value(bool)) s2022.Method.aes_128_gcm else s2022.Method.aes_256_gcm;
    var key = testKey(method);
    defer key.deinit();

    var session_id: [8]u8 = undefined;
    smith.bytes(&session_id);
    const packet_id = smith.value(u64);
    var separate_plain: [16]u8 = undefined;
    @memcpy(separate_plain[0..8], &session_id);
    std.mem.writeInt(u64, separate_plain[8..16], packet_id, .big);

    var packet: [16 + s2022.max_payload + 16]u8 = undefined;
    encryptSeparate(method, key.slice(), &separate_plain, packet[0..16]);

    var subkey: [32]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &subkey);
    s2022.deriveSubkey(method, key.slice(), &session_id, &subkey);
    const nonce: [s2022.nonce_length]u8 = separate_plain[4..16].*;

    var body: [s2022.max_payload]u8 = undefined;
    body[0] = 0;
    std.mem.writeInt(u64, body[1..9], try s2022.timestampNow(ctx.io), .big);
    var fuzz_body: [s2022.max_payload]u8 = undefined;
    const fuzz_len = @min(
        @as(usize, smith.slice(&fuzz_body)),
        s2022.max_payload - 9,
    );
    @memcpy(body[9..][0..fuzz_len], fuzz_body[0..fuzz_len]);
    const body_len: usize = 9 + fuzz_len;

    s2022.seal(
        method,
        &subkey,
        nonce,
        body[0..body_len],
        packet[16..],
    );
    const packet_len = 16 + body_len + s2022.tag_length;

    var plaintext: [s2022.max_payload]u8 = undefined;
    _ = s2022.decodeUdpPacket(
        ctx.io,
        method,
        key.slice(),
        packet[0..packet_len],
        .client_to_server,
        null,
        &plaintext,
    ) catch return;
}

fn fuzzSocks5Negotiate(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const len = smith.slice(&input);
    var output: [512]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    socks5.negotiate(ctx.io, memory.stream()) catch return;
}

fn fuzzSocks5Address(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const len = smith.slice(&input);
    if (len == 0) return;
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[1..len], .output = &output };
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    _ = socks5.readAddress(
        ctx.io,
        memory.stream(),
        input[0],
        arena.allocator(),
    ) catch return;
}

fn fuzzSocks5UdpRequest(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [s2022.max_payload]u8 = undefined;
    const len = smith.slice(&input);
    _ = socks5.parseUdpRequest(input[0..len]) catch return;
}

fn fuzzHttpParse(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [http_headers_max]u8 = undefined;
    const len = smith.slice(&input);
    _ = http_inbound.parseAbsolute(input[0..len]) catch {};
    _ = http_inbound.parseAuthority(input[0..len]) catch {};
}

fn fuzzHttpHead(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [http_headers_max]u8 = undefined;
    const len = smith.slice(&input);
    var output: [http_headers_max]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    _ = http_inbound.readHeaders(ctx.io, memory.stream(), &output) catch return;
}

fn fuzzHttpHandle(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [http_headers_max]u8 = undefined;
    const len = smith.slice(&input);
    var output: [32 * 1024]u8 = undefined;
    var memory: MemoryStream = .{ .input = input[0..len], .output = &output };
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    var fake: FakeDispatch = .{};
    http_inbound.handle(
        ctx.io,
        memory.stream(),
        "fuzz",
        fake.dispatch(),
        arena.allocator(),
    ) catch return;
}

fn fuzzHttpForwardHead(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [http_headers_max]u8 = undefined;
    const len = smith.slice(&input);
    const target = http_inbound.parseAbsolute(input[0..len]) catch blk: {
        break :blk http_inbound.AbsoluteTarget{
            .endpoint = .{ .ip = .{ .ip4 = .loopback(80) } },
            .authority = "127.0.0.1:80",
            .path = "/",
            .needs_slash = false,
        };
    };
    var output: [http_head_max]u8 = undefined;
    _ = http_inbound.buildForwardHead(
        &output,
        "GET",
        "HTTP/1.1",
        target,
        input[0..len],
    ) catch return;
}

fn fuzzConfig(ctx: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    const len = smith.slice(&input);
    var parsed = config.fromJson(ctx.allocator, input[0..len]) catch |err| switch (err) {
        error.InvalidJson, error.OutOfMemory => return,
    };
    defer parsed.deinit();
    var diagnostic: marmo.Diagnostic = .{};
    config.validate(parsed.config().*, &diagnostic) catch return;
}

fn fuzzPrimitives(_: Context, smith: *std.testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const len = smith.slice(&input);
    _ = Endpoint.parse(input[0..len]) catch {};
    _ = Cidr.parse(input[0..len]) catch {};
    _ = vless.parseUuid(input[0..len]) catch {};
    _ = s2022.Method.parse(input[0..len]);

    for ([_]s2022.Method{ .aes_128_gcm, .aes_256_gcm }) |method| {
        var key = s2022.Key.parse(method, input[0..len]) catch continue;
        key.deinit();
    }
}

fn testKey(method: s2022.Method) s2022.Key {
    var key: s2022.Key = .{ .len = @intCast(method.keyLength()) };
    for (key.bytes[0..method.keyLength()], 0..) |*byte, index| {
        byte.* = @intCast(index +% 0x5a);
    }
    return key;
}

fn encryptSeparate(
    method: s2022.Method,
    psk: []const u8,
    input: *const [16]u8,
    out: *[16]u8,
) void {
    switch (method) {
        .aes_128_gcm => {
            var key: [16]u8 = undefined;
            @memcpy(&key, psk[0..16]);
            var context = std.crypto.core.aes.Aes128.initEnc(key);
            context.encrypt(out, input);
        },
        .aes_256_gcm => {
            var key: [32]u8 = undefined;
            @memcpy(&key, psk[0..32]);
            var context = std.crypto.core.aes.Aes256.initEnc(key);
            context.encrypt(out, input);
        },
    }
}

pub const targets = [_]Target{
    .{ .name = "tls_client_hello", .max_input = 16 * 1024, .run = fuzzTlsClientHello },
    .{ .name = "tls_client_hello_mutated", .max_input = 1024, .run = fuzzTlsClientHelloMutated },
    .{ .name = "tls_record_read", .max_input = 17 * 1024, .run = fuzzTlsRecordRead },
    .{ .name = "tls_record_open", .max_input = 17 * 1024, .run = fuzzTlsRecordOpen },
    .{ .name = "tls_record_open_valid", .max_input = 16 * 1024, .run = fuzzTlsRecordOpenValid },
    .{ .name = "tls_record_seal", .max_input = 16 * 1024, .run = fuzzTlsRecordSeal },
    .{ .name = "tls_server_handshake", .max_input = 16 * 1024, .run = fuzzTlsServerHandshake },
    .{ .name = "tls_server_handshake_mutated", .max_input = 1024, .run = fuzzTlsServerHandshakeMutated },
    .{ .name = "tls_credentials", .max_input = 4096, .run = fuzzTlsCredentials },
    .{ .name = "tls_key_schedule", .max_input = 64, .run = fuzzTlsKeySchedule },
    .{ .name = "ws_frame", .max_input = ws.max_frame_payload, .run = fuzzWsFrame },
    .{ .name = "ws_handshake", .max_input = ws.max_handshake, .run = fuzzWsHandshake },
    .{ .name = "http2_frame", .max_input = http2.max_frame_size + http2.frame.header_len, .run = fuzzHttp2Frame },
    .{ .name = "http2_hpack", .max_input = http2.max_header_block, .run = fuzzHttp2Hpack },
    .{ .name = "vless_request", .max_input = 1024, .run = fuzzVlessRequest },
    .{ .name = "trojan_auth", .max_input = trojan.auth_prefix_len, .run = fuzzTrojanAuth },
    .{ .name = "trojan_request", .max_input = 1024, .run = fuzzTrojanRequest },
    .{ .name = "trojan_udp_frame", .max_input = 66 * 1024, .run = fuzzTrojanUdpFrame },
    .{ .name = "xudp_frame", .max_input = 66 * 1024, .run = fuzzXudpFrame },
    .{ .name = "ss2022_request", .max_input = s2022.max_payload, .run = fuzzSs2022Request },
    .{ .name = "ss2022_request_layout", .max_input = s2022.max_payload, .run = fuzzSs2022RequestLayout },
    .{ .name = "ss2022_chunks", .max_input = s2022.max_payload, .run = fuzzSs2022Chunks },
    .{ .name = "ss2022_udp_raw", .max_input = s2022.max_payload, .run = fuzzSs2022UdpRaw },
    .{ .name = "ss2022_udp_layout", .max_input = s2022.max_payload, .run = fuzzSs2022UdpLayout },
    .{ .name = "socks5_negotiate", .max_input = 512, .run = fuzzSocks5Negotiate },
    .{ .name = "socks5_address", .max_input = 512, .run = fuzzSocks5Address },
    .{ .name = "socks5_udp_request", .max_input = s2022.max_payload, .run = fuzzSocks5UdpRequest },
    .{ .name = "http_parse", .max_input = http_headers_max, .run = fuzzHttpParse },
    .{ .name = "http_head", .max_input = http_headers_max, .run = fuzzHttpHead },
    .{ .name = "http_handle", .max_input = http_headers_max, .run = fuzzHttpHandle },
    .{ .name = "http_forward_head", .max_input = http_headers_max, .run = fuzzHttpForwardHead },
    .{ .name = "config_json", .max_input = 4096, .run = fuzzConfig },
    .{ .name = "primitives", .max_input = 512, .run = fuzzPrimitives },
};

pub fn runOne(
    ctx: Context,
    target: Target,
    input: []const u8,
) !void {
    var smith: std.testing.Smith = .{ .in = input };
    return target.run(ctx, &smith);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.Args.Iterator.initAllocator(init.args, allocator);
    defer args.deinit();
    _ = args.next(); // Executable name.
    const seed = if (args.next()) |text|
        std.fmt.parseInt(u64, text, 0) catch 0x6d61726d6f
    else
        0x6d61726d6f;
    const requested = if (args.next()) |text|
        std.fmt.parseInt(u32, text, 0) catch 1024
    else
        1024;
    const iterations = @min(requested, 10_000_000);

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);
    const ctx: Context = .{
        .allocator = allocator,
        .io = io,
        .cert = &cert,
    };

    for (targets, 0..) |target, index| {
        var prng = std.Random.DefaultPrng.init(seed +% @as(u64, index) *% 0x9e3779b97f4a7c15);
        var input: [max_input]u8 = undefined;
        var iteration: u32 = 0;
        while (iteration < iterations) : (iteration += 1) {
            prng.random().bytes(input[0..target.max_input]);
            runOne(ctx, target, input[0..target.max_input]) catch |err| {
                std.log.err("fuzz target {s} failed: {s}", .{
                    target.name,
                    @errorName(err),
                });
                return err;
            };
        }
        std.log.info("fuzz target {s}: {d} inputs", .{ target.name, iterations });
    }
}

const tls_client_hello_fixture: []const u8 = @embedFile(
    "fixtures/tls/client_hello.bin",
);
const tls_record_fixture: []const u8 = @embedFile(
    "fixtures/tls/record_appdata.bin",
);
const tls_client_hello_record: []const u8 = @embedFile(
    "fixtures/tls/client_hello_record.bin",
);
const vless_request_fixture: []const u8 = @embedFile(
    "fixtures/vless/request_ipv4.bin",
);
const trojan_auth_fixture: []const u8 = @embedFile(
    "fixtures/trojan/auth_line.bin",
);
const trojan_request_fixture: []const u8 = @embedFile(
    "fixtures/trojan/request_ipv4.bin",
);
const trojan_udp_fixture: []const u8 = @embedFile(
    "fixtures/trojan/udp_packet.bin",
);
const xudp_frame_fixture: []const u8 = @embedFile(
    "fixtures/vless/xudp_new.bin",
);
const ss_tcp_fixture: []const u8 = @embedFile(
    "fixtures/shadowsocks2022/tcp_request.bin",
);
const ss_udp_fixture: []const u8 = @embedFile(
    "fixtures/shadowsocks2022/udp_packet.bin",
);
const socks5_greeting_fixture: []const u8 = @embedFile(
    "fixtures/socks5/greeting.bin",
);
const socks5_connect_fixture: []const u8 = @embedFile(
    "fixtures/socks5/connect_ipv4.bin",
);
const socks5_udp_fixture: []const u8 = @embedFile(
    "fixtures/socks5/udp_request.bin",
);
const http_connect_fixture: []const u8 = @embedFile(
    "fixtures/http/connect.txt",
);
const http_forward_fixture: []const u8 = @embedFile(
    "fixtures/http/forward.txt",
);
const config_fixture: []const u8 = @embedFile(
    "fixtures/config/valid.json",
);
const config_bad_fixture: []const u8 = @embedFile(
    "fixtures/config/malformed.json",
);

fn testContext() Context {
    return .{ .allocator = std.testing.allocator, .io = std.testing.io };
}

test "fuzz corpus: TLS ClientHello" {
    try std.testing.fuzz(testContext(), fuzzTlsClientHello, .{
        .corpus = &.{tls_client_hello_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzTlsClientHelloMutated, .{
        .corpus = &.{tls_client_hello_fixture},
    });
}

test "fuzz corpus: WebSocket and HTTP/2 parsers" {
    try std.testing.fuzz(testContext(), fuzzWsFrame, .{
        .corpus = &.{"\x82\x05hello"},
    });
    try std.testing.fuzz(testContext(), fuzzWsHandshake, .{
        .corpus = &.{ "GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 101\r\n\r\n" },
    });
    try std.testing.fuzz(testContext(), fuzzHttp2Frame, .{
        .corpus = &.{ "\x00\x00\x03\x00\x01\x00\x00\x00\x01abc", "" },
    });
    try std.testing.fuzz(testContext(), fuzzHttp2Hpack, .{
        .corpus = &.{ "\x82\x86\x84", "\x40\x06x-test\x05value" },
    });
}

test "fuzz corpus: TLS record read and open" {
    try std.testing.fuzz(testContext(), fuzzTlsRecordRead, .{
        .corpus = &.{ tls_record_fixture, tls_client_hello_fixture },
    });
    try std.testing.fuzz(testContext(), fuzzTlsRecordOpen, .{
        .corpus = &.{tls_record_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzTlsRecordOpenValid, .{
        .corpus = &.{"hello"},
    });
}

test "fuzz corpus: TLS credentials and key schedule" {
    var cert = try tls13.test_cert.generate(
        std.testing.allocator,
        std.testing.io,
    );
    defer cert.deinit(std.testing.allocator);
    var ctx = testContext();
    ctx.cert = &cert;
    try std.testing.fuzz(ctx, fuzzTlsCredentials, .{
        .corpus = &.{@embedFile("fixtures/tls/cert.pem")},
    });
    const zeros = @as([64]u8, @splat(0));
    try std.testing.fuzz(ctx, fuzzTlsKeySchedule, .{
        .corpus = &.{&zeros},
    });
}

test "fuzz corpus: TLS server handshake" {
    var cert = try tls13.test_cert.generate(
        std.testing.allocator,
        std.testing.io,
    );
    defer cert.deinit(std.testing.allocator);
    var ctx = testContext();
    ctx.cert = &cert;
    try std.testing.fuzz(ctx, fuzzTlsServerHandshake, .{
        .corpus = &.{ tls_client_hello_record, tls_record_fixture },
    });
    try std.testing.fuzz(ctx, fuzzTlsServerHandshakeMutated, .{
        .corpus = &.{tls_client_hello_record},
    });
}

test "fuzz corpus: VLESS and XUDP" {
    try std.testing.fuzz(testContext(), fuzzVlessRequest, .{
        .corpus = &.{vless_request_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzXudpFrame, .{
        .corpus = &.{xudp_frame_fixture},
    });
}

test "fuzz corpus: Trojan" {
    try std.testing.fuzz(testContext(), fuzzTrojanAuth, .{
        .corpus = &.{trojan_auth_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzTrojanRequest, .{
        .corpus = &.{trojan_request_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzTrojanUdpFrame, .{
        .corpus = &.{trojan_udp_fixture},
    });
}

test "fuzz corpus: Shadowsocks 2022" {
    try std.testing.fuzz(testContext(), fuzzSs2022Request, .{
        .corpus = &.{ss_tcp_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzSs2022RequestLayout, .{
        .corpus = &.{&[_]u8{ 1, 1, 2, 3, 4, 0, 80 }},
    });
    try std.testing.fuzz(testContext(), fuzzSs2022Chunks, .{
        .corpus = &.{&[_]u8{ 0, 4 }},
    });
    try std.testing.fuzz(testContext(), fuzzSs2022UdpRaw, .{
        .corpus = &.{ss_udp_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzSs2022UdpLayout, .{
        .corpus = &.{&[_]u8{ 1, 1, 2, 3, 4, 0, 80 }},
    });
}

test "SS2022 rejects a maximum-length variable header with a short body" {
    const method = s2022.Method.aes_128_gcm;
    var key = testKey(method);
    defer key.deinit();
    var salt: [32]u8 = @splat(0x7e);
    var recv_key: [32]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &recv_key);
    s2022.deriveSubkey(method, key.slice(), salt[0..method.saltLength()], &recv_key);

    var stream_bytes: [64]u8 = undefined;
    @memcpy(stream_bytes[0..method.saltLength()], salt[0..method.saltLength()]);
    var fixed: [11]u8 = undefined;
    fixed[0] = 0;
    std.mem.writeInt(
        u64,
        fixed[1..9],
        try s2022.timestampNow(std.testing.io),
        .big,
    );
    // Claim the largest variable header, but supply no ciphertext for it.
    std.mem.writeInt(u16, fixed[9..11], 0xffff, .big);
    s2022.seal(
        method,
        &recv_key,
        s2022.nonceFromCounter(0),
        &fixed,
        stream_bytes[method.saltLength()..],
    );
    const used = method.saltLength() + fixed.len + s2022.tag_length;

    var replay: s2022.ReplayCache = .{};
    var plaintext: [s2022.max_payload]u8 = undefined;
    var output: [1]u8 = undefined;
    var memory: MemoryStream = .{ .input = stream_bytes[0..used], .output = &output };
    try std.testing.expectError(
        error.EndOfStream,
        s2022.readClientRequest(
            std.testing.io,
            memory.stream(),
            method,
            &key,
            &replay,
            &plaintext,
        ),
    );
}

test "fuzz corpus: SOCKS5" {
    try std.testing.fuzz(testContext(), fuzzSocks5Negotiate, .{
        .corpus = &.{socks5_greeting_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzSocks5Address, .{
        .corpus = &.{socks5_connect_fixture},
    });
    try std.testing.fuzz(testContext(), fuzzSocks5UdpRequest, .{
        .corpus = &.{socks5_udp_fixture},
    });
}

test "fuzz corpus: HTTP" {
    try std.testing.fuzz(testContext(), fuzzHttpParse, .{
        .corpus = &.{ http_connect_fixture, http_forward_fixture },
    });
    try std.testing.fuzz(testContext(), fuzzHttpHead, .{
        .corpus = &.{ http_connect_fixture, http_forward_fixture },
    });
    try std.testing.fuzz(testContext(), fuzzHttpHandle, .{
        .corpus = &.{ http_connect_fixture, http_forward_fixture },
    });
    try std.testing.fuzz(testContext(), fuzzHttpForwardHead, .{
        .corpus = &.{http_forward_fixture},
    });
}

test "fuzz corpus: config and primitives" {
    try std.testing.fuzz(testContext(), fuzzConfig, .{
        .corpus = &.{ config_fixture, config_bad_fixture },
    });
    try std.testing.fuzz(testContext(), fuzzPrimitives, .{
        .corpus = &.{
            "10.0.0.0/8",
            "example.com:443",
            "00112233-4455-6677-8899-aabbccddeeff",
        },
    });
}
