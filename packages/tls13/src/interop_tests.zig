//! Loopback regression tests for the TLS 1.3 package.
//!
//! These tests never touch a live network: every case binds loopback port 0 and
//! generates its certificates at runtime.

const std = @import("std");
const client_module = @import("client.zig");
const Client = client_module.Client;
const min_buffer_len = client_module.min_buffer_len;
const Server = @import("server.zig").Server;
const ClientAuth = @import("server.zig").ClientAuth;
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const cert_path = @import("cert_path.zig");
const test_cert = @import("test_cert.zig");

const ClientCase = struct {
    suite: record.CipherSuite = .aes_128_gcm_sha256,
    group: ?u16 = null,
    client_auth: ClientAuth = .none,
    client_ca: ?*const std.crypto.Certificate.Bundle = null,
    client_chain: []const []const u8 = &.{},
    client_key: ?std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair = null,
};

const ServerOutcome = struct {
    listener: *std.Io.net.Server,
    cert: *test_cert.Certificate,
    suite: record.CipherSuite = .aes_128_gcm_sha256,
    group: ?u16 = null,
    client_auth: ClientAuth = .none,
    client_ca: ?*const std.crypto.Certificate.Bundle = null,
    key_update: bool = false,
    echo_count: usize = 0,
    error_code: ?anyerror = null,

    fn server(self: *ServerOutcome, io: std.Io) void {
        self.run(io) catch |err| {
            self.error_code = err;
        };
    }

    fn run(self: *ServerOutcome, io: std.Io) !void {
        const stream = try self.listener.accept(io);
        defer stream.close(io);

        var socket_read: [min_buffer_len]u8 = undefined;
        var socket_write: [min_buffer_len]u8 = undefined;
        var net_reader = stream.reader(io, &socket_read);
        var net_writer = stream.writer(io, &socket_write);
        var plain_read: [4096]u8 = undefined;
        var plain_write: [4096]u8 = undefined;

        const tls_server = try Server.create(
            io,
            std.testing.allocator,
            &net_reader.interface,
            &net_writer.interface,
            .{
                .certificate_chain = &.{self.cert.der},
                .private_key = self.cert.key_pair,
                .cipher_suites = &.{self.suite},
                .key_exchange_group = self.group,
                .client_auth = self.client_auth,
                .client_ca = self.client_ca,
                .read_buffer = &plain_read,
                .write_buffer = &plain_write,
            },
        );
        defer {
            tls_server.end() catch {};
            tls_server.deinit();
        }
        self.suite = tls_server.negotiatedCipherSuite();
        self.group = tls_server.negotiatedGroup();
        if (self.key_update) try tls_server.keyUpdate(true);

        var buffer: [64]u8 = undefined;
        var buffers = [_][]u8{&buffer};
        while (true) {
            const read_len = @import("reader.zig").readSome(
                tls_server.reader(),
                &buffers,
            ) catch |err| return err;
            if (read_len == 0) break;
            self.echo_count += 1;
            try tls_server.writer().writeAll(buffer[0..read_len]);
            try tls_server.flush();
        }
    }
};

fn runExchange(
    io: std.Io,
    cert: *test_cert.Certificate,
    case: ClientCase,
    outcome: *ServerOutcome,
    client_options: ClientCase,
) !void {
    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    outcome.* = .{
        .listener = &listener,
        .cert = cert,
        .suite = case.suite,
        .group = case.group,
        .client_auth = case.client_auth,
        .client_ca = case.client_ca,
        .key_update = false,
    };
    var future = io.async(ServerOutcome.server, .{ outcome, io });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(listener.socket.address.getPort()) };
    const stream = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer stream.close(io);

    var socket_read: [min_buffer_len]u8 = undefined;
    var socket_write: [min_buffer_len]u8 = undefined;
    var net_reader = stream.reader(io, &socket_read);
    var net_writer = stream.writer(io, &socket_write);
    var plain_read: [4096]u8 = undefined;
    var plain_write: [4096]u8 = undefined;

    var tls_client = try Client.init(
        io,
        &net_reader.interface,
        &net_writer.interface,
        .{
            .server_name = "localhost",
            .verify = false,
            .cipher_suites = &.{client_options.suite},
            .client_certificate_chain = client_options.client_chain,
            .client_private_key = client_options.client_key,
            .read_buffer = &plain_read,
            .write_buffer = &plain_write,
        },
    );
    defer tls_client.deinit();

    try std.testing.expectEqual(client_options.suite, tls_client.negotiatedCipherSuite());
    try tls_client.writer().writeAll("ping");
    try tls_client.writer().flush();
    try net_writer.interface.flush();

    var response: [4]u8 = undefined;
    var offset: usize = 0;
    while (offset < response.len) {
        const read_len = try tls_client.reader().readSliceShort(response[offset..]);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
    try std.testing.expectEqualStrings("ping", &response);

    try tls_client.end();
    _ = future.await(io);
    if (outcome.error_code) |err| return err;
    try std.testing.expectEqual(client_options.suite, outcome.suite);
    if (client_options.group) |group| {
        try std.testing.expectEqual(group, outcome.group orelse 0);
    }
}

fn readExact(reader: *std.Io.Reader, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const read_len = try reader.readSliceShort(buffer[offset..]);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
}

test "every suite and key exchange group complete a loopback exchange" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for (record.CipherSuite.list) |suite| {
        inline for (.{ handshake.group_x25519, handshake.group_secp256r1 }) |group| {
            var cert = try test_cert.generate(allocator, io);
            defer cert.deinit(allocator);
            var outcome: ServerOutcome = undefined;
            const case: ClientCase = .{ .suite = suite, .group = group };
            try runExchange(io, &cert, case, &outcome, .{
                .suite = suite,
                .group = group,
            });
            try std.testing.expectEqual(group, outcome.group orelse 0);
        }
    }
}

test "required client authentication accepts a trusted client certificate" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_cert = try test_cert.generate(allocator, io);
    defer server_cert.deinit(allocator);
    var root = try test_cert.generateCa(allocator, io, "marmo client ca");
    defer root.deinit(allocator);
    var client_cert = try test_cert.generateParams(allocator, io, .{
        .common_name = "marmo client",
        .issuer_name = "marmo client ca",
        .issuer_key = root.key_pair,
        .san = null,
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_client_auth = true,
    });
    defer client_cert.deinit(allocator);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, root.der, now);

    var outcome: ServerOutcome = undefined;
    const case: ClientCase = .{
        .suite = .aes_256_gcm_sha384,
        .group = handshake.group_secp256r1,
        .client_auth = .required,
        .client_ca = &bundle,
    };
    try runExchange(io, &server_cert, case, &outcome, .{
        .suite = .aes_256_gcm_sha384,
        .client_chain = &.{client_cert.der},
        .client_key = client_cert.key_pair,
    });
}

test "required client authentication rejects a missing client certificate" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_cert = try test_cert.generate(allocator, io);
    defer server_cert.deinit(allocator);
    var root = try test_cert.generateCa(allocator, io, "marmo required ca");
    defer root.deinit(allocator);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, root.der, now);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var outcome: ServerOutcome = .{
        .listener = &listener,
        .cert = &server_cert,
        .client_auth = .required,
        .client_ca = &bundle,
    };
    var future = io.async(ServerOutcome.server, .{ &outcome, io });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(listener.socket.address.getPort()) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream });
    defer stream.close(io);
    var socket_read: [min_buffer_len]u8 = undefined;
    var socket_write: [min_buffer_len]u8 = undefined;
    var net_reader = stream.reader(io, &socket_read);
    var net_writer = stream.writer(io, &socket_write);
    var plain_read: [4096]u8 = undefined;
    var plain_write: [4096]u8 = undefined;
    var tls_client = try Client.init(
        io,
        &net_reader.interface,
        &net_writer.interface,
        .{
            .server_name = "localhost",
            .verify = false,
            .read_buffer = &plain_read,
            .write_buffer = &plain_write,
        },
    );
    defer tls_client.deinit();
    _ = future.await(io);
    try std.testing.expectEqual(error.HandshakeFailed, outcome.error_code.?);
}

test "optional client authentication accepts a missing certificate" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_cert = try test_cert.generate(allocator, io);
    defer server_cert.deinit(allocator);
    var root = try test_cert.generateCa(allocator, io, "marmo optional ca");
    defer root.deinit(allocator);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, root.der, now);

    var outcome: ServerOutcome = undefined;
    const case: ClientCase = .{
        .suite = .chacha20_poly1305_sha256,
        .client_auth = .optional,
        .client_ca = &bundle,
    };
    try runExchange(io, &server_cert, case, &outcome, .{
        .suite = .chacha20_poly1305_sha256,
    });
}

test "client authentication fails against the wrong trust anchor" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_cert = try test_cert.generate(allocator, io);
    defer server_cert.deinit(allocator);
    var trusted = try test_cert.generateCa(allocator, io, "trusted ca");
    defer trusted.deinit(allocator);
    var other = try test_cert.generateCa(allocator, io, "other ca");
    defer other.deinit(allocator);
    var client_cert = try test_cert.generateParams(allocator, io, .{
        .common_name = "marmo untrusted client",
        .issuer_name = "other ca",
        .issuer_key = other.key_pair,
        .san = null,
        .include_basic_constraints = true,
        .include_key_usage = true,
        .eku_client_auth = true,
    });
    defer client_cert.deinit(allocator);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    try test_cert.addTrustedDer(&bundle, allocator, trusted.der, now);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var outcome: ServerOutcome = .{
        .listener = &listener,
        .cert = &server_cert,
        .client_auth = .required,
        .client_ca = &bundle,
    };
    var future = io.async(ServerOutcome.server, .{ &outcome, io });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(listener.socket.address.getPort()) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream });
    defer stream.close(io);
    var socket_read: [min_buffer_len]u8 = undefined;
    var socket_write: [min_buffer_len]u8 = undefined;
    var net_reader = stream.reader(io, &socket_read);
    var net_writer = stream.writer(io, &socket_write);
    var plain_read: [4096]u8 = undefined;
    var plain_write: [4096]u8 = undefined;
    var tls_client = try Client.init(
        io,
        &net_reader.interface,
        &net_writer.interface,
        .{
            .server_name = "localhost",
            .verify = false,
            .client_certificate_chain = &.{client_cert.der},
            .client_private_key = client_cert.key_pair,
            .read_buffer = &plain_read,
            .write_buffer = &plain_write,
        },
    );
    defer tls_client.deinit();
    _ = future.await(io);
    try std.testing.expectEqual(error.HandshakeFailed, outcome.error_code.?);
}

test "KeyUpdate under traffic updates both directions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_cert = try test_cert.generate(allocator, io);
    defer server_cert.deinit(allocator);
    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var outcome: ServerOutcome = .{
        .listener = &listener,
        .cert = &server_cert,
        .suite = .chacha20_poly1305_sha256,
        .key_update = true,
    };
    var future = io.async(ServerOutcome.server, .{ &outcome, io });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(listener.socket.address.getPort()) };
    const stream = try std.Io.net.IpAddress.connect(&address, io, .{ .mode = .stream });
    defer stream.close(io);
    var socket_read: [min_buffer_len]u8 = undefined;
    var socket_write: [min_buffer_len]u8 = undefined;
    var net_reader = stream.reader(io, &socket_read);
    var net_writer = stream.writer(io, &socket_write);
    var plain_read: [4096]u8 = undefined;
    var plain_write: [4096]u8 = undefined;
    var tls_client = try Client.init(
        io,
        &net_reader.interface,
        &net_writer.interface,
        .{
            .server_name = "localhost",
            .verify = false,
            .cipher_suites = &.{.chacha20_poly1305_sha256},
            .read_buffer = &plain_read,
            .write_buffer = &plain_write,
        },
    );
    defer tls_client.deinit();

    try tls_client.writer().writeAll("one");
    try tls_client.writer().flush();
    try net_writer.interface.flush();
    var first: [3]u8 = undefined;
    try readExact(tls_client.reader(), &first);
    try std.testing.expectEqualStrings("one", &first);

    // The server asked for an update before echoing; writing now must first
    // send the client's KeyUpdate response.
    try tls_client.writer().writeAll("two");
    try tls_client.writer().flush();
    try net_writer.interface.flush();
    var second: [3]u8 = undefined;
    try readExact(tls_client.reader(), &second);
    try std.testing.expectEqualStrings("two", &second);

    // A client-initiated update followed by traffic exercises the reverse
    // direction (server read-key update).
    try tls_client.keyUpdate(true);
    try tls_client.writer().writeAll("three");
    try tls_client.writer().flush();
    try net_writer.interface.flush();
    var third: [5]u8 = undefined;
    try readExact(tls_client.reader(), &third);
    try std.testing.expectEqualStrings("three", &third);

    try tls_client.end();
    _ = future.await(io);
    if (outcome.error_code) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), outcome.echo_count);
}
