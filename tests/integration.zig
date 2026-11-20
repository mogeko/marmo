const std = @import("std");
const marmo = @import("marmo");
const tls13 = @import("tls13");

const allocator = std.heap.smp_allocator;

fn tcpWrite(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var writer = std.Io.net.Stream.Writer.init(stream, io, &.{});
    writer.interface.writeAll(bytes) catch return error.WriteFailed;
    writer.interface.flush() catch return error.WriteFailed;
}

fn tcpReadExact(io: std.Io, stream: std.Io.net.Stream, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var buffers = [_][]u8{buffer[offset..]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
}

fn tcpReadHeaders(io: std.Io, stream: std.Io.net.Stream, buffer: []u8) ![]const u8 {
    var len: usize = 0;
    while (len < buffer.len) {
        var buffers = [_][]u8{buffer[len .. len + 1]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        len += 1;
        if (len >= 4 and std.mem.endsWith(u8, buffer[0..len], "\r\n\r\n")) {
            return buffer[0..len];
        }
    }
    return error.HeadersTooLarge;
}

fn socksNegotiate(io: std.Io, stream: std.Io.net.Stream) !void {
    try tcpWrite(io, stream, &.{ 5, 1, 0 });
    var greeting: [2]u8 = undefined;
    try tcpReadExact(io, stream, &greeting);
    try std.testing.expectEqualSlices(u8, &.{ 5, 0 }, &greeting);
}

fn mockHttpProxyLoop(io: std.Io, server: *std.Io.net.Server) void {
    const stream = server.accept(io) catch return;

    var headers: [2048]u8 = undefined;
    const request = tcpReadHeaders(io, stream, &headers) catch {
        stream.close(io);
        return;
    };
    if (!std.mem.startsWith(u8, request, "CONNECT ")) {
        stream.close(io);
        return;
    }

    tcpWrite(io, stream, "HTTP/1.1 200 Connection Established\r\n\r\n") catch {
        stream.close(io);
        return;
    };
    echoConnection(io, stream);
    stream.close(io);
}

fn acceptOnceSignal(io: std.Io, server: *std.Io.net.Server, event: *std.Io.Event) void {
    const stream = server.accept(io) catch return;
    event.set(io);
    stream.close(io);
}

fn udpEchoOnce(io: std.Io, socket: *std.Io.net.Socket) void {
    var buffer: [1500]u8 = undefined;
    const message = socket.receive(io, &buffer) catch return;
    socket.send(io, &message.from, message.data) catch return;
}

fn originHttpLoop(io: std.Io, server: *std.Io.net.Server, expected_host: []const u8) void {
    const stream = server.accept(io) catch return;

    var headers: [4096]u8 = undefined;
    const request = tcpReadHeaders(io, stream, &headers) catch {
        stream.close(io);
        return;
    };

    const valid = std.mem.startsWith(u8, request, "GET /hello HTTP/1.1\r\n") and
        std.mem.find(u8, request, expected_host) != null and
        std.mem.find(u8, request, "Connection: close\r\n") != null and
        std.mem.find(u8, request, "Proxy-Connection") == null;

    const response = if (valid)
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    else
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad";

    tcpWrite(io, stream, response) catch {};
    stream.close(io);
}

fn echoConnection(io: std.Io, stream: std.Io.net.Stream) void {
    var buffer: [1024]u8 = undefined;
    while (true) {
        var buffers = [_][]u8{buffer[0..]};
        const read_len = stream.read(io, &buffers) catch return;
        if (read_len == 0) return;
        var writer = std.Io.net.Stream.Writer.init(stream, io, &.{});
        writer.interface.writeAll(buffer[0..read_len]) catch return;
        writer.interface.flush() catch return;
    }
}

fn echoLoopOnce(io: std.Io, server: *std.Io.net.Server) void {
    const stream = server.accept(io) catch return;
    echoConnection(io, stream);
    stream.close(io);
}

test "SOCKS5 CONNECT reaches a direct TCP target" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_server = try echo_address.listen(io, .{ .reuse_address = true });
    defer echo_server.deinit(io);
    var echo_future = io.async(echoLoopOnce, .{ io, &echo_server });

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{ .tag = "direct", .protocol = .direct },
        },
        .route = .{ .final = "direct" },
    };

    var instance = marmo.Instance.init(allocator, io, config, &diagnostic) catch |err| {
        std.debug.print("init failed: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer instance.deinit();
    try instance.start();

    const socks_endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try tcpWrite(io, client, &.{ 5, 1, 0 });
    var greeting: [2]u8 = undefined;
    try tcpReadExact(io, client, &greeting);
    try std.testing.expectEqualSlices(u8, &.{ 5, 0 }, &greeting);

    const echo_address_value = echo_server.socket.address;
    const port = echo_address_value.getPort();
    try tcpWrite(io, client, &.{
        5,                   1,                     0, 1, 127, 0, 0, 1,
        @intCast(port >> 8), @intCast(port & 0xff),
    });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 5), reply[0]);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try tcpWrite(io, client, "hello");
    var echoed: [5]u8 = undefined;
    try tcpReadExact(io, client, &echoed);
    try std.testing.expectEqualStrings("hello", &echoed);

    instance.stop();
    _ = echo_future.await(io);
}

test "HTTP CONNECT reaches a direct TCP target" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_server = try echo_address.listen(io, .{ .reuse_address = true });
    defer echo_server.deinit(io);
    var echo_future = io.async(echoLoopOnce, .{ io, &echo_server });

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "http", .protocol = .http, .listen = "127.0.0.1:0" },
        },
        .route = .{ .final = "direct" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const http_endpoint = instance.inboundEndpoint("http") orelse
        return error.TestUnexpectedResult;
    const http_address = switch (http_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &http_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    const port = echo_server.socket.address.getPort();
    var request_buffer: [128]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buffer,
        "CONNECT 127.0.0.1:{d} HTTP/1.1\r\nHost: echo\r\n\r\n",
        .{port},
    );
    try tcpWrite(io, client, request);

    var response_buffer: [512]u8 = undefined;
    const response = try tcpReadHeaders(io, client, &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));

    try tcpWrite(io, client, "hello");
    var echoed: [5]u8 = undefined;
    try tcpReadExact(io, client, &echoed);
    try std.testing.expectEqualStrings("hello", &echoed);

    instance.stop();
    _ = echo_future.await(io);
}

test "SOCKS5 routes a domain through an HTTP CONNECT outbound" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var proxy_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var proxy_server = try proxy_address.listen(io, .{ .reuse_address = true });
    defer proxy_server.deinit(io);
    var proxy_future = io.async(mockHttpProxyLoop, .{ io, &proxy_server });

    var server_buffer: [32]u8 = undefined;
    const server_text = try std.fmt.bufPrint(
        &server_buffer,
        "127.0.0.1:{d}",
        .{proxy_server.socket.address.getPort()},
    );

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{ .tag = "proxy", .protocol = .http, .server = server_text },
        },
        .route = .{ .final = "proxy" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const socks_endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    var request: [32]u8 = undefined;
    @memcpy(request[0..5], &[_]u8{ 5, 1, 0, 3, 11 });
    @memcpy(request[5..16], "example.com");
    request[16] = 0x01;
    request[17] = 0xbb;
    try tcpWrite(io, client, request[0..18]);

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try tcpWrite(io, client, "hello");
    var echoed: [5]u8 = undefined;
    try tcpReadExact(io, client, &echoed);
    try std.testing.expectEqualStrings("hello", &echoed);

    instance.stop();
    _ = proxy_future.await(io);
}

test "routing rejects a blocked domain" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .route = .{
            .rules = &.{
                .{ .domain_suffix = &.{"blocked.test"}, .outbound = "reject" },
            },
            .final = "direct",
        },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const socks_endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    var request: [32]u8 = undefined;
    @memcpy(request[0..5], &[_]u8{ 5, 1, 0, 3, 12 });
    @memcpy(request[5..17], "blocked.test");
    request[17] = 0x00;
    request[18] = 0x50;
    try tcpWrite(io, client, request[0..19]);

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 0x02), reply[1]);

    instance.stop();
}

test "SOCKS5 UDP ASSOCIATE relays a datagram to a direct target" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_socket = try echo_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer echo_socket.close(io);
    var echo_future = io.async(udpEchoOnce, .{ io, &echo_socket });

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .route = .{ .final = "direct" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const socks_endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    try tcpWrite(io, client, &[_]u8{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 5), reply[0]);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);
    try std.testing.expectEqual(@as(u8, 1), reply[3]);

    const bnd_port = (@as(u16, reply[8]) << 8) | reply[9];
    const bnd_address: std.Io.net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = bnd_port,
    } };

    var local_bind: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
    const udp_socket = try local_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer udp_socket.close(io);

    const echo_port = echo_socket.address.getPort();
    var packet: [15]u8 = undefined;
    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 1;
    @memcpy(packet[4..8], &[_]u8{ 127, 0, 0, 1 });
    packet[8] = @intCast(echo_port >> 8);
    packet[9] = @intCast(echo_port & 0xff);
    @memcpy(packet[10..15], "hello");
    try udp_socket.send(io, &bnd_address, &packet);

    var receive_buffer: [1500]u8 = undefined;
    const message = try udp_socket.receive(io, &receive_buffer);
    try std.testing.expectEqual(@as(usize, 15), message.data.len);
    try std.testing.expectEqual(@as(u8, 1), message.data[3]);
    try std.testing.expectEqualStrings("hello", message.data[10..15]);

    instance.stop();
    _ = echo_future.await(io);
}

test "Shadowsocks 2022 TCP outbound and inbound" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_server = try echo_address.listen(io, .{ .reuse_address = true });
    defer echo_server.deinit(io);
    var echo_future = io.async(echoLoopOnce, .{ io, &echo_server });

    const method = "2022-blake3-aes-128-gcm";
    const password = "MDEyMzQ1Njc4OWFiY2RlZg==";

    var diagnostic: marmo.Diagnostic = .{};
    const server_config: marmo.Config = .{
        .inbounds = &.{
            .{
                .tag = "ss-in",
                .protocol = .shadowsocks,
                .listen = "127.0.0.1:0",
                .method = method,
                .password = password,
            },
        },
        .route = .{ .final = "direct" },
    };
    var server = marmo.Instance.init(allocator, io, server_config, &diagnostic) catch |err| {
        std.debug.print("ss server init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer server.deinit();
    try server.start();

    const ss_endpoint = server.inboundEndpoint("ss-in") orelse
        return error.TestUnexpectedResult;
    var endpoint_buffer: [32]u8 = undefined;
    const endpoint_text = try std.fmt.bufPrint(
        &endpoint_buffer,
        "127.0.0.1:{d}",
        .{ss_endpoint.port()},
    );

    const client_config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{
                .tag = "ss-out",
                .protocol = .shadowsocks,
                .server = endpoint_text,
                .method = method,
                .password = password,
            },
        },
        .route = .{ .final = "ss-out" },
    };
    var client_instance = marmo.Instance.init(
        allocator,
        io,
        client_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("ss client init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer client_instance.deinit();
    try client_instance.start();

    const socks_endpoint = client_instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    const echo_port = echo_server.socket.address.getPort();
    try tcpWrite(io, client, &.{
        5,                        1,                          0, 1, 127, 0, 0, 1,
        @intCast(echo_port >> 8), @intCast(echo_port & 0xff),
    });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try tcpWrite(io, client, "hello shadowsocks");
    var echoed: [17]u8 = undefined;
    try tcpReadExact(io, client, &echoed);
    try std.testing.expectEqualStrings("hello shadowsocks", &echoed);

    client_instance.stop();
    server.stop();
    _ = echo_future.await(io);
}

test "Shadowsocks 2022 UDP outbound and inbound" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_socket = try echo_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer echo_socket.close(io);
    var echo_future = io.async(udpEchoOnce, .{ io, &echo_socket });

    const method = "2022-blake3-aes-128-gcm";
    const password = "MDEyMzQ1Njc4OWFiY2RlZg==";

    var diagnostic: marmo.Diagnostic = .{};
    const server_config: marmo.Config = .{
        .inbounds = &.{
            .{
                .tag = "ss-in",
                .protocol = .shadowsocks,
                .listen = "127.0.0.1:0",
                .method = method,
                .password = password,
            },
        },
        .route = .{ .final = "direct" },
    };
    var server = marmo.Instance.init(allocator, io, server_config, &diagnostic) catch |err| {
        std.debug.print("ss udp server init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer server.deinit();
    try server.start();

    const ss_endpoint = server.inboundEndpoint("ss-in") orelse
        return error.TestUnexpectedResult;
    var endpoint_buffer: [32]u8 = undefined;
    const endpoint_text = try std.fmt.bufPrint(
        &endpoint_buffer,
        "127.0.0.1:{d}",
        .{ss_endpoint.port()},
    );

    const client_config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{
                .tag = "ss-out",
                .protocol = .shadowsocks,
                .server = endpoint_text,
                .method = method,
                .password = password,
            },
        },
        .route = .{ .final = "ss-out" },
    };
    var client_instance = marmo.Instance.init(
        allocator,
        io,
        client_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("ss udp client init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer client_instance.deinit();
    try client_instance.start();

    const socks_endpoint = client_instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const control = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer control.close(io);

    try socksNegotiate(io, control);
    try tcpWrite(io, control, &[_]u8{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, control, &reply);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);
    const bnd_port = (@as(u16, reply[8]) << 8) | reply[9];
    const bnd_address: std.Io.net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = bnd_port,
    } };

    var local_bind: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
    const udp_socket = try local_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer udp_socket.close(io);

    const echo_port = echo_socket.address.getPort();
    var packet: [15]u8 = undefined;
    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 1;
    @memcpy(packet[4..8], &[_]u8{ 127, 0, 0, 1 });
    packet[8] = @intCast(echo_port >> 8);
    packet[9] = @intCast(echo_port & 0xff);
    @memcpy(packet[10..15], "hello");
    try udp_socket.send(io, &bnd_address, &packet);

    var receive_buffer: [1500]u8 = undefined;
    const message = try udp_socket.receive(io, &receive_buffer);
    try std.testing.expectEqual(@as(usize, 15), message.data.len);
    try std.testing.expectEqual(@as(u8, 1), message.data[3]);
    try std.testing.expectEqualStrings("hello", message.data[10..15]);

    client_instance.stop();
    server.stop();
    _ = echo_future.await(io);
}

test "HTTP forward proxy rewrites absolute-form requests" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var origin_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var origin_server = try origin_bind.listen(io, .{ .reuse_address = true });
    defer origin_server.deinit(io);

    var host_buffer: [64]u8 = undefined;
    const expected_host = try std.fmt.bufPrint(
        &host_buffer,
        "Host: 127.0.0.1:{d}\r\n",
        .{origin_server.socket.address.getPort()},
    );
    var origin_future = io.concurrent(
        originHttpLoop,
        .{ io, &origin_server, expected_host },
    ) catch return error.TestUnexpectedResult;

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "http", .protocol = .http, .listen = "127.0.0.1:0" },
        },
        .route = .{ .final = "direct" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const http_endpoint = instance.inboundEndpoint("http") orelse
        return error.TestUnexpectedResult;
    const http_address = switch (http_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &http_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    var request_buffer: [512]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buffer,
        "GET http://127.0.0.1:{d}/hello HTTP/1.1\r\n" ++
            "Host: ignored.example\r\n" ++
            "Proxy-Connection: keep-alive\r\n" ++
            "X-Test: yes\r\n\r\n",
        .{origin_server.socket.address.getPort()},
    );
    try tcpWrite(io, client, request);

    var response_buffer: [512]u8 = undefined;
    const response = try tcpReadHeaders(io, client, &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));

    var body: [2]u8 = undefined;
    try tcpReadExact(io, client, &body);
    try std.testing.expectEqualStrings("ok", &body);

    instance.stop();
    _ = origin_future.await(io);
}

const vless_test_uuid_text = "00112233-4455-6677-8899-aabbccddeeff";
const vless_test_uuid = [16]u8{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

fn vlessReadHeader(
    io: std.Io,
    stream: std.Io.net.Stream,
    expected_port: u16,
) !void {
    var fixed: [18]u8 = undefined;
    try tcpReadExact(io, stream, &fixed);
    if (fixed[0] != 0) return error.InvalidVlessVersion;
    if (!std.mem.eql(u8, fixed[1..17], &vless_test_uuid)) {
        return error.InvalidVlessUuid;
    }

    var scratch: [255]u8 = undefined;
    const addon_len = fixed[17];
    if (addon_len != 0) try tcpReadExact(io, stream, scratch[0..addon_len]);

    var command: [1]u8 = undefined;
    try tcpReadExact(io, stream, &command);
    if (command[0] != 1) return error.InvalidVlessCommand;

    var port_bytes: [2]u8 = undefined;
    try tcpReadExact(io, stream, &port_bytes);
    const port = (@as(u16, port_bytes[0]) << 8) | port_bytes[1];
    if (port != expected_port) return error.InvalidVlessPort;

    var atyp: [1]u8 = undefined;
    try tcpReadExact(io, stream, &atyp);
    switch (atyp[0]) {
        1 => {
            var address: [4]u8 = undefined;
            try tcpReadExact(io, stream, &address);
            if (!std.mem.eql(u8, &address, &.{ 127, 0, 0, 1 })) {
                return error.InvalidVlessAddress;
            }
        },
        2 => {
            var name_len: [1]u8 = undefined;
            try tcpReadExact(io, stream, &name_len);
            try tcpReadExact(io, stream, scratch[0..name_len[0]]);
        },
        3 => {
            var address: [16]u8 = undefined;
            try tcpReadExact(io, stream, &address);
        },
        else => return error.InvalidVlessAddress,
    }
}

fn mockVlessLoop(
    io: std.Io,
    server: *std.Io.net.Server,
    expected_port: u16,
) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);

    vlessReadHeader(io, stream, expected_port) catch return;
    // Version 0, two addon bytes, then payload.
    tcpWrite(io, stream, &.{ 0, 2, 0xaa, 0xbb }) catch return;
    echoConnection(io, stream);
}

test "VLESS TCP outbound reaches a mock VLESS server" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var vless_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var vless_server = try vless_bind.listen(io, .{ .reuse_address = true });
    defer vless_server.deinit(io);
    const target_port = vless_server.socket.address.getPort();
    var vless_future = io.async(
        mockVlessLoop,
        .{ io, &vless_server, target_port },
    );

    var server_text_buffer: [32]u8 = undefined;
    const server_text = try std.fmt.bufPrint(
        &server_text_buffer,
        "127.0.0.1:{d}",
        .{target_port},
    );

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{
                .tag = "proxy",
                .protocol = .vless,
                .server = server_text,
                .uuid = vless_test_uuid_text,
            },
        },
        .route = .{ .final = "proxy" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const socks_endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    try tcpWrite(io, client, &.{
        5,                          1,                            0, 1, 127, 0, 0, 1,
        @intCast(target_port >> 8), @intCast(target_port & 0xff),
    });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 5), reply[0]);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try tcpWrite(io, client, "hello");
    var echoed: [5]u8 = undefined;
    try tcpReadExact(io, client, &echoed);
    try std.testing.expectEqualStrings("hello", &echoed);

    instance.stop();
    _ = vless_future.await(io);
}

test "VLESS TLS handshake failure is reported to SOCKS5" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tls_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var tls_server = try tls_bind.listen(io, .{ .reuse_address = true });
    defer tls_server.deinit(io);
    const target_port = tls_server.socket.address.getPort();

    var event: std.Io.Event = .unset;
    var accept_future = io.concurrent(
        acceptOnceSignal,
        .{ io, &tls_server, &event },
    ) catch return error.TestUnexpectedResult;

    var server_text_buffer: [32]u8 = undefined;
    const server_text = try std.fmt.bufPrint(
        &server_text_buffer,
        "127.0.0.1:{d}",
        .{target_port},
    );

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{
                .tag = "proxy",
                .protocol = .vless,
                .server = server_text,
                .uuid = vless_test_uuid_text,
                .tls = .{ .sni = "localhost", .insecure = true },
            },
        },
        .route = .{ .final = "proxy" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const socks_endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    try tcpWrite(io, client, &.{ 5, 1, 0, 1, 127, 0, 0, 1, 0, 80 });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 5), reply[0]);
    try std.testing.expect(reply[1] != 0);

    try event.wait(io);
    instance.stop();
    _ = accept_future.await(io);
}

test "selector fallback skips a failing outbound" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var dead_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var dead_server = try dead_bind.listen(io, .{ .reuse_address = true });
    const dead_port = dead_server.socket.address.getPort();
    dead_server.deinit(io);

    var dead_buffer: [32]u8 = undefined;
    const dead_text = try std.fmt.bufPrint(
        &dead_buffer,
        "127.0.0.1:{d}",
        .{dead_port},
    );

    var echo_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_server = try echo_bind.listen(io, .{ .reuse_address = true });
    defer echo_server.deinit(io);
    var echo_future = io.async(echoLoopOnce, .{ io, &echo_server });

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{ .tag = "dead", .protocol = .http, .server = dead_text },
            .{ .tag = "direct", .protocol = .direct },
            .{
                .tag = "auto",
                .protocol = .selector,
                .nodes = &.{ "dead", "direct" },
                .strategy = .fallback,
            },
        },
        .route = .{ .final = "auto" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const socks_endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    const echo_port = echo_server.socket.address.getPort();
    try tcpWrite(io, client, &[_]u8{
        5,                        1,                          0, 1, 127, 0, 0, 1,
        @intCast(echo_port >> 8), @intCast(echo_port & 0xff),
    });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try tcpWrite(io, client, "fallback");
    var echoed: [8]u8 = undefined;
    try tcpReadExact(io, client, &echoed);
    try std.testing.expectEqualStrings("fallback", &echoed);

    instance.stop();
    _ = echo_future.await(io);
}

test "selector health check probes a node" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var health_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var health_server = try health_bind.listen(io, .{ .reuse_address = true });
    defer health_server.deinit(io);

    var health_text_buffer: [32]u8 = undefined;
    const health_text = try std.fmt.bufPrint(
        &health_text_buffer,
        "127.0.0.1:{d}",
        .{health_server.socket.address.getPort()},
    );

    var event: std.Io.Event = .unset;
    var health_future = io.concurrent(
        acceptOnceSignal,
        .{ io, &health_server, &event },
    ) catch return error.TestUnexpectedResult;

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .outbounds = &.{
            .{ .tag = "direct", .protocol = .direct },
            .{
                .tag = "auto",
                .protocol = .selector,
                .nodes = &.{"direct"},
                .strategy = .least_latency,
                .health_check = .{
                    .target = health_text,
                    .interval_s = 1,
                    .timeout_s = 1,
                },
            },
        },
        .route = .{ .final = "auto" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    try event.wait(io);
    instance.stop();
    _ = health_future.await(io);
}

const TlsAdapterContext = struct {
    listener: *std.Io.net.Server,
    cert: *tls13.test_cert.Certificate,
    error_code: ?anyerror = null,
};

fn tlsAdapterServer(io: std.Io, context: *TlsAdapterContext) void {
    tlsAdapterServerRun(io, context) catch |err| {
        context.error_code = err;
    };
}

fn tlsAdapterServerRun(io: std.Io, context: *TlsAdapterContext) !void {
    const accepted = try context.listener.accept(io);
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const local: marmo.Endpoint = .{ .ip = context.listener.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, local, remote);
    const tls = marmo.TlsServerStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .certificate_chain = &.{context.cert.der},
            .private_key = context.cert.key_pair,
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    const stream = tls.stream();
    defer stream.close(io);

    var buffer: [128]u8 = undefined;
    while (true) {
        var buffers = [_][]u8{&buffer};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) break;
        _ = try stream.write(io, &.{buffer[0..read_len]});
    }
}

test "TLS 1.3 adapters exchange application data" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var context: TlsAdapterContext = .{
        .listener = &listener,
        .cert = &cert,
    };
    var server_future = io.async(tlsAdapterServer, .{ io, &context });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const accepted = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, remote, remote);
    const tls = marmo.TlsClientStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .server_name = "localhost",
            .insecure = true,
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    const stream = tls.stream();
    defer stream.close(io);

    _ = try stream.write(io, &.{"hello"});
    var response: [5]u8 = undefined;
    var offset: usize = 0;
    while (offset < response.len) {
        var buffers = [_][]u8{response[offset..]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
    try std.testing.expectEqualStrings("hello", &response);

    stream.shutdown(io, .send) catch |err| switch (err) {
        error.NotConnected => {},
        else => return err,
    };
    _ = server_future.await(io);
    if (context.error_code) |err| return err;
}

fn streamReadExact(io: std.Io, stream: marmo.Stream, buffer: []u8) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var buffers = [_][]u8{buffer[offset..]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        offset += read_len;
    }
}

test "VLESS inbound over TLS proxies to a direct target" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_server = try echo_bind.listen(io, .{ .reuse_address = true });
    defer echo_server.deinit(io);
    var echo_future = io.async(echoLoopOnce, .{ io, &echo_server });

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);
    const cert_pem = try tls13.test_cert.certificatePem(allocator, cert.der);
    defer allocator.free(cert_pem);
    const key_pem = try tls13.test_cert.privateKeyPem(allocator, cert.key_pair);
    defer {
        std.crypto.secureZero(u8, key_pem);
        allocator.free(key_pem);
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "key.pem", .data = key_pem });

    var cert_path_buffer: [128]u8 = undefined;
    const cert_path = try std.fmt.bufPrint(
        &cert_path_buffer,
        ".zig-cache/tmp/{s}/cert.pem",
        .{tmp.sub_path},
    );
    var key_path_buffer: [128]u8 = undefined;
    const key_path = try std.fmt.bufPrint(
        &key_path_buffer,
        ".zig-cache/tmp/{s}/key.pem",
        .{tmp.sub_path},
    );

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{
                .tag = "vless",
                .protocol = .vless,
                .listen = "127.0.0.1:0",
                .uuid = vless_test_uuid_text,
                .tls = .{
                    .certificate = cert_path,
                    .private_key = key_path,
                },
            },
        },
        .outbounds = &.{
            .{ .tag = "direct", .protocol = .direct },
        },
        .route = .{ .final = "direct" },
    };
    var instance = marmo.Instance.init(allocator, io, config, &diagnostic) catch |err| {
        std.debug.print("init failed: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer instance.deinit();
    try instance.start();

    const vless_endpoint = instance.inboundEndpoint("vless") orelse
        return error.TestUnexpectedResult;
    const vless_address = switch (vless_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const net_stream = try std.Io.net.IpAddress.connect(
        &vless_address,
        io,
        .{ .mode = .stream },
    );
    const remote: marmo.Endpoint = .{ .ip = net_stream.socket.address };
    const tcp = try marmo.TcpStream.create(
        allocator,
        net_stream,
        vless_endpoint,
        remote,
    );
    const tls = marmo.TlsClientStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .server_name = "localhost",
            .insecure = true,
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    const stream = tls.stream();
    defer stream.close(io);

    const target_port = echo_server.socket.address.getPort();
    var target_text_buffer: [32]u8 = undefined;
    const target_text = try std.fmt.bufPrint(
        &target_text_buffer,
        "127.0.0.1:{d}",
        .{target_port},
    );
    const target = try marmo.Endpoint.parse(target_text);
    var header: [marmo.VlessProtocol.request_header_max]u8 = undefined;
    const header_len = try marmo.VlessProtocol.encodeRequest(
        &header,
        &vless_test_uuid,
        target,
    );
    _ = try stream.write(io, &.{header[0..header_len]});
    _ = try stream.write(io, &.{"hello"});

    var response_header: [2]u8 = undefined;
    try streamReadExact(io, stream, &response_header);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, &response_header);

    var echoed: [5]u8 = undefined;
    try streamReadExact(io, stream, &echoed);
    try std.testing.expectEqualStrings("hello", &echoed);

    stream.shutdown(io, .both) catch |err| switch (err) {
        error.NotConnected => {},
        else => return err,
    };
    instance.stop();
    _ = echo_future.await(io);
}

const TestTlsFiles = struct {
    tmp: std.testing.TmpDir,
    cert_path: [160]u8 = undefined,
    cert_path_len: usize = 0,
    key_path: [160]u8 = undefined,
    key_path_len: usize = 0,

    fn init(
        io: std.Io,
        gpa: std.mem.Allocator,
        cert: *tls13.test_cert.Certificate,
    ) !TestTlsFiles {
        var files: TestTlsFiles = .{ .tmp = std.testing.tmpDir(.{}) };
        errdefer files.tmp.cleanup();

        const cert_pem = try tls13.test_cert.certificatePem(gpa, cert.der);
        defer gpa.free(cert_pem);
        const key_pem = try tls13.test_cert.privateKeyPem(gpa, cert.key_pair);
        defer {
            std.crypto.secureZero(u8, key_pem);
            gpa.free(key_pem);
        }

        try files.tmp.dir.writeFile(
            io,
            .{ .sub_path = "cert.pem", .data = cert_pem },
        );
        try files.tmp.dir.writeFile(
            io,
            .{ .sub_path = "key.pem", .data = key_pem },
        );

        const cert_path = try std.fmt.bufPrint(
            &files.cert_path,
            ".zig-cache/tmp/{s}/cert.pem",
            .{files.tmp.sub_path},
        );
        files.cert_path_len = cert_path.len;
        const key_path = try std.fmt.bufPrint(
            &files.key_path,
            ".zig-cache/tmp/{s}/key.pem",
            .{files.tmp.sub_path},
        );
        files.key_path_len = key_path.len;
        return files;
    }

    fn certificatePath(self: *const TestTlsFiles) []const u8 {
        return self.cert_path[0..self.cert_path_len];
    }

    fn privateKeyPath(self: *const TestTlsFiles) []const u8 {
        return self.key_path[0..self.key_path_len];
    }

    fn deinit(self: *TestTlsFiles) void {
        self.tmp.cleanup();
    }
};

fn vlessUdpLoop(use_xudp: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_socket = try echo_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer echo_socket.close(io);
    var echo_future = io.async(udpEchoOnce, .{ io, &echo_socket });

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);
    var files = try TestTlsFiles.init(io, allocator, &cert);
    defer files.deinit();

    var diagnostic: marmo.Diagnostic = .{};
    const server_config: marmo.Config = .{
        .inbounds = &.{
            .{
                .tag = "vless-in",
                .protocol = .vless,
                .listen = "127.0.0.1:0",
                .uuid = vless_test_uuid_text,
                .tls = .{
                    .certificate = files.certificatePath(),
                    .private_key = files.privateKeyPath(),
                },
            },
        },
        .route = .{ .final = "direct" },
    };
    var server_instance = marmo.Instance.init(
        allocator,
        io,
        server_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("vless udp server init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer server_instance.deinit();
    try server_instance.start();

    const vless_endpoint = server_instance.inboundEndpoint("vless-in") orelse
        return error.TestUnexpectedResult;
    var server_text_buffer: [32]u8 = undefined;
    const server_text = try std.fmt.bufPrint(
        &server_text_buffer,
        "127.0.0.1:{d}",
        .{vless_endpoint.port()},
    );

    const client_config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{
                .tag = "vless-out",
                .protocol = .vless,
                .server = server_text,
                .uuid = vless_test_uuid_text,
                .tls = .{ .sni = "localhost", .insecure = true },
                .xudp = use_xudp,
            },
        },
        .route = .{ .final = "vless-out" },
    };
    var client_instance = marmo.Instance.init(
        allocator,
        io,
        client_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("vless udp client init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer client_instance.deinit();
    try client_instance.start();

    const socks_endpoint = client_instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    try tcpWrite(io, client, &[_]u8{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 5), reply[0]);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);
    try std.testing.expectEqual(@as(u8, 1), reply[3]);

    const relay_port = (@as(u16, reply[8]) << 8) | reply[9];
    const relay_address: std.Io.net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = relay_port,
    } };

    var local_bind: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
    const udp_socket = try local_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer udp_socket.close(io);

    const echo_port = echo_socket.address.getPort();
    var packet: [15]u8 = undefined;
    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = 1;
    @memcpy(packet[4..8], &[_]u8{ 127, 0, 0, 1 });
    packet[8] = @intCast(echo_port >> 8);
    packet[9] = @intCast(echo_port & 0xff);
    @memcpy(packet[10..15], "hello");
    try udp_socket.send(io, &relay_address, &packet);

    var receive_buffer: [1500]u8 = undefined;
    const message = try udp_socket.receive(io, &receive_buffer);
    try std.testing.expectEqual(@as(usize, 15), message.data.len);
    try std.testing.expectEqual(@as(u8, 1), message.data[3]);
    try std.testing.expectEqualStrings("hello", message.data[10..15]);

    client_instance.stop();
    server_instance.stop();
    _ = echo_future.await(io);
}

test "VLESS UDP outbound and inbound relay datagrams" {
    try vlessUdpLoop(false);
}

test "VLESS XUDP outbound and inbound relay datagrams" {
    try vlessUdpLoop(true);
}

fn acceptAndHold(
    io: std.Io,
    server: *std.Io.net.Server,
    event: *std.Io.Event,
) void {
    const stream = server.accept(io) catch return;
    event.set(io);
    std.Io.sleep(io, .{ .nanoseconds = 200 * std.time.ns_per_ms }, .awake) catch {};
    stream.close(io);
}

test "TLS client handshake times out" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var event: std.Io.Event = .unset;
    var accept_future = io.concurrent(
        acceptAndHold,
        .{ io, &listener, &event },
    ) catch return error.TestUnexpectedResult;

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const net_stream = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    const remote: marmo.Endpoint = .{ .ip = net_stream.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, net_stream, remote, remote);

    try event.wait(io);
    const result = marmo.TlsClientStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .server_name = "localhost",
            .insecure = true,
            .handshake_timeout_ns = 50 * std.time.ns_per_ms,
        },
    );
    try std.testing.expectError(error.TimedOut, result);

    tcp.stream().close(io);
    _ = accept_future.await(io);
}

const ServerTimeoutContext = struct {
    listener: *std.Io.net.Server,
    cert: *tls13.test_cert.Certificate,
    started: std.Io.Event = .unset,
    error_code: ?anyerror = null,
};

fn tlsServerTimeoutTask(io: std.Io, context: *ServerTimeoutContext) void {
    tlsServerTimeoutRun(io, context) catch |err| {
        context.error_code = err;
    };
}

fn tlsServerTimeoutRun(io: std.Io, context: *ServerTimeoutContext) !void {
    const accepted = try context.listener.accept(io);
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const local: marmo.Endpoint = .{ .ip = context.listener.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, local, remote);

    context.started.set(io);
    const result = marmo.TlsServerStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .certificate_chain = &.{context.cert.der},
            .private_key = context.cert.key_pair,
            .handshake_timeout_ns = 50 * std.time.ns_per_ms,
        },
    );
    if (result) |tls| {
        tls.stream().close(io);
    } else |err| {
        context.error_code = err;
        tcp.stream().close(io);
    }
}

test "TLS server handshake times out" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var context: ServerTimeoutContext = .{
        .listener = &listener,
        .cert = &cert,
    };
    var server_future = io.async(tlsServerTimeoutTask, .{ io, &context });

    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const client = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try context.started.wait(io);
    try std.Io.sleep(io, .{ .nanoseconds = 150 * std.time.ns_per_ms }, .awake);

    _ = server_future.await(io);
    try std.testing.expectEqual(error.TimedOut, context.error_code.?);
}

fn streamReadHeaders(
    io: std.Io,
    stream: marmo.Stream,
    buffer: []u8,
) ![]const u8 {
    var len: usize = 0;
    while (len < buffer.len) {
        var buffers = [_][]u8{buffer[len .. len + 1]};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) return error.EndOfStream;
        len += 1;
        if (len >= 4 and std.mem.endsWith(u8, buffer[0..len], "\r\n\r\n")) {
            return buffer[0..len];
        }
    }
    return error.HeadersTooLarge;
}

fn connectTlsStream(io: std.Io, endpoint: marmo.Endpoint) !marmo.Stream {
    const address = switch (endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const net_stream = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    const remote: marmo.Endpoint = .{ .ip = net_stream.socket.address };
    const tcp = try marmo.TcpStream.create(
        allocator,
        net_stream,
        endpoint,
        remote,
    );
    const tls = marmo.TlsClientStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .server_name = "localhost",
            .insecure = true,
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    return tls.stream();
}

fn fallbackHttpLoop(io: std.Io, server: *std.Io.net.Server) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);

    var headers: [2048]u8 = undefined;
    const request = tcpReadHeaders(io, stream, &headers) catch return;
    if (!std.mem.startsWith(u8, request, "GET / HTTP/1.1\r\n")) {
        tcpWrite(io, stream, "HTTP/1.1 400 Bad Request\r\n\r\n") catch {};
        return;
    }
    tcpWrite(io, stream, "HTTP/1.1 204 No Content\r\n\r\n") catch {};
}

fn buildSocksUdpPacket(
    buffer: []u8,
    port: u16,
    payload: []const u8,
) []const u8 {
    buffer[0] = 0;
    buffer[1] = 0;
    buffer[2] = 0;
    buffer[3] = 1;
    @memcpy(buffer[4..8], &[_]u8{ 127, 0, 0, 1 });
    buffer[8] = @intCast(port >> 8);
    buffer[9] = @intCast(port & 0xff);
    @memcpy(buffer[10..][0..payload.len], payload);
    return buffer[0 .. 10 + payload.len];
}

test "Trojan TCP outbound and inbound relay over TLS" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo_server = try echo_bind.listen(io, .{ .reuse_address = true });
    defer echo_server.deinit(io);
    var echo_future = io.async(echoLoopOnce, .{ io, &echo_server });

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);
    var files = try TestTlsFiles.init(io, allocator, &cert);
    defer files.deinit();

    var diagnostic: marmo.Diagnostic = .{};
    const server_config: marmo.Config = .{
        .inbounds = &.{
            .{
                .tag = "trojan-in",
                .protocol = .trojan,
                .listen = "127.0.0.1:0",
                .password = "trojan-test-secret",
                .tls = .{
                    .certificate = files.certificatePath(),
                    .private_key = files.privateKeyPath(),
                },
            },
        },
        .route = .{ .final = "direct" },
    };
    var server_instance = marmo.Instance.init(
        allocator,
        io,
        server_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("trojan server init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer server_instance.deinit();
    try server_instance.start();

    const trojan_endpoint = server_instance.inboundEndpoint("trojan-in") orelse
        return error.TestUnexpectedResult;
    var server_text_buffer: [32]u8 = undefined;
    const server_text = try std.fmt.bufPrint(
        &server_text_buffer,
        "127.0.0.1:{d}",
        .{trojan_endpoint.port()},
    );

    const client_config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{
                .tag = "trojan-out",
                .protocol = .trojan,
                .server = server_text,
                .password = "trojan-test-secret",
                .tls = .{ .sni = "localhost", .insecure = true },
            },
        },
        .route = .{ .final = "trojan-out" },
    };
    var client_instance = marmo.Instance.init(
        allocator,
        io,
        client_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("trojan client init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer client_instance.deinit();
    try client_instance.start();

    const socks_endpoint = client_instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    const target_port = echo_server.socket.address.getPort();
    try tcpWrite(io, client, &[_]u8{
        5,                          1,                            0, 1, 127, 0, 0, 1,
        @intCast(target_port >> 8), @intCast(target_port & 0xff),
    });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 5), reply[0]);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try tcpWrite(io, client, "hello");
    var echoed: [5]u8 = undefined;
    try tcpReadExact(io, client, &echoed);
    try std.testing.expectEqualStrings("hello", &echoed);

    client_instance.stop();
    server_instance.stop();
    _ = echo_future.await(io);
}

test "Trojan UDP association relays multiple destinations" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var echo1_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo1 = try echo1_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer echo1.close(io);
    var echo1_future = io.async(udpEchoOnce, .{ io, &echo1 });

    var echo2_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var echo2 = try echo2_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer echo2.close(io);
    var echo2_future = io.async(udpEchoOnce, .{ io, &echo2 });

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);
    var files = try TestTlsFiles.init(io, allocator, &cert);
    defer files.deinit();

    var diagnostic: marmo.Diagnostic = .{};
    const server_config: marmo.Config = .{
        .inbounds = &.{
            .{
                .tag = "trojan-in",
                .protocol = .trojan,
                .listen = "127.0.0.1:0",
                .password = "trojan-test-secret",
                .tls = .{
                    .certificate = files.certificatePath(),
                    .private_key = files.privateKeyPath(),
                },
            },
        },
        .route = .{ .final = "direct" },
    };
    var server_instance = marmo.Instance.init(
        allocator,
        io,
        server_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("trojan udp server init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer server_instance.deinit();
    try server_instance.start();

    const trojan_endpoint = server_instance.inboundEndpoint("trojan-in") orelse
        return error.TestUnexpectedResult;
    var server_text_buffer: [32]u8 = undefined;
    const server_text = try std.fmt.bufPrint(
        &server_text_buffer,
        "127.0.0.1:{d}",
        .{trojan_endpoint.port()},
    );

    const client_config: marmo.Config = .{
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .outbounds = &.{
            .{
                .tag = "trojan-out",
                .protocol = .trojan,
                .server = server_text,
                .password = "trojan-test-secret",
                .tls = .{ .sni = "localhost", .insecure = true },
            },
        },
        .route = .{ .final = "trojan-out" },
    };
    var client_instance = marmo.Instance.init(
        allocator,
        io,
        client_config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("trojan udp client init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer client_instance.deinit();
    try client_instance.start();

    const socks_endpoint = client_instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const socks_address = switch (socks_endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &socks_address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try socksNegotiate(io, client);
    try tcpWrite(io, client, &[_]u8{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 });

    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 5), reply[0]);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    const relay_port = (@as(u16, reply[8]) << 8) | reply[9];
    const relay_address: std.Io.net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = relay_port,
    } };

    var local_bind: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
    const udp_socket = try local_bind.bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer udp_socket.close(io);

    var packet: [64]u8 = undefined;
    const first = buildSocksUdpPacket(
        &packet,
        echo1.address.getPort(),
        "first",
    );
    try udp_socket.send(io, &relay_address, first);

    var receive_buffer: [1500]u8 = undefined;
    const first_reply = try udp_socket.receive(io, &receive_buffer);
    try std.testing.expectEqualStrings("first", first_reply.data[10..]);

    const second = buildSocksUdpPacket(
        &packet,
        echo2.address.getPort(),
        "second",
    );
    try udp_socket.send(io, &relay_address, second);
    const second_reply = try udp_socket.receive(io, &receive_buffer);
    try std.testing.expectEqualStrings("second", second_reply.data[10..]);

    client_instance.stop();
    server_instance.stop();
    _ = echo1_future.await(io);
    _ = echo2_future.await(io);
}

test "Trojan fallback receives an unauthenticated HTTP probe" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fallback_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var fallback_server = try fallback_bind.listen(
        io,
        .{ .reuse_address = true },
    );
    defer fallback_server.deinit(io);
    var fallback_future = io.async(
        fallbackHttpLoop,
        .{ io, &fallback_server },
    );

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);
    var files = try TestTlsFiles.init(io, allocator, &cert);
    defer files.deinit();

    var fallback_text_buffer: [32]u8 = undefined;
    const fallback_text = try std.fmt.bufPrint(
        &fallback_text_buffer,
        "127.0.0.1:{d}",
        .{fallback_server.socket.address.getPort()},
    );

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .inbounds = &.{
            .{
                .tag = "trojan-in",
                .protocol = .trojan,
                .listen = "127.0.0.1:0",
                .password = "trojan-test-secret",
                .fallback = fallback_text,
                .tls = .{
                    .certificate = files.certificatePath(),
                    .private_key = files.privateKeyPath(),
                },
            },
        },
        .route = .{ .final = "direct" },
    };
    var instance = marmo.Instance.init(
        allocator,
        io,
        config,
        &diagnostic,
    ) catch |err| {
        std.debug.print("trojan fallback init: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer instance.deinit();
    try instance.start();

    const endpoint = instance.inboundEndpoint("trojan-in") orelse
        return error.TestUnexpectedResult;
    const stream = try connectTlsStream(io, endpoint);
    defer stream.close(io);

    _ = try stream.write(io, &.{"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"});
    var response: [512]u8 = undefined;
    const headers = try streamReadHeaders(io, stream, &response);
    try std.testing.expect(std.mem.startsWith(u8, headers, "HTTP/1.1 204"));

    stream.shutdown(io, .both) catch |err| switch (err) {
        error.NotConnected => {},
        else => return err,
    };
    instance.stop();
    _ = fallback_future.await(io);
}

const WsAdapterContext = struct {
    listener: *std.Io.net.Server,
    cert: *tls13.test_cert.Certificate,
    alpn: []const u8,
    error_code: ?anyerror = null,
};

fn wsAdapterServer(io: std.Io, context: *WsAdapterContext) void {
    wsAdapterServerRun(io, context) catch |err| {
        context.error_code = err;
    };
}

fn wsAdapterServerRun(io: std.Io, context: *WsAdapterContext) !void {
    const accepted = try context.listener.accept(io);
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const local: marmo.Endpoint = .{ .ip = context.listener.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, local, remote);

    const tls = marmo.TlsServerStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .certificate_chain = &.{context.cert.der},
            .private_key = context.cert.key_pair,
            .alpn_protocols = &.{context.alpn},
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    if (!std.mem.eql(
        u8,
        tls.negotiatedProtocol() orelse "",
        context.alpn,
    )) return error.TestUnexpectedResult;

    const ws = marmo.WsStream.createServer(
        io,
        allocator,
        tls.stream(),
        .{ .path = "/ws" },
    ) catch |err| {
        tls.stream().close(io);
        return err;
    };
    const stream = ws.stream();
    defer stream.close(io);

    var buffer: [128]u8 = undefined;
    while (true) {
        var buffers = [_][]u8{&buffer};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) break;
        _ = try stream.write(io, &.{buffer[0..read_len]});
    }
}

test "WebSocket over TLS echoes and negotiates ALPN" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var context: WsAdapterContext = .{
        .listener = &listener,
        .cert = &cert,
        .alpn = "http/1.1",
    };
    var server_future = io.async(wsAdapterServer, .{ io, &context });

    var address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };
    const accepted = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, remote, remote);
    const tls = marmo.TlsClientStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .server_name = "localhost",
            .insecure = true,
            .alpn_protocols = &.{"http/1.1"},
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    try std.testing.expectEqualStrings(
        "http/1.1",
        tls.negotiatedProtocol() orelse "",
    );

    const ws = marmo.WsStream.createClient(
        io,
        allocator,
        tls.stream(),
        .{ .host = "localhost", .path = "/ws" },
    ) catch |err| {
        tls.stream().close(io);
        return err;
    };
    const stream = ws.stream();
    defer stream.close(io);

    _ = try stream.write(io, &.{"hello over ws"});
    var response: [13]u8 = undefined;
    try streamReadExact(io, stream, &response);
    try std.testing.expectEqualStrings("hello over ws", &response);

    stream.shutdown(io, .send) catch |err| switch (err) {
        error.NotConnected => {},
        else => return err,
    };
    _ = server_future.await(io);
    if (context.error_code) |err| return err;
}

const H2AdapterContext = struct {
    listener: *std.Io.net.Server,
    cert: *tls13.test_cert.Certificate,
    error_code: ?anyerror = null,
    /// Lets the half-closed server keep the socket open until the client has
    /// consumed the response, avoiding a close-with-unread-data RST.
    done: std.Io.Event = .unset,
};

fn h2AdapterServer(io: std.Io, context: *H2AdapterContext) void {
    h2AdapterServerRun(io, context) catch |err| {
        context.error_code = err;
    };
}

fn h2AdapterServerRun(io: std.Io, context: *H2AdapterContext) !void {
    const accepted = try context.listener.accept(io);
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const local: marmo.Endpoint = .{ .ip = context.listener.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, local, remote);

    const tls = marmo.TlsServerStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .certificate_chain = &.{context.cert.der},
            .private_key = context.cert.key_pair,
            .alpn_protocols = &.{"h2"},
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    if (!std.mem.eql(u8, tls.negotiatedProtocol() orelse "", "h2")) {
        return error.TestUnexpectedResult;
    }

    const h2 = marmo.H2Stream.createServer(
        io,
        allocator,
        tls.stream(),
        .{},
    ) catch |err| {
        tls.stream().close(io);
        return err;
    };
    const stream = h2.stream();
    defer stream.close(io);

    var buffer: [128]u8 = undefined;
    while (true) {
        var buffers = [_][]u8{&buffer};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) break;
        _ = try stream.write(io, &.{buffer[0..read_len]});
    }
}

test "HTTP/2 over TLS echoes and negotiates ALPN" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var context: H2AdapterContext = .{
        .listener = &listener,
        .cert = &cert,
    };
    var server_future = io.async(h2AdapterServer, .{ io, &context });

    var address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };
    const accepted = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, remote, remote);
    const tls = marmo.TlsClientStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .server_name = "localhost",
            .insecure = true,
            .alpn_protocols = &.{"h2"},
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    try std.testing.expectEqualStrings(
        "h2",
        tls.negotiatedProtocol() orelse "",
    );

    const h2 = marmo.H2Stream.createClient(
        io,
        allocator,
        tls.stream(),
        .{ .host = "localhost", .path = "/" },
    ) catch |err| {
        tls.stream().close(io);
        return err;
    };
    const stream = h2.stream();
    defer stream.close(io);

    _ = try stream.write(io, &.{"hello over h2"});
    var response: [13]u8 = undefined;
    try streamReadExact(io, stream, &response);
    try std.testing.expectEqualStrings("hello over h2", &response);

    stream.shutdown(io, .send) catch |err| switch (err) {
        error.NotConnected => {},
        else => return err,
    };
    _ = server_future.await(io);
    if (context.error_code) |err| return err;
}

const HoldContext = struct {
    listener: *std.Io.net.Server,
    release: std.Io.Event = .unset,
    error_code: ?anyerror = null,
};

fn holdServer(io: std.Io, context: *HoldContext) void {
    const stream = context.listener.accept(io) catch |err| {
        context.error_code = err;
        return;
    };
    defer stream.close(io);
    context.release.waitUncancelable(io);
}

fn socksConnectRequest(buffer: []u8, port: u16) []const u8 {
    buffer[0] = 5;
    buffer[1] = 1;
    buffer[2] = 0;
    buffer[3] = 1;
    @memcpy(buffer[4..8], &[_]u8{ 127, 0, 0, 1 });
    buffer[8] = @intCast(port >> 8);
    buffer[9] = @intCast(port & 0xff);
    return buffer[0..10];
}

test "limits reject connections over max_connections" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .limits = .{ .max_connections = 1 },
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .route = .{ .final = "direct" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const address = switch (endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };

    const first = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer first.close(io);
    var waits: usize = 0;
    while (instance.metricsSnapshot().connections_active == 0 and waits < 200) : (waits += 1) {
        try std.Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake);
    }
    try std.testing.expectEqual(
        @as(u64, 1),
        instance.metricsSnapshot().connections_active,
    );

    const second = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer second.close(io);

    var buffer: [1]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const read_len = second.read(io, &buffers) catch 0;
    try std.testing.expectEqual(@as(usize, 0), read_len);
    waits = 0;
    while (instance.metricsSnapshot().connections_rejected == 0 and waits < 200) : (waits += 1) {
        try std.Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake);
    }
    const snapshot = instance.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), snapshot.connections_rejected);
    try std.testing.expectEqual(@as(u64, 1), snapshot.connections_active);
}

test "handshake timeout closes a silent inbound" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .limits = .{ .handshake_timeout_s = 1 },
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .route = .{ .final = "direct" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const address = switch (endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    try std.Io.sleep(io, .{ .nanoseconds = 1300 * std.time.ns_per_ms }, .awake);
    var buffer: [1]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const read_len = client.read(io, &buffers) catch 0;
    try std.testing.expectEqual(@as(usize, 0), read_len);
    var waits: usize = 0;
    while (waits < 200) : (waits += 1) {
        const current = instance.metricsSnapshot();
        if (current.timeouts_handshake >= 1 and
            current.connections_active == 0)
        {
            break;
        }
        try std.Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake);
    }
    const snapshot = instance.metricsSnapshot();
    try std.testing.expect(snapshot.timeouts_handshake >= 1);
    try std.testing.expectEqual(@as(u64, 0), snapshot.connections_active);
}

test "idle timeout closes a relay with no traffic" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var hold_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var hold_listener = try hold_bind.listen(io, .{ .reuse_address = true });
    defer hold_listener.deinit(io);
    var hold_context: HoldContext = .{ .listener = &hold_listener };
    var hold_future = io.async(holdServer, .{ io, &hold_context });

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .limits = .{ .idle_timeout_s = 1 },
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .route = .{ .final = "direct" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const address = switch (endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    try socksNegotiate(io, client);

    var request_buffer: [10]u8 = undefined;
    try tcpWrite(io, client, socksConnectRequest(
        &request_buffer,
        hold_listener.socket.address.getPort(),
    ));
    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try std.Io.sleep(io, .{ .nanoseconds = 1300 * std.time.ns_per_ms }, .awake);
    var buffer: [1]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const read_len = client.read(io, &buffers) catch 0;
    try std.testing.expectEqual(@as(usize, 0), read_len);
    try std.Io.sleep(io, .{ .nanoseconds = 100 * std.time.ns_per_ms }, .awake);
    var waits: usize = 0;
    while (waits < 200) : (waits += 1) {
        const current = instance.metricsSnapshot();
        if (current.timeouts_idle >= 1 and current.connections_active == 0) {
            break;
        }
        try std.Io.sleep(io, .{ .nanoseconds = 10 * std.time.ns_per_ms }, .awake);
    }
    const snapshot = instance.metricsSnapshot();
    try std.testing.expect(snapshot.timeouts_idle >= 1);
    try std.testing.expectEqual(@as(u64, 0), snapshot.connections_active);

    hold_context.release.set(io);
    _ = hold_future.await(io);
    if (hold_context.error_code) |err| return err;
}

test "half-close grace closes the remaining direction" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var hold_bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var hold_listener = try hold_bind.listen(io, .{ .reuse_address = true });
    defer hold_listener.deinit(io);
    var hold_context: HoldContext = .{ .listener = &hold_listener };
    var hold_future = io.async(holdServer, .{ io, &hold_context });

    var diagnostic: marmo.Diagnostic = .{};
    const config: marmo.Config = .{
        .limits = .{
            .idle_timeout_s = 60,
            .downlink_only_s = 1,
        },
        .inbounds = &.{
            .{ .tag = "socks", .protocol = .socks5, .listen = "127.0.0.1:0" },
        },
        .route = .{ .final = "direct" },
    };
    var instance = try marmo.Instance.init(allocator, io, config, &diagnostic);
    defer instance.deinit();
    try instance.start();

    const endpoint = instance.inboundEndpoint("socks") orelse
        return error.TestUnexpectedResult;
    const address = switch (endpoint) {
        .ip => |ip| ip,
        .domain => return error.TestUnexpectedResult,
    };
    const client = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    try socksNegotiate(io, client);

    var request_buffer: [10]u8 = undefined;
    try tcpWrite(io, client, socksConnectRequest(
        &request_buffer,
        hold_listener.socket.address.getPort(),
    ));
    var reply: [10]u8 = undefined;
    try tcpReadExact(io, client, &reply);
    try std.testing.expectEqual(@as(u8, 0), reply[1]);

    try client.shutdown(io, .send);
    try std.Io.sleep(io, .{ .nanoseconds = 1300 * std.time.ns_per_ms }, .awake);
    var buffer: [1]u8 = undefined;
    var buffers = [_][]u8{&buffer};
    const read_len = client.read(io, &buffers) catch 0;
    try std.testing.expectEqual(@as(usize, 0), read_len);
    const snapshot = instance.metricsSnapshot();
    try std.testing.expect(snapshot.timeouts_idle >= 1);

    hold_context.release.set(io);
    _ = hold_future.await(io);
    if (hold_context.error_code) |err| return err;
}

fn h2HalfClosedServerRun(io: std.Io, context: *H2AdapterContext) !void {
    const accepted = try context.listener.accept(io);
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const local: marmo.Endpoint = .{ .ip = context.listener.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, local, remote);

    const tls = marmo.TlsServerStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .certificate_chain = &.{context.cert.der},
            .private_key = context.cert.key_pair,
            .alpn_protocols = &.{"h2"},
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    const h2 = marmo.H2Stream.createServer(
        io,
        allocator,
        tls.stream(),
        .{},
    ) catch |err| {
        tls.stream().close(io);
        return err;
    };
    const stream = h2.stream();
    defer stream.close(io);

    var buffer: [16]u8 = undefined;
    while (true) {
        var buffers = [_][]u8{&buffer};
        if (try stream.read(io, &buffers) == 0) break;
    }

    // The peer half-closed its side. Keep writing past its initial flow
    // control window; the connection must still process WINDOW_UPDATE.
    const chunk = try allocator.alloc(u8, 16 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 0x5a);
    var written: usize = 0;
    while (written < 3 * 1024 * 1024) : (written += chunk.len) {
        _ = try stream.write(io, &.{chunk});
    }
    stream.shutdown(io, .send) catch |err| switch (err) {
        error.NotConnected => {},
        else => return err,
    };
    context.done.waitUncancelable(io);
}

test "HTTP/2 keeps reading flow control after the peer half-closes" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cert = try tls13.test_cert.generate(allocator, io);
    defer cert.deinit(allocator);

    var bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try bind.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var context: H2AdapterContext = .{
        .listener = &listener,
        .cert = &cert,
    };
    var server_future = io.async(h2HalfClosedServerRun, .{ io, &context });

    var address: std.Io.net.IpAddress = .{
        .ip4 = .loopback(listener.socket.address.getPort()),
    };
    const accepted = try std.Io.net.IpAddress.connect(
        &address,
        io,
        .{ .mode = .stream },
    );
    const remote: marmo.Endpoint = .{ .ip = accepted.socket.address };
    const tcp = try marmo.TcpStream.create(allocator, accepted, remote, remote);
    const tls = marmo.TlsClientStream.create(
        io,
        allocator,
        tcp.stream(),
        .{
            .server_name = "localhost",
            .insecure = true,
            .alpn_protocols = &.{"h2"},
        },
    ) catch |err| {
        tcp.stream().close(io);
        return err;
    };
    const h2 = marmo.H2Stream.createClient(
        io,
        allocator,
        tls.stream(),
        .{ .host = "localhost", .path = "/" },
    ) catch |err| {
        tls.stream().close(io);
        return err;
    };
    const stream = h2.stream();
    defer stream.close(io);

    _ = try stream.write(io, &.{"request"});
    try stream.shutdown(io, .send);

    defer context.done.set(io);
    var buffer: [16 * 1024]u8 = undefined;
    var total: usize = 0;
    while (total < 3 * 1024 * 1024) {
        var buffers = [_][]u8{&buffer};
        const read_len = try stream.read(io, &buffers);
        if (read_len == 0) break;
        total += read_len;
    }
    try std.testing.expectEqual(@as(usize, 3 * 1024 * 1024), total);
    context.done.set(io);
    try server_future.await(io);
    if (context.error_code) |err| return err;
}
