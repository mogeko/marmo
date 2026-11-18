const std = @import("std");
const marmo = @import("marmo");

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

fn udpEchoOnce(io: std.Io, socket: *std.Io.net.Socket) void {
    var buffer: [1500]u8 = undefined;
    const message = socket.receive(io, &buffer) catch return;
    socket.send(io, &message.from, message.data) catch return;
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
