//! Network endpoints used by the public API.

const std = @import("std");

/// A destination or source address.
///
/// The domain name is borrowed. Metadata that stores an endpoint must keep the
/// backing bytes alive for the lifetime of the connection.
pub const Endpoint = union(enum) {
    ip: std.Io.net.IpAddress,
    domain: Domain,

    pub const Domain = struct {
        name: []const u8,
        port: u16,
    };

    pub const ParseError = error{
        EmptyHost,
        InvalidAddress,
        InvalidEndpoint,
        InvalidPort,
        MissingPort,
    };

    /// Parse `host:port`, `1.2.3.4:port`, or `[::1]:port`.
    ///
    /// Unbracketed IPv6 is rejected because the port separator is ambiguous.
    pub fn parse(text: []const u8) ParseError!Endpoint {
        if (text.len == 0) return error.InvalidEndpoint;

        if (text[0] == '[') {
            const ip = std.Io.net.IpAddress.parseLiteral(text) catch |err| switch (err) {
                error.InvalidAddress => return error.InvalidAddress,
                error.InvalidPort => return error.InvalidPort,
            };
            return .{ .ip = ip };
        }

        const colon = std.mem.findScalar(u8, text, ':') orelse return error.MissingPort;
        if (std.mem.findScalar(u8, text[colon + 1 ..], ':')) |_| {
            return error.InvalidEndpoint;
        }

        const host = text[0..colon];
        if (host.len == 0) return error.EmptyHost;

        const port_number = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch
            return error.InvalidPort;

        const ip4 = std.Io.net.Ip4Address.parse(host, port_number) catch {
            return .{ .domain = .{ .name = host, .port = port_number } };
        };
        return .{ .ip = .{ .ip4 = ip4 } };
    }

    pub fn port(self: Endpoint) u16 {
        return switch (self) {
            .ip => |ip| ip.getPort(),
            .domain => |domain| domain.port,
        };
    }

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        return switch (a) {
            .ip => |a_ip| switch (b) {
                .ip => |b_ip| std.Io.net.IpAddress.eql(&a_ip, &b_ip),
                .domain => false,
            },
            .domain => |a_domain| switch (b) {
                .domain => |b_domain| a_domain.port == b_domain.port and
                    std.mem.eql(u8, a_domain.name, b_domain.name),
                .ip => false,
            },
        };
    }

    pub fn format(self: Endpoint, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ip => |ip| try ip.format(writer),
            .domain => |domain| try writer.print("{s}:{d}", .{
                domain.name,
                domain.port,
            }),
        }
    }
};

test "parse a domain endpoint" {
    const endpoint = try Endpoint.parse("example.com:443");
    try std.testing.expectEqual(@as(u16, 443), endpoint.port());
    try std.testing.expectEqualStrings("example.com", endpoint.domain.name);
}

test "parse an IPv4 endpoint" {
    const endpoint = try Endpoint.parse("127.0.0.1:8080");
    try std.testing.expectEqual(@as(u16, 8080), endpoint.port());
    switch (endpoint) {
        .ip => |ip| switch (ip) {
            .ip4 => {},
            .ip6 => return error.TestUnexpectedResult,
        },
        .domain => return error.TestUnexpectedResult,
    }
}

test "parse an IPv6 endpoint" {
    const endpoint = try Endpoint.parse("[::1]:8443");
    try std.testing.expectEqual(@as(u16, 8443), endpoint.port());
    switch (endpoint) {
        .ip => |ip| switch (ip) {
            .ip4 => return error.TestUnexpectedResult,
            .ip6 => {},
        },
        .domain => return error.TestUnexpectedResult,
    }
}

test "reject malformed endpoints" {
    try std.testing.expectError(error.MissingPort, Endpoint.parse("example.com"));
    try std.testing.expectError(error.EmptyHost, Endpoint.parse(":443"));
    try std.testing.expectError(error.InvalidPort, Endpoint.parse("example.com:https"));
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse("::1:443"));
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse(""));
}

test "format endpoints" {
    var buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);

    const domain: Endpoint = .{ .domain = .{ .name = "example.com", .port = 443 } };
    try domain.format(&writer);
    try std.testing.expectEqualStrings("example.com:443", writer.buffered());

    var buffer_ip: [64]u8 = undefined;
    var writer_ip = std.Io.Writer.fixed(&buffer_ip);
    const ip: Endpoint = .{ .ip = .{ .ip4 = .{ .port = 80, .bytes = .{ 127, 0, 0, 1 } } } };
    try ip.format(&writer_ip);
    try std.testing.expectEqualStrings("127.0.0.1:80", writer_ip.buffered());
}

test "endpoint equality" {
    const a = try Endpoint.parse("example.com:443");
    const b = try Endpoint.parse("example.com:443");
    const c = try Endpoint.parse("example.com:8443");
    try std.testing.expect(Endpoint.eql(a, b));
    try std.testing.expect(!Endpoint.eql(a, c));
}
