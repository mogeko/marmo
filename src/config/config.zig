//! Strict JSON configuration and validation.

const std = @import("std");
const Diagnostic = @import("../core/diagnostic.zig").Diagnostic;
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Cidr = @import("../net/cidr.zig").Cidr;
const Network = @import("../routing/metadata.zig").Network;

pub const Config = struct {
    version: u8 = 1,
    inbounds: []const Inbound = &.{},
    outbounds: []const Outbound = &.{},
    route: Route = .{},

    pub const Inbound = struct {
        tag: []const u8,
        protocol: InboundProtocol,
        listen: []const u8,
    };

    pub const InboundProtocol = enum { socks5, http };

    pub const Outbound = struct {
        tag: []const u8,
        protocol: OutboundProtocol,
        server: ?[]const u8 = null,
        method: ?[]const u8 = null,
        password: ?[]const u8 = null,
    };

    pub const OutboundProtocol = enum { direct, http, shadowsocks };

    pub const Route = struct {
        rules: []const Rule = &.{},
        final: []const u8 = "direct",
    };

    pub const Rule = struct {
        domain: ?[]const []const u8 = null,
        domain_suffix: ?[]const []const u8 = null,
        ip_cidr: ?[]const []const u8 = null,
        port: ?[]const u16 = null,
        network: ?Network = null,
        outbound: []const u8,
    };
};

pub const ValidationError = error{InvalidConfig};

pub const ParseError = error{ InvalidJson, OutOfMemory };

pub const Parsed = struct {
    inner: std.json.Parsed(Config),

    /// Keep this value alive while an `Instance` uses `config()`, because the
    /// instance borrows every slice in the configuration.
    pub fn deinit(self: *Parsed) void {
        self.inner.deinit();
    }

    pub fn config(self: *const Parsed) *const Config {
        return &self.inner.value;
    }
};

pub fn fromJson(gpa: std.mem.Allocator, text: []const u8) ParseError!Parsed {
    const inner = std.json.parseFromSlice(Config, gpa, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    return .{ .inner = inner };
}

pub fn validate(config: Config, diagnostic: *Diagnostic) ValidationError!void {
    if (config.version != 1) {
        diagnostic.set("version: unsupported version {d}", .{config.version});
        return error.InvalidConfig;
    }

    try validateInbounds(config.inbounds, diagnostic);
    try validateOutbounds(config.outbounds, diagnostic);
    try validateRoute(config.route, config.outbounds, diagnostic);
}

fn validateInbounds(
    inbounds: []const Config.Inbound,
    diagnostic: *Diagnostic,
) ValidationError!void {
    for (inbounds, 0..) |inbound, index| {
        if (inbound.tag.len == 0) {
            diagnostic.set("inbounds[{d}].tag: must not be empty", .{index});
            return error.InvalidConfig;
        }
        for (inbounds[0..index]) |previous| {
            if (std.mem.eql(u8, previous.tag, inbound.tag)) {
                diagnostic.set("inbounds[{d}].tag: duplicate '{s}'", .{
                    index,
                    inbound.tag,
                });
                return error.InvalidConfig;
            }
        }

        const endpoint = Endpoint.parse(inbound.listen) catch {
            diagnostic.set("inbounds[{d}].listen: invalid endpoint '{s}'", .{
                index,
                inbound.listen,
            });
            return error.InvalidConfig;
        };
        switch (endpoint) {
            .ip => {},
            .domain => {
                diagnostic.set("inbounds[{d}].listen: must be an IP endpoint", .{index});
                return error.InvalidConfig;
            },
        }
    }
}

fn validateOutbounds(
    outbounds: []const Config.Outbound,
    diagnostic: *Diagnostic,
) ValidationError!void {
    for (outbounds, 0..) |outbound, index| {
        if (outbound.tag.len == 0) {
            diagnostic.set("outbounds[{d}].tag: must not be empty", .{index});
            return error.InvalidConfig;
        }
        if (std.mem.eql(u8, outbound.tag, "reject")) {
            diagnostic.set("outbounds[{d}].tag: 'reject' is reserved", .{index});
            return error.InvalidConfig;
        }
        for (outbounds[0..index]) |previous| {
            if (std.mem.eql(u8, previous.tag, outbound.tag)) {
                diagnostic.set("outbounds[{d}].tag: duplicate '{s}'", .{
                    index,
                    outbound.tag,
                });
                return error.InvalidConfig;
            }
        }

        switch (outbound.protocol) {
            .direct => try validateDirect(outbound, index, diagnostic),
            .http => try validateHttp(outbound, index, diagnostic),
            .shadowsocks => try validateShadowsocks(outbound, index, diagnostic),
        }
    }
}

fn validateDirect(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (outbound.server != null or outbound.method != null or outbound.password != null) {
        diagnostic.set("outbounds[{d}]: direct does not take server or credentials", .{index});
        return error.InvalidConfig;
    }
}

fn validateHttp(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    const server = outbound.server orelse {
        diagnostic.set("outbounds[{d}].server: required for http", .{index});
        return error.InvalidConfig;
    };
    _ = Endpoint.parse(server) catch {
        diagnostic.set("outbounds[{d}].server: invalid endpoint '{s}'", .{
            index,
            server,
        });
        return error.InvalidConfig;
    };
    if (outbound.method != null or outbound.password != null) {
        diagnostic.set("outbounds[{d}]: http does not take method or password", .{index});
        return error.InvalidConfig;
    }
}

fn validateShadowsocks(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    const server = outbound.server orelse {
        diagnostic.set("outbounds[{d}].server: required for shadowsocks", .{index});
        return error.InvalidConfig;
    };
    _ = Endpoint.parse(server) catch {
        diagnostic.set("outbounds[{d}].server: invalid endpoint '{s}'", .{
            index,
            server,
        });
        return error.InvalidConfig;
    };

    const method = outbound.method orelse {
        diagnostic.set("outbounds[{d}].method: required for shadowsocks", .{index});
        return error.InvalidConfig;
    };
    const key_len = shadowsocksKeyLength(method) orelse {
        diagnostic.set("outbounds[{d}].method: unsupported '{s}'", .{ index, method });
        return error.InvalidConfig;
    };

    const password = outbound.password orelse {
        diagnostic.set("outbounds[{d}].password: required for shadowsocks", .{index});
        return error.InvalidConfig;
    };
    if (password.len == 0) {
        diagnostic.set("outbounds[{d}].password: must not be empty", .{index});
        return error.InvalidConfig;
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(password) catch {
        diagnostic.set("outbounds[{d}].password: invalid base64", .{index});
        return error.InvalidConfig;
    };
    if (decoded_len != key_len) {
        diagnostic.set("outbounds[{d}].password: wrong key length for {s}", .{
            index,
            method,
        });
        return error.InvalidConfig;
    }
    var key_buffer: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(
        key_buffer[0..decoded_len],
        password,
    ) catch {
        diagnostic.set("outbounds[{d}].password: invalid base64", .{index});
        return error.InvalidConfig;
    };
}

fn shadowsocksKeyLength(method: []const u8) ?usize {
    if (std.mem.eql(u8, method, "2022-blake3-aes-128-gcm")) return 16;
    if (std.mem.eql(u8, method, "2022-blake3-aes-256-gcm")) return 32;
    if (std.mem.eql(u8, method, "2022-blake3-chacha20-poly1305")) return 32;
    return null;
}

fn validateRoute(
    route: Config.Route,
    outbounds: []const Config.Outbound,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (!isValidRouteTarget(route.final, outbounds)) {
        diagnostic.set("route.final: unknown outbound '{s}'", .{route.final});
        return error.InvalidConfig;
    }

    for (route.rules, 0..) |rule, index| {
        if (!isValidRouteTarget(rule.outbound, outbounds)) {
            diagnostic.set("route.rules[{d}].outbound: unknown '{s}'", .{
                index,
                rule.outbound,
            });
            return error.InvalidConfig;
        }
        try validateRule(rule, index, diagnostic);
    }
}

fn validateRule(
    rule: Config.Rule,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (rule.domain) |domains| {
        for (domains) |domain| {
            if (domain.len == 0) {
                diagnostic.set("route.rules[{d}].domain: empty value", .{index});
                return error.InvalidConfig;
            }
        }
    }
    if (rule.domain_suffix) |suffixes| {
        for (suffixes) |suffix| {
            if (suffix.len == 0) {
                diagnostic.set("route.rules[{d}].domain_suffix: empty value", .{index});
                return error.InvalidConfig;
            }
        }
    }
    if (rule.ip_cidr) |cidrs| {
        for (cidrs) |cidr| {
            _ = Cidr.parse(cidr) catch {
                diagnostic.set("route.rules[{d}].ip_cidr: invalid '{s}'", .{
                    index,
                    cidr,
                });
                return error.InvalidConfig;
            };
        }
    }
    if (rule.port) |ports| {
        if (ports.len == 0) {
            diagnostic.set("route.rules[{d}].port: must not be empty", .{index});
            return error.InvalidConfig;
        }
    }
}

fn isValidRouteTarget(tag: []const u8, outbounds: []const Config.Outbound) bool {
    if (std.mem.eql(u8, tag, "direct")) return true;
    if (std.mem.eql(u8, tag, "reject")) return true;
    for (outbounds) |outbound| {
        if (std.mem.eql(u8, outbound.tag, tag)) return true;
    }
    return false;
}

test "config parses defaults and validates" {
    var diagnostic: Diagnostic = .{};
    var parsed = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:1080" }
        \\  ],
        \\  "outbounds": [
        \\    { "tag": "direct", "protocol": "direct" }
        \\  ],
        \\  "route": {
        \\    "rules": [
        \\      { "domain_suffix": ["example.com"], "outbound": "direct" }
        \\    ],
        \\    "final": "direct"
        \\  }
        \\}
    );
    defer parsed.deinit();

    try validate(parsed.inner.value, &diagnostic);
    try std.testing.expectEqual(@as(usize, 1), parsed.inner.value.inbounds.len);
    try std.testing.expectEqualStrings("direct", parsed.inner.value.route.final);
}

test "config rejects unknown fields and duplicate tags" {
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.InvalidJson, fromJson(std.testing.allocator,
        \\{ "unknown": true }
    ));

    var parsed = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "a", "protocol": "socks5", "listen": "127.0.0.1:1" },
        \\    { "tag": "a", "protocol": "http", "listen": "127.0.0.1:2" }
        \\  ]
        \\}
    );
    defer parsed.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(parsed.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[1].tag: duplicate 'a'",
        diagnostic.message(),
    );
}

test "config rejects domain listen addresses and bad CIDRs" {
    var diagnostic: Diagnostic = .{};
    var parsed = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "a", "protocol": "http", "listen": "localhost:8080" }
        \\  ],
        \\  "route": {
        \\    "rules": [
        \\      { "ip_cidr": ["10.0.0.0/33"], "outbound": "direct" }
        \\    ]
        \\  }
        \\}
    );
    defer parsed.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(parsed.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0].listen: must be an IP endpoint",
        diagnostic.message(),
    );
}
