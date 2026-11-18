//! Strict JSON configuration and validation.

const std = @import("std");
const Diagnostic = @import("../core/diagnostic.zig").Diagnostic;
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Cidr = @import("../net/cidr.zig").Cidr;
const Network = @import("../routing/metadata.zig").Network;
const s2022 = @import("../protocol/shadowsocks2022.zig");

pub const Config = struct {
    version: u8 = 1,
    inbounds: []const Inbound = &.{},
    outbounds: []const Outbound = &.{},
    route: Route = .{},

    /// Parse strict JSON. Keep the returned `Parsed` alive for as long as the
    /// config is used; the instance borrows all slices.
    pub fn parseJson(gpa: std.mem.Allocator, text: []const u8) ParseError!Parsed {
        return fromJson(gpa, text);
    }

    pub const Inbound = struct {
        tag: []const u8,
        protocol: InboundProtocol,
        listen: []const u8,
        method: ?[]const u8 = null,
        password: ?[]const u8 = null,
    };

    pub const InboundProtocol = enum { http, shadowsocks, socks5 };

    pub const Outbound = struct {
        tag: []const u8,
        protocol: OutboundProtocol,
        server: ?[]const u8 = null,
        method: ?[]const u8 = null,
        password: ?[]const u8 = null,
        nodes: ?[]const []const u8 = null,
        strategy: ?Strategy = null,
    };

    pub const OutboundProtocol = enum { direct, http, selector, shadowsocks };

    pub const Strategy = enum { fallback, least_latency, manual, random, round_robin };

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

        switch (inbound.protocol) {
            .socks5, .http => {
                if (inbound.method != null or inbound.password != null) {
                    diagnostic.set(
                        "inbounds[{d}]: credentials only apply to shadowsocks",
                        .{index},
                    );
                    return error.InvalidConfig;
                }
            },
            .shadowsocks => try validateShadowsocksInbound(inbound, index, diagnostic),
        }
    }
}

fn validateShadowsocksInbound(
    inbound: Config.Inbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    const method_text = inbound.method orelse {
        diagnostic.set("inbounds[{d}].method: required for shadowsocks", .{index});
        return error.InvalidConfig;
    };
    const method = s2022.Method.parse(method_text) orelse {
        diagnostic.set("inbounds[{d}].method: unsupported '{s}'", .{ index, method_text });
        return error.InvalidConfig;
    };
    const password = inbound.password orelse {
        diagnostic.set("inbounds[{d}].password: required for shadowsocks", .{index});
        return error.InvalidConfig;
    };
    var key = s2022.Key.parse(method, password) catch {
        diagnostic.set("inbounds[{d}].password: invalid base64 or key length", .{index});
        return error.InvalidConfig;
    };
    key.deinit();
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
        if (std.mem.eql(u8, outbound.tag, "direct") and outbound.protocol != .direct) {
            diagnostic.set("outbounds[{d}].tag: 'direct' is reserved for direct", .{index});
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
            .selector => try validateSelector(outbound, index, outbounds, diagnostic),
        }
    }
}

fn validateDirect(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    try rejectSelectorFields(outbound, index, diagnostic);
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
    try rejectSelectorFields(outbound, index, diagnostic);
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
    try rejectSelectorFields(outbound, index, diagnostic);
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

    const method_text = outbound.method orelse {
        diagnostic.set("outbounds[{d}].method: required for shadowsocks", .{index});
        return error.InvalidConfig;
    };
    const method = s2022.Method.parse(method_text) orelse {
        diagnostic.set("outbounds[{d}].method: unsupported '{s}'", .{ index, method_text });
        return error.InvalidConfig;
    };

    const password = outbound.password orelse {
        diagnostic.set("outbounds[{d}].password: required for shadowsocks", .{index});
        return error.InvalidConfig;
    };
    var key = s2022.Key.parse(method, password) catch {
        diagnostic.set("outbounds[{d}].password: invalid base64 or key length", .{index});
        return error.InvalidConfig;
    };
    key.deinit();
}

fn rejectSelectorFields(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (outbound.nodes != null or outbound.strategy != null) {
        diagnostic.set("outbounds[{d}]: nodes/strategy only apply to selector", .{index});
        return error.InvalidConfig;
    }
}

fn validateSelector(
    outbound: Config.Outbound,
    index: usize,
    outbounds: []const Config.Outbound,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (outbound.server != null or outbound.method != null or outbound.password != null) {
        diagnostic.set("outbounds[{d}]: selector does not take server or credentials", .{index});
        return error.InvalidConfig;
    }
    const nodes = outbound.nodes orelse {
        diagnostic.set("outbounds[{d}].nodes: required for selector", .{index});
        return error.InvalidConfig;
    };
    if (nodes.len == 0) {
        diagnostic.set("outbounds[{d}].nodes: must not be empty", .{index});
        return error.InvalidConfig;
    }
    _ = outbound.strategy orelse {
        diagnostic.set("outbounds[{d}].strategy: required for selector", .{index});
        return error.InvalidConfig;
    };

    for (nodes, 0..) |node_tag, node_index| {
        if (node_tag.len == 0) {
            diagnostic.set("outbounds[{d}].nodes[{d}]: empty tag", .{ index, node_index });
            return error.InvalidConfig;
        }
        if (std.mem.eql(u8, node_tag, outbound.tag)) {
            diagnostic.set("outbounds[{d}].nodes[{d}]: refers to itself", .{ index, node_index });
            return error.InvalidConfig;
        }
        var found = false;
        for (outbounds) |candidate| {
            if (!std.mem.eql(u8, candidate.tag, node_tag)) continue;
            if (candidate.protocol == .selector) {
                diagnostic.set(
                    "outbounds[{d}].nodes[{d}]: nested selectors are not supported",
                    .{ index, node_index },
                );
                return error.InvalidConfig;
            }
            found = true;
            break;
        }
        if (!found) {
            diagnostic.set("outbounds[{d}].nodes[{d}]: unknown '{s}'", .{
                index,
                node_index,
                node_tag,
            });
            return error.InvalidConfig;
        }
    }
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

test "selector config validates node references" {
    var diagnostic: Diagnostic = .{};
    var parsed = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "direct", "protocol": "direct" },
        \\    { "tag": "auto", "protocol": "selector",
        \\      "nodes": ["direct"], "strategy": "fallback" }
        \\  ],
        \\  "route": { "final": "auto" }
        \\}
    );
    defer parsed.deinit();
    try validate(parsed.inner.value, &diagnostic);

    var bad = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "auto", "protocol": "selector",
        \\      "nodes": ["missing"], "strategy": "fallback" }
        \\  ]
        \\}
    );
    defer bad.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0].nodes[0]: unknown 'missing'",
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
