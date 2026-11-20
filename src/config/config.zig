//! Strict JSON configuration and validation.

const std = @import("std");
const Diagnostic = @import("../core/diagnostic.zig").Diagnostic;
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Cidr = @import("../net/cidr.zig").Cidr;
const Network = @import("../routing/metadata.zig").Network;
const s2022 = @import("../protocol/shadowsocks2022.zig");
const vless = @import("../protocol/vless.zig");

pub const Config = struct {
    version: u8 = 1,
    limits: Limits = .{},
    inbounds: []const Inbound = &.{},
    outbounds: []const Outbound = &.{},
    route: Route = .{},

    /// Parse strict JSON. Keep the returned `Parsed` alive for as long as the
    /// config is used; the instance borrows all slices.
    pub fn parseJson(gpa: std.mem.Allocator, text: []const u8) ParseError!Parsed {
        return fromJson(gpa, text);
    }

    pub const Limits = struct {
        /// Maximum accepted TCP streams owned by this Instance; 0 rejects all.
        max_connections: u32 = 1024,
        /// Absolute deadline from accept through protocol handshake.
        handshake_timeout_s: u16 = 10,
        /// Activity-based relay/UDP idle timeout; 0 disables it.
        idle_timeout_s: u32 = 300,
        /// Absolute grace after the client uplink closes; 0 closes immediately.
        uplink_only_s: u32 = 1,
        /// Absolute grace after the remote downlink closes; 0 closes immediately.
        downlink_only_s: u32 = 1,
    };

    pub const Inbound = struct {
        tag: []const u8,
        protocol: InboundProtocol,
        listen: []const u8,
        method: ?[]const u8 = null,
        password: ?[]const u8 = null,
        uuid: ?[]const u8 = null,
        tls: ?InboundTls = null,
        /// Optional Trojan fallback endpoint for unauthenticated traffic.
        fallback: ?[]const u8 = null,
    };

    pub const InboundProtocol = enum { http, shadowsocks, socks5, trojan, vless };

    pub const InboundTls = struct {
        /// PEM or DER certificate chain file, leaf first.
        certificate: []const u8,
        /// PEM or DER ECDSA P-256 private key file.
        private_key: []const u8,
        /// ALPN protocols in server preference order.
        alpn: ?[]const []const u8 = null,
        /// PEM or DER client-certificate trust anchors.
        client_ca: ?[]const u8 = null,
        /// Whether a client certificate is requested and verified.
        client_auth: ClientAuth = .none,
        handshake_timeout_s: u16 = 10,
    };

    pub const ClientAuth = enum { none, optional, required };

    pub const Outbound = struct {
        tag: []const u8,
        protocol: OutboundProtocol,
        server: ?[]const u8 = null,
        method: ?[]const u8 = null,
        password: ?[]const u8 = null,
        uuid: ?[]const u8 = null,
        tls: ?Tls = null,
        xudp: bool = false,
        nodes: ?[]const []const u8 = null,
        strategy: ?Strategy = null,
        health_check: ?HealthCheck = null,
    };

    pub const OutboundProtocol = enum { direct, http, selector, shadowsocks, trojan, vless };

    pub const Tls = struct {
        sni: ?[]const u8 = null,
        insecure: bool = false,
        /// ALPN protocols in client preference order.
        alpn: ?[]const []const u8 = null,
        /// Require the server to select this protocol.
        required_alpn: ?[]const u8 = null,
        /// PEM or DER client certificate chain file, leaf first.
        client_certificate: ?[]const u8 = null,
        /// PEM or DER ECDSA P-256 client private key file.
        client_private_key: ?[]const u8 = null,
        /// Treat a missing close_notify as EOF instead of ConnectionReset.
        allow_truncation_attacks: bool = false,
        handshake_timeout_s: u16 = 10,
    };

    pub const Strategy = enum { fallback, least_latency, manual, random, round_robin };

    pub const HealthCheck = struct {
        target: []const u8,
        interval_s: u16 = 30,
        timeout_s: u16 = 5,
    };

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

/// Upper bound for a configuration document. It is far above any realistic
/// deployment and keeps a hostile or accidental huge input from allocating
/// without bound during JSON parsing.
pub const max_config_bytes: usize = 4 * 1024 * 1024;

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
    if (text.len > max_config_bytes) return error.InvalidJson;
    const inner = std.json.parseFromSlice(Config, gpa, text, .{
        .max_value_len = max_config_bytes,
    }) catch |err| switch (err) {
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

    try validateLimits(config.limits, diagnostic);
    try validateInbounds(config.inbounds, diagnostic);
    try validateOutbounds(config.outbounds, diagnostic);
    try validateRoute(config.route, config.outbounds, diagnostic);
}

fn validateLimits(
    limits: Config.Limits,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (limits.max_connections > 65535) {
        diagnostic.set("limits.max_connections: must be at most 65535", .{});
        return error.InvalidConfig;
    }
    if (limits.handshake_timeout_s == 0 or limits.handshake_timeout_s > 600) {
        diagnostic.set("limits.handshake_timeout_s: must be 1..600", .{});
        return error.InvalidConfig;
    }
    if (limits.idle_timeout_s > 86400) {
        diagnostic.set("limits.idle_timeout_s: must be at most 86400", .{});
        return error.InvalidConfig;
    }
    if (limits.uplink_only_s > 86400) {
        diagnostic.set("limits.uplink_only_s: must be at most 86400", .{});
        return error.InvalidConfig;
    }
    if (limits.downlink_only_s > 86400) {
        diagnostic.set("limits.downlink_only_s: must be at most 86400", .{});
        return error.InvalidConfig;
    }
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
                if (inbound.method != null or inbound.password != null or
                    inbound.uuid != null or inbound.tls != null or
                    inbound.fallback != null)
                {
                    diagnostic.set(
                        "inbounds[{d}]: socks5/http do not take credentials, TLS, or fallback",
                        .{index},
                    );
                    return error.InvalidConfig;
                }
            },
            .shadowsocks => try validateShadowsocksInbound(inbound, index, diagnostic),
            .trojan => try validateTrojanInbound(inbound, index, diagnostic),
            .vless => try validateVlessInbound(inbound, index, diagnostic),
        }
    }
}

fn validateShadowsocksInbound(
    inbound: Config.Inbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (inbound.uuid != null or inbound.tls != null or inbound.fallback != null) {
        diagnostic.set(
            "inbounds[{d}]: uuid/tls/fallback do not apply to shadowsocks",
            .{index},
        );
        return error.InvalidConfig;
    }
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

fn validateVlessInbound(
    inbound: Config.Inbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (inbound.method != null or inbound.password != null or
        inbound.fallback != null)
    {
        diagnostic.set(
            "inbounds[{d}]: vless does not take method, password, or fallback",
            .{index},
        );
        return error.InvalidConfig;
    }
    const uuid_text = inbound.uuid orelse {
        diagnostic.set("inbounds[{d}].uuid: required for vless", .{index});
        return error.InvalidConfig;
    };
    _ = vless.parseUuid(uuid_text) catch {
        diagnostic.set("inbounds[{d}].uuid: invalid UUID", .{index});
        return error.InvalidConfig;
    };
    const tls = inbound.tls orelse {
        diagnostic.set("inbounds[{d}].tls: required for vless", .{index});
        return error.InvalidConfig;
    };
    if (tls.certificate.len == 0) {
        diagnostic.set("inbounds[{d}].tls.certificate: must not be empty", .{index});
        return error.InvalidConfig;
    }
    if (tls.private_key.len == 0) {
        diagnostic.set("inbounds[{d}].tls.private_key: must not be empty", .{index});
        return error.InvalidConfig;
    }
    if (tls.handshake_timeout_s == 0) {
        diagnostic.set(
            "inbounds[{d}].tls.handshake_timeout_s: must be positive",
            .{index},
        );
        return error.InvalidConfig;
    }
    try validateInboundTlsAuth(tls, index, diagnostic);
    var alpn_path_buffer: [64]u8 = undefined;
    const alpn_path = std.fmt.bufPrint(
        &alpn_path_buffer,
        "inbounds[{d}].tls",
        .{index},
    ) catch return error.InvalidConfig;
    try validateAlpn(tls.alpn, null, alpn_path, diagnostic);
}

fn validateInboundTlsAuth(
    tls: Config.InboundTls,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (tls.client_auth != .none) {
        const ca = tls.client_ca orelse {
            diagnostic.set(
                "inbounds[{d}].tls.client_ca: required when client_auth is enabled",
                .{index},
            );
            return error.InvalidConfig;
        };
        if (ca.len == 0) {
            diagnostic.set(
                "inbounds[{d}].tls.client_ca: must not be empty",
                .{index},
            );
            return error.InvalidConfig;
        }
    } else if (tls.client_ca) |ca| {
        if (ca.len == 0) {
            diagnostic.set(
                "inbounds[{d}].tls.client_ca: must not be empty",
                .{index},
            );
            return error.InvalidConfig;
        }
    }
}

fn validateTrojanInbound(
    inbound: Config.Inbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (inbound.method != null or inbound.uuid != null) {
        diagnostic.set(
            "inbounds[{d}]: trojan does not take method or uuid",
            .{index},
        );
        return error.InvalidConfig;
    }
    const password = inbound.password orelse {
        diagnostic.set("inbounds[{d}].password: required for trojan", .{index});
        return error.InvalidConfig;
    };
    if (password.len == 0) {
        diagnostic.set("inbounds[{d}].password: must not be empty", .{index});
        return error.InvalidConfig;
    }
    const tls = inbound.tls orelse {
        diagnostic.set("inbounds[{d}].tls: required for trojan", .{index});
        return error.InvalidConfig;
    };
    if (tls.certificate.len == 0) {
        diagnostic.set("inbounds[{d}].tls.certificate: must not be empty", .{index});
        return error.InvalidConfig;
    }
    if (tls.private_key.len == 0) {
        diagnostic.set("inbounds[{d}].tls.private_key: must not be empty", .{index});
        return error.InvalidConfig;
    }
    if (tls.handshake_timeout_s == 0) {
        diagnostic.set(
            "inbounds[{d}].tls.handshake_timeout_s: must be positive",
            .{index},
        );
        return error.InvalidConfig;
    }
    try validateInboundTlsAuth(tls, index, diagnostic);
    if (inbound.fallback) |fallback| {
        if (fallback.len == 0) {
            diagnostic.set("inbounds[{d}].fallback: must not be empty", .{index});
            return error.InvalidConfig;
        }
        _ = Endpoint.parse(fallback) catch {
            diagnostic.set(
                "inbounds[{d}].fallback: invalid endpoint '{s}'",
                .{ index, fallback },
            );
            return error.InvalidConfig;
        };
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
            .trojan => try validateTrojan(outbound, index, diagnostic),
            .vless => try validateVless(outbound, index, diagnostic),
        }
    }
}

fn validateDirect(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    try rejectSelectorFields(outbound, index, diagnostic);
    try rejectVlessFields(outbound, index, diagnostic);
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
    try rejectVlessFields(outbound, index, diagnostic);
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
    try rejectVlessFields(outbound, index, diagnostic);
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

fn rejectVlessFields(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (outbound.uuid != null or outbound.tls != null or outbound.xudp) {
        diagnostic.set(
            "outbounds[{d}]: uuid/xudp only apply to vless; tls applies to vless/trojan",
            .{index},
        );
        return error.InvalidConfig;
    }
}

fn validateOutboundTls(
    tls_config: Config.Tls,
    server: Endpoint,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (tls_config.sni) |sni| {
        if (sni.len == 0) {
            diagnostic.set("outbounds[{d}].tls.sni: must not be empty", .{index});
            return error.InvalidConfig;
        }
    }
    if (!tls_config.insecure and tls_config.sni == null) {
        switch (server) {
            .domain => {},
            .ip => {
                diagnostic.set(
                    "outbounds[{d}].tls.sni: required for an IP server",
                    .{index},
                );
                return error.InvalidConfig;
            },
        }
    }
    if (tls_config.handshake_timeout_s == 0) {
        diagnostic.set(
            "outbounds[{d}].tls.handshake_timeout_s: must be positive",
            .{index},
        );
        return error.InvalidConfig;
    }
    const has_certificate = tls_config.client_certificate != null;
    const has_private_key = tls_config.client_private_key != null;
    if (has_certificate != has_private_key) {
        diagnostic.set(
            "outbounds[{d}].tls.client_certificate: requires client_private_key and vice versa",
            .{index},
        );
        return error.InvalidConfig;
    }
    if (tls_config.client_certificate) |path| {
        if (path.len == 0) {
            diagnostic.set(
                "outbounds[{d}].tls.client_certificate: must not be empty",
                .{index},
            );
            return error.InvalidConfig;
        }
    }
    if (tls_config.client_private_key) |path| {
        if (path.len == 0) {
            diagnostic.set(
                "outbounds[{d}].tls.client_private_key: must not be empty",
                .{index},
            );
            return error.InvalidConfig;
        }
    }
    var alpn_path_buffer: [64]u8 = undefined;
    const alpn_path = std.fmt.bufPrint(
        &alpn_path_buffer,
        "outbounds[{d}].tls",
        .{index},
    ) catch return error.InvalidConfig;
    try validateAlpn(
        tls_config.alpn,
        tls_config.required_alpn,
        alpn_path,
        diagnostic,
    );
}

fn validateTrojan(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    try rejectSelectorFields(outbound, index, diagnostic);
    if (outbound.method != null or outbound.uuid != null or outbound.xudp) {
        diagnostic.set(
            "outbounds[{d}]: trojan does not take method, uuid, or xudp",
            .{index},
        );
        return error.InvalidConfig;
    }

    const server_text = outbound.server orelse {
        diagnostic.set("outbounds[{d}].server: required for trojan", .{index});
        return error.InvalidConfig;
    };
    const server = Endpoint.parse(server_text) catch {
        diagnostic.set("outbounds[{d}].server: invalid endpoint '{s}'", .{
            index,
            server_text,
        });
        return error.InvalidConfig;
    };

    const password = outbound.password orelse {
        diagnostic.set("outbounds[{d}].password: required for trojan", .{index});
        return error.InvalidConfig;
    };
    if (password.len == 0) {
        diagnostic.set("outbounds[{d}].password: must not be empty", .{index});
        return error.InvalidConfig;
    }

    const tls_config = outbound.tls orelse {
        diagnostic.set("outbounds[{d}].tls: required for trojan", .{index});
        return error.InvalidConfig;
    };
    try validateOutboundTls(tls_config, server, index, diagnostic);
}

fn validateVless(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    try rejectSelectorFields(outbound, index, diagnostic);
    if (outbound.method != null or outbound.password != null) {
        diagnostic.set("outbounds[{d}]: vless does not take method or password", .{index});
        return error.InvalidConfig;
    }

    const server_text = outbound.server orelse {
        diagnostic.set("outbounds[{d}].server: required for vless", .{index});
        return error.InvalidConfig;
    };
    const server = Endpoint.parse(server_text) catch {
        diagnostic.set("outbounds[{d}].server: invalid endpoint '{s}'", .{
            index,
            server_text,
        });
        return error.InvalidConfig;
    };

    const uuid_text = outbound.uuid orelse {
        diagnostic.set("outbounds[{d}].uuid: required for vless", .{index});
        return error.InvalidConfig;
    };
    _ = vless.parseUuid(uuid_text) catch {
        diagnostic.set("outbounds[{d}].uuid: invalid UUID", .{index});
        return error.InvalidConfig;
    };

    const tls_config = outbound.tls orelse return;
    try validateOutboundTls(tls_config, server, index, diagnostic);
}

fn rejectSelectorFields(
    outbound: Config.Outbound,
    index: usize,
    diagnostic: *Diagnostic,
) ValidationError!void {
    if (outbound.nodes != null or outbound.strategy != null or
        outbound.health_check != null)
    {
        diagnostic.set("outbounds[{d}]: group fields only apply to selector", .{index});
        return error.InvalidConfig;
    }
}

fn validateSelector(
    outbound: Config.Outbound,
    index: usize,
    outbounds: []const Config.Outbound,
    diagnostic: *Diagnostic,
) ValidationError!void {
    try rejectVlessFields(outbound, index, diagnostic);
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
    if (outbound.health_check) |health| {
        _ = Endpoint.parse(health.target) catch {
            diagnostic.set("outbounds[{d}].health_check.target: invalid endpoint", .{index});
            return error.InvalidConfig;
        };
        if (health.interval_s == 0 or health.timeout_s == 0) {
            diagnostic.set("outbounds[{d}].health_check: intervals must be positive", .{index});
            return error.InvalidConfig;
        }
        if (health.timeout_s > health.interval_s) {
            diagnostic.set("outbounds[{d}].health_check: timeout exceeds interval", .{index});
            return error.InvalidConfig;
        }
    }

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

fn validateAlpn(
    protocols: ?[]const []const u8,
    required: ?[]const u8,
    base: []const u8,
    diagnostic: *Diagnostic,
) ValidationError!void {
    const list = protocols orelse &.{};
    if (list.len == 0 and required != null) {
        diagnostic.set("{s}.required_alpn: requires alpn protocols", .{base});
        return error.InvalidConfig;
    }
    var seen: [32][]const u8 = undefined;
    if (list.len > seen.len) {
        diagnostic.set("{s}.alpn: too many protocols", .{base});
        return error.InvalidConfig;
    }
    for (list, 0..) |protocol, list_index| {
        if (protocol.len == 0 or protocol.len > 255) {
            diagnostic.set("{s}.alpn[{d}]: invalid protocol name", .{
                base,
                list_index,
            });
            return error.InvalidConfig;
        }
        for (seen[0..list_index]) |previous| {
            if (std.mem.eql(u8, previous, protocol)) {
                diagnostic.set("{s}.alpn[{d}]: duplicate '{s}'", .{
                    base,
                    list_index,
                    protocol,
                });
                return error.InvalidConfig;
            }
        }
        seen[list_index] = protocol;
    }
    if (required) |needed| {
        var found = false;
        for (list) |protocol| {
            if (std.mem.eql(u8, protocol, needed)) found = true;
        }
        if (!found) {
            diagnostic.set("{s}.required_alpn: not present in alpn", .{base});
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

test "config rejects oversized documents" {
    const oversized = try std.testing.allocator.alloc(
        u8,
        max_config_bytes + 1,
    );
    defer std.testing.allocator.free(oversized);
    @memset(oversized, ' ');
    try std.testing.expectError(
        error.InvalidJson,
        fromJson(std.testing.allocator, oversized),
    );
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
        \\      "nodes": ["direct"], "strategy": "fallback",
        \\      "health_check": { "target": "127.0.0.1:1",
        \\                        "interval_s": 30, "timeout_s": 5 } }
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

test "vless config validates uuid and TLS options" {
    var diagnostic: Diagnostic = .{};
    var valid = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "vless",
        \\      "server": "example.com:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "sni": "cdn.example.com" },
        \\      "xudp": true }
        \\  ],
        \\  "route": { "final": "proxy" }
        \\}
    );
    defer valid.deinit();
    try validate(valid.inner.value, &diagnostic);

    var bad_uuid = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "vless",
        \\      "server": "example.com:443", "uuid": "not-a-uuid" }
        \\  ]
        \\}
    );
    defer bad_uuid.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad_uuid.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0].uuid: invalid UUID",
        diagnostic.message(),
    );

    var ip_without_sni = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "vless",
        \\      "server": "127.0.0.1:443",
        \\      "uuid": "00112233445566778899aabbccddeeff",
        \\      "tls": {} }
        \\  ]
        \\}
    );
    defer ip_without_sni.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(ip_without_sni.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0].tls.sni: required for an IP server",
        diagnostic.message(),
    );

    var tls_on_direct = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "direct", "protocol": "direct", "tls": {} }
        \\  ]
        \\}
    );
    defer tls_on_direct.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(tls_on_direct.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0]: uuid/xudp only apply to vless; tls applies to vless/trojan",
        diagnostic.message(),
    );

    var zero_timeout = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "vless",
        \\      "server": "example.com:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "sni": "cdn.example.com",
        \\               "handshake_timeout_s": 0 } }
        \\  ]
        \\}
    );
    defer zero_timeout.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(zero_timeout.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0].tls.handshake_timeout_s: must be positive",
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

test "config validates VLESS inbound TLS fields" {
    var diagnostic: Diagnostic = .{};
    var valid = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "vless", "protocol": "vless", "listen": "127.0.0.1:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "certificate": "cert.pem",
        \\               "private_key": "key.pem" } }
        \\  ]
        \\}
    );
    defer valid.deinit();
    try validate(valid.inner.value, &diagnostic);

    var missing_tls = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "vless", "protocol": "vless", "listen": "127.0.0.1:443",
        \\      "uuid": "00112233445566778899aabbccddeeff" }
        \\  ]
        \\}
    );
    defer missing_tls.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(missing_tls.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0].tls: required for vless",
        diagnostic.message(),
    );

    var bad_uuid = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "vless", "protocol": "vless", "listen": "127.0.0.1:443",
        \\      "uuid": "nope",
        \\      "tls": { "certificate": "cert.pem", "private_key": "key.pem" } }
        \\  ]
        \\}
    );
    defer bad_uuid.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad_uuid.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0].uuid: invalid UUID",
        diagnostic.message(),
    );
}

test "config validates TLS client authentication and client credentials" {
    var diagnostic: Diagnostic = .{};
    var valid = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "vless", "protocol": "vless", "listen": "127.0.0.1:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "certificate": "cert.pem", "private_key": "key.pem",
        \\               "client_ca": "clients.pem", "client_auth": "required" } }
        \\  ],
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "vless",
        \\      "server": "example.com:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "sni": "example.com",
        \\               "client_certificate": "client.pem",
        \\               "client_private_key": "client-key.pem" } }
        \\  ]
        \\}
    );
    defer valid.deinit();
    try validate(valid.inner.value, &diagnostic);

    var missing_ca = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "vless", "protocol": "vless", "listen": "127.0.0.1:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "certificate": "cert.pem", "private_key": "key.pem",
        \\               "client_auth": "optional" } }
        \\  ]
        \\}
    );
    defer missing_ca.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(missing_ca.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0].tls.client_ca: required when client_auth is enabled",
        diagnostic.message(),
    );

    var half_client_cert = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "vless",
        \\      "server": "example.com:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "sni": "example.com",
        \\               "client_certificate": "client.pem" } }
        \\  ]
        \\}
    );
    defer half_client_cert.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(half_client_cert.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0].tls.client_certificate: requires client_private_key and vice versa",
        diagnostic.message(),
    );
}

test "config validates Trojan credentials, TLS, and fallback" {
    var diagnostic: Diagnostic = .{};
    var valid = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "trojan", "protocol": "trojan", "listen": "127.0.0.1:443",
        \\      "password": "secret",
        \\      "fallback": "127.0.0.1:8080",
        \\      "tls": { "certificate": "cert.pem",
        \\               "private_key": "key.pem" } }
        \\  ],
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "trojan",
        \\      "server": "example.com:443", "password": "secret",
        \\      "tls": { "sni": "example.com" } }
        \\  ],
        \\  "route": { "final": "proxy" }
        \\}
    );
    defer valid.deinit();
    try validate(valid.inner.value, &diagnostic);

    var missing_password = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "trojan", "protocol": "trojan", "listen": "127.0.0.1:443",
        \\      "tls": { "certificate": "cert.pem", "private_key": "key.pem" } }
        \\  ]
        \\}
    );
    defer missing_password.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(missing_password.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0].password: required for trojan",
        diagnostic.message(),
    );

    var missing_tls = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "trojan",
        \\      "server": "example.com:443", "password": "secret" }
        \\  ]
        \\}
    );
    defer missing_tls.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(missing_tls.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0].tls: required for trojan",
        diagnostic.message(),
    );

    var fallback_on_socks = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:1080",
        \\      "fallback": "127.0.0.1:8080" }
        \\  ]
        \\}
    );
    defer fallback_on_socks.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(fallback_on_socks.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0]: socks5/http do not take credentials, TLS, or fallback",
        diagnostic.message(),
    );

    var bad_fallback = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "trojan", "protocol": "trojan", "listen": "127.0.0.1:443",
        \\      "password": "secret", "fallback": "not-an-endpoint",
        \\      "tls": { "certificate": "cert.pem", "private_key": "key.pem" } }
        \\  ]
        \\}
    );
    defer bad_fallback.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad_fallback.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0].fallback: invalid endpoint 'not-an-endpoint'",
        diagnostic.message(),
    );
}

test "TLS ALPN config validates names and required selection" {
    var diagnostic: Diagnostic = .{};
    var valid = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "vless", "protocol": "vless", "listen": "127.0.0.1:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "certificate": "cert.pem", "private_key": "key.pem",
        \\               "alpn": ["h2", "http/1.1"] } }
        \\  ],
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "trojan",
        \\      "server": "example.com:443", "password": "secret",
        \\      "tls": { "sni": "example.com", "alpn": ["h2"],
        \\               "required_alpn": "h2" } }
        \\  ],
        \\  "route": { "final": "proxy" }
        \\}
    );
    defer valid.deinit();
    try validate(valid.inner.value, &diagnostic);

    var bad_required = try fromJson(std.testing.allocator,
        \\{
        \\  "outbounds": [
        \\    { "tag": "proxy", "protocol": "trojan",
        \\      "server": "example.com:443", "password": "secret",
        \\      "tls": { "sni": "example.com", "alpn": ["http/1.1"],
        \\               "required_alpn": "h2" } }
        \\  ],
        \\  "route": { "final": "proxy" }
        \\}
    );
    defer bad_required.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad_required.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "outbounds[0].tls.required_alpn: not present in alpn",
        diagnostic.message(),
    );

    var duplicate = try fromJson(std.testing.allocator,
        \\{
        \\  "inbounds": [
        \\    { "tag": "vless", "protocol": "vless", "listen": "127.0.0.1:443",
        \\      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        \\      "tls": { "certificate": "cert.pem", "private_key": "key.pem",
        \\               "alpn": ["h2", "h2"] } }
        \\  ]
        \\}
    );
    defer duplicate.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(duplicate.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "inbounds[0].tls.alpn[1]: duplicate 'h2'",
        diagnostic.message(),
    );
}

test "limits config validates bounds" {
    var diagnostic: Diagnostic = .{};
    var valid = try fromJson(std.testing.allocator,
        \\{
        \\  "limits": {
        \\    "max_connections": 0,
        \\    "handshake_timeout_s": 1,
        \\    "idle_timeout_s": 86400,
        \\    "uplink_only_s": 0,
        \\    "downlink_only_s": 0
        \\  }
        \\}
    );
    defer valid.deinit();
    try validate(valid.inner.value, &diagnostic);

    var bad_handshake = try fromJson(std.testing.allocator,
        \\{ "limits": { "handshake_timeout_s": 0 } }
    );
    defer bad_handshake.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad_handshake.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "limits.handshake_timeout_s: must be 1..600",
        diagnostic.message(),
    );

    var bad_max = try fromJson(std.testing.allocator,
        \\{ "limits": { "max_connections": 65536 } }
    );
    defer bad_max.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad_max.inner.value, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "limits.max_connections: must be at most 65535",
        diagnostic.message(),
    );

    var bad_idle = try fromJson(std.testing.allocator,
        \\{ "limits": { "idle_timeout_s": 86401 } }
    );
    defer bad_idle.deinit();
    try std.testing.expectError(
        error.InvalidConfig,
        validate(bad_idle.inner.value, &diagnostic),
    );
}
