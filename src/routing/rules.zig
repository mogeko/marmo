//! Compile routing rules once and match them without allocation.

const std = @import("std");
const Config = @import("../config/config.zig").Config;
const Diagnostic = @import("../core/diagnostic.zig").Diagnostic;
const Cidr = @import("../net/cidr.zig").Cidr;
const Metadata = @import("metadata.zig").Metadata;
const Network = @import("metadata.zig").Network;
const Action = @import("router.zig").Action;
const RejectReason = @import("router.zig").RejectReason;

pub const CompiledRule = struct {
    domain: []const []const u8,
    domain_suffix: []const []const u8,
    cidrs: []const Cidr,
    ports: []const u16,
    network: ?Network,
    action: Action,

    pub fn matches(self: CompiledRule, metadata: *const Metadata) bool {
        if (self.domain.len > 0) {
            const domain = domainOf(metadata) orelse return false;
            var found = false;
            for (self.domain) |expected| {
                if (std.mem.eql(u8, expected, domain)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.domain_suffix.len > 0) {
            const domain = domainOf(metadata) orelse return false;
            var found = false;
            for (self.domain_suffix) |suffix| {
                if (matchesSuffix(domain, suffix)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.cidrs.len > 0) {
            const address = switch (metadata.destination) {
                .ip => |ip| ip,
                .domain => return false,
            };
            var found = false;
            for (self.cidrs) |cidr| {
                if (cidr.matches(address)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.ports.len > 0) {
            var found = false;
            for (self.ports) |port| {
                if (metadata.destination.port() == port) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }

        if (self.network) |network| {
            if (metadata.network != network) return false;
        }

        return true;
    }
};

pub const RuleSet = struct {
    rules: []const CompiledRule,
    final: Action,

    pub fn compile(
        allocator: std.mem.Allocator,
        route: Config.Route,
        diagnostic: *Diagnostic,
    ) error{ InvalidConfig, OutOfMemory }!RuleSet {
        const rules = try allocator.alloc(CompiledRule, route.rules.len);
        for (route.rules, 0..) |rule, index| {
            rules[index] = .{
                .domain = rule.domain orelse &.{},
                .domain_suffix = rule.domain_suffix orelse &.{},
                .cidrs = try compileCidrs(allocator, rule.ip_cidr, index, diagnostic),
                .ports = rule.port orelse &.{},
                .network = rule.network,
                .action = actionFor(rule.outbound),
            };
        }
        return .{
            .rules = rules,
            .final = actionFor(route.final),
        };
    }

    pub fn match(self: RuleSet, metadata: *const Metadata) Action {
        for (self.rules) |rule| {
            if (rule.matches(metadata)) return rule.action;
        }
        return self.final;
    }
};

fn compileCidrs(
    allocator: std.mem.Allocator,
    texts: ?[]const []const u8,
    rule_index: usize,
    diagnostic: *Diagnostic,
) error{ InvalidConfig, OutOfMemory }![]const Cidr {
    const values = texts orelse return &.{};
    const cidrs = try allocator.alloc(Cidr, values.len);
    for (values, 0..) |text, index| {
        cidrs[index] = Cidr.parse(text) catch {
            diagnostic.set("route.rules[{d}].ip_cidr[{d}]: invalid '{s}'", .{
                rule_index,
                index,
                text,
            });
            return error.InvalidConfig;
        };
    }
    return cidrs;
}

fn actionFor(tag: []const u8) Action {
    if (std.mem.eql(u8, tag, "reject")) return .{ .reject = .rule };
    return .{ .route = tag };
}

fn domainOf(metadata: *const Metadata) ?[]const u8 {
    if (metadata.domain) |domain| return domain;
    return switch (metadata.destination) {
        .domain => |domain| domain.name,
        .ip => null,
    };
}

fn matchesSuffix(domain: []const u8, suffix: []const u8) bool {
    if (std.mem.eql(u8, domain, suffix)) return true;
    if (domain.len <= suffix.len) return false;
    if (!std.mem.endsWith(u8, domain, suffix)) return false;
    if (suffix[0] == '.') return true;
    return domain[domain.len - suffix.len - 1] == '.';
}

test "rules match domain suffixes, CIDRs, and ports" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var diagnostic: Diagnostic = .{};
    const route: Config.Route = .{
        .rules = &.{
            .{
                .domain_suffix = &.{"example.com"},
                .outbound = "proxy",
            },
            .{
                .ip_cidr = &.{"10.0.0.0/8"},
                .outbound = "direct",
            },
        },
        .final = "reject",
    };
    const rules = try RuleSet.compile(arena.allocator(), route, &diagnostic);

    const domain_endpoint = try std.Io.net.IpAddress.parse("127.0.0.1", 443);
    const proxy_metadata: Metadata = .{
        .network = .tcp,
        .source = .{ .ip = domain_endpoint },
        .destination = .{ .domain = .{ .name = "www.example.com", .port = 443 } },
        .inbound = "socks",
    };
    const proxy_action = rules.match(&proxy_metadata);
    try std.testing.expectEqualStrings("proxy", proxy_action.route);

    const ip_endpoint = try std.Io.net.IpAddress.parse("10.1.2.3", 80);
    const direct_metadata: Metadata = .{
        .network = .tcp,
        .source = .{ .ip = domain_endpoint },
        .destination = .{ .ip = ip_endpoint },
        .inbound = "socks",
    };
    const direct_action = rules.match(&direct_metadata);
    try std.testing.expectEqualStrings("direct", direct_action.route);

    const final_action = rules.match(&.{
        .network = .tcp,
        .source = .{ .ip = domain_endpoint },
        .destination = .{ .ip = try std.Io.net.IpAddress.parse("8.8.8.8", 53) },
        .inbound = "socks",
    });
    try std.testing.expect(final_action == .reject);
}

test "suffix matching respects label boundaries" {
    try std.testing.expect(matchesSuffix("example.com", "example.com"));
    try std.testing.expect(matchesSuffix("www.example.com", "example.com"));
    try std.testing.expect(matchesSuffix("www.example.com", ".example.com"));
    try std.testing.expect(!matchesSuffix("notexample.com", "example.com"));
}
