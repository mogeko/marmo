//! IPv4/IPv6 CIDR matching for routing rules.

const std = @import("std");

pub const Cidr = struct {
    family: Family,
    bytes: [16]u8,
    prefix: u8,

    pub const Family = enum { ipv4, ipv6 };

    pub const ParseError = error{InvalidCidr};

    pub fn parse(text: []const u8) ParseError!Cidr {
        const slash = std.mem.findScalar(u8, text, '/') orelse
            return error.InvalidCidr;
        const address_text = text[0..slash];
        const prefix_text = text[slash + 1 ..];
        if (address_text.len == 0 or prefix_text.len == 0) {
            return error.InvalidCidr;
        }

        const address = std.Io.net.IpAddress.parse(address_text, 0) catch
            return error.InvalidCidr;
        const prefix = std.fmt.parseInt(u8, prefix_text, 10) catch
            return error.InvalidCidr;

        var bytes: [16]u8 = @splat(0);
        switch (address) {
            .ip4 => |ip4| {
                if (prefix > 32) return error.InvalidCidr;
                @memcpy(bytes[0..4], &ip4.bytes);
                return .{ .family = .ipv4, .bytes = bytes, .prefix = prefix };
            },
            .ip6 => |ip6| {
                if (prefix > 128) return error.InvalidCidr;
                bytes = ip6.bytes;
                return .{ .family = .ipv6, .bytes = bytes, .prefix = prefix };
            },
        }
    }

    pub fn matches(self: Cidr, address: std.Io.net.IpAddress) bool {
        return switch (address) {
            .ip4 => |ip4| blk: {
                var bytes: [16]u8 = @splat(0);
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk self.matchesBytes(.ipv4, &bytes);
            },
            .ip6 => |ip6| self.matchesBytes(.ipv6, &ip6.bytes),
        };
    }

    fn matchesBytes(self: Cidr, family: Family, bytes: *const [16]u8) bool {
        if (self.family != family) return false;

        const full_bytes = self.prefix / 8;
        var index: usize = 0;
        while (index < full_bytes) : (index += 1) {
            if (self.bytes[index] != bytes[index]) return false;
        }

        const remaining_bits = self.prefix % 8;
        if (remaining_bits == 0) return true;

        const shift: u3 = @intCast(8 - remaining_bits);
        const mask: u8 = @as(u8, 0xff) << shift;
        return (self.bytes[full_bytes] & mask) == (bytes[full_bytes] & mask);
    }
};

test "IPv4 CIDR matches its range" {
    const cidr = try Cidr.parse("10.0.0.0/8");
    const inside = try std.Io.net.IpAddress.parse("10.1.2.3", 443);
    const outside = try std.Io.net.IpAddress.parse("11.0.0.1", 443);
    try std.testing.expect(cidr.matches(inside));
    try std.testing.expect(!cidr.matches(outside));
}

test "IPv6 CIDR matches its range" {
    const cidr = try Cidr.parse("2001:db8::/32");
    const inside = try std.Io.net.IpAddress.parse("2001:db8::1", 443);
    const outside = try std.Io.net.IpAddress.parse("2001:db9::1", 443);
    try std.testing.expect(cidr.matches(inside));
    try std.testing.expect(!cidr.matches(outside));
}

test "CIDR rejects invalid prefixes" {
    try std.testing.expectError(error.InvalidCidr, Cidr.parse("10.0.0.0/33"));
    try std.testing.expectError(error.InvalidCidr, Cidr.parse("::/129"));
    try std.testing.expectError(error.InvalidCidr, Cidr.parse("10.0.0.0"));
}
