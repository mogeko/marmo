//! Fixed-size, allocation-free configuration diagnostics.

const std = @import("std");

pub const Diagnostic = struct {
    buffer: [256]u8 = undefined,
    len: usize = 0,

    pub fn clear(self: *Diagnostic) void {
        self.len = 0;
    }

    /// Format a message into the fixed buffer. Long messages are truncated;
    /// diagnostics must never fail or allocate.
    pub fn set(self: *Diagnostic, comptime fmt: []const u8, args: anytype) void {
        const written = std.fmt.bufPrint(&self.buffer, fmt, args) catch {
            self.len = self.buffer.len;
            return;
        };
        self.len = written.len;
    }

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.buffer[0..self.len];
    }
};

test "diagnostic formats and clears" {
    var diagnostic: Diagnostic = .{};
    diagnostic.set("inbounds[{d}].listen: invalid", .{0});
    try std.testing.expectEqualStrings("inbounds[0].listen: invalid", diagnostic.message());
    diagnostic.clear();
    try std.testing.expectEqualStrings("", diagnostic.message());
}
