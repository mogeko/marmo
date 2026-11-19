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
    ///
    /// The writer reports what it actually wrote, so a truncated message never
    /// exposes uninitialized bytes past the formatted prefix.
    pub fn set(self: *Diagnostic, comptime fmt: []const u8, args: anytype) void {
        var writer = std.Io.Writer.fixed(&self.buffer);
        writer.print(fmt, args) catch {};
        self.len = writer.end;
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

test "diagnostic truncation never exposes unwritten bytes" {
    var diagnostic: Diagnostic = .{};
    const long = @as([256 + 32]u8, @splat('x'));
    diagnostic.set("tag: {s}", .{long});
    // The reported length is the formatted prefix, not the whole buffer.
    const message = diagnostic.message();
    try std.testing.expectEqual(@as(usize, 256), message.len);
    try std.testing.expectEqualStrings("tag: ", message[0..5]);
    for (message[5..]) |byte| try std.testing.expectEqual(@as(u8, 'x'), byte);
}
