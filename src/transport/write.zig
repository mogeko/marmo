//! Safe vectored writes over a `std.Io.Writer`.
//!
//! `Writer.writeVecAll` takes a mutable slice array because it temporarily
//! rewrites entries for partial writes. Callers of `Stream.write` provide a
//! const slice array, so copy the entries to a small mutable buffer first.

const std = @import("std");

const max_vecs = 8;

pub fn writeSlices(
    writer: *std.Io.Writer,
    buffers: []const []const u8,
) std.Io.Writer.Error!void {
    var storage: [max_vecs][]const u8 = undefined;
    var offset: usize = 0;
    while (offset < buffers.len) {
        const count = @min(max_vecs, buffers.len - offset);
        @memcpy(storage[0..count], buffers[offset..][0..count]);
        try writer.writeVecAll(storage[0..count]);
        offset += count;
    }
}

test "writes const slice arrays" {
    var buffer: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeSlices(&writer, &.{ "hello", " ", "world" });
    try std.testing.expectEqualStrings("hello world", buffer[0..11]);
}
