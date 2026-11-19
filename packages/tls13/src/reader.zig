//! Reader helpers shared by the TLS adapters.

const std = @import("std");

/// Reads whatever is currently available, without trying to fill `buffers`.
///
/// `std.Io.Reader.readVec` treats a full caller buffer as the goal and can block
/// for more data; a proxy stream needs one record's worth instead. Returns 0 on
/// clean end of stream.
pub fn readSome(
    reader: *std.Io.Reader,
    buffers: [][]u8,
) std.Io.Reader.ShortError!usize {
    if (reader.bufferedLen() == 0) {
        reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => return 0,
            error.ReadFailed => return error.ReadFailed,
        };
    }

    const available = reader.buffered();
    if (available.len == 0) return 0;

    var copied: usize = 0;
    for (buffers) |buffer| {
        const count = @min(buffer.len, available.len - copied);
        @memcpy(buffer[0..count], available[copied..][0..count]);
        copied += count;
        if (copied == available.len) break;
    }
    reader.toss(copied);
    return copied;
}
