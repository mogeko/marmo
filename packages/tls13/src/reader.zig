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
        // The TLS client can consume a partial record and return 0 without an
        // error. A stream read must not report that as EOF, so keep filling
        // until a complete record is available or the peer closes.
        while (true) {
            reader.fillMore() catch |err| switch (err) {
                error.EndOfStream => return 0,
                error.ReadFailed => return error.ReadFailed,
            };
            if (reader.bufferedLen() != 0) break;
        }
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

const ChunkReader = struct {
    reader: std.Io.Reader,
    calls: usize = 0,
    sent: bool = false,
    buffer: [32]u8 = undefined,

    fn init(self: *ChunkReader) void {
        self.* = .{
            .reader = .{
                .vtable = &.{ .stream = stream },
                .buffer = &self.buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        _ = limit;
        const self: *ChunkReader = @fieldParentPtr("reader", r);
        self.calls += 1;
        if (self.calls == 1) return 0;
        if (self.sent) return error.EndOfStream;
        self.sent = true;
        w.writeAll("hello") catch return error.WriteFailed;
        return 5;
    }
};

test "readSome retries after a partial record" {
    var source: ChunkReader = undefined;
    source.init();
    var output: [16]u8 = undefined;
    var buffers = [_][]u8{&output};

    const len = try readSome(&source.reader, &buffers);
    try std.testing.expectEqualStrings("hello", output[0..len]);
}
