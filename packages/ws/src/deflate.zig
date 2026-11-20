//! RFC 7692 message compression: raw DEFLATE encode and decode.
//!
//! `std.compress.flate.Compress` is not used: its writer flush does not emit
//! the RFC 7692 sync-flush marker (an empty stored block plus the four
//! `00 00 ff ff` octets) and its output is rejected by strict inflaters. The
//! encoder below emits fixed-Huffman blocks and the RFC 1951/7692 sync flush;
//! the decoder wraps `std.compress.flate.Decompress`, which is interoperable.

const std = @import("std");
const flate = std.compress.flate;

/// RFC 1951 maximum LZ77 distance and RFC 7692 maximum window.
pub const max_window = 1 << 15;
pub const window_len = 2 * max_window;
pub const hash_bits = 15;
pub const hash_size = 1 << hash_bits;

comptime {
    std.debug.assert(window_len == flate.max_window_len);
}

pub const Error = error{
    Canceled,
    Closed,
    ProtocolViolation,
    Unexpected,
};

pub const DecodeError = error{
    InvalidData,
    MessageTooBig,
};

/// Raw-DEFLATE encoder with an optional 32 KiB history across messages.
///
/// One encoder belongs to one connection. `encode` emits exactly one
/// sync-flushed message and leaves the stream open for context takeover. Call
/// `resetContext` between messages when no_context_takeover is negotiated.
pub const Encoder = struct {
    history: [window_len]u8 = undefined,
    /// Absolute position plus one for the newest three-byte hash, zero empty.
    head: [hash_size]u32 = @splat(0),
    pos: u32 = 0,
    max_distance: u32 = max_window,
    bit_buffer: u64 = 0,
    bit_count: u6 = 0,

    pub const Token = struct {
        code: u16,
        bits: u6,
    };

    pub fn init() Encoder {
        return .{};
    }

    /// Drops all match candidates. The bit stream itself remains open.
    pub fn resetContext(self: *Encoder) void {
        @memset(&self.head, 0);
    }

    /// Sets the compressor window. `bits` is one of 8..15.
    pub fn setWindowBits(self: *Encoder, bits: u4) void {
        std.debug.assert(bits >= 8 and bits <= 15);
        self.max_distance = @as(u32, 1) << bits;
    }

    pub fn encode(self: *Encoder, sink: anytype, message: []const u8) Error!void {
        // Restart absolute positions long before the u32 head marker wraps.
        if (self.pos >= 0x7000_0000) {
            self.pos = 0;
            self.resetContext();
        }
        self.bit_buffer = 0;
        self.bit_count = 0;

        var offset: usize = 0;
        var fixed_started = false;
        while (offset < message.len) {
            var match_len: usize = 0;
            var match_distance: u32 = 0;
            if (message.len - offset >= 3) {
                const hash = hash3(message[offset..][0..3]);
                const stored = self.head[hash];
                if (stored != 0) {
                    const candidate = stored - 1;
                    if (self.matchAllowed(candidate)) {
                        match_len = self.matchLength(message, offset, candidate);
                        if (match_len >= 3) {
                            match_distance = self.pos - candidate;
                        } else {
                            match_len = 0;
                        }
                    }
                }
                self.head[hash] = self.pos + 1;
            }

            if (match_len >= 3) {
                if (!fixed_started) {
                    try self.emitBits(sink, block_fixed, 3);
                    fixed_started = true;
                }
                try self.emitMatch(sink, match_len, match_distance);
                self.consume(message, offset, match_len, true);
                offset += match_len;
            } else {
                if (!fixed_started) {
                    try self.emitBits(sink, block_fixed, 3);
                    fixed_started = true;
                }
                try self.emitSymbol(sink, @intCast(message[offset]));
                self.consume(message, offset, 1, false);
                offset += 1;
            }
        }

        if (fixed_started) try self.emitSymbol(sink, end_of_block);
        // Empty stored block header; its LEN/NLEN (00 00 ff ff) is stripped
        // from the message payload as RFC 7692 section 7.2.1 requires.
        try self.emitBits(sink, block_stored, 3);
        try self.alignToByte(sink);
    }

    fn matchAllowed(self: *const Encoder, candidate: u32) bool {
        if (candidate >= self.pos) return false;
        const distance = self.pos - candidate;
        return distance <= self.max_distance;
    }

    fn matchLength(
        self: *const Encoder,
        message: []const u8,
        offset: usize,
        candidate: u32,
    ) usize {
        const limit = @min(message.len - offset, max_match);
        var length: usize = 0;
        while (length < limit) : (length += 1) {
            const source_pos = candidate + @as(u32, @intCast(length));
            const source: u8 = if (source_pos < self.pos)
                self.history[source_pos & (window_len - 1)]
            else
                message[offset + (source_pos - self.pos)];
            if (source != message[offset + length]) break;
        }
        return length;
    }

    fn consume(
        self: *Encoder,
        message: []const u8,
        offset: usize,
        length: usize,
        seed_hash: bool,
    ) void {
        var consumed: usize = 0;
        while (consumed < length) : (consumed += 1) {
            const index = offset + consumed;
            if (seed_hash or consumed != 0) {
                if (message.len - index >= 3) {
                    self.head[hash3(message[index..][0..3])] = self.pos + 1;
                }
            }
            self.history[self.pos & (window_len - 1)] = message[index];
            self.pos +%= 1;
        }
    }

    fn emitMatch(
        self: *Encoder,
        sink: anytype,
        length: usize,
        distance: u32,
    ) Error!void {
        std.debug.assert(length >= 3 and length <= max_match);
        std.debug.assert(distance >= 1 and distance <= max_window);

        var index: usize = 0;
        while (index < length_base.len) : (index += 1) {
            const extra = length_extra[index];
            const maximum = length_base[index] +
                (@as(u32, 1) << @intCast(extra)) - 1;
            if (length <= maximum) break;
        }
        std.debug.assert(index < length_base.len);
        const extra = length_extra[index];
        try self.emitSymbol(sink, @intCast(257 + index));
        if (extra != 0) {
            const value: u32 = @intCast(length - length_base[index]);
            try self.emitBits(sink, value, extra);
        }

        index = 0;
        while (index < distance_base.len) : (index += 1) {
            const shift = distance_extra[index];
            const maximum = distance_base[index] +
                (@as(u32, 1) << @intCast(shift)) - 1;
            if (distance <= maximum) break;
        }
        std.debug.assert(index < distance_base.len);
        try self.emitHuffman(sink, @intCast(index), 5);
        const shift = distance_extra[index];
        if (shift != 0) {
            const value = distance - distance_base[index];
            try self.emitBits(sink, value, shift);
        }
    }

    fn emitSymbol(self: *Encoder, sink: anytype, symbol: u16) Error!void {
        const token = fixedLiteral(symbol);
        try self.emitHuffman(sink, token.code, token.bits);
    }

    /// Writes a Huffman code whose bits are defined most-significant first.
    fn emitHuffman(
        self: *Encoder,
        sink: anytype,
        code: u16,
        count: u6,
    ) Error!void {
        std.debug.assert(count >= 1 and count <= 15);
        var reversed: u16 = 0;
        var remaining = code;
        var index: u6 = 0;
        while (index < count) : (index += 1) {
            reversed = (reversed << 1) | (remaining & 1);
            remaining >>= 1;
        }
        try self.emitBits(sink, reversed, count);
    }

    fn emitBits(
        self: *Encoder,
        sink: anytype,
        value: u32,
        count: u6,
    ) Error!void {
        std.debug.assert(count <= 32);
        self.bit_buffer |= @as(u64, value) << self.bit_count;
        self.bit_count += count;
        while (self.bit_count >= 8) {
            try sink.writeByte(@truncate(self.bit_buffer));
            self.bit_buffer >>= 8;
            self.bit_count -= 8;
        }
        std.debug.assert(self.bit_count < 8);
    }

    fn alignToByte(self: *Encoder, sink: anytype) Error!void {
        if (self.bit_count == 0) return;
        try sink.writeByte(@truncate(self.bit_buffer));
        self.bit_buffer = 0;
        self.bit_count = 0;
    }
};

/// Bounded RFC 7692 message decoder with optional peer context takeover.
pub const Inflater = struct {
    window: [window_len]u8 = undefined,
    inner: flate.Decompress = undefined,
    ready: bool = false,

    pub fn init() Inflater {
        return .{};
    }

    /// Drops the peer history, used when no_context_takeover is negotiated.
    pub fn resetContext(self: *Inflater) void {
        self.ready = false;
    }

    /// Decodes one message from `input[0..compressed_len]` into `output`.
    ///
    /// `input` must have four spare bytes after `compressed_len`; the RFC 7692
    /// `00 00 ff ff` suffix is written there. Returns the decompressed length.
    pub fn decompress(
        self: *Inflater,
        input: []u8,
        compressed_len: usize,
        output: []u8,
    ) DecodeError!usize {
        if (compressed_len > input.len or input.len - compressed_len < 4) {
            return error.InvalidData;
        }
        input[compressed_len..][0..4].* = suffix;

        var reader = std.Io.Reader.fixed(input[0 .. compressed_len + 4]);
        if (!self.ready) {
            self.inner = flate.Decompress.init(&reader, .raw, &self.window);
            self.ready = true;
        } else {
            if (self.inner.consumed_bits != 0) {
                self.ready = false;
                return error.InvalidData;
            }
            self.inner.input = &reader;
            self.inner.err = null;
        }

        var writer = std.Io.Writer.fixed(output);
        const result = self.inner.reader.streamRemaining(&writer);
        const written = writer.buffered().len;
        if (result) |_| {
            // A final block ends the peer's deflate stream; a later message
            // cannot reuse its history.
            self.ready = false;
            return written;
        } else |err| switch (err) {
            error.WriteFailed => {
                self.ready = false;
                if (written == output.len) return error.MessageTooBig;
                return error.InvalidData;
            },
            error.ReadFailed => {
                if (self.inner.err) |inner_err| {
                    if (inner_err == error.EndOfStream and
                        self.inner.state == .block_header)
                    {
                        return written;
                    }
                }
                self.ready = false;
                return error.InvalidData;
            },
        }
    }
};

const block_stored: u32 = 0b000;
const block_fixed: u32 = 0b010;
const end_of_block: u16 = 256;
const max_match: usize = 258;
const suffix = [4]u8{ 0x00, 0x00, 0xff, 0xff };

const length_base = [_]u32{
    3,   4,   5,   6,   7,   8,  9,  10,
    11,  13,  15,  17,  19,  23, 27, 31,
    35,  43,  51,  59,  67,  83, 99, 115,
    131, 163, 195, 227, 258,
};
const length_extra = [_]u6{
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5, 0,
};
const distance_base = [_]u32{
    1,    2,    3,    4,     5,     7,     9,    13,
    17,   25,   33,   49,    65,    97,    129,  193,
    257,  385,  513,  769,   1025,  1537,  2049, 3073,
    4097, 6145, 8193, 12289, 16385, 24577,
};
const distance_extra = [_]u6{
    0,  0,  0,  0,  1,  1,  2,  2,
    3,  3,  4,  4,  5,  5,  6,  6,
    7,  7,  8,  8,  9,  9,  10, 10,
    11, 11, 12, 12, 13, 13,
};

fn hash3(bytes: *const [3]u8) u32 {
    const value = (@as(u32, bytes[0]) << 16) |
        (@as(u32, bytes[1]) << 8) |
        bytes[2];
    return (value *% 2_654_435_761) >> (32 - hash_bits);
}

fn fixedLiteral(symbol: u16) Encoder.Token {
    if (symbol <= 143) {
        return .{ .code = 0x30 + symbol, .bits = 8 };
    }
    if (symbol <= 255) {
        return .{ .code = 0x190 + (symbol - 144), .bits = 9 };
    }
    if (symbol <= 279) {
        return .{ .code = symbol - 256, .bits = 7 };
    }
    return .{ .code = 0xC0 + (symbol - 280), .bits = 8 };
}

const TestSink = struct {
    buffer: [128 * 1024]u8 = undefined,
    len: usize = 0,

    fn writeByte(self: *TestSink, byte: u8) Error!void {
        if (self.len == self.buffer.len) return error.Unexpected;
        self.buffer[self.len] = byte;
        self.len += 1;
    }

    fn bytes(self: *const TestSink) []const u8 {
        return self.buffer[0..self.len];
    }
};

fn roundTrip(allocator: std.mem.Allocator, message: []const u8) !void {
    var encoder = Encoder.init();
    var sink: TestSink = .{};
    try encoder.encode(&sink, message);

    const input = try allocator.alloc(u8, sink.len + 4);
    defer allocator.free(input);
    @memcpy(input[0..sink.len], sink.bytes());
    const output = try allocator.alloc(u8, @max(message.len, 1));
    defer allocator.free(output);
    var inflater = Inflater.init();
    const len = try inflater.decompress(input, sink.len, output);
    try std.testing.expectEqual(message.len, len);
    try std.testing.expectEqualSlices(u8, message, output[0..len]);
}

test "encoder round-trips empty, short, and repetitive messages" {
    const allocator = std.testing.allocator;
    try roundTrip(allocator, "");
    try roundTrip(allocator, "a");
    try roundTrip(allocator, "hello hello hello hello hello");
    try roundTrip(allocator, "abcdefghijklmnopqrstuvwxyz0123456789");

    const repeated = try allocator.alloc(u8, 70_000);
    defer allocator.free(repeated);
    for (repeated, 0..) |*byte, index| byte.* = @intCast(index % 251);
    try roundTrip(allocator, repeated);
}

test "encoder compresses repetitive data" {
    const allocator = std.testing.allocator;
    const message = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(message);
    @memset(message, 'x');

    var encoder = Encoder.init();
    var sink: TestSink = .{};
    try encoder.encode(&sink, message);
    try std.testing.expect(sink.len < message.len / 100);
}

test "context takeover matches across messages" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init();
    var inflater = Inflater.init();

    const messages = [_][]const u8{
        "the quick brown fox jumps over the lazy dog",
        "the quick brown fox jumps over the lazy dog again",
        "again and again and again",
    };
    for (messages) |message| {
        var sink: TestSink = .{};
        try encoder.encode(&sink, message);
        const input = try allocator.alloc(u8, sink.len + 4);
        defer allocator.free(input);
        @memcpy(input[0..sink.len], sink.bytes());
        const output = try allocator.alloc(u8, message.len + 1);
        defer allocator.free(output);
        const len = try inflater.decompress(input, sink.len, output);
        try std.testing.expectEqualSlices(u8, message, output[0..len]);
    }
}

test "no context takeover decodes with independent streams" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init();
    var inflater = Inflater.init();

    const messages = [_][]const u8{ "repeat me", "repeat me", "repeat me" };
    for (messages) |message| {
        encoder.resetContext();
        inflater.resetContext();
        var sink: TestSink = .{};
        try encoder.encode(&sink, message);
        const input = try allocator.alloc(u8, sink.len + 4);
        defer allocator.free(input);
        @memcpy(input[0..sink.len], sink.bytes());
        const output = try allocator.alloc(u8, message.len);
        defer allocator.free(output);
        const len = try inflater.decompress(input, sink.len, output);
        try std.testing.expectEqualSlices(u8, message, output[0..len]);
    }
}

test "window bits limit the encoder distance" {
    const allocator = std.testing.allocator;
    const message = "0123456789abcdef0123456789abcdef0123456789abcdef";
    var encoder = Encoder.init();
    encoder.setWindowBits(8);
    var sink: TestSink = .{};
    try encoder.encode(&sink, message);

    const input = try allocator.alloc(u8, sink.len + 4);
    defer allocator.free(input);
    @memcpy(input[0..sink.len], sink.bytes());
    const output = try allocator.alloc(u8, message.len);
    defer allocator.free(output);
    var inflater = Inflater.init();
    const len = try inflater.decompress(input, sink.len, output);
    try std.testing.expectEqualSlices(u8, message, output[0..len]);
}

test "invalid and truncated streams are rejected" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        &.{},
        &.{ 0x00, 0x00, 0x00, 0xff, 0x00 },
        &.{ 0x00, 0x05, 0x00, 0x00, 0x00 },
        &.{ 0xff, 0xff, 0xff, 0xff },
    };
    for (cases) |compressed| {
        const input = try allocator.alloc(u8, compressed.len + 4);
        defer allocator.free(input);
        @memcpy(input[0..compressed.len], compressed);
        const output = try allocator.alloc(u8, 1024);
        defer allocator.free(output);
        var inflater = Inflater.init();
        try std.testing.expectError(
            error.InvalidData,
            inflater.decompress(input, compressed.len, output),
        );
    }
}

test "canonical empty message payload decodes" {
    const compressed = [_]u8{0x00};
    var input: [compressed.len + 4]u8 = undefined;
    @memcpy(input[0..compressed.len], &compressed);
    var output: [1]u8 = undefined;
    var inflater = Inflater.init();
    const len = try inflater.decompress(&input, compressed.len, &output);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "decompressed output is bounded" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init();
    var sink: TestSink = .{};
    const message = try allocator.alloc(u8, 4096);
    defer allocator.free(message);
    @memset(message, 'a');
    try encoder.encode(&sink, message);

    const input = try allocator.alloc(u8, sink.len + 4);
    defer allocator.free(input);
    @memcpy(input[0..sink.len], sink.bytes());
    var output: [64]u8 = undefined;
    var inflater = Inflater.init();
    try std.testing.expectError(
        error.MessageTooBig,
        inflater.decompress(input, sink.len, &output),
    );
}

test "arbitrary compressed bytes fail without panicking" {
    var input: [256]u8 = undefined;
    var output: [512]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x6d61726d6f);
    const random = prng.random();
    var iteration: usize = 0;
    while (iteration < 512) : (iteration += 1) {
        const len = random.uintLessThan(usize, input.len - 4);
        random.bytes(input[0..len]);
        var inflater = Inflater.init();
        _ = inflater.decompress(&input, len, &output) catch |err| switch (err) {
            error.InvalidData, error.MessageTooBig => continue,
        };
    }
}

test "context takeover reuses the previous message" {
    const allocator = std.testing.allocator;
    const message = try allocator.alloc(u8, 32 * 1024);
    defer allocator.free(message);
    for (message, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);

    var sink: TestSink = .{};
    var encoder = Encoder.init();
    try encoder.encode(&sink, message);
    const first_len = sink.len;
    sink.len = 0;
    try encoder.encode(&sink, message);
    const takeover_len = sink.len;
    try std.testing.expect(takeover_len < first_len);

    sink.len = 0;
    encoder.resetContext();
    try encoder.encode(&sink, message);
    try std.testing.expectEqual(first_len, sink.len);
}
