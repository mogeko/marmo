//! HPACK (RFC 7541) bounded decoder and simple encoder for HTTP/2 transports.

const std = @import("std");
const huffman_table = @import("huffman_table.zig");

pub const max_header_list = 8 * 1024;
pub const max_headers = 256;
pub const max_dynamic_size = 4096;
pub const max_dynamic_entries = 128;
pub const max_name = 256;
pub const max_value = 16 * 1024;

pub const Error = error{
    Malformed,
    OutOfMemory,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

const static_table = [61]Header{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

const DynamicEntry = struct {
    name_off: u16 = 0,
    name_len: u16 = 0,
    value_off: u16 = 0,
    value_len: u16 = 0,

    fn header(self: *const DynamicEntry, storage: *const [max_dynamic_size]u8) Header {
        return .{
            .name = storage[self.name_off..][0..self.name_len],
            .value = storage[self.value_off..][0..self.value_len],
        };
    }

    fn size(self: *const DynamicEntry) usize {
        return @as(usize, self.name_len) + self.value_len + 32;
    }
};

const DecodeState = struct {
    storage: []u8,
    headers: []Header,
    storage_used: usize = 0,
    header_count: usize = 0,
    list_size: usize = 0,
    header_seen: bool = false,
    size_updates: usize = 0,
    max_list_size: usize,

    fn append(
        self: *DecodeState,
        name: []const u8,
        value: []const u8,
    ) Error!void {
        if (self.header_count == self.headers.len) return error.Malformed;
        if (name.len == 0 or name.len > max_name or value.len > max_value) {
            return error.Malformed;
        }
        const entry_size = name.len + value.len + 32;
        if (entry_size > self.max_list_size -| self.list_size) {
            return error.OutOfMemory;
        }
        const name_copy = try ensureInStorage(
            self.storage,
            &self.storage_used,
            name,
        );
        const value_copy = try ensureInStorage(
            self.storage,
            &self.storage_used,
            value,
        );
        self.headers[self.header_count] = .{
            .name = name_copy,
            .value = value_copy,
        };
        self.header_count += 1;
        self.list_size += entry_size;
    }
};

pub const Decoder = struct {
    entries: [max_dynamic_entries]DynamicEntry = undefined,
    storage: [max_dynamic_size]u8 = undefined,
    storage_len: usize = 0,
    count: usize = 0,
    size: usize = 0,
    max_size: usize = max_dynamic_size,

    pub fn init() Decoder {
        return .{};
    }

    pub fn decode(
        self: *Decoder,
        block: []const u8,
        storage: []u8,
        headers: []Header,
    ) Error![]Header {
        return self.decodeBounded(block, storage, headers, max_header_list);
    }

    /// Decodes a header block while enforcing a caller-selected header-list
    /// limit. RFC 9113 counts `name.len + value.len + 32` per field, so the
    /// byte-only storage limit is not sufficient.
    pub fn decodeBounded(
        self: *Decoder,
        block: []const u8,
        storage: []u8,
        headers: []Header,
        max_list_size: usize,
    ) Error![]Header {
        var state: DecodeState = .{
            .storage = storage,
            .headers = headers,
            .max_list_size = max_list_size,
        };
        var pos: usize = 0;
        while (pos < block.len) {
            try self.decodeField(&state, block, &pos);
        }
        return headers[0..state.header_count];
    }

    fn decodeField(
        self: *Decoder,
        state: *DecodeState,
        block: []const u8,
        pos: *usize,
    ) Error!void {
        const first = block[pos.*];
        if (first & 0x80 != 0) {
            return self.decodeIndexed(state, block, pos);
        }
        if (first & 0x40 != 0) {
            return self.decodeIncremental(state, block, pos);
        }
        if (first & 0x20 != 0) {
            return self.decodeSizeUpdate(state, block, pos);
        }
        return self.decodeLiteral(state, block, pos);
    }

    fn decodeIndexed(
        self: *Decoder,
        state: *DecodeState,
        block: []const u8,
        pos: *usize,
    ) Error!void {
        state.header_seen = true;
        const index = try decodeInt(block, pos, 7);
        const header = try self.lookup(index);
        try state.append(header.name, header.value);
    }

    fn decodeIncremental(
        self: *Decoder,
        state: *DecodeState,
        block: []const u8,
        pos: *usize,
    ) Error!void {
        state.header_seen = true;
        const name = try self.decodeName(state, block, pos, 6);
        const value = try decodeString(block, pos, state.storage, &state.storage_used);
        try state.append(name, value);
        try self.add(name, value);
    }

    fn decodeSizeUpdate(
        self: *Decoder,
        state: *DecodeState,
        block: []const u8,
        pos: *usize,
    ) Error!void {
        if (state.header_seen or state.size_updates >= 2) {
            return error.Malformed;
        }
        state.size_updates += 1;
        const size = try decodeInt(block, pos, 5);
        if (size > max_dynamic_size) return error.Malformed;
        self.max_size = size;
        self.evict();
    }

    fn decodeLiteral(
        self: *Decoder,
        state: *DecodeState,
        block: []const u8,
        pos: *usize,
    ) Error!void {
        state.header_seen = true;
        const name = try self.decodeName(state, block, pos, 4);
        const value = try decodeString(block, pos, state.storage, &state.storage_used);
        try state.append(name, value);
    }

    pub fn zeroize(self: *Decoder) void {
        std.crypto.secureZero(u8, &self.storage);
        for (&self.entries) |*entry| entry.* = .{};
        self.storage_len = 0;
        self.count = 0;
        self.size = 0;
    }

    fn decodeName(
        self: *Decoder,
        state: *DecodeState,
        block: []const u8,
        pos: *usize,
        prefix: u4,
    ) Error![]const u8 {
        const index = try decodeInt(block, pos, prefix);
        if (index == 0) {
            return decodeString(
                block,
                pos,
                state.storage,
                &state.storage_used,
            );
        }
        const header = try self.lookup(index);
        return copyToStorage(state.storage, &state.storage_used, header.name);
    }

    fn lookup(self: *const Decoder, index: usize) Error!Header {
        if (index == 0) return error.Malformed;
        if (index <= static_table.len) return static_table[index - 1];
        const dynamic_index = index - static_table.len - 1;
        if (dynamic_index >= self.count) return error.Malformed;
        return self.entries[dynamic_index].header(&self.storage);
    }

    fn add(self: *Decoder, name: []const u8, value: []const u8) Error!void {
        if (name.len == 0 or name.len > max_name or value.len > max_value) {
            return error.Malformed;
        }
        const entry_size = name.len + value.len + 32;
        if (entry_size > self.max_size) {
            // RFC 7541 4.4: an entry larger than the table empties it and is
            // not added.
            self.count = 0;
            self.size = 0;
            self.storage_len = 0;
            return;
        }
        while (self.count > 0 and
            (self.size + entry_size > self.max_size or
                self.count == max_dynamic_entries))
        {
            self.evictOldest();
        }
        self.compact();
        if (self.storage.len - self.storage_len < name.len + value.len) {
            return error.Malformed;
        }

        const name_off: u16 = @intCast(self.storage_len);
        @memcpy(self.storage[self.storage_len..][0..name.len], name);
        self.storage_len += name.len;
        const value_off: u16 = @intCast(self.storage_len);
        @memcpy(self.storage[self.storage_len..][0..value.len], value);
        self.storage_len += value.len;

        var index = self.count;
        while (index > 0) : (index -= 1) {
            self.entries[index] = self.entries[index - 1];
        }
        self.entries[0] = .{
            .name_off = name_off,
            .name_len = @intCast(name.len),
            .value_off = value_off,
            .value_len = @intCast(value.len),
        };
        self.count += 1;
        self.size += entry_size;
    }

    fn compact(self: *Decoder) void {
        var cursor: usize = 0;
        var index = self.count;
        while (index > 0) {
            index -= 1;
            const entry = &self.entries[index];
            const name = self.storage[entry.name_off..][0..entry.name_len];
            const value = self.storage[entry.value_off..][0..entry.value_len];
            if (cursor != entry.name_off) {
                std.mem.copyForwards(
                    u8,
                    self.storage[cursor..][0..name.len],
                    name,
                );
            }
            entry.name_off = @intCast(cursor);
            cursor += name.len;
            if (cursor != entry.value_off) {
                std.mem.copyForwards(
                    u8,
                    self.storage[cursor..][0..value.len],
                    value,
                );
            }
            entry.value_off = @intCast(cursor);
            cursor += value.len;
        }
        self.storage_len = cursor;
    }

    fn evict(self: *Decoder) void {
        while (self.count > 0 and self.size > self.max_size) {
            self.evictOldest();
        }
    }

    fn evictOldest(self: *Decoder) void {
        if (self.count == 0) return;
        self.count -= 1;
        self.size -= self.entries[self.count].size();
    }
};

fn ensureInStorage(
    storage: []u8,
    used: *usize,
    bytes: []const u8,
) Error![]const u8 {
    if (bytes.len != 0) {
        const start = @intFromPtr(storage.ptr);
        const end = start + storage.len;
        const pointer = @intFromPtr(bytes.ptr);
        if (pointer >= start and pointer + bytes.len <= end) return bytes;
    }
    return copyToStorage(storage, used, bytes);
}

fn copyToStorage(
    storage: []u8,
    used: *usize,
    bytes: []const u8,
) Error![]const u8 {
    if (used.* > storage.len) return error.Malformed;
    if (storage.len - used.* < bytes.len) return error.OutOfMemory;
    @memcpy(storage[used.*..][0..bytes.len], bytes);
    const result = storage[used.*..][0..bytes.len];
    used.* += bytes.len;
    return result;
}

fn decodeString(
    block: []const u8,
    pos: *usize,
    storage: []u8,
    storage_used: *usize,
) Error![]const u8 {
    if (pos.* >= block.len) return error.Malformed;
    const huffman = block[pos.*] & 0x80 != 0;
    const length = try decodeInt(block, pos, 7);
    if (length > max_value) return error.Malformed;
    if (block.len - pos.* < length) return error.Malformed;
    const encoded = block[pos.*..][0..length];
    pos.* += length;
    if (!huffman) {
        return copyToStorage(storage, storage_used, encoded);
    }
    const out = storage[storage_used.*..];
    const decoded = try decodeHuffman(encoded, out);
    storage_used.* += decoded.len;
    return decoded;
}

fn decodeInt(block: []const u8, pos: *usize, prefix_bits: u4) Error!usize {
    if (pos.* >= block.len) return error.Malformed;
    const shift_bits: u3 = @intCast(prefix_bits);
    const mask: u8 = (@as(u8, 1) << shift_bits) - 1;
    var value: u64 = block[pos.*] & mask;
    pos.* += 1;
    if (value < mask) return @intCast(value);

    // HPACK integers are used as lengths and table indices, all bounded by
    // 32 bits. Accumulate in 64 bits and reject anything above that instead
    // of overflowing the native `usize` on 32-bit targets.
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= block.len) return error.Malformed;
        const byte = block[pos.*];
        pos.* += 1;
        if (shift > 28) return error.Malformed;
        value += @as(u64, byte & 0x7f) << shift;
        if (value > std.math.maxInt(u32)) return error.Malformed;
        if (byte & 0x80 == 0) return @intCast(value);
        shift += 7;
    }
}

pub fn encodeHeader(
    output: []u8,
    pos: *usize,
    name: []const u8,
    value: []const u8,
) Error!void {
    if (!validName(name) or !validValue(value)) return error.Malformed;
    if (findStatic(name, value)) |index| {
        try encodeInt(output, pos, index, 7, 0x80);
        return;
    }
    if (findStaticName(name)) |index| {
        try encodeInt(output, pos, index, 4, 0x00);
    } else {
        try encodeInt(output, pos, 0, 4, 0x00);
        try encodeString(output, pos, name);
    }
    try encodeString(output, pos, value);
}

fn encodeString(output: []u8, pos: *usize, value: []const u8) Error!void {
    try encodeInt(output, pos, value.len, 7, 0x00);
    if (output.len - pos.* < value.len) return error.OutOfMemory;
    @memcpy(output[pos.*..][0..value.len], value);
    pos.* += value.len;
}

fn encodeInt(
    output: []u8,
    pos: *usize,
    value: usize,
    prefix_bits: u4,
    flags: u8,
) Error!void {
    if (pos.* >= output.len) return error.OutOfMemory;
    const shift_bits: u3 = @intCast(prefix_bits);
    const mask: u8 = (@as(u8, 1) << shift_bits) - 1;
    if (value < mask) {
        output[pos.*] = flags | @as(u8, @intCast(value));
        pos.* += 1;
        return;
    }
    output[pos.*] = flags | mask;
    pos.* += 1;
    var remaining = value - mask;
    while (remaining >= 0x80) {
        if (pos.* >= output.len) return error.OutOfMemory;
        output[pos.*] = @as(u8, @intCast(remaining & 0x7f)) | 0x80;
        pos.* += 1;
        remaining >>= 7;
    }
    if (pos.* >= output.len) return error.OutOfMemory;
    output[pos.*] = @intCast(remaining);
    pos.* += 1;
}

fn validName(name: []const u8) bool {
    if (name.len == 0) return false;
    var start: usize = 0;
    if (name[0] == ':') {
        if (name.len == 1) return false;
        start = 1;
    }
    for (name[start..]) |byte| {
        if (byte >= 'A' and byte <= 'Z') return false;
        const tchar = std.ascii.isAlphanumeric(byte) or
            byte == '!' or byte == '#' or byte == '$' or byte == '%' or
            byte == '&' or byte == '\'' or byte == '*' or byte == '+' or
            byte == '-' or byte == '.' or byte == '^' or byte == '_' or
            byte == '`' or byte == '|' or byte == '~';
        if (!tchar) return false;
    }
    return true;
}

fn validValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or byte == 0x7f) {
            return false;
        }
    }
    return true;
}

fn findStatic(name: []const u8, value: []const u8) ?usize {
    for (static_table, 1..) |header, index| {
        if (std.mem.eql(u8, header.name, name) and
            std.mem.eql(u8, header.value, value))
        {
            return index;
        }
    }
    return null;
}

fn findStaticName(name: []const u8) ?usize {
    for (static_table, 1..) |header, index| {
        if (std.mem.eql(u8, header.name, name)) return index;
    }
    return null;
}

const Node = struct {
    child: [2]u16 = .{ 0, 0 },
    symbol: i16 = -1,
};

fn buildTree() [1024]Node {
    @setEvalBranchQuota(20000);
    var nodes: [1024]Node = undefined;
    var index: usize = 0;
    while (index < nodes.len) : (index += 1) nodes[index] = .{};
    var count: u16 = 1;
    for (huffman_table.table, 0..) |entry, symbol| {
        var node: u16 = 0;
        var bit: i32 = @as(i32, entry.bits) - 1;
        while (bit >= 0) : (bit -= 1) {
            const shift: u5 = @intCast(bit);
            const branch: usize = @intCast((entry.code >> shift) & 1);
            if (nodes[node].child[branch] == 0) {
                nodes[count] = .{};
                nodes[node].child[branch] = count;
                count += 1;
            }
            node = nodes[node].child[branch];
        }
        nodes[node].symbol = @intCast(symbol);
    }
    return nodes;
}

const huffman_tree = buildTree();

fn decodeHuffman(encoded: []const u8, out: []u8) Error![]const u8 {
    var node: u16 = 0;
    // RFC 7541 codes are at most 30 bits; the padding check below requires
    // counting up to 7 leftover bits.
    var pending: u6 = 0;
    var pending_ones = true;
    var used: usize = 0;
    for (encoded) |byte| {
        var bit: u4 = 8;
        while (bit > 0) {
            bit -= 1;
            const branch: usize = (byte >> @intCast(bit)) & 1;
            const next = huffman_tree[node].child[branch];
            if (next == 0) return error.Malformed;
            node = next;
            pending += 1;
            if (branch == 0) pending_ones = false;
            const symbol = huffman_tree[node].symbol;
            if (symbol < 0) continue;
            if (symbol == 256) return error.Malformed;
            if (used == out.len) return error.OutOfMemory;
            out[used] = @intCast(symbol);
            used += 1;
            node = 0;
            pending = 0;
            pending_ones = true;
        }
    }
    if (pending > 7 or !pending_ones) return error.Malformed;
    return out[0..used];
}

test "static indexed header" {
    const block = [_]u8{0x82};
    var decoder = Decoder.init();
    var storage: [256]u8 = undefined;
    var headers: [4]Header = undefined;
    const list = try decoder.decode(&block, &storage, &headers);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings(":method", list[0].name);
    try std.testing.expectEqualStrings("GET", list[0].value);
}

test "RFC 7541 Huffman example decodes" {
    const block = [_]u8{
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2,
        0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
        0xff,
    };
    var decoder = Decoder.init();
    var storage: [256]u8 = undefined;
    var headers: [4]Header = undefined;
    const list = try decoder.decode(&block, &storage, &headers);
    try std.testing.expectEqual(@as(usize, 4), list.len);
    try std.testing.expectEqualStrings(":authority", list[3].name);
    try std.testing.expectEqualStrings("www.example.com", list[3].value);
}

test "encode then decode a literal header" {
    var block: [256]u8 = undefined;
    var pos: usize = 0;
    try encodeHeader(&block, &pos, "x-test", "value");
    var decoder = Decoder.init();
    var storage: [256]u8 = undefined;
    var headers: [4]Header = undefined;
    const list = try decoder.decode(block[0..pos], &storage, &headers);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings("x-test", list[0].name);
    try std.testing.expectEqualStrings("value", list[0].value);
}

test "dynamic table indexes a second block" {
    var block: [256]u8 = undefined;
    var pos: usize = 0;
    try encodeHeader(&block, &pos, "x-test", "value");
    var decoder = Decoder.init();
    var storage: [256]u8 = undefined;
    var headers: [4]Header = undefined;
    _ = try decoder.decode(block[0..pos], &storage, &headers);
    try std.testing.expectEqual(@as(usize, 0), decoder.count);

    const incremental = [_]u8{
        0x40, 0x06, 'x', '-', 't', 'e', 's', 't', 0x05, 'v', 'a', 'l', 'u', 'e',
    };
    _ = try decoder.decode(&incremental, &storage, &headers);
    try std.testing.expectEqual(@as(usize, 1), decoder.count);
    const indexed = [_]u8{0xbe};
    const list = try decoder.decode(&indexed, &storage, &headers);
    try std.testing.expectEqualStrings("x-test", list[0].name);
    try std.testing.expectEqualStrings("value", list[0].value);
}

test "30-bit Huffman codes do not overflow the pending-bit counter" {
    const block = [_]u8{ 0x41, 0x84, 0xff, 0xff, 0xff, 0xf3 };
    var decoder = Decoder.init();
    var storage: [256]u8 = undefined;
    var headers: [4]Header = undefined;
    const list = try decoder.decode(&block, &storage, &headers);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings(":authority", list[0].name);
    try std.testing.expectEqual(@as(usize, 1), list[0].value.len);
    try std.testing.expectEqual(@as(u8, 10), list[0].value[0]);
}

test "dynamic table keeps more than sixteen entries" {
    var block: [1024]u8 = undefined;
    var pos: usize = 0;
    var index: usize = 0;
    while (index < 20) : (index += 1) {
        block[pos] = 0x40;
        pos += 1;
        var name_buffer: [8]u8 = undefined;
        var value_buffer: [8]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "x-{d:0>2}", .{index});
        const value = try std.fmt.bufPrint(&value_buffer, "v-{d:0>2}", .{index});
        try encodeString(&block, &pos, name);
        try encodeString(&block, &pos, value);
    }

    var decoder = Decoder.init();
    var storage: [4096]u8 = undefined;
    var headers: [32]Header = undefined;
    const first = try decoder.decode(block[0..pos], &storage, &headers);
    try std.testing.expectEqual(@as(usize, 20), first.len);
    try std.testing.expectEqual(@as(usize, 20), decoder.count);

    const oldest = [_]u8{0x80 | (static_table.len + 1 + 19)};
    const second = try decoder.decode(&oldest, &storage, &headers);
    try std.testing.expectEqualStrings("x-00", second[0].name);
    try std.testing.expectEqualStrings("v-00", second[0].value);
}

test "encoder rejects invalid header names and values" {
    var block: [256]u8 = undefined;
    var pos: usize = 0;
    try std.testing.expectError(
        error.Malformed,
        encodeHeader(&block, &pos, "X-Test", "value"),
    );
    try std.testing.expectError(
        error.Malformed,
        encodeHeader(&block, &pos, "x-test", "bad\r\nvalue"),
    );
    try std.testing.expectError(
        error.Malformed,
        encodeHeader(&block, &pos, "", "value"),
    );
}

test "literal headers are bounded by max_name and max_value" {
    var block: [max_value + 64]u8 = undefined;
    var pos: usize = 0;
    var large_value: [max_value + 1]u8 = undefined;
    @memset(&large_value, 'a');
    block[pos] = 0x00;
    pos += 1;
    try encodeString(&block, &pos, "x-test");
    try encodeString(&block, &pos, &large_value);

    var decoder = Decoder.init();
    var storage: [max_header_list]u8 = undefined;
    var headers: [64]Header = undefined;
    try std.testing.expectError(
        error.Malformed,
        decoder.decode(block[0..pos], &storage, &headers),
    );
}

test "header-list accounting rejects an oversized decoded list" {
    var block: [16 * 1024]u8 = undefined;
    var value: [200]u8 = undefined;
    @memset(&value, 'a');
    var pos: usize = 0;
    var index: usize = 0;
    while (index < 40) : (index += 1) {
        try encodeHeader(&block, &pos, "x-list", &value);
    }
    var decoder = Decoder.init();
    var storage: [max_header_list]u8 = undefined;
    var headers: [max_headers]Header = undefined;
    try std.testing.expectError(
        error.OutOfMemory,
        decoder.decode(block[0..pos], &storage, &headers),
    );
}

test "HPACK integers larger than 32 bits are rejected" {
    const block = [_]u8{
        0x40,
        0x7f,
        0xff,
        0xff,
        0xff,
        0xff,
        0x0f,
        0x01,
        'v',
    };
    var decoder = Decoder.init();
    var storage: [256]u8 = undefined;
    var headers: [4]Header = undefined;
    try std.testing.expectError(
        error.Malformed,
        decoder.decode(&block, &storage, &headers),
    );
}
