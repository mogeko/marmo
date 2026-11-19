//! HTTP/2 (RFC 9113) frame codec.

const std = @import("std");

pub const header_len = 9;
pub const max_frame_size = 16 * 1024;
pub const default_window = 65535;
pub const max_window = 0x7fffffff;

pub const type_data: u8 = 0x0;
pub const type_headers: u8 = 0x1;
pub const type_priority: u8 = 0x2;
pub const type_rst_stream: u8 = 0x3;
pub const type_settings: u8 = 0x4;
pub const type_push_promise: u8 = 0x5;
pub const type_ping: u8 = 0x6;
pub const type_goaway: u8 = 0x7;
pub const type_window_update: u8 = 0x8;
pub const type_continuation: u8 = 0x9;

pub const flag_end_stream: u8 = 0x1;
pub const flag_ack: u8 = 0x1;
pub const flag_end_headers: u8 = 0x4;
pub const flag_padded: u8 = 0x8;
pub const flag_priority: u8 = 0x20;

pub const Error = error{
    Canceled,
    EndOfStream,
    ProtocolViolation,
    Unexpected,
};

pub const Frame = struct {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: []u8,
};

pub fn read(
    input: *std.Io.Reader,
    buffer: []u8,
) Error!Frame {
    var header: [header_len]u8 = undefined;
    try readExact(input, &header, true);
    const length = std.mem.readInt(u24, header[0..3], .big);
    if (length > max_frame_size or length > buffer.len) {
        return error.ProtocolViolation;
    }
    const stream_id = std.mem.readInt(u32, header[5..9], .big);
    if (stream_id & 0x80000000 != 0) return error.ProtocolViolation;
    const payload = buffer[0..length];
    readExact(input, payload, false) catch |err| switch (err) {
        error.EndOfStream => return error.ProtocolViolation,
        else => return err,
    };
    return .{
        .frame_type = header[3],
        .flags = header[4],
        .stream_id = stream_id,
        .payload = payload,
    };
}

pub fn write(
    output: *std.Io.Writer,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: []const u8,
) Error!void {
    if (payload.len > max_frame_size) return error.ProtocolViolation;
    if (stream_id & 0x80000000 != 0) return error.ProtocolViolation;
    var header: [header_len]u8 = undefined;
    std.mem.writeInt(u24, header[0..3], @intCast(payload.len), .big);
    header[3] = frame_type;
    header[4] = flags;
    std.mem.writeInt(u32, header[5..9], stream_id, .big);
    output.writeAll(&header) catch return error.Unexpected;
    output.writeAll(payload) catch return error.Unexpected;
}

pub fn readExact(
    input: *std.Io.Reader,
    buffer: []u8,
    allow_eof: bool,
) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const read_len = input.readSliceShort(buffer[offset..]) catch
            return error.Unexpected;
        if (read_len == 0) {
            if (allow_eof and offset == 0) return error.EndOfStream;
            return error.ProtocolViolation;
        }
        offset += read_len;
    }
}

test "frame round-trip" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();
    try write(&storage.writer, type_data, flag_end_stream, 1, "hello");

    var reader = std.Io.Reader.fixed(storage.written());
    var buffer: [max_frame_size]u8 = undefined;
    const parsed = try read(&reader, &buffer);
    try std.testing.expectEqual(type_data, parsed.frame_type);
    try std.testing.expectEqual(flag_end_stream, parsed.flags);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
    try std.testing.expectEqualStrings("hello", parsed.payload);
}

test "oversized frames are rejected" {
    var header = [_]u8{ 0x00, 0x40, 0x01, type_data, 0, 0, 0, 0, 1 };
    var reader = std.Io.Reader.fixed(&header);
    var buffer: [max_frame_size]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        read(&reader, &buffer),
    );
}
