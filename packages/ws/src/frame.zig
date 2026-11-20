//! RFC 6455 frame codec.

const std = @import("std");

/// Largest frame the writer emits before fragmenting.
pub const max_payload = 64 * 1024;
/// Largest frame the reader accepts. Standard clients send messages up to
/// their configured max_size as a single frame, so this matches the 1 MiB
/// message limit instead of the write fragment size.
pub const max_read_payload = 1024 * 1024;
pub const max_mask_scratch = 4 * 1024;
pub const max_control_payload = 125;
pub const header_max = 14;

pub const opcode_continuation: u8 = 0x0;
pub const opcode_text: u8 = 0x1;
pub const opcode_binary: u8 = 0x2;
pub const opcode_close: u8 = 0x8;
pub const opcode_ping: u8 = 0x9;
pub const opcode_pong: u8 = 0xa;

pub const Role = enum { client, server };

pub const Error = error{
    Canceled,
    EndOfStream,
    MessageTooBig,
    ProtocolViolation,
    Unexpected,
};

pub const Frame = struct {
    fin: bool,
    opcode: u8,
    payload: []u8,
    /// Set when a permessage-deflate encoded data frame carries RSV1.
    rsv1: bool = false,
};

pub const ReadOptions = struct {
    /// Allow RSV1 on a first text/binary frame. The caller enforces message
    /// state (RSV1 is never valid on a continuation or control frame).
    allow_rsv1: bool = false,
};

pub const WriteOptions = struct {
    /// Set RSV1 on a data frame. Only valid for text/binary first frames.
    rsv1: bool = false,
};

/// Reads exactly one frame with default options. Server roles require masked
/// client frames; client roles require unmasked server frames.
pub fn read(
    input: *std.Io.Reader,
    role: Role,
    payload_buffer: []u8,
) Error!Frame {
    return readFrame(input, role, payload_buffer, .{});
}

/// Reads exactly one frame. RSV1 is accepted only for a text/binary frame
/// when `options.allow_rsv1` is set; RSV2/RSV3 and compressed control or
/// continuation frames are always protocol violations.
pub fn readFrame(
    input: *std.Io.Reader,
    role: Role,
    payload_buffer: []u8,
    options: ReadOptions,
) Error!Frame {
    var header: [2]u8 = undefined;
    try readExact(input, &header, true);

    const fin = header[0] & 0x80 != 0;
    const opcode = header[0] & 0x0f;
    switch (opcode) {
        opcode_continuation,
        opcode_text,
        opcode_binary,
        opcode_close,
        opcode_ping,
        opcode_pong,
        => {},
        else => return error.ProtocolViolation,
    }
    const rsv1 = try validateReserved(header[0], opcode, options);

    const masked = header[1] & 0x80 != 0;
    switch (role) {
        .server => if (!masked) return error.ProtocolViolation,
        .client => if (masked) return error.ProtocolViolation,
    }

    var payload_len: u64 = header[1] & 0x7f;
    if (payload_len == 126) {
        var extended: [2]u8 = undefined;
        try readExact(input, &extended, false);
        payload_len = std.mem.readInt(u16, &extended, .big);
    } else if (payload_len == 127) {
        var extended: [8]u8 = undefined;
        try readExact(input, &extended, false);
        payload_len = std.mem.readInt(u64, &extended, .big);
        if (payload_len >> 63 != 0) return error.ProtocolViolation;
    }
    if (payload_len > max_read_payload) return error.MessageTooBig;
    if (opcode >= opcode_close) {
        if (!fin or payload_len > max_control_payload) {
            return error.ProtocolViolation;
        }
    }
    const length: usize = @intCast(payload_len);
    if (payload_buffer.len < length) return error.MessageTooBig;

    var mask: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) try readExact(input, &mask, false);

    const payload = payload_buffer[0..length];
    readExact(input, payload, false) catch |err| switch (err) {
        error.EndOfStream => return error.ProtocolViolation,
        else => return err,
    };
    if (masked) {
        for (payload, 0..) |*byte, index| {
            byte.* ^= mask[index % 4];
        }
    }
    return .{
        .fin = fin,
        .opcode = opcode,
        .payload = payload,
        .rsv1 = rsv1,
    };
}

/// Validates reserved bits and returns whether RSV1 marks a compressed
/// message. RSV1 is legal only on a first text/binary frame when enabled.
fn validateReserved(
    header: u8,
    opcode: u8,
    options: ReadOptions,
) Error!bool {
    const reserved = header & 0x70;
    if (reserved == 0) return false;
    if (reserved != 0x40 or !options.allow_rsv1) {
        return error.ProtocolViolation;
    }
    if (opcode != opcode_text and opcode != opcode_binary) {
        return error.ProtocolViolation;
    }
    return true;
}

/// Writes one frame with default options. `scratch` must be at least
/// `payload.len` bytes and is used only when client masking is required.
pub fn write(
    io: std.Io,
    output: *std.Io.Writer,
    role: Role,
    opcode: u8,
    fin: bool,
    payload: []const u8,
    scratch: []u8,
) Error!void {
    return writeFrame(io, output, role, opcode, fin, payload, scratch, .{});
}

/// Writes one frame. RSV1 is rejected on control and continuation frames.
pub fn writeFrame(
    io: std.Io,
    output: *std.Io.Writer,
    role: Role,
    opcode: u8,
    fin: bool,
    payload: []const u8,
    scratch: []u8,
    options: WriteOptions,
) Error!void {
    if (payload.len > max_payload) return error.ProtocolViolation;
    if (opcode >= opcode_close) {
        if (!fin or payload.len > max_control_payload or options.rsv1) {
            return error.ProtocolViolation;
        }
    }
    if (options.rsv1 and opcode != opcode_text and opcode != opcode_binary) {
        return error.ProtocolViolation;
    }

    var header: [header_max]u8 = undefined;
    var header_len: usize = 2;
    header[0] = opcode | (if (fin) @as(u8, 0x80) else 0);
    if (options.rsv1) header[0] |= 0x40;
    header[1] = 0;
    const masked = role == .client;
    if (masked) header[1] = 0x80;

    if (payload.len < 126) {
        header[1] |= @intCast(payload.len);
    } else if (payload.len <= std.math.maxInt(u16)) {
        header[1] |= 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len += 2;
    } else {
        header[1] |= 127;
        std.mem.writeInt(u64, header[2..10], payload.len, .big);
        header_len += 8;
    }

    if (masked) {
        if (scratch.len == 0) return error.ProtocolViolation;
        var mask: [4]u8 = undefined;
        std.Io.randomSecure(io, &mask) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.Unexpected,
        };
        @memcpy(header[header_len..][0..4], &mask);
        header_len += 4;
        output.writeAll(header[0..header_len]) catch return error.Unexpected;
        var offset: usize = 0;
        while (offset < payload.len) {
            const chunk_len = @min(scratch.len, payload.len - offset);
            for (0..chunk_len) |index| {
                scratch[index] = payload[offset + index] ^
                    mask[(offset + index) % 4];
            }
            output.writeAll(scratch[0..chunk_len]) catch
                return error.Unexpected;
            offset += chunk_len;
        }
        return;
    }

    output.writeAll(header[0..header_len]) catch return error.Unexpected;
    output.writeAll(payload) catch return error.Unexpected;
}

fn readExact(
    input: *std.Io.Reader,
    buffer: []u8,
    allow_eof: bool,
) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const read_len = input.readSliceShort(buffer[offset..]) catch return error.Unexpected;
        if (read_len == 0) {
            if (allow_eof and offset == 0) return error.EndOfStream;
            return error.ProtocolViolation;
        }
        offset += read_len;
    }
}

test "client frames are masked and round-trip" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();

    var scratch: [16]u8 = undefined;
    try write(
        std.testing.io,
        &storage.writer,
        .client,
        opcode_binary,
        true,
        "hello",
        &scratch,
    );

    var reader = std.Io.Reader.fixed(storage.written());
    var payload: [16]u8 = undefined;
    const parsed = try read(&reader, .server, &payload);
    try std.testing.expect(parsed.fin);
    try std.testing.expectEqual(opcode_binary, parsed.opcode);
    try std.testing.expectEqualStrings("hello", parsed.payload);
}

test "server rejects unmasked client frames" {
    var bytes = [_]u8{ 0x82, 0x00 };
    var reader = std.Io.Reader.fixed(&bytes);
    var payload: [16]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        read(&reader, .server, &payload),
    );
}

test "control frames must not be fragmented" {
    var bytes = [_]u8{ 0x09, 0x00 };
    var reader = std.Io.Reader.fixed(&bytes);
    var payload: [16]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        read(&reader, .client, &payload),
    );
}

test "RSV1 is rejected unless explicitly allowed" {
    var bytes = [_]u8{ 0xc2, 0x00 };
    var reader = std.Io.Reader.fixed(&bytes);
    var payload: [16]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        read(&reader, .client, &payload),
    );

    var allowed_reader = std.Io.Reader.fixed(&bytes);
    const parsed = try readFrame(
        &allowed_reader,
        .client,
        &payload,
        .{ .allow_rsv1 = true },
    );
    try std.testing.expect(parsed.rsv1);
    try std.testing.expectEqual(opcode_binary, parsed.opcode);
}

test "RSV1 is invalid on continuation and control frames" {
    var continuation = [_]u8{ 0xc0, 0x00 };
    var reader = std.Io.Reader.fixed(&continuation);
    var payload: [16]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        readFrame(&reader, .client, &payload, .{ .allow_rsv1 = true }),
    );

    var control = [_]u8{ 0xc9, 0x00 };
    var control_reader = std.Io.Reader.fixed(&control);
    try std.testing.expectError(
        error.ProtocolViolation,
        readFrame(&control_reader, .client, &payload, .{ .allow_rsv1 = true }),
    );
}

test "RSV2 and RSV3 are always rejected" {
    var rsv2 = [_]u8{ 0xa2, 0x00 };
    var rsv2_reader = std.Io.Reader.fixed(&rsv2);
    var payload: [16]u8 = undefined;
    try std.testing.expectError(
        error.ProtocolViolation,
        readFrame(&rsv2_reader, .client, &payload, .{ .allow_rsv1 = true }),
    );
    var rsv3 = [_]u8{ 0x92, 0x00 };
    var rsv3_reader = std.Io.Reader.fixed(&rsv3);
    try std.testing.expectError(
        error.ProtocolViolation,
        readFrame(&rsv3_reader, .client, &payload, .{ .allow_rsv1 = true }),
    );
}

test "writer sets RSV1 only on allowed data frames" {
    const allocator = std.testing.allocator;
    var storage: std.Io.Writer.Allocating = .init(allocator);
    defer storage.deinit();

    try writeFrame(
        std.testing.io,
        &storage.writer,
        .server,
        opcode_text,
        true,
        "hi",
        &.{},
        .{ .rsv1 = true },
    );
    var reader = std.Io.Reader.fixed(storage.written());
    var payload: [16]u8 = undefined;
    const parsed = try readFrame(
        &reader,
        .client,
        &payload,
        .{ .allow_rsv1 = true },
    );
    try std.testing.expect(parsed.rsv1);
    try std.testing.expectEqual(opcode_text, parsed.opcode);

    storage.clearRetainingCapacity();
    try std.testing.expectError(
        error.ProtocolViolation,
        writeFrame(
            std.testing.io,
            &storage.writer,
            .server,
            opcode_ping,
            true,
            "hi",
            &.{},
            .{ .rsv1 = true },
        ),
    );
    try std.testing.expectError(
        error.ProtocolViolation,
        writeFrame(
            std.testing.io,
            &storage.writer,
            .server,
            opcode_continuation,
            true,
            "hi",
            &.{},
            .{ .rsv1 = true },
        ),
    );
}
