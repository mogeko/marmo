//! TLS client session over a `std.Io.Reader`/`Writer` pair.
//!
//! The public surface is intentionally transport-neutral: callers provide the
//! encrypted byte stream and plaintext buffers, and this module performs the
//! handshake, certificate verification, record protection, and shutdown.

const std = @import("std");
const Ca = @import("ca.zig").Ca;

/// The input reader must have at least this much buffered capacity.
pub const min_buffer_len = std.crypto.tls.Client.min_buffer_len;

pub const Options = struct {
    /// Server name for SNI and certificate host verification. Required when
    /// `verify` is true.
    server_name: ?[]const u8,
    /// Verify the certificate chain against `ca`.
    verify: bool = true,
    /// System CA bundle. Required when `verify` is true.
    ca: ?*Ca = null,
    /// Plaintext reader buffer. Must be non-empty.
    read_buffer: []u8,
    /// Plaintext writer buffer. Must be non-empty.
    write_buffer: []u8,
    /// Treat a missing `close_notify` as EOF. Byte-stream protocols without
    /// their own truncation check normally want this.
    allow_truncation_attacks: bool = true,
};

pub const InitError = error{
    Canceled,
    HandshakeFailed,
};

pub const Client = struct {
    inner: std.crypto.tls.Client,

    pub fn init(
        io: std.Io,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        options: Options,
    ) InitError!Client {
        if (options.verify) {
            if (options.server_name == null or options.ca == null) {
                return error.HandshakeFailed;
            }
            options.ca.?.ensure(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.LoadFailed => return error.HandshakeFailed,
            };
        }
        std.debug.assert(input.buffer.len >= min_buffer_len);
        std.debug.assert(output.buffer.len >= min_buffer_len);
        std.debug.assert(options.read_buffer.len > 0);
        std.debug.assert(options.write_buffer.len > 0);

        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        std.Io.randomSecure(io, &entropy) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.HandshakeFailed,
        };

        const inner = std.crypto.tls.Client.init(input, output, .{
            .host = if (options.server_name) |name|
                .{ .explicit = name }
            else
                .no_verification,
            .ca = if (options.verify) .{ .bundle = .{
                .gpa = options.ca.?.gpa,
                .io = io,
                .lock = options.ca.?.lockPtr(),
                .bundle = options.ca.?.bundlePtr(),
            } } else .no_verification,
            .write_buffer = options.write_buffer,
            .read_buffer = options.read_buffer,
            .entropy = &entropy,
            .realtime_now = std.Io.Timestamp.now(io, .real),
            .allow_truncation_attacks = options.allow_truncation_attacks,
        }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.HandshakeFailed,
        };
        return .{ .inner = inner };
    }

    pub fn reader(self: *Client) *std.Io.Reader {
        return &self.inner.reader;
    }

    pub fn writer(self: *Client) *std.Io.Writer {
        return &self.inner.writer;
    }

    pub fn end(self: *Client) std.Io.Writer.Error!void {
        return self.inner.end();
    }

    pub fn eof(self: Client) bool {
        return self.inner.eof();
    }

    /// Zeroizes the session state; the caller still owns the buffers.
    pub fn deinit(self: *Client) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.inner));
    }
};

fn failingStream(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    _ = reader;
    _ = writer;
    _ = limit;
    return error.EndOfStream;
}

fn discardDrain(
    writer: *std.Io.Writer,
    data: []const []const u8,
    splat: usize,
) std.Io.Writer.Error!usize {
    writer.end = 0;
    var total: usize = 0;
    for (data, 0..) |slice, index| {
        const repeat = if (index + 1 == data.len) splat else 1;
        total += slice.len * repeat;
    }
    return total;
}

test "a peer close during the handshake fails the handshake" {
    var input_buffer: [min_buffer_len]u8 = undefined;
    var input: std.Io.Reader = .{
        .vtable = &.{ .stream = failingStream },
        .buffer = &input_buffer,
        .seek = 0,
        .end = 0,
    };
    var output_buffer: [min_buffer_len]u8 = undefined;
    var output: std.Io.Writer = .{
        .vtable = &.{ .drain = discardDrain },
        .buffer = &output_buffer,
    };
    var read_buffer: [512]u8 = undefined;
    var write_buffer: [512]u8 = undefined;

    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = "localhost",
            .verify = false,
            .read_buffer = &read_buffer,
            .write_buffer = &write_buffer,
        }),
    );
}

test "verification requires a server name and a CA" {
    var input: std.Io.Reader = .failing;
    var output: std.Io.Writer = .failing;
    var dummy: [1]u8 = undefined;
    var ca = Ca.init(std.testing.allocator);
    defer ca.deinit();

    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = "localhost",
            .verify = true,
            .ca = null,
            .read_buffer = &dummy,
            .write_buffer = &dummy,
        }),
    );
    try std.testing.expectError(
        error.HandshakeFailed,
        Client.init(std.testing.io, &input, &output, .{
            .server_name = null,
            .verify = true,
            .ca = &ca,
            .read_buffer = &dummy,
            .write_buffer = &dummy,
        }),
    );
}
