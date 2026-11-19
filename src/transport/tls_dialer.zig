//! TLS transport dialer: wraps another dialer and adds a TLS client handshake.

const std = @import("std");
const Endpoint = @import("../net/endpoint.zig").Endpoint;
const Dialer = @import("dialer.zig").Dialer;
const Stream = @import("stream.zig").Stream;
const TlsClientStream = @import("tls_client.zig").TlsClientStream;

pub const TlsDialer = struct {
    gpa: std.mem.Allocator,
    base: Dialer,
    /// SNI and certificate host; null disables both.
    server_name: ?[]const u8,
    insecure: bool,
    bundle: std.crypto.Certificate.Bundle = .empty,
    bundle_lock: std.Io.RwLock = .init,
    bundle_loaded: bool = false,

    pub fn asDialer(self: *TlsDialer) Dialer {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn deinit(self: *TlsDialer) void {
        if (self.bundle_loaded) self.bundle.deinit(self.gpa);
        self.bundle = .empty;
        self.bundle_loaded = false;
    }

    fn connect(
        ctx: *anyopaque,
        io: std.Io,
        endpoint: Endpoint,
    ) Dialer.ConnectError!Stream {
        const self: *TlsDialer = @ptrCast(@alignCast(ctx));
        const inner = try self.base.connect(io, endpoint);
        const tls_stream = self.wrap(io, inner) catch |err| {
            inner.close(io);
            return err;
        };
        return tls_stream.stream();
    }

    fn wrap(
        self: *TlsDialer,
        io: std.Io,
        inner: Stream,
    ) Dialer.ConnectError!*TlsClientStream {
        if (!self.insecure) try self.loadBundle(io);
        return TlsClientStream.create(io, self.gpa, inner, .{
            .server_name = self.server_name,
            .verify = !self.insecure,
            .ca = if (self.insecure) null else &self.bundle,
            .ca_lock = if (self.insecure) null else &self.bundle_lock,
        }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.OutOfMemory => return error.Unexpected,
            error.HandshakeFailed => return error.ProtocolViolation,
        };
    }

    /// Loads the system CA bundle once, on the first verifying connection.
    fn loadBundle(self: *TlsDialer, io: std.Io) Dialer.ConnectError!void {
        self.bundle_lock.lock(io) catch return error.Canceled;
        defer self.bundle_lock.unlock(io);
        if (self.bundle_loaded) return;

        self.bundle.rescan(
            self.gpa,
            io,
            std.Io.Timestamp.now(io, .real),
        ) catch {
            self.bundle.deinit(self.gpa);
            self.bundle = .empty;
            return error.Unexpected;
        };
        self.bundle_loaded = true;
    }

    const vtable: Dialer.VTable = .{ .connect = connect };
};
