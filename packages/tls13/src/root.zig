//! TLS 1.3 package.
//!
//! This package has no dependency on marmo. It operates on `std.Io.Reader` and
//! `std.Io.Writer`, so a different TLS implementation can replace it as long
//! as the `Client`, `Options`, and `Ca` API stays compatible.

const std = @import("std");
const builtin = @import("builtin");

/// Runtime-generated certificates for integration tests. Empty outside tests.
pub const test_cert = if (builtin.is_test) @import("test_cert.zig") else struct {};

pub const Ca = @import("ca.zig").Ca;
pub const Client = @import("client.zig").Client;
pub const Options = @import("client.zig").Options;
pub const Server = @import("server.zig").Server;
pub const ServerOptions = @import("server.zig").ServerOptions;
pub const validateCredentials = @import("server.zig").validateCredentials;
pub const readSome = @import("reader.zig").readSome;
pub const min_buffer_len = @import("client.zig").min_buffer_len;

test {
    std.testing.refAllDecls(@This());
}
