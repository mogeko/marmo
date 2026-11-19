//! TLS 1.3 package.
//!
//! This package has no dependency on marmo. It operates on `std.Io.Reader` and
//! `std.Io.Writer`, so a different TLS implementation can replace it as long
//! as the `Client`, `Options`, and `Ca` API stays compatible.

const std = @import("std");

/// Runtime-generated certificates for tests, examples, and fuzz harnesses.
/// No private key is committed; each call generates a fresh key pair.
pub const test_cert = @import("test_cert.zig");

/// Wire-level handshake and record modules. Exposed so adapters and fuzz
/// harnesses can exercise the parser without a socket; no stability guarantee.
pub const handshake = @import("handshake.zig");
pub const record = @import("record.zig");

pub const Ca = @import("ca.zig").Ca;
pub const Client = @import("client.zig").Client;
pub const InitError = @import("client.zig").InitError;
pub const Options = @import("client.zig").Options;
pub const Server = @import("server.zig").Server;
pub const ServerOptions = @import("server.zig").ServerOptions;
pub const validateCredentials = @import("server.zig").validateCredentials;
pub const readSome = @import("reader.zig").readSome;
pub const min_buffer_len = @import("client.zig").min_buffer_len;

test {
    std.testing.refAllDecls(@This());
}
