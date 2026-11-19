//! WebSocket (RFC 6455) transport package.
//!
//! The package performs the opening handshake and exposes a bounded duplex
//! byte connection. It imports only `std`.

const std = @import("std");

pub const handshake = @import("handshake.zig");
pub const frame = @import("frame.zig");
const connection = @import("connection.zig");
pub const Connection = connection.Connection;
pub const clientHandshake = @import("connection.zig").clientHandshake;
pub const serverHandshake = @import("connection.zig").serverHandshake;
pub const ClientOptions = @import("connection.zig").ClientOptions;
pub const ServerOptions = @import("connection.zig").ServerOptions;
pub const Error = @import("connection.zig").Error;
pub const max_handshake = handshake.max_handshake;
pub const max_frame_payload = frame.max_payload;
pub const max_message = connection.max_message;

test {
    std.testing.refAllDecls(@This());
}
