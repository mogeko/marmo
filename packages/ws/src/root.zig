//! WebSocket (RFC 6455) transport package.
//!
//! The package performs the opening handshake and exposes a bounded duplex
//! byte connection. It imports only `std`.

const std = @import("std");

pub const handshake = @import("handshake.zig");
pub const frame = @import("frame.zig");
pub const deflate = @import("deflate.zig");
const connection = @import("connection.zig");
pub const Connection = connection.Connection;
pub const clientHandshake = @import("connection.zig").clientHandshake;
pub const serverHandshake = @import("connection.zig").serverHandshake;
pub const ClientOptions = @import("connection.zig").ClientOptions;
pub const ServerOptions = @import("connection.zig").ServerOptions;
pub const DeflateOptions = @import("connection.zig").DeflateOptions;
pub const DeflateNegotiated = @import("connection.zig").DeflateNegotiated;
pub const Error = @import("connection.zig").Error;
pub const max_handshake = handshake.max_handshake;
pub const max_frame_payload = frame.max_payload;
pub const max_read_payload = frame.max_read_payload;
pub const max_message = connection.max_message;
pub const max_compressed_message = connection.max_compressed_message;
pub const max_subprotocol = connection.max_subprotocol;

test {
    std.testing.refAllDecls(@This());
}
