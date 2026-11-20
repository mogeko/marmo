//! HTTP/2 transport package.
//!
//! Implements bounded HTTP/2 multiplexing, framing, HPACK, SETTINGS, flow
//! control, 1xx responses, and trailers for proxy and gRPC-style transports.
//! It imports only `std` and operates on `std.Io.Reader`/`Writer`.

const std = @import("std");

pub const frame = @import("frame.zig");
pub const hpack = @import("hpack.zig");
pub const connection = @import("connection.zig");
pub const Connection = connection.Connection;
pub const Stream = connection.Stream;
pub const Client = connection.Client;
pub const Server = connection.Server;
pub const Header = connection.Header;
pub const Error = connection.Error;
pub const max_frame_size = frame.max_frame_size;
pub const max_header_block = connection.max_header_block;

test {
    std.testing.refAllDecls(@This());
}
