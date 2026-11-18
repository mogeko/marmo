//! Fixed limits used by the relay and session layers.

const std = @import("std");

pub const relay_buffer_size_default: usize = 32 * 1024;
pub const relay_buffer_size_max: usize = 1024 * 1024;

comptime {
    std.debug.assert(relay_buffer_size_default > 0);
    std.debug.assert(relay_buffer_size_default <= relay_buffer_size_max);
}
