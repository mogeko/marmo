//! Rule evaluation result.

const Metadata = @import("metadata.zig").Metadata;

pub const RejectReason = enum {
    no_route,
    rule,
    unsupported_network,
};

/// The router returns a tag, not an outbound, so routing stays independent of
/// outbound construction. `route` names a configured outbound.
pub const Action = union(enum) {
    route: []const u8,
    direct,
    reject: RejectReason,
    hijack_dns,
};

pub const Router = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        match: *const fn (ctx: *anyopaque, metadata: *const Metadata) Action,
    };

    /// `match` is allocation-free and safe for concurrent reads; the router is
    /// immutable after construction.
    pub fn match(self: Router, metadata: *const Metadata) Action {
        return self.vtable.match(self.ctx, metadata);
    }
};
