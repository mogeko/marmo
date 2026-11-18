const std = @import("std");
const marmo = @import("marmo");

test "public API exposes endpoint and metadata" {
    const endpoint = try marmo.Endpoint.parse("example.com:443");
    try std.testing.expectEqual(@as(u16, 443), endpoint.port());

    const metadata: marmo.Metadata = .{
        .network = .tcp,
        .source = endpoint,
        .destination = endpoint,
        .inbound = "test",
    };
    try std.testing.expect(metadata.domain == null);
}

test "public API exposes routing actions" {
    const action: marmo.Action = .direct;
    switch (action) {
        .direct => {},
        else => return error.TestUnexpectedResult,
    }
}

test "public API exposes fixed relay limits" {
    try std.testing.expect(marmo.limits.relay_buffer_size_default > 0);
    try std.testing.expect(
        marmo.limits.relay_buffer_size_default <= marmo.limits.relay_buffer_size_max,
    );
}

test "public API parses JSON config" {
    var parsed = try marmo.Config.parseJson(std.testing.allocator,
        \\{ "route": { "final": "direct" } }
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings("direct", parsed.config().route.final);
}
