const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const http2 = b.addModule("http2", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{ .root_module = http2 });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run HTTP/2 package tests");
    test_step.dependOn(&run_tests.step);
}
