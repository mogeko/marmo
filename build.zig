const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const tls13 = b.dependency("tls13", .{
        .target = target,
        .optimize = optimize,
    });

    const marmo = b.addModule("marmo", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "tls13", .module = tls13.module("tls13") },
        },
    });

    const unit_tests = b.addTest(.{ .root_module = marmo });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const public_api = b.createModule(.{
        .root_source_file = b.path("tests/public_api.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "marmo", .module = marmo },
        },
    });
    const public_api_tests = b.addTest(.{ .root_module = public_api });
    const run_public_api_tests = b.addRunArtifact(public_api_tests);

    const integration = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "marmo", .module = marmo },
            .{ .name = "tls13", .module = tls13.module("tls13") },
        },
    });
    const integration_tests = b.addTest(.{ .root_module = integration });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run unit, public API, and integration tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_public_api_tests.step);
    test_step.dependOn(&run_integration_tests.step);
}
