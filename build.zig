const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Define the zttp library
    const lib = b.addStaticLibrary(.{
        .name = "zttp",
        .root_source_file = b.path("src/zttp.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Export zttp module for dependencies
    _ = b.addModule("zttp", .{
        .root_source_file = b.path("src/zttp.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Tests
    const test_step = b.step("test", "Run library tests");
    // Create a test step
    const tests = b.addTest(.{
        .root_source_file = b.path("tests/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.root_module.addImport("zttp", lib.root_module);
    const run_tests = b.addRunArtifact(tests);
    test_step.dependOn(&run_tests.step);
}
