// build.zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Export zttp module for dependencies
    const zttp_module = b.addModule("zttp", .{
        .root_source_file = b.path("src/zttp.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Routegen executable
    const routegen = b.addExecutable(.{
        .name = "routegen",
        .root_source_file = b.path("tools/routegen.zig"),
        .target = target,
        .optimize = optimize,
    });
    routegen.root_module.addImport("zttp", zttp_module);

    // Install routegen as an artifact
    const install_routegen = b.addInstallArtifact(routegen, .{
        .dest_dir = .{ .override = .bin },
    });
    const routegen_step = b.step("routegen", "Build routegen tool");
    routegen_step.dependOn(&install_routegen.step);

    // Define the zttp library
    const lib = b.addStaticLibrary(.{
        .name = "zttp",
        .root_source_file = b.path("src/zttp.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.step.dependOn(routegen_step);

    b.installArtifact(lib);

    // Ensure routegen is installed for dependencies
    b.getInstallStep().dependOn(&install_routegen.step);

    // Tests
    const test_step = b.step("test", "Run library tests");
    const tests = b.addTest(.{
        .root_source_file = b.path("tests/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.root_module.addImport("zttp", zttp_module);

    const run_tests = b.addRunArtifact(tests);
    test_step.dependOn(&run_tests.step);
}
