const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Executable
    const exe = b.addExecutable(.{
        .name = "example",
        .root_source_file = b.path("src/hello.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add zttp dependency
    const zttp_dep = b.dependency("zttp", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("zttp", zttp_dep.module("zttp"));

    // Install artifact
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the example");
    run_step.dependOn(&run_cmd.step);
}
