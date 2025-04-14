const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get zttp dependency
    const zttp_dep = b.dependency("zttp", .{
        .target = target,
        .optimize = optimize,
    });

    // Get the routegen tool
    const routegen = zttp_dep.artifact("routegen");

    // Create the routegen step
    const routegen_step = b.step("routegen", "Generate routes");

    // Create a run command for routegen (note the proper dependency)
    const run_routegen = b.addRunArtifact(routegen);
    run_routegen.addArg("src/routes/"); // Input routes directory
    run_routegen.addArg("src/generated_routes.zig"); // Output file

    routegen_step.dependOn(&run_routegen.step);

    // Executable
    const exe = b.addExecutable(.{
        .name = "example",
        .root_source_file = b.path("src/hello.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("zttp", zttp_dep.module("zttp"));
    exe.step.dependOn(routegen_step); // Ensure routes are generated

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
