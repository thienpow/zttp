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

    // Route generator tool (built but not run here)
    // const routegen = b.addExecutable(.{
    //     .name = "routegen",
    //     .root_source_file = b.path("tools/routegen.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    // b.installArtifact(routegen); // Installs to zig-out/bin/routegen

    // Example: Hello World server
    const hello_exe = b.addExecutable(.{
        .name = "hello",
        .root_source_file = b.path("examples/hello.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Remove the & operator here:
    hello_exe.root_module.addImport("zttp", lib.root_module);

    b.installArtifact(hello_exe);

    const run_hello = b.addRunArtifact(hello_exe);
    run_hello.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_hello.addArgs(args);
    const run_hello_step = b.step("run-hello", "Run the Hello World example");
    run_hello_step.dependOn(&run_hello.step);

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
