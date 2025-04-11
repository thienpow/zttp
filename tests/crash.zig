const std = @import("std");
const zttp = @import("zttp");
const ThreadPool = zttp.ThreadPool;

fn crashTaskFunc(_: void, _: *ThreadPool.TaskResult) void {
    @panic("Intentional task crash");
}

test "Task crash resilience" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 4 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const task_id = try pool.schedule(crashTaskFunc, {}, null, 10, 1 * std.time.ns_per_s, 0, 0, null, null);
    std.debug.print("Test: Scheduled crashing task {d}\n", .{task_id});

    const completed = try pool.waitForTask(task_id, 2 * std.time.ns_per_s);
    try std.testing.expect(!completed); // Should fail due to crash
    try std.testing.expect(pool.active_threads.load(.monotonic) > 0); // Threads still alive
}
