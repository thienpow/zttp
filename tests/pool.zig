const std = @import("std");
const zttp = @import("zttp");
const ThreadPool = zttp.ThreadPool;

fn taskFunc(_: void, result: *ThreadPool.TaskResult) void {
    std.debug.print("TaskFunc: Running in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    result.success = true;
}

fn slowTaskFunc(_: void, result: *ThreadPool.TaskResult) void {
    std.debug.print("SlowTaskFunc: Starting in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    std.time.sleep(500 * std.time.ns_per_ms); // Simulate 500ms work
    std.debug.print("SlowTaskFunc: Completed in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    result.success = true;
}

// Test 1: Basic single task (original test)
test "Single task completes" {
    std.debug.print("Test: Starting single task test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const task_id = try pool.schedule(taskFunc, {}, null, 10, 1 * std.time.ns_per_s, 0, 0, null, null);
    std.debug.print("Test: Scheduled task {d}\n", .{task_id});

    const completed = try pool.waitForTask(task_id, 2 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any}\n", .{ task_id, completed });
    try std.testing.expect(completed);
}

// Test 2: Multiple independent tasks
test "Multiple independent tasks" {
    std.debug.print("Test: Starting multiple tasks test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const num_tasks = 4;
    var task_ids: [num_tasks]u64 = undefined;
    for (0..num_tasks) |i| {
        task_ids[i] = try pool.schedule(
            taskFunc,
            {},
            null,
            @intCast(10 - i), // Higher index = lower priority
            1 * std.time.ns_per_s,
            0,
            0,
            null,
            null,
        );
        std.debug.print("Test: Scheduled task {d} with priority {d}\n", .{ task_ids[i], 10 - i });
    }

    for (task_ids) |task_id| {
        const completed = try pool.waitForTask(task_id, 2 * std.time.ns_per_s);
        std.debug.print("Test: Task {d} completed: {any}\n", .{ task_id, completed });
        try std.testing.expect(completed);
    }
}

// Test 3: Tasks with dependencies
test "Tasks with dependencies" {
    std.debug.print("Test: Starting dependency test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    // Task 0: Independent
    const task0_id = try pool.schedule(taskFunc, {}, null, 10, 1 * std.time.ns_per_s, 0, 0, null, null);
    std.debug.print("Test: Scheduled independent task {d}\n", .{task0_id});

    // Task 1: Depends on Task 0
    var deps1 = try allocator.alloc(u64, 1);
    deps1[0] = task0_id;
    const task1_id = try pool.schedule(taskFunc, {}, null, 8, 1 * std.time.ns_per_s, 0, 0, deps1, null);
    std.debug.print("Test: Scheduled task {d} dependent on {d}\n", .{ task1_id, task0_id });

    // Task 2: Depends on Task 0 and Task 1
    var deps2 = try allocator.alloc(u64, 2);
    deps2[0] = task0_id;
    deps2[1] = task1_id;
    const task2_id = try pool.schedule(taskFunc, {}, null, 6, 1 * std.time.ns_per_s, 0, 0, deps2, null);
    std.debug.print("Test: Scheduled task {d} dependent on {d} and {d}\n", .{ task2_id, task0_id, task1_id });

    const completed0 = try pool.waitForTask(task0_id, 2 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any}\n", .{ task0_id, completed0 });
    try std.testing.expect(completed0);

    const completed1 = try pool.waitForTask(task1_id, 2 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any}\n", .{ task1_id, completed1 });
    try std.testing.expect(completed1);

    const completed2 = try pool.waitForTask(task2_id, 2 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any}\n", .{ task2_id, completed2 });
    try std.testing.expect(completed2);
}

// Test 4: Task with timeout
test "Task with timeout" {
    std.debug.print("Test: Starting timeout test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const fast_task_id = try pool.schedule(taskFunc, {}, null, 10, 1 * std.time.ns_per_s, 0, 0, null, null);
    std.debug.print("Test: Scheduled fast task {d}\n", .{fast_task_id});

    const slow_task_id = try pool.schedule(slowTaskFunc, {}, null, 5, 100 * std.time.ns_per_ms, 0, 0, null, null);
    std.debug.print("Test: Scheduled slow task {d} with 100ms timeout\n", .{slow_task_id});

    const fast_completed = try pool.waitForTask(fast_task_id, 2 * std.time.ns_per_s);
    std.debug.print("Test: Fast task {d} completed: {any}\n", .{ fast_task_id, fast_completed });
    try std.testing.expect(fast_completed);

    const slow_completed = try pool.waitForTask(slow_task_id, 2 * std.time.ns_per_s);
    std.debug.print("Test: Slow task {d} completed: {any} (expecting false due to timeout)\n", .{ slow_task_id, slow_completed });
    try std.testing.expect(!slow_completed); // Now works with false
}
