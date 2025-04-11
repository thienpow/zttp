const std = @import("std");
const zttp = @import("zttp");
const ThreadPool = zttp.ThreadPool;

fn taskFunc(_: void, result: *ThreadPool.TaskResult) void {
    std.debug.print("TaskFunc: Running in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    result.success = true;
}

fn slowTaskFunc(_: void, result: *ThreadPool.TaskResult) void {
    std.debug.print("SlowTaskFunc: Starting in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    std.time.sleep(2 * std.time.ns_per_s); // 2s work
    std.debug.print("SlowTaskFunc: Completed in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    result.success = true;
}

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
            @intCast(10 - i),
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

test "Tasks with dependencies" {
    std.debug.print("Test: Starting dependency test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const task0_id = try pool.schedule(taskFunc, {}, null, 10, 1 * std.time.ns_per_s, 0, 0, null, null);
    std.debug.print("Test: Scheduled independent task {d}\n", .{task0_id});

    var deps1 = try allocator.alloc(u64, 1);
    deps1[0] = task0_id;
    const task1_id = try pool.schedule(taskFunc, {}, null, 8, 1 * std.time.ns_per_s, 0, 0, deps1, null);
    std.debug.print("Test: Scheduled task {d} dependent on {d}\n", .{ task1_id, task0_id });

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
    try std.testing.expect(!slow_completed);
}

var count: u32 = 0;
fn retryTaskFunc(_: void, result: *ThreadPool.TaskResult) void {
    @atomicStore(u32, &count, @atomicLoad(u32, &count, .monotonic) + 1, .monotonic);
    std.debug.print("retryTaskFunc: Attempt {d} in thread {d}\n", .{ count, std.Thread.getCurrentId() });
    result.success = count >= 3;
    result.retry = !result.success;
}

test "Task with retries" {
    std.debug.print("Test: Starting retry test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const task_id = try pool.schedule(
        retryTaskFunc,
        {},
        null,
        10,
        1 * std.time.ns_per_s,
        2,
        100 * std.time.ns_per_ms,
        null,
        null,
    );
    std.debug.print("Test: Scheduled task {d} with 2 retries\n", .{task_id});

    const completed = try pool.waitForTask(task_id, 3 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any}\n", .{ task_id, completed });
    try std.testing.expect(completed);
}

var count1: u32 = 0;
fn failRetryTaskFunc(_: void, result: *ThreadPool.TaskResult) void {
    count1 += 1;
    std.debug.print("failRetryTaskFunc: Attempt {d} in thread {d}\n", .{ count1, std.Thread.getCurrentId() });
    result.success = false;
    result.retry = true;
}

test "Task fails after retries" {
    std.debug.print("Test: Starting retry failure test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const task_id = try pool.schedule(
        failRetryTaskFunc,
        {},
        null,
        10,
        1 * std.time.ns_per_s,
        2,
        100 * std.time.ns_per_ms,
        null,
        null,
    );
    std.debug.print("Test: Scheduled task {d} with 2 retries\n", .{task_id});

    const completed = try pool.waitForTask(task_id, 3 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any} (expecting false)\n", .{ task_id, completed });
    try std.testing.expect(!completed);
}

test "Task with dependency timeout" {
    std.debug.print("Test: Starting dependency timeout test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const task0_id = try pool.schedule(
        slowTaskFunc,
        {},
        null,
        10,
        3 * std.time.ns_per_s,
        0,
        0,
        null,
        null,
    );
    std.debug.print("Test: Scheduled slow task {d}\n", .{task0_id});

    var deps = try allocator.alloc(u64, 1);
    deps[0] = task0_id;
    const task1_id = try pool.schedule(
        taskFunc,
        {},
        null,
        8,
        1 * std.time.ns_per_s,
        0,
        0,
        deps,
        100 * std.time.ns_per_ms,
    );
    std.debug.print("Test: Scheduled task {d} dependent on {d} with 100ms timeout\n", .{ task1_id, task0_id });

    const completed0 = try pool.waitForTask(task0_id, 4 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any}\n", .{ task0_id, completed0 });
    try std.testing.expect(completed0);

    const completed1 = try pool.waitForTask(task1_id, 2 * std.time.ns_per_s);
    std.debug.print("Test: Task {d} completed: {any} (expecting false due to dep timeout)\n", .{ task1_id, completed1 });
    try std.testing.expect(!completed1);
}

test "Priority queue respects order" {
    std.debug.print("Test: Starting priority queue test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 2, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(2);

    const task_ids = [_]u64{
        try pool.schedule(taskFunc, {}, null, 5, 1 * std.time.ns_per_s, 0, 0, null, null),
        try pool.schedule(taskFunc, {}, null, 10, 1 * std.time.ns_per_s, 0, 0, null, null),
        try pool.schedule(taskFunc, {}, null, 7, 1 * std.time.ns_per_s, 0, 0, null, null),
    };
    std.debug.print("Test: Scheduled tasks with priorities 5, 10, 7\n", .{});

    const completed = [_]bool{
        try pool.waitForTask(task_ids[0], 2 * std.time.ns_per_s),
        try pool.waitForTask(task_ids[1], 2 * std.time.ns_per_s),
        try pool.waitForTask(task_ids[2], 2 * std.time.ns_per_s),
    };
    for (completed, task_ids) |c, id| {
        std.debug.print("Test: Task {d} completed: {any}\n", .{ id, c });
        try std.testing.expect(c);
    }
}

test "Deinit during heavy load" {
    std.debug.print("Test: Starting deinit heavy load test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 4, .max_threads = 8 });
    defer pool.deinit();

    try pool.startWorkers(4);

    for (0..20) |i| {
        const timeout: u64 = if (i % 2 == 0) 100 * std.time.ns_per_ms else 1 * std.time.ns_per_s;
        const task_id = try pool.schedule(
            slowTaskFunc,
            {},
            null,
            10,
            timeout,
            0,
            0,
            null,
            null,
        );
        std.debug.print("Test: Scheduled task {d} with timeout {d}ms\n", .{ task_id, timeout / std.time.ns_per_ms });
    }

    std.debug.print("Test: Initiating deinit under load\n", .{});
}
