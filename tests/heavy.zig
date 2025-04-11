const std = @import("std");
const zttp = @import("zttp");
const ThreadPool = zttp.ThreadPool;

fn slowTaskFunc(_: void, result: *ThreadPool.TaskResult) void {
    std.debug.print("SlowTaskFunc: Starting in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    std.time.sleep(2 * std.time.ns_per_s); // 2s work
    std.debug.print("SlowTaskFunc: Completed in thread {d} at {d} ns\n", .{ std.Thread.getCurrentId(), std.time.nanoTimestamp() });
    result.success = true;
}

test "Deinit during heavy load" {
    std.debug.print("Test: Starting deinit heavy load test at {d} ns\n", .{std.time.nanoTimestamp()});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = try ThreadPool.init(allocator, .{ .min_threads = 4, .max_threads = 8 });

    try pool.startWorkers(4);

    var task_ids: [20]u64 = undefined;
    for (0..20) |i| {
        const timeout: u64 = if (i % 2 == 0) 100 * std.time.ns_per_ms else 1 * std.time.ns_per_s;
        task_ids[i] = try pool.schedule(
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
        std.debug.print("Test: Scheduled task {d} with timeout {d}ms\n", .{ task_ids[i], timeout / std.time.ns_per_ms });
    }

    std.debug.print("Test: Initiating deinit under load\n", .{});
    pool.running.store(false, .monotonic); // Signal shutdown early to interrupt tasks
    pool.cond.broadcast();

    // Wait for threads to finish processing
    while (pool.active_threads.load(.monotonic) > 0) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    // Check task statuses before final cleanup
    pool.mutex.lock();
    defer pool.mutex.unlock();
    for (task_ids) |task_id| { // Removed ', 0..' and 'i'
        const status = pool.all_tasks.get(task_id) orelse .Failed;
        std.debug.print("Test: Task {d} final status: {s}\n", .{ task_id, @tagName(status) });
        try std.testing.expect(status == .Failed);
    }

    // Manually complete deinit
    for (pool.threads[0..pool.spawned_threads]) |thread| {
        std.debug.print("ThreadPool.deinit: Joining thread {d}\n", .{thread.getHandle()});
        thread.join();
    }

    while (pool.tasks.count() > 0) {
        const task = pool.tasks.remove();
        std.debug.print("ThreadPool.deinit: Cleaning task {d}, ptr: {*}\n", .{ task.id, task });
        pool.all_tasks.put(task.id, .Failed) catch |err| {
            std.debug.print("ThreadPool.deinit: Failed to update task {d} status: {}\n", .{ task.id, err });
        };
        task.deinit(pool.allocator);
    }

    var pending_it = pool.pending_tasks.iterator();
    while (pending_it.next()) |entry| {
        const task = entry.value_ptr.*;
        std.debug.print("ThreadPool.deinit: Cleaning pending task {d}, ptr: {*}\n", .{ entry.key_ptr.*, task });
        pool.all_tasks.put(entry.key_ptr.*, .Failed) catch |err| {
            std.debug.print("ThreadPool.deinit: Failed to update pending task {d} status: {}\n", .{ entry.key_ptr.*, err });
        };
        task.deinit(pool.allocator);
    }

    pool.pending_tasks.deinit();
    pool.all_tasks.deinit();
    pool.tasks.deinit();
    pool.allocator.free(pool.threads);

    std.debug.print("ThreadPool.deinit() completed at {d} ns\n", .{std.time.nanoTimestamp()});
}
