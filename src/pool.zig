// src/pool.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

/// ThreadPool implements a basic task scheduling system with worker threads.
pub const ThreadPool = struct {
    allocator: std.mem.Allocator,
    threads: []std.Thread,
    tasks: std.PriorityQueue(*Task, void, compareTaskPriority),
    running: std.atomic.Value(bool),
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    min_threads: usize,
    max_threads: usize,
    max_tasks: usize,
    active_threads: std.atomic.Value(usize),
    spawned_threads: usize, // Tracks number of spawned threads
    next_task_id: std.atomic.Value(u64),
    all_tasks: std.AutoHashMap(u64, TaskStatus),
    pending_tasks: std.AutoHashMap(u64, *Task),
    options: Options,

    /// Options for configuring the ThreadPool
    pub const Options = struct {
        min_threads: usize = 2,
        max_threads: usize = 8,
        max_tasks: usize = 100,
        shutdown_timeout_ns: u64 = 5 * std.time.ns_per_s,
        affinity_map: ?[]const usize = null,
        adaptive_scaling: bool = true,
        scaling_interval_ns: u64 = 1 * std.time.ns_per_s,
    };

    /// Represents the current status of a task in the system
    const TaskStatus = enum {
        Pending,
        Running,
        Completed,
        Failed,
    };

    /// Task represents a unit of work that can be scheduled on the thread pool
    pub const Task = struct {
        func: *const fn (*anyopaque, *TaskResult) void,
        arg: *anyopaque,
        completed: std.atomic.Value(bool),
        result: ?*anyopaque,
        arg_deinit: ?*const fn (*anyopaque) void,
        ctx_destroy: *const fn (std.mem.Allocator, *anyopaque) void,
        priority: u8,
        id: u64,
        timeout_ns: ?u64,
        queued_at: i64,
        retries: u8,
        max_retries: u8,
        retry_delay_ns: u64,
        dependencies: ?[]u64,
        dep_timeout_ns: ?u64,

        fn create(
            allocator: std.mem.Allocator,
            comptime FuncType: anytype,
            arg_val: anytype,
            result_ptr: ?*anyopaque,
            priority_val: u8,
            id_val: u64,
            timeout_ns_val: ?u64,
            max_retries_val: u8,
            retry_delay_ns_val: u64,
            dependencies_val: ?[]u64,
            dep_timeout_ns_val: ?u64,
        ) !*Task {
            const ArgType = @TypeOf(arg_val);
            const Context = struct {
                f: *const fn (ArgType, *TaskResult) void,
                a: ArgType,

                fn run(ctx_opaque: *anyopaque, res: *TaskResult) void {
                    const self = @as(*@This(), @ptrCast(@alignCast(ctx_opaque)));
                    self.f(self.a, res);
                }

                fn deinitArg(ctx_opaque: *anyopaque) void {
                    const self = @as(*@This(), @ptrCast(@alignCast(ctx_opaque)));
                    if (@typeInfo(ArgType) == .@"struct") {
                        if (@hasDecl(ArgType, "deinit")) {
                            self.a.deinit();
                        }
                    }
                }

                fn destroy(alloc: std.mem.Allocator, ctx_opaque: *anyopaque) void {
                    const self = @as(*@This(), @ptrCast(@alignCast(ctx_opaque)));
                    alloc.destroy(self);
                }
            };

            const ctx = try allocator.create(Context);
            //std.debug.print("Task.create: Allocated ctx at {*}\n", .{ctx});
            ctx.* = .{ .f = FuncType, .a = arg_val };

            const task = try allocator.create(Task);
            //std.debug.print("Task.create: Allocated task at {*}, id: {d}\n", .{ task, id_val });
            task.* = .{
                .func = Context.run,
                .arg = ctx,
                .completed = std.atomic.Value(bool).init(false),
                .result = result_ptr,
                .arg_deinit = Context.deinitArg,
                .ctx_destroy = Context.destroy,
                .priority = priority_val,
                .id = id_val,
                .timeout_ns = timeout_ns_val,
                .queued_at = @as(i64, @intCast(std.time.nanoTimestamp())),
                .retries = max_retries_val,
                .max_retries = max_retries_val,
                .retry_delay_ns = retry_delay_ns_val,
                .dependencies = dependencies_val,
                .dep_timeout_ns = dep_timeout_ns_val,
            };
            return task;
        }

        pub fn deinit(self: *Task, allocator: std.mem.Allocator) void {
            if (self.arg_deinit) |arg_deinit_fn| {
                arg_deinit_fn(self.arg);
            }
            self.ctx_destroy(allocator, self.arg);
            if (self.dependencies) |deps| {
                allocator.free(deps);
            }
            allocator.destroy(self);
        }
    };

    /// TaskResult is returned by task execution functions to indicate success/failure
    pub const TaskResult = struct {
        success: bool = false,
        retry: bool = false,
        payload: ?*anyopaque = null,
        payload_size: usize = 0,

        pub fn copyPayloadTo(self: *TaskResult, dest: *anyopaque, size: usize) bool {
            if (self.payload == null or self.payload_size == 0) return false;
            if (size < self.payload_size) return false;

            const dest_ptr: [*]u8 = @ptrCast(dest);
            const src_ptr: [*]u8 = @ptrCast(self.payload.?);

            var i: usize = 0;
            while (i < self.payload_size) : (i += 1) {
                dest_ptr[i] = src_ptr[i];
            }

            return true;
        }
    };

    /// Error set for ThreadPool operations
    pub const Error = error{
        PoolClosed,
        QueueFull,
        TaskNotFound,
        TaskNotCancellable,
        TaskAlreadyFinished,
        InvalidConfiguration,
        OutOfMemory,
        SystemLimitReached,
    };

    fn compareTaskPriority(_: void, a: *ThreadPool.Task, b: *ThreadPool.Task) std.math.Order {
        return std.math.order(b.priority, a.priority);
    }

    /// Initialize a new thread pool without starting threads
    pub fn init(allocator: Allocator, options: Options) !ThreadPool {
        //std.debug.print("ThreadPool.init: Starting at {d} ns\n", .{std.time.nanoTimestamp()});
        const threads = try allocator.alloc(std.Thread, options.max_threads);
        const tasks = std.PriorityQueue(*Task, void, compareTaskPriority).init(allocator, {});
        const all_tasks = std.AutoHashMap(u64, TaskStatus).init(allocator);
        const pending_tasks = std.AutoHashMap(u64, *Task).init(allocator);
        return ThreadPool{
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(true),
            .threads = threads,
            .tasks = tasks,
            .all_tasks = all_tasks,
            .pending_tasks = pending_tasks,
            .mutex = std.Thread.Mutex{},
            .cond = std.Thread.Condition{},
            .min_threads = options.min_threads,
            .max_threads = options.max_threads,
            .max_tasks = options.max_tasks,
            .active_threads = std.atomic.Value(usize).init(0),
            .spawned_threads = 0,
            .next_task_id = std.atomic.Value(u64).init(0),
            .options = options,
        };
    }

    /// Start worker threads after initialization
    pub fn startWorkers(self: *ThreadPool, num_threads: usize) !void {
        //std.debug.print("ThreadPool.startWorkers: Starting {d} threads\n", .{num_threads});
        const count = @min(num_threads, self.max_threads);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            //std.debug.print("ThreadPool.startWorkers: Spawning thread {d}/{d}\n", .{ i + 1, count });
            const thread = try std.Thread.spawn(.{}, workerLoop, .{self});
            self.threads[i] = thread;
        }
        self.spawned_threads = count;
        //std.debug.print("ThreadPool.startWorkers: Completed\n", .{});
    }

    /// Clean up all resources associated with the thread pool
    pub fn deinit(self: *ThreadPool) void {
        //std.debug.print("ThreadPool.deinit() started at {d} ns\n", .{std.time.nanoTimestamp()});

        self.running.store(false, .monotonic);
        self.cond.broadcast();

        while (self.active_threads.load(.monotonic) > 0) {
            //std.debug.print("ThreadPool.deinit: Waiting for {d} active threads\n", .{self.active_threads.load(.monotonic)});
            std.time.sleep(10 * std.time.ns_per_ms);
        }

        for (self.threads[0..self.spawned_threads]) |thread| {
            //std.debug.print("ThreadPool.deinit: Joining thread {d}\n", .{thread.getHandle()});
            thread.join();
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.tasks.count() > 0) {
            const task = self.tasks.remove();
            //std.debug.print("ThreadPool.deinit: Cleaning task {d}, ptr: {*}\n", .{ task.id, task });
            self.all_tasks.put(task.id, .Failed) catch |err| {
                std.debug.print("ThreadPool.deinit: Failed to update task {d} status: {}\n", .{ task.id, err });
            };
            task.deinit(self.allocator);
        }

        var pending_it = self.pending_tasks.iterator();
        while (pending_it.next()) |entry| {
            const task = entry.value_ptr.*;
            //std.debug.print("ThreadPool.deinit: Cleaning pending task {d}, ptr: {*}\n", .{ entry.key_ptr.*, task });
            self.all_tasks.put(entry.key_ptr.*, .Failed) catch |err| {
                std.debug.print("ThreadPool.deinit: Failed to update pending task {d} status: {}\n", .{ entry.key_ptr.*, err });
            };
            task.deinit(self.allocator);
        }

        self.pending_tasks.deinit();
        self.all_tasks.deinit();
        self.tasks.deinit();
        self.allocator.free(self.threads);

        //std.debug.print("ThreadPool.deinit() completed at {d} ns\n", .{std.time.nanoTimestamp()});
    }

    /// Check if all dependencies for a task have been met
    fn areDependenciesMetLocked(self: *ThreadPool, dependencies: []const u64) bool {
        for (dependencies) |dep_id| {
            if (self.all_tasks.get(dep_id)) |status| {
                if (status != .Completed) return false;
            } else {
                return false;
            }
        }
        return true;
    }

    /// Process tasks whose dependencies are now met
    fn checkDependentsLocked(self: *ThreadPool, completed_task_id: u64) void {
        _ = completed_task_id;

        var dependents_to_move = std.ArrayList(*ThreadPool.Task).init(self.allocator);
        defer dependents_to_move.deinit();

        var tasks_to_fail = std.ArrayList(u64).init(self.allocator);
        defer tasks_to_fail.deinit();

        const now = std.time.nanoTimestamp();
        var it = self.pending_tasks.iterator();
        while (it.next()) |entry| {
            const task = entry.value_ptr.*;
            if (task.dep_timeout_ns) |dep_timeout| {
                if (now - task.queued_at > dep_timeout) {
                    std.debug.print("checkDependentsLocked: Task {d} dependency timeout expired (elapsed: {d} ns, timeout: {d} ns)\n", .{
                        task.id, now - task.queued_at, dep_timeout,
                    });
                    tasks_to_fail.append(task.id) catch {
                        std.debug.print("checkDependentsLocked: Failed to append task {d} to fail list\n", .{task.id});
                    };
                    continue;
                }
            }
            if (task.dependencies) |deps| {
                if (self.areDependenciesMetLocked(deps)) {
                    dependents_to_move.append(task) catch {
                        std.debug.print("checkDependentsLocked: Failed to append task {d} to dependents list\n", .{task.id});
                    };
                }
            } else {
                dependents_to_move.append(task) catch {
                    std.debug.print("checkDependentsLocked: Failed to append task {d} to dependents list (no deps)\n", .{task.id});
                };
            }
        }

        for (tasks_to_fail.items) |task_id| {
            if (self.pending_tasks.getPtr(task_id)) |task_ptr| {
                const task = task_ptr.*;
                _ = self.pending_tasks.remove(task_id);
                self.all_tasks.put(task_id, .Failed) catch {
                    std.debug.print("checkDependentsLocked: Failed to update status for task {d}\n", .{task_id});
                };
                std.debug.print("checkDependentsLocked: Task {d} marked as Failed, ptr: {*}\n", .{ task_id, task });
                task.deinit(self.allocator); // Free the task here
            }
        }

        for (dependents_to_move.items) |task| {
            if (self.pending_tasks.remove(task.id)) {
                self.tasks.add(task) catch |err| {
                    std.debug.print("checkDependentsLocked: Failed to add task {d} to tasks: {}\n", .{ task.id, err });
                    _ = self.all_tasks.put(task.id, .Failed) catch {};
                    task.deinit(self.allocator);
                    continue;
                };
                self.cond.signal();
                std.debug.print("checkDependentsLocked: Task {d} dependencies met, moved to tasks\n", .{task.id});
            }
        }
    }

    /// Schedule a task for execution
    pub fn schedule(
        self: *ThreadPool,
        comptime func: anytype,
        arg: anytype,
        result: ?*anyopaque,
        priority: u8,
        timeout_ns: ?u64,
        max_retries: u8,
        retry_delay_ns: u64,
        dependencies: ?[]u64,
        dep_timeout_ns: ?u64,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        //std.debug.print("Schedule called. Pool running: {}\n", .{self.running.load(.monotonic)});

        if (!self.running.load(.monotonic)) {
            if (dependencies) |deps| self.allocator.free(deps);
            return Error.PoolClosed;
        }

        if (self.tasks.count() + self.pending_tasks.count() >= self.max_tasks) {
            if (dependencies) |deps| self.allocator.free(deps);
            return Error.QueueFull;
        }

        const task_id = self.next_task_id.fetchAdd(1, .monotonic);
        const task = try Task.create(
            self.allocator,
            func,
            arg,
            result,
            priority,
            task_id,
            timeout_ns,
            max_retries,
            retry_delay_ns,
            dependencies,
            dep_timeout_ns,
        );
        errdefer {
            if (dependencies) |deps| self.allocator.free(deps);
            task.deinit(self.allocator);
        }

        if (task.dependencies != null and task.dependencies.?.len > 0) {
            try self.all_tasks.put(task_id, .Pending);
            if (self.areDependenciesMetLocked(task.dependencies.?)) {
                try self.all_tasks.put(task_id, .Running);
                try self.tasks.add(task);
                //std.debug.print("Schedule: Task {d} dependencies met, added to tasks\n", .{task_id});
                self.cond.signal();
            } else {
                try self.pending_tasks.put(task_id, task);
                //std.debug.print("Schedule: Task {d} pending with dependencies\n", .{task_id});
            }
        } else {
            try self.all_tasks.put(task_id, .Running);
            try self.tasks.add(task);
            //std.debug.print("Schedule: Task {d} added to tasks\n", .{task_id});
            self.cond.signal();
        }

        return task_id;
    }

    /// Get the current status of a task
    pub fn getTaskStatus(self: *ThreadPool, task_id: u64) ?TaskStatus {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.all_tasks.get(task_id);
    }

    /// Wait for a task to complete with a timeout
    pub fn waitForTask(self: *ThreadPool, task_id: u64, timeout_ns: ?u64) !bool {
        const start = std.time.nanoTimestamp();

        while (self.running.load(.monotonic)) {
            self.mutex.lock();
            const status_opt = self.all_tasks.get(task_id);
            self.mutex.unlock();

            if (status_opt) |status| {
                return switch (status) {
                    .Completed => true,
                    .Failed => false,
                    .Running, .Pending => {
                        if (timeout_ns) |timeout| {
                            if (std.time.nanoTimestamp() - start > timeout) {
                                return false;
                            }
                        }
                        std.time.sleep(10 * std.time.ns_per_ms);
                        continue;
                    },
                };
            } else {
                return error.TaskNotFound;
            }
        }
        return false;
    }

    /// Cancel a task by ID
    pub fn cancel(self: *ThreadPool, task_id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.pending_tasks.getPtr(task_id)) |task_ptr| {
            const task = task_ptr.*;
            _ = self.pending_tasks.remove(task_id);
            try self.all_tasks.put(task_id, .Failed);
            task.deinit(self.allocator);
            return;
        }

        if (self.all_tasks.get(task_id)) |status| {
            switch (status) {
                .Completed, .Failed => return Error.TaskAlreadyFinished,
                .Running => return Error.TaskNotCancellable,
                .Pending => unreachable,
            }
        }

        return Error.TaskNotFound;
    }

    /// Cancel all child tasks - stub implementation
    pub fn cancelChildren(self: *ThreadPool, parent_task_id: u64) !usize {
        _ = self;
        _ = parent_task_id;
        return 0;
    }

    /// Worker thread loop that processes tasks
    fn workerLoop(self: *ThreadPool) void {
        _ = self.active_threads.fetchAdd(1, .monotonic);
        defer _ = self.active_threads.fetchSub(1, .monotonic);

        const thread_id = std.Thread.getCurrentId();
        //std.debug.print("workerLoop: Started thread {d}, running: {any}\n", .{ thread_id, self.running.load(.monotonic) });

        while (true) {
            self.mutex.lock();
            const is_running = self.running.load(.monotonic);
            //std.debug.print("workerLoop: Thread {d} locked mutex, running: {any}, tasks len: {d}\n", .{ thread_id, is_running, self.tasks.count() });

            if (!is_running and self.tasks.count() == 0) {
                //std.debug.print("workerLoop: Thread {d} shutting down (not running, no tasks)\n", .{thread_id});
                self.mutex.unlock();
                break;
            }

            var tasks_to_fail = std.ArrayList(u64).init(self.allocator);
            defer tasks_to_fail.deinit();
            var pending_it = self.pending_tasks.iterator();
            const now = std.time.nanoTimestamp();
            while (pending_it.next()) |entry| {
                const task_id = entry.key_ptr.*;
                const task = entry.value_ptr.*;
                if (task.dep_timeout_ns) |dep_timeout| {
                    if (now - task.queued_at > dep_timeout) {
                        //std.debug.print("workerLoop: Thread {d} task {d} dependency timeout expired (elapsed: {d} ns, timeout: {d} ns)\n", .{ thread_id, task_id, now - task.queued_at, dep_timeout });
                        tasks_to_fail.append(task_id) catch {
                            std.debug.print("workerLoop: Thread {d} failed to append task {d} to fail list\n", .{ thread_id, task_id });
                        };
                    }
                }
            }

            for (tasks_to_fail.items) |task_id| {
                if (self.pending_tasks.getPtr(task_id)) |task_ptr| {
                    const task = task_ptr.*;
                    _ = self.pending_tasks.remove(task_id);
                    self.all_tasks.put(task_id, .Failed) catch {
                        std.debug.print("workerLoop: Thread {d} failed to update status for task {d}\n", .{ thread_id, task_id });
                    };
                    //std.debug.print("workerLoop: Thread {d} marked task {d} as Failed, ptr: {*}\n", .{ thread_id, task_id, task });
                    task.deinit(self.allocator); // Free the task here
                }
            }

            var current_task: ?*ThreadPool.Task = null;
            if (self.tasks.count() > 0 and self.tasks.count() <= self.max_tasks) {
                //std.debug.print("workerLoop: Thread {d} found {d} tasks\n", .{ thread_id, self.tasks.count() });
                const peeked_task = self.tasks.peek();
                if (peeked_task) |task| {
                    if (task.id > 1_000_000_000) {
                        //std.debug.print("workerLoop: Thread {d} removing invalid task id {d}\n", .{ thread_id, task.id });
                        current_task = self.tasks.remove();
                        _ = self.all_tasks.put(current_task.?.id, .Failed) catch {};
                        current_task.?.deinit(self.allocator);
                    } else if (task.timeout_ns) |timeout| {
                        if (now - task.queued_at > timeout) {
                            //std.debug.print("workerLoop: Thread {d} marking task {d} as timed out\n", .{ thread_id, task.id });
                            current_task = self.tasks.remove();
                            _ = self.all_tasks.put(current_task.?.id, .Failed) catch {};
                        } else {
                            current_task = self.tasks.remove();
                            //std.debug.print("workerLoop: Thread {d} selected task {d} with priority {d}\n", .{ thread_id, current_task.?.id, current_task.?.priority });
                        }
                    } else {
                        current_task = self.tasks.remove();
                        //std.debug.print("workerLoop: Thread {d} selected task {d} with priority {d}\n", .{ thread_id, current_task.?.id, current_task.?.priority });
                    }
                }
            } else if (self.tasks.count() > self.max_tasks) {
                //std.debug.print("workerLoop: Thread {d} invalid task count {d}, resetting\n", .{ thread_id, self.tasks.count() });
                while (self.tasks.count() > 0) {
                    const task = self.tasks.remove();
                    _ = self.all_tasks.put(task.id, .Failed) catch {};
                    task.deinit(self.allocator);
                }
            }

            if (current_task) |task| {
                //std.debug.print("workerLoop: Thread {d} unlocking mutex for task {d}\n", .{ thread_id, task.id });
                self.mutex.unlock();

                var result = ThreadPool.TaskResult{};
                const start_time = std.time.nanoTimestamp();
                //std.debug.print("workerLoop: Thread {d} executing task {d}\n", .{ thread_id, task.id });
                task.func(task.arg, &result);
                const end_time = std.time.nanoTimestamp();
                //std.debug.print("workerLoop: Thread {d} task {d} executed, success: {any}, retry: {any}\n", .{ thread_id, task.id, result.success, result.retry });

                self.mutex.lock();
                task.completed.store(true, .monotonic);
                const elapsed = end_time - start_time;
                var status: ThreadPool.TaskStatus = undefined;

                if (result.retry and task.retries > 0) {
                    task.retries -= 1;
                    task.completed.store(false, .monotonic);
                    task.queued_at = @as(i64, @intCast(std.time.nanoTimestamp()));
                    //std.debug.print("workerLoop: Thread {d} task {d} retry requested, retries left: {d}\n", .{ thread_id, task.id, task.retries });
                    if (task.retry_delay_ns > 0) {
                        self.mutex.unlock();
                        std.time.sleep(task.retry_delay_ns);
                        self.mutex.lock();
                    }
                    self.tasks.add(task) catch {
                        std.debug.print("workerLoop: Thread {d} task {d} failed to requeue (OutOfMemory), marking as Failed\n", .{ thread_id, task.id });
                        status = .Failed;
                        self.all_tasks.put(task.id, status) catch {};
                        self.checkDependentsLocked(task.id);
                        task.deinit(self.allocator);
                        self.mutex.unlock();
                        return;
                    };
                    self.all_tasks.put(task.id, .Running) catch {
                        std.debug.print("workerLoop: Thread {d} task {d} failed to update status (OutOfMemory), marking as Failed\n", .{ thread_id, task.id });
                        if (self.tasks.count() > 0) {
                            const removed_task = self.tasks.remove();
                            removed_task.deinit(self.allocator);
                        }
                        status = .Failed;
                        self.all_tasks.put(task.id, status) catch {};
                        self.checkDependentsLocked(task.id);
                        task.deinit(self.allocator);
                        self.mutex.unlock();
                        return;
                    };
                    self.cond.signal();
                    //std.debug.print("workerLoop: Thread {d} task {d} requeued for retry\n", .{ thread_id, task.id });
                } else {
                    status = if (self.all_tasks.get(task.id) == .Failed)
                        .Failed
                    else if (result.success and (task.timeout_ns == null or elapsed <= task.timeout_ns.?))
                        .Completed
                    else
                        .Failed;
                    if (status == .Failed and self.all_tasks.get(task.id) != .Failed) {
                        std.debug.print("workerLoop: Thread {d} task {d} failed due to timeout (elapsed: {d} ns, timeout: {d} ns) or no success\n", .{
                            thread_id, task.id, elapsed, task.timeout_ns orelse 0,
                        });
                    }
                    self.all_tasks.put(task.id, status) catch {
                        std.debug.print("workerLoop: Thread {d} failed to update status for task {d}, marking as Failed\n", .{ thread_id, task.id });
                        status = .Failed;
                        _ = self.all_tasks.put(task.id, .Failed) catch {};
                    };
                    //std.debug.print("workerLoop: Thread {d} task {d} status: {s}\n", .{ thread_id, task.id, @tagName(status) });
                    self.checkDependentsLocked(task.id);
                    task.deinit(self.allocator);
                }
                self.mutex.unlock();
            } else {
                //std.debug.print("workerLoop: Thread {d} no tasks, waiting\n", .{thread_id});
                self.cond.wait(&self.mutex);
                //std.debug.print("workerLoop: Thread {d} woke up from wait\n", .{thread_id});
                self.mutex.unlock();
            }
        }
        //std.debug.print("workerLoop: Thread {d} exiting\n", .{thread_id});
    }
};
