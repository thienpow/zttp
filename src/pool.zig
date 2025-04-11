const std = @import("std");

/// ThreadPool implements a basic task scheduling system with worker threads.
pub const ThreadPool = struct {
    allocator: std.mem.Allocator,
    threads: std.ArrayList(std.Thread),
    tasks: std.ArrayList(*Task),
    running: std.atomic.Value(bool),
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    min_threads: usize,
    max_threads: usize,
    max_tasks: usize,
    active_threads: std.atomic.Value(usize),
    next_task_id: std.atomic.Value(u64),
    all_tasks: std.AutoHashMap(u64, TaskStatus),
    pending_tasks: std.AutoHashMap(u64, *Task),

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
            std.debug.print("Task.create: Allocated ctx at {*}\n", .{ctx});
            ctx.* = .{ .f = FuncType, .a = arg_val };

            const task = try allocator.create(Task);
            std.debug.print("Task.create: Allocated task at {*}, id: {d}\n", .{ task, id_val });
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

        fn deinit(self: *Task, allocator: std.mem.Allocator) void {
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

    /// Initialize a new thread pool without starting threads
    pub fn init(allocator: std.mem.Allocator, options: Options) !ThreadPool {
        std.debug.print("ThreadPool.init: Starting at {d} ns\n", .{std.time.nanoTimestamp()});
        const min_t = @min(options.min_threads, options.max_threads);
        const max_t = @max(options.min_threads, options.max_threads);

        if (min_t == 0) return Error.InvalidConfiguration;

        std.debug.print("ThreadPool.init: Allocating threads list\n", .{});
        var threads = std.ArrayList(std.Thread).init(allocator);
        errdefer threads.deinit();
        try threads.ensureTotalCapacity(max_t);

        std.debug.print("ThreadPool.init: Allocating tasks list\n", .{});
        var task_list = std.ArrayList(*Task).init(allocator);
        errdefer task_list.deinit();

        std.debug.print("ThreadPool.init: Allocating hash maps\n", .{});
        var all_tasks = std.AutoHashMap(u64, TaskStatus).init(allocator);
        errdefer all_tasks.deinit();
        var pending_tasks = std.AutoHashMap(u64, *Task).init(allocator);
        errdefer pending_tasks.deinit();

        std.debug.print("ThreadPool.init: Creating ThreadPool struct\n", .{});
        const tp = ThreadPool{ // Changed 'var' to 'const'
            .allocator = allocator,
            .threads = threads,
            .tasks = task_list,
            .running = std.atomic.Value(bool).init(true),
            .mutex = .{},
            .cond = .{},
            .min_threads = min_t,
            .max_threads = max_t,
            .max_tasks = options.max_tasks,
            .active_threads = std.atomic.Value(usize).init(0),
            .next_task_id = std.atomic.Value(u64).init(0),
            .all_tasks = all_tasks,
            .pending_tasks = pending_tasks,
        };

        std.debug.print("ThreadPool.init: Completed at {d} ns\n", .{std.time.nanoTimestamp()});
        return tp;
    }

    /// Start worker threads after initialization
    pub fn startWorkers(self: *ThreadPool, num_threads: usize) !void {
        std.debug.print("ThreadPool.startWorkers: Starting {d} threads\n", .{num_threads});
        const count = @min(num_threads, self.max_threads);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            std.debug.print("ThreadPool.startWorkers: Spawning thread {d}/{d}\n", .{ i + 1, count });
            const thread = try std.Thread.spawn(.{}, workerLoop, .{self});
            std.debug.print("ThreadPool.startWorkers: Spawned thread {d} with handle {d}\n", .{ i + 1, thread.getHandle() });
            try self.threads.append(thread);
        }
        std.debug.print("ThreadPool.startWorkers: Completed\n", .{});
    }

    /// Clean up all resources associated with the thread pool
    pub fn deinit(self: *ThreadPool) void {
        std.debug.print("ThreadPool.deinit() started at {d} ns\n", .{std.time.nanoTimestamp()});

        self.running.store(false, .monotonic);
        self.mutex.lock();
        self.cond.broadcast();
        self.mutex.unlock();

        for (self.threads.items) |thread| {
            thread.join();
        }

        self.mutex.lock();
        for (self.tasks.items) |task| {
            task.deinit(self.allocator);
        }
        self.tasks.deinit();

        var pending_it = self.pending_tasks.iterator();
        while (pending_it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.pending_tasks.deinit();
        self.mutex.unlock();

        self.all_tasks.deinit();
        self.threads.deinit();

        std.debug.print("ThreadPool.deinit() completed at {d} ns\n", .{std.time.nanoTimestamp()});
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
    fn checkDependentsLocked(self: *ThreadPool, completed_id: u64) void {
        var tasks_to_move = std.ArrayList(u64).init(self.allocator);
        defer tasks_to_move.deinit();

        var pending_it = self.pending_tasks.iterator();
        while (pending_it.next()) |entry| {
            const task_id = entry.key_ptr.*;
            const task = entry.value_ptr.*;

            if (task.dependencies) |deps| {
                var depends_on_completed = false;
                for (deps) |dep_id| {
                    if (dep_id == completed_id) {
                        depends_on_completed = true;
                        break;
                    }
                }

                if (depends_on_completed and self.areDependenciesMetLocked(deps)) {
                    tasks_to_move.append(task_id) catch continue;
                }
            }
        }

        for (tasks_to_move.items) |task_id| {
            if (self.pending_tasks.getPtr(task_id)) |task_ptr| {
                const task = task_ptr.*;
                _ = self.pending_tasks.remove(task_id);

                _ = self.all_tasks.put(task_id, .Running) catch {};
                self.tasks.append(task) catch {
                    _ = self.all_tasks.put(task_id, .Failed) catch {};
                    task.deinit(self.allocator);
                    continue;
                };
            }
        }

        if (tasks_to_move.items.len > 0) {
            self.cond.signal();
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

        std.debug.print("Schedule called. Pool running: {}\n", .{self.running.load(.monotonic)});

        if (!self.running.load(.monotonic)) {
            std.debug.print("PoolClosed error triggered in schedule\n", .{});
            if (dependencies) |deps| self.allocator.free(deps);
            return Error.PoolClosed;
        }

        if (self.tasks.items.len + self.pending_tasks.count() >= self.max_tasks) {
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
        std.debug.print("Schedule: Created task {d} at {*}\n", .{ task_id, task });

        if (task.dependencies != null and task.dependencies.?.len > 0) {
            try self.all_tasks.put(task_id, .Pending);
            if (self.areDependenciesMetLocked(task.dependencies.?)) {
                try self.all_tasks.put(task_id, .Running);
                try self.tasks.append(task);
                std.debug.print("Schedule: Task {d} dependencies met, appended to tasks\n", .{task_id});
                self.cond.signal();
            } else {
                try self.pending_tasks.put(task_id, task);
                std.debug.print("Schedule: Task {d} pending with dependencies\n", .{task_id});
            }
        } else {
            try self.all_tasks.put(task_id, .Running);
            try self.tasks.append(task);
            std.debug.print("Schedule: Task {d} appended to tasks\n", .{task_id});
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
                    .Failed => false, // Changed from error.TaskFailed to false
                    .Running, .Pending => {
                        if (timeout_ns) |timeout| {
                            if (std.time.nanoTimestamp() - start > timeout) {
                                return false; // Wait timeout exceeded
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
        return false; // Pool shut down
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

        var i: usize = 0;
        while (i < self.tasks.items.len) {
            const task = self.tasks.items[i];
            if (task.id == task_id) {
                _ = self.tasks.orderedRemove(i);
                try self.all_tasks.put(task_id, .Failed);
                task.deinit(self.allocator);
                return;
            }
            i += 1;
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
        std.debug.print("workerLoop: Started thread {d}, running: {any}\n", .{ thread_id, self.running.load(.monotonic) });

        while (true) {
            self.mutex.lock();
            const is_running = self.running.load(.monotonic);
            std.debug.print("workerLoop: Thread {d} locked mutex, running: {any}, tasks len: {d}\n", .{ thread_id, is_running, self.tasks.items.len });

            if (!is_running and self.tasks.items.len == 0) {
                std.debug.print("workerLoop: Thread {d} shutting down (not running, no tasks)\n", .{thread_id});
                self.mutex.unlock();
                break;
            }

            var current_task: ?*ThreadPool.Task = null;
            if (self.tasks.items.len > 0 and self.tasks.items.len <= self.max_tasks) {
                std.debug.print("workerLoop: Thread {d} found {d} tasks\n", .{ thread_id, self.tasks.items.len });
                const now = std.time.nanoTimestamp();
                var i: usize = 0;
                while (i < self.tasks.items.len) {
                    const t = self.tasks.items[i];
                    std.debug.print("workerLoop: Thread {d} checking task at index {d}, id: {d}\n", .{ thread_id, i, t.id });
                    if (t.id > 1_000_000_000) {
                        std.debug.print("workerLoop: Thread {d} removing invalid task id {d}\n", .{ thread_id, t.id });
                        const bad_task = self.tasks.orderedRemove(i);
                        _ = self.all_tasks.put(bad_task.id, .Failed) catch {};
                        bad_task.deinit(self.allocator);
                        continue;
                    }
                    if (t.timeout_ns) |timeout| {
                        if (now - t.queued_at > timeout) {
                            std.debug.print("workerLoop: Thread {d} removing timed out task {d}\n", .{ thread_id, t.id });
                            const expired_task = self.tasks.orderedRemove(i);
                            _ = self.all_tasks.put(expired_task.id, .Failed) catch {};
                            expired_task.deinit(self.allocator);
                            continue;
                        }
                    }
                    i += 1;
                }

                if (self.tasks.items.len > 0) {
                    var highest_pri_idx: ?usize = null;
                    var highest_pri: u8 = 0;
                    for (self.tasks.items, 0..) |t, idx| {
                        if (t.id > 1_000_000_000) continue;
                        if (highest_pri_idx == null or t.priority > highest_pri) {
                            highest_pri = t.priority;
                            highest_pri_idx = idx;
                        }
                    }
                    if (highest_pri_idx) |idx| {
                        current_task = self.tasks.orderedRemove(idx);
                        std.debug.print("workerLoop: Thread {d} selected task {d} with priority {d}\n", .{
                            thread_id,
                            current_task.?.id,
                            current_task.?.priority,
                        });
                    }
                }
            } else if (self.tasks.items.len > self.max_tasks) {
                std.debug.print("workerLoop: Thread {d} invalid task count {d}, resetting\n", .{ thread_id, self.tasks.items.len });
                self.tasks.clearRetainingCapacity();
            }

            if (current_task) |task| {
                std.debug.print("workerLoop: Thread {d} unlocking mutex for task {d}\n", .{ thread_id, task.id });
                self.mutex.unlock();

                var result = ThreadPool.TaskResult{};
                //const start_time = std.time.nanoTimestamp();
                std.debug.print("workerLoop: Thread {d} executing task {d}\n", .{ thread_id, task.id });
                task.func(task.arg, &result);
                const end_time = std.time.nanoTimestamp();
                std.debug.print("workerLoop: Thread {d} task {d} executed, success: {any}\n", .{ thread_id, task.id, result.success });

                self.mutex.lock();
                task.completed.store(true, .monotonic);
                const elapsed = end_time - task.queued_at;
                const status: ThreadPool.TaskStatus = if (result.success and (task.timeout_ns == null or elapsed <= task.timeout_ns.?))
                    .Completed
                else
                    .Failed;
                if (status == .Failed) {
                    std.debug.print("workerLoop: Thread {d} task {d} failed due to timeout (elapsed: {d} ns, timeout: {d} ns)\n", .{
                        thread_id, task.id, elapsed, task.timeout_ns orelse 0,
                    });
                }
                _ = self.all_tasks.put(task.id, status) catch {};
                std.debug.print("workerLoop: Thread {d} task {d} status: {s}\n", .{ thread_id, task.id, @tagName(status) });
                self.checkDependentsLocked(task.id);
                task.deinit(self.allocator);
                self.mutex.unlock();
            } else {
                std.debug.print("workerLoop: Thread {d} no tasks, waiting\n", .{thread_id});
                self.cond.wait(&self.mutex);
                std.debug.print("workerLoop: Thread {d} woke up from wait\n", .{thread_id});
                self.mutex.unlock();
            }
        }
        std.debug.print("workerLoop: Thread {d} exiting\n", .{thread_id});
    }
};
