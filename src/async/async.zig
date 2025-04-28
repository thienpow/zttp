// zttp/src/async/async.zig
const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const posix = std.posix;

pub const Queue = @import("queue.zig").Intrusive;
pub const IOUringBackend = @import("io_uring.zig").IOUringBackend;
pub const Task = @import("task.zig").Task; // Ensure Task is imported
pub const OperationType = @import("op_request.zig").OperationType;
pub const Request = @import("op_request.zig").Request;
pub const Result = @import("op_request.zig").Result;
pub const ResultError = @import("op_request.zig").ResultError;
pub const CancelError = @import("op_request.zig").CancelError;
pub const RecvError = @import("op_request.zig").RecvError;

/// Used for timeouts and timers. Matches the Linux kernel timespec structure.
pub const Timespec = extern struct {
    sec: i64 = 0,
    nsec: i64 = 0,

    pub fn isZero(self: Timespec) bool {
        return self.sec == 0 and self.nsec == 0;
    }
};

/// Context passed with an asynchronous request, defining the user callback and data.
pub const Context = struct {
    ptr: ?*anyopaque = null, // User-defined pointer
    msg: u16 = 0, // User-defined message
    callback: *const fn (*AsyncIoContext, Task) anyerror!void, // Function to call upon completion
};

/// The core asynchronous runtime instance, managing the backend and tasks.
pub const AsyncIoContext = struct { // Renamed from Ring
    gpa: Allocator, // General purpose allocator for Task allocation etc.
    backend: IOUringBackend, // The specific I/O backend (io_uring in this case)

    // Queues to manage tasks internally
    submission_q: Queue(Task, .in_flight) = .{}, // Tasks queued by the user, ready to be submitted to the backend
    free_q: Queue(Task, .free) = .{}, // Tasks that have completed and are available for reuse
    // The in_flight queue is now managed by the backend.
    // in_flight: Queue(Task, .in_flight) = .{}, // Tasks currently submitted to the kernel - MOVED TO BACKEND

    /// Initializes the asynchronous runtime context.
    pub fn init(gpa: Allocator, entries: u16) !AsyncIoContext { // Updated function signature
        // Ensure we are on Linux, as this backend only supports io_uring
        if (builtin.os.tag != .linux) {
            @compileError("zttp async backend only supports Linux (io_uring)");
        }

        return .{
            .gpa = gpa,
            // Initialize the backend
            .backend = try IOUringBackend.init(entries),
            .submission_q = .{}, // Initialize queues
            .free_q = .{},
            // .in_flight is now in the backend
        };
    }

    /// Deinitializes the asynchronous runtime context, freeing resources.
    pub fn deinit(self: *AsyncIoContext) void { // Updated function signature
        // Deinitialize the backend first to ensure pending ops are handled/cleaned.
        self.backend.deinit(self.gpa);
        // Free any tasks remaining in queues.
        while (self.submission_q.pop()) |task| self.gpa.destroy(task);
        while (self.free_q.pop()) |task| self.gpa.destroy(task);
        // The backend's deinit should free tasks in its in_flight queue.
        // If the backend doesn't free them itself (like the dummy one doesn't),
        // we would need to iterate the backend's in_flight queue here.
        // Let's adjust IOUringBackend.deinit to free its in_flight tasks.
    }

    /// Gets an available Task struct, either from the free list or by allocating a new one.
    pub fn getTask(self: *AsyncIoContext) Allocator.Error!*Task { // Updated function signature
        // Pop from free_q or create a new one
        const task = self.free_q.pop() orelse try self.gpa.create(Task);
        // Reset essential fields for reuse (callback, userdata, msg, result)
        task.* = .{
            .userdata = null,
            .msg = 0,
            .callback = noopCallback, // Default to no-op callback
            .req = .noop, // Default request
            .result = null, // Clear previous result
            .state = .free, // Ensure state is free initially (getTask implies it's free)
            .next = null,
            .prev = null,
        };
        return task;
    }

    /// Submits tasks currently in the submission queue to the backend and blocks
    /// until at least one completion is available, then reaps completions.
    /// Use this when you need to wait for I/O to happen.
    pub fn submitAndWait(self: *AsyncIoContext) !void { // Updated function signature
        // The backend takes tasks from submission_q, submits them,
        // adds them to its in_flight queue, and waits for completions.
        try self.backend.submitAndWait(&self.submission_q);
        // After waiting, reap the completions.
        try self.reapCompletions();
    }

    /// Submits tasks currently in the submission queue to the backend without waiting.
    /// Use this when you have other work to do and will reap completions later.
    pub fn submit(self: *AsyncIoContext) !void { // Updated function signature
        // The backend takes tasks from submission_q, submits them,
        // adds them to its in_flight queue.
        try self.backend.submit(&self.submission_q);
        // It might be useful to reap completions immediately after submitting,
        // as some operations might complete synchronously.
        // Let's add a non-blocking reap here.
        try self.reapCompletions();
    }

    /// Reaps and processes any completed tasks from the backend.
    /// This function calls the completion callbacks for completed tasks
    /// and returns tasks to the free list via `self.free_q`. Non-blocking.
    pub fn reapCompletions(self: *AsyncIoContext) !void { // Updated function signature
        // The backend retrieves completed events, calls `self.handleCompletion`,
        // which then uses `self.free_q.push(task)` to return tasks.
        try self.backend.reapCompletions(self);
    }

    /// Provides a file descriptor that can be polled to detect when completions are available.
    /// Useful for integrating with external event loops (like std.posix.poll).
    pub fn pollableFd(self: *AsyncIoContext) !posix.fd_t { // Updated function signature
        return self.backend.pollableFd();
    }

    /// Checks if the backend considers itself "done" (no active operations in kernel queues).
    /// We also check our own submission queue.
    pub fn done(self: *AsyncIoContext) bool { // Updated function signature
        return self.backend.done() and self.submission_q.empty();
    }

    // --- Task Management Helpers (Called by the backend) ---
    // These methods facilitate the backend's interaction with the AsyncIoContext's queues.

    /// Called by the backend to add a task to the AsyncIoContext's free list.
    /// Note: The backend manages its own `in_flight` queue. This is only for freeing.
    pub fn releaseTaskToFreeQueue(self: *AsyncIoContext, task: *Task) void {
        task.state = .free; // Mark as free
        self.free_q.push(task); // Return to the free list
    }

    // --- Task Creation Helper Methods ---
    // These methods get a Task, set its request and context, and push it to the submission queue.
    // Task state will be set to .in_flight when pushed to submission_q.

    /// Schedules a no-operation task. Useful for testing or waking up the loop.
    pub fn noop(
        self: *AsyncIoContext, // Updated function signature
        ctx: Context,
    ) Allocator.Error!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .noop,
            // state is .free, push to submission_q sets it to .in_flight
        };
        self.submission_q.push(task);
        return task;
    }

    /// Schedules an accept operation on a server socket.
    pub fn accept(
        self: *AsyncIoContext, // Updated function signature
        fd: posix.fd_t, // The server socket file descriptor
        ctx: Context, // Callback for when a new connection is accepted
    ) Allocator.Error!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .accept = fd },
            // state is .free, push to submission_q sets it to .in_flight
        };
        self.submission_q.push(task);
        return task;
    }

    /// Schedules a read (recv) operation on a socket.
    pub fn recv(
        self: *AsyncIoContext, // Updated function signature
        fd: posix.fd_t,
        buffer: []u8, // Buffer to read into
        ctx: Context, // Callback for when read completes
    ) Allocator.Error!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .recv = .{ .fd = fd, .buffer = buffer } },
            // state is .free, push to submission_q sets it to .in_flight
        };
        self.submission_q.push(task);
        return task;
    }

    /// Schedules a write operation on a socket.
    pub fn write(
        self: *AsyncIoContext, // Updated function signature
        fd: posix.fd_t,
        buffer: []const u8, // Buffer to write from
        ctx: Context, // Callback for when write completes
    ) Allocator.Error!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .write = .{ .fd = fd, .buffer = buffer } },
            // state is .free, push to submission_q sets it to .in_flight
        };
        self.submission_q.push(task);
        return task;
    }

    /// Schedules a writev (gather write) operation on a socket.
    pub fn writev(
        self: *AsyncIoContext, // Updated function signature
        fd: posix.fd_t,
        vecs: []const posix.iovec_const, // Vector of buffers to write from
        ctx: Context, // Callback for when write completes
    ) Allocator.Error!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .writev = .{ .fd = fd, .vecs = vecs } },
            // state is .free, push to submission_q sets it to .in_flight
        };
        self.submission_q.push(task);
        return task;
    }

    /// Schedules a close operation on a file descriptor.
    pub fn close(
        self: *AsyncIoContext, // Updated function signature
        fd: posix.fd_t,
        ctx: Context, // Callback for when close completes
    ) Allocator.Error!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .close = fd },
            // state is .free, push to submission_q sets it to .in_flight
        };
        self.submission_q.push(task);
        return task;
    }

    /// Schedules a timer.
    ///
    /// This method will be implemented later, after the backend supports timers.
    pub fn timer(
        self: *AsyncIoContext, // Updated function signature
        duration: Timespec,
        ctx: Context,
    ) Allocator.Error!*Task {
        _ = self;
        _ = duration; // Unused for now
        _ = ctx; // Unused for now
        // Implementation will be similar to other ops: getTask, set req/ctx, push to submission_q
        return error.OperationNotImplemented; // Placeholder
    }

    /// Schedules a request to cancel all in-flight tasks.
    ///
    /// This method will be implemented later, after the backend supports cancel.
    pub fn cancelAll(self: *AsyncIoContext) Allocator.Error!*Task { // Updated function signature
        _ = self;
        // Need a specific OperationType::cancel variant for 'all'
        // For now:
        return error.OperationNotImplemented; // Placeholder
    }
};

/// A default no-operation callback function.
pub fn noopCallback(_: *AsyncIoContext, _: Task) anyerror!void {} // Updated function signature
