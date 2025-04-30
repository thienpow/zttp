const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const posix = std.posix;

pub const Queue = @import("queue.zig").Intrusive;
pub const Backend = if (builtin.os.tag == .linux)
    @import("io_uring.zig").IOUringBackend
else if (builtin.os.tag == .macos or builtin.os.tag == .freebsd or builtin.os.tag == .netbsd or builtin.os.tag == .openbsd or builtin.os.tag == .dragonfly)
    @import("kqueue.zig").KqueueBackend
else
    @compileError("No async backend available for this platform");
pub const Task = @import("task.zig").Task;
pub const OperationType = @import("op_request.zig").OperationType;
pub const Request = @import("op_request.zig").Request;
pub const Result = @import("op_request.zig").Result;
pub const ResultError = @import("op_request.zig").ResultError;
pub const CancelError = @import("op_request.zig").CancelError;
pub const RecvError = @import("op_request.zig").RecvError;

pub const Timespec = extern struct {
    sec: i64 = 0,
    nsec: i64 = 0,

    pub fn isZero(self: Timespec) bool {
        return self.sec == 0 and self.nsec == 0;
    }
};

pub const Callback = *const fn (*AsyncIo, *Task) anyerror!void;
pub fn noopCallback(_: *AsyncIo, _: *Task) anyerror!void {}

pub const Context = struct {
    ptr: ?*anyopaque = null,
    msg: u16 = 0,
    cb: Callback = noopCallback,
};

const log = std.log.scoped(.async_io);
pub const FreeQueue = Queue(Task, .queue);
pub const SubmissionQueue = Queue(Task, .queue);

pub const AsyncIo = struct {
    gpa: Allocator,
    backend: Backend,
    submission_q: SubmissionQueue = .{},
    free_q: FreeQueue = .{},
    pending_submissions: SubmissionQueue = .{}, // For tasks not submitted due to backend constraints

    pub fn init(gpa: Allocator, entries: u16) !AsyncIo {
        return .{
            .gpa = gpa,
            .backend = try Backend.init(entries),
            .submission_q = .{},
            .free_q = .{},
            .pending_submissions = .{},
        };
    }

    pub fn deinit(self: *AsyncIo) void {
        while (self.submission_q.pop()) |task| {
            self.gpa.destroy(task);
        }
        while (self.pending_submissions.pop()) |task| {
            self.gpa.destroy(task);
        }
        while (self.free_q.pop()) |task| {
            self.gpa.destroy(task);
        }
        while (self.backend.in_flight.pop()) |task| {
            self.gpa.destroy(task);
        }
        self.backend.deinit(self.gpa);
    }

    pub fn submit(self: *AsyncIo) !void {
        while (self.pending_submissions.pop()) |task| {
            self.submission_q.push(task);
        }

        const initial_len = self.submission_q.len;
        const prepped = try self.backend.submit(&self.submission_q);
        if (prepped < initial_len) {
            while (self.submission_q.pop()) |task| {
                self.pending_submissions.push(task);
            }
            log.warn("Queued {}/{} tasks to pending_submissions", .{ initial_len - prepped, initial_len });
        }
        try self.reapCompletions();
    }

    pub fn submitAndWait(self: *AsyncIo) !void {
        while (self.pending_submissions.pop()) |task| {
            self.submission_q.push(task);
        }

        const initial_len = self.submission_q.len();
        const prepped = try self.backend.submitAndWait(&self.submission_q);
        if (prepped < initial_len) {
            while (self.submission_q.pop()) |task| {
                self.pending_submissions.push(task);
            }
            log.warn("Queued {}/{} tasks to pending_submissions", .{ initial_len - prepped, initial_len });
        }
        try self.reapCompletions();
    }

    /// Resets a task to its initial state for reuse.
    pub fn resetTask(_: *AsyncIo, task: *Task) void {
        task.* = .{
            .userdata = null,
            .msg = 0,
            .callback = noopCallback,
            .req = .noop,
            .result = null,
            .state = .free,
            .queue = .{},
        };
    }

    pub fn getTask(self: *AsyncIo) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = self.free_q.pop() orelse blk: {
            const task = try self.gpa.create(Task);
            self.resetTask(task);
            break :blk task;
        };
        if (task.userdata != null) {
            std.log.err("Task reused with non-null userdata: {x}", .{@intFromPtr(task.userdata)});
            return error.TaskReuseError;
        }
        self.resetTask(task);
        return task;
    }

    pub fn reapCompletions(self: *AsyncIo) !void {
        try self.backend.reapCompletions(self);
    }

    pub fn done(self: *AsyncIo) bool {
        return self.backend.done();
    }

    pub fn pollableFd(self: *AsyncIo) !posix.fd_t {
        return self.backend.pollableFd();
    }

    pub fn noop(self: *AsyncIo, ctx: Context) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .noop,
        };
        self.submission_q.push(task);
        return task;
    }

    pub fn accept(self: *AsyncIo, fd: posix.fd_t, ctx: Context) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .accept = fd },
        };
        self.submission_q.push(task);
        return task;
    }

    pub fn recv(self: *AsyncIo, fd: posix.fd_t, buffer: []u8, ctx: Context) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .recv = .{ .fd = fd, .buffer = buffer } },
        };
        self.submission_q.push(task);
        return task;
    }

    pub fn write(self: *AsyncIo, fd: posix.fd_t, buffer: []const u8, ctx: Context) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .write = .{ .fd = fd, .buffer = buffer } },
        };
        self.submission_q.push(task);
        return task;
    }

    pub fn writev(self: *AsyncIo, fd: posix.fd_t, vecs: []const posix.iovec_const, ctx: Context) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .writev = .{ .fd = fd, .vecs = vecs } },
        };
        self.submission_q.push(task);
        return task;
    }

    pub fn close(self: *AsyncIo, fd: posix.fd_t, ctx: Context) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .close = fd },
        };
        self.submission_q.push(task);
        return task;
    }

    pub fn timer(self: *AsyncIo, duration: Timespec, ctx: Context) error{ OutOfMemory, TaskReuseError }!*Task {
        const task = try self.getTask();
        task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .timer = duration },
        };
        self.submission_q.push(task);
        return task;
    }

    pub fn cancelAll(self: *AsyncIo) error{ OutOfMemory, TaskReuseError }!void {
        const task = try self.getTask();
        task.* = .{
            .req = .{ .cancel = .all },
            .callback = cancelAllCallback,
        };
        self.submission_q.push(task);
    }

    fn cancelAllCallback(_: *AsyncIo, task: *Task) anyerror!void {
        if (task.result) |res| {
            _ = res.cancel catch |err| {
                log.err("cancelAll failed: {s}", .{@errorName(err)});
                return err;
            };
        }
    }
};
