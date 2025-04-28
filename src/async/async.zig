// zttp/src/async/async.zig
const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const posix = std.posix;

pub const Queue = @import("queue.zig").Intrusive;
pub const IOUringBackend = @import("io_uring.zig").IOUringBackend;
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

pub const Callback = *const fn (*AsyncIo, Task) anyerror!void;
pub fn noopCallback(_: *AsyncIo, _: Task) anyerror!void {}

pub const Context = struct {
    ptr: ?*anyopaque = null,
    msg: u16 = 0,
    cb: Callback = noopCallback,
};

pub const CompletionQueue = Queue(Task, .complete);
pub const FreeQueue = Queue(Task, .free);
pub const SubmissionQueue = Queue(Task, .in_flight);

pub const AsyncIo = struct {
    gpa: Allocator,
    backend: IOUringBackend,
    completion_q: CompletionQueue = .{},
    submission_q: SubmissionQueue = .{},
    free_q: FreeQueue = .{},

    pub fn init(gpa: Allocator, entries: u16) !AsyncIo {
        if (builtin.os.tag != .linux) {
            @compileError("zttp async backend (io_uring) only supports Linux");
        }
        return .{
            .gpa = gpa,
            .backend = try IOUringBackend.init(entries),
            .submission_q = .{},
            .free_q = .{},
        };
    }

    pub fn deinit(self: *AsyncIo) void {
        self.backend.deinit(self.gpa);
        while (self.submission_q.pop()) |task| {
            std.log.debug("Deinit: destroying submission_q task={*}", .{task});
            self.gpa.destroy(task);
        }
        while (self.free_q.pop()) |task| {
            std.log.debug("Deinit: destroying free_q task={*}", .{task});
            self.gpa.destroy(task);
        }
    }

    pub fn submit(self: *AsyncIo) !void {
        try self.backend.submit(&self.submission_q);
        try self.reapCompletions();
    }

    pub fn getTask(self: *AsyncIo) Allocator.Error!*Task {
        const task = self.free_q.pop() orelse try self.gpa.create(Task);
        task.* = .{
            .userdata = null,
            .msg = 0,
            .callback = noopCallback,
            .req = .noop,
            .result = null,
            .state = .free,
            .next = null,
            .prev = null,
        };
        std.log.debug("Task acquired (ptr: {*}, req: {s})", .{ task, @tagName(task.req) });
        return task;
    }

    pub fn submitAndWait(self: *AsyncIo) !void {
        try self.backend.submitAndWait(&self.submission_q);
        try self.reapCompletions();
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

    pub fn noop(self: *AsyncIo, ctx: Context) Allocator.Error!*Task {
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

    pub fn accept(self: *AsyncIo, fd: posix.fd_t, ctx: Context) Allocator.Error!*Task {
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

    pub fn recv(self: *AsyncIo, fd: posix.fd_t, buffer: []u8, ctx: Context) Allocator.Error!*Task {
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

    pub fn write(self: *AsyncIo, fd: posix.fd_t, buffer: []const u8, ctx: Context) Allocator.Error!*Task {
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

    pub fn writev(self: *AsyncIo, fd: posix.fd_t, vecs: []const posix.iovec_const, ctx: Context) Allocator.Error!*Task {
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

    pub fn close(self: *AsyncIo, fd: posix.fd_t, ctx: Context) Allocator.Error!*Task {
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

    pub fn timer(self: *AsyncIo, duration: Timespec, ctx: Context) Allocator.Error!*Task {
        _ = self;
        _ = duration;
        _ = ctx;
        return error.OperationNotImplemented;
    }

    pub fn cancelAll(self: *AsyncIo) Allocator.Error!void {
        const task = try self.getTask();
        task.* = .{
            .req = .{ .cancel = .all },
        };

        self.submission_q.push(task);
    }
};
