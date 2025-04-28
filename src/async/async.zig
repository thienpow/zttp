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

pub const Context = struct {
    ptr: ?*anyopaque = null,
    msg: u16 = 0,
    cb: *const fn (*AsyncIoContext, Task) anyerror!void,
};

pub const BackendType = enum {
    io_uring,
    dummy,
};

pub const AsyncIoContext = struct {
    gpa: Allocator,
    backend: union(BackendType) {
        io_uring: IOUringBackend,
        dummy: void,
    },
    submission_q: Queue(Task, .in_flight) = .{},
    free_q: Queue(Task, .free) = .{},

    pub fn init(gpa: Allocator, entries: u16, backend_type: BackendType) !AsyncIoContext {
        std.log.debug("AsyncIoContext.init: backend_type={any}, entries={d}", .{ backend_type, entries });
        switch (backend_type) {
            .io_uring => {
                if (builtin.os.tag != .linux) {
                    @compileError("zttp async backend (io_uring) only supports Linux");
                }
                return .{
                    .gpa = gpa,
                    .backend = .{ .io_uring = try IOUringBackend.init(entries) },
                    .submission_q = .{},
                    .free_q = .{},
                };
            },
            .dummy => {
                std.log.debug("AsyncIoContext.init: Dummy backend initialized", .{});
                return .{
                    .gpa = gpa,
                    .backend = .dummy,
                    .submission_q = .{},
                    .free_q = .{},
                };
            },
        }
    }

    pub fn deinit(self: *AsyncIoContext) void {
        std.log.debug("AsyncIoContext.deinit: backend={any}", .{self.backend});
        switch (self.backend) {
            .io_uring => |*backend| backend.deinit(self.gpa),
            .dummy => {},
        }
        while (self.submission_q.pop()) |task| {
            std.log.debug("Deinit: destroying submission_q task={*}", .{task});
            self.gpa.destroy(task);
        }
        while (self.free_q.pop()) |task| {
            std.log.debug("Deinit: destroying free_q task={*}", .{task});
            self.gpa.destroy(task);
        }
    }

    pub fn submit(self: *AsyncIoContext) !void {
        switch (self.backend) {
            .io_uring => |*backend| {
                try backend.submit(&self.submission_q);
                try self.reapCompletions();
            },
            .dummy => {
                std.log.debug("AsyncIoContext.submit: Dummy backend, no async I/O", .{});
                // Simulate task processing by moving tasks to free_q
                while (self.submission_q.pop()) |task| {
                    task.state = .complete;
                    self.free_q.push(task);
                }
            },
        }
    }

    pub fn getTask(self: *AsyncIoContext) Allocator.Error!*Task {
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
        return task;
    }

    pub fn submitAndWait(self: *AsyncIoContext) !void {
        switch (self.backend) {
            .io_uring => |*backend| {
                try backend.submitAndWait(&self.submission_q);
                try self.reapCompletions();
            },
            .dummy => return error.BackendNotImplemented,
        }
    }

    pub fn reapCompletions(self: *AsyncIoContext) !void {
        switch (self.backend) {
            .io_uring => |*backend| try backend.reapCompletions(self),
            .dummy => {
                std.log.debug("AsyncIoContext.reapCompletions: Dummy backend, no completions", .{});
            },
        }
    }

    pub fn done(self: *AsyncIoContext) bool {
        switch (self.backend) {
            .io_uring => |*backend| return backend.done() and self.submission_q.empty(),
            .dummy => return self.submission_q.empty(),
        }
    }

    pub fn pollableFd(self: *AsyncIoContext) !posix.fd_t {
        switch (self.backend) {
            .io_uring => |*backend| return backend.pollableFd(),
            .dummy => return error.NoPollableFd,
        }
    }

    pub fn releaseTaskToFreeQueue(self: *AsyncIoContext, task: *Task) void {
        task.state = .free;
        self.free_q.push(task);
    }

    pub fn noop(self: *AsyncIoContext, ctx: Context) Allocator.Error!*Task {
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

    pub fn accept(self: *AsyncIoContext, fd: posix.fd_t, ctx: Context) Allocator.Error!*Task {
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

    pub fn recv(self: *AsyncIoContext, fd: posix.fd_t, buffer: []u8, ctx: Context) Allocator.Error!*Task {
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

    pub fn write(self: *AsyncIoContext, fd: posix.fd_t, buffer: []const u8, ctx: Context) Allocator.Error!*Task {
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

    pub fn writev(self: *AsyncIoContext, fd: posix.fd_t, vecs: []const posix.iovec_const, ctx: Context) Allocator.Error!*Task {
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

    pub fn close(self: *AsyncIoContext, fd: posix.fd_t, ctx: Context) Allocator.Error!*Task {
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

    pub fn timer(self: *AsyncIoContext, duration: Timespec, ctx: Context) Allocator.Error!*Task {
        _ = self;
        _ = duration;
        _ = ctx;
        return error.OperationNotImplemented;
    }

    pub fn cancelAll(self: *AsyncIoContext) Allocator.Error!*Task {
        _ = self;
        return error.OperationNotImplemented;
    }
};

pub fn noopCallback(_: *AsyncIoContext, _: Task) anyerror!void {}
