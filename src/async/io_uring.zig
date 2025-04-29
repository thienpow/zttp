const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;
const log = std.log.scoped(.iouring);

const Queue = @import("queue.zig").Intrusive;
const Task = @import("task.zig").Task;
const AsyncIo = @import("async.zig").AsyncIo;
const OperationType = @import("op_request.zig").OperationType;
const Request = @import("op_request.zig").Request;
const Result = @import("op_request.zig").Result;
const ResultError = @import("op_request.zig").ResultError;
const CancelError = @import("op_request.zig").CancelError;
const RecvError = @import("op_request.zig").RecvError;
const Timespec = @import("async.zig").Timespec;

/// Backend for AsyncIo using Linux io_uring.
/// Manages the io_uring instance and an in_flight queue of tasks.
/// Single-threaded: no mutex, as server is single-threaded.
pub const IOUringBackend = struct {
    ring: linux.IoUring,
    in_flight: Queue(Task, .queue) = .{},

    /// Initializes an io_uring instance with the specified number of entries.
    pub fn init(entries: u16) anyerror!IOUringBackend {
        var params = std.mem.zeroInit(linux.io_uring_params, .{
            .flags = linux.IORING_SETUP_CLAMP | linux.IORING_SETUP_SUBMIT_ALL,
        });

        log.debug("Initializing io_uring with {} entries", .{entries});
        const ring = try linux.IoUring.init_params(entries, &params);
        log.debug("io_uring initialized (FD: {d})", .{ring.fd});

        return .{ .ring = ring };
    }

    /// Deinitializes the io_uring instance.
    /// Task deallocation is handled by AsyncIo.deinit.
    pub fn deinit(self: *IOUringBackend, _: Allocator) void {
        log.debug("IOUringBackend.deinit started", .{});
        if (self.ring.fd >= 0) {
            log.debug("Deinitializing io_uring ring (FD: {d})", .{self.ring.fd});
            self.ring.deinit();
        }
        log.debug("IOUringBackend.deinit complete", .{});
    }

    /// Submits tasks from submission_q and waits for at least one completion.
    /// Returns the number of tasks successfully prepped.
    pub fn submitAndWait(self: *IOUringBackend, submission_q: *Queue(Task, .queue)) anyerror!usize {
        const prepped_count = try self.prepSubmissionQueue(submission_q);
        const submitted_count = self.ring.sq_ready();

        if (submitted_count > 0) {
            log.debug("Submitting {} SQEs and waiting for 1 completion", .{submitted_count});
            _ = try self.ring.submit_and_wait(1);
        } else if (!self.in_flight.empty()) {
            log.debug("Submission queue empty, but {} in-flight tasks. Waiting for 1 completion...", .{self.in_flight.len()});
            _ = try self.ring.submit_and_wait(1);
        } else {
            log.debug("Submission queue empty and no in-flight tasks. Skipping wait.", .{});
        }

        if (prepped_count < submission_q.len()) {
            log.warn("Only prepped {}/{} tasks due to SQ full", .{ prepped_count, submission_q.len() });
        }
        return prepped_count;
    }

    /// Submits tasks from submission_q without waiting.
    /// Returns the number of tasks successfully prepped.
    pub fn submit(self: *IOUringBackend, submission_q: *Queue(Task, .queue)) anyerror!usize {
        const prepped_count = try self.prepSubmissionQueue(submission_q);
        const submitted_count = self.ring.sq_ready();
        if (submitted_count > 0) {
            log.debug("Submitting {} SQEs without waiting", .{submitted_count});
            _ = try self.ring.submit();
        }
        if (prepped_count < submission_q.len) {
            log.warn("Only prepped {}/{} tasks due to SQ full", .{ prepped_count, submission_q.len });
        }
        return prepped_count;
    }

    /// Prepares SQEs from submission_q, moving tasks to in_flight.
    /// Returns the number of tasks successfully prepped.
    fn prepSubmissionQueue(self: *IOUringBackend, submission_q: *Queue(Task, .queue)) anyerror!usize {
        var prepped_count: usize = 0;
        while (submission_q.pop()) |task| {
            const sqe = self.ring.get_sqe() catch |err| {
                submission_q.pushFront(task);
                log.warn("io_uring SQ full ({} ready), {any} (ptr: {*}) re-queued to front.  err: {any}", .{ self.ring.sq_ready(), task.req, task, err });
                return prepped_count;
            };

            self.prepTask(sqe, task);
            self.in_flight.push(task);
            prepped_count += 1;
            log.debug("Prepped SQE for task {s} (ptr: {*}), moved to in_flight", .{ taskReqName(task.req), task });
        }
        return prepped_count;
    }

    /// Prepares an SQE for a task based on its request type.
    fn prepTask(_: *IOUringBackend, sqe: *linux.io_uring_sqe, task: *Task) void {
        sqe.user_data = @intFromPtr(task);

        switch (task.req) {
            .noop => {
                log.debug("Prep SQE: noop", .{});
                sqe.opcode = linux.IORING_OP.NOP;
            },
            .accept => |fd| {
                log.debug("Prep SQE: accept (fd={d})", .{fd});
                sqe.opcode = linux.IORING_OP.ACCEPT;
                sqe.fd = fd;
                sqe.flags = 0;
                sqe.addr = 0;
                sqe.len = 0;
            },
            .recv => |req| {
                log.debug("Prep SQE: recv (fd={d}, len={d})", .{ req.fd, req.buffer.len });
                sqe.opcode = linux.IORING_OP.RECV;
                sqe.fd = req.fd;
                sqe.addr = @intFromPtr(req.buffer.ptr);
                sqe.len = @intCast(req.buffer.len);
            },
            .write => |req| {
                log.debug("Prep SQE: write (fd={d}, len={d})", .{ req.fd, req.buffer.len });
                sqe.opcode = linux.IORING_OP.SEND;
                sqe.fd = req.fd;
                sqe.addr = @intFromPtr(req.buffer.ptr);
                sqe.len = @intCast(req.buffer.len);
            },
            .writev => |req| {
                log.debug("Prep SQE: Fwritev (fd={d}, iovcnt={d})", .{ req.fd, req.vecs.len });
                sqe.opcode = linux.IORING_OP.WRITEV;
                sqe.fd = req.fd;
                sqe.addr = @intFromPtr(req.vecs.ptr);
                sqe.len = @intCast(req.vecs.len);
            },
            .close => |fd| {
                log.debug("Prep SQE: close (fd={d})", .{fd});
                sqe.opcode = linux.IORING_OP.CLOSE;
                sqe.fd = fd;
            },
            .timer => |ts| {
                log.debug("Prep SQE: timer (sec={d}, nsec={d})", .{ ts.sec, ts.nsec });
                sqe.opcode = linux.IORING_OP.TIMEOUT;
                sqe.fd = -1;
                sqe.addr = @intFromPtr(&ts);
                sqe.len = 1; // One timespec
                sqe.off = 0; // Absolute timeout
            },
            .cancel => |cancel_req| {
                switch (cancel_req) {
                    .task => |task_to_cancel| {
                        log.debug("Prep SQE: cancel task {s} (ptr: {*})", .{ taskReqName(task_to_cancel.req), task_to_cancel });
                        sqe.opcode = linux.IORING_OP.ASYNC_CANCEL;
                        sqe.addr = @intFromPtr(task_to_cancel);
                        sqe.flags = 0;
                    },
                    .all => {
                        log.debug("Prep SQE: cancel all tasks", .{});
                        sqe.opcode = linux.IORING_OP.ASYNC_CANCEL;
                        sqe.addr = 0; // Cancel all
                        sqe.flags = linux.IORING_ASYNC_CANCEL_ALL;
                    },
                }
            },
        }
    }

    /// Reaps completed CQEs and processes them.
    pub fn reapCompletions(self: *IOUringBackend, async_io: *AsyncIo) anyerror!void {
        var cqe_count: usize = 0;
        var cqes: [16]linux.io_uring_cqe = undefined;

        const num_cqes = try self.ring.copy_cqes(&cqes, 0);
        for (cqes[0..num_cqes]) |cqe| {
            cqe_count += 1;
            const task: *Task = @ptrFromInt(cqe.user_data);
            if (cqe.user_data == 0 or !self.in_flight.hasItem(task)) {
                log.err("Invalid task pointer {*}, user_data={d} not in in_flight queue, skipping CQE", .{ task, cqe.user_data });
                continue;
            }
            log.debug("Reaping CQE for task (ptr: {*}, state: {s}, res={d}, flags={b})", .{ task, @tagName(task.state), cqe.res, cqe.flags });
            self.handleCompletion(async_io, task, &cqe);
        }

        if (cqe_count > 0) {
            log.debug("Reaped {} completions", .{cqe_count});
        }
    }

    /// Processes a single CQE for a task.
    fn handleCompletion(self: *IOUringBackend, async_io: *AsyncIo, task: *Task, cqe: *const linux.io_uring_cqe) void {
        const res = cqe.res;
        var op_error: ?anyerror = null;

        log.debug("Handling completion for task (ptr: {*}, req: {s}, state: {s})", .{ task, taskReqName(task.req), @tagName(task.state) });

        if (res < 0) {
            const errno = @as(u32, @intCast(-res));
            const fd = switch (task.req) {
                .recv => |r| r.fd,
                .write => |w| w.fd,
                .writev => |wv| wv.fd,
                .close => |c| c,
                .accept => |a| a,
                else => -1,
            };
            log.debug("io_uring operation failed with errno: {d} for task (ptr: {*}, req: {s}, fd={d})", .{ errno, task, taskReqName(task.req), fd });
            op_error = switch (errno) {
                @intFromEnum(linux.E.BADF), @intFromEnum(linux.E.FAULT) => if (task.req == .recv or task.req == .write or task.req == .writev) error.Unexpected else error.BadFileDescriptor,
                @intFromEnum(linux.E.CANCELED) => error.Canceled,
                @intFromEnum(linux.E.CONNRESET) => if (task.req == .recv) RecvError.ConnectionResetByPeer else error.ConnectionReset,
                @intFromEnum(linux.E.PIPE) => if (task.req == .recv) error.Unexpected else error.BrokenPipe,
                @intFromEnum(linux.E.INVAL) => error.InvalidArgument,
                @intFromEnum(linux.E.AGAIN) => if (task.req == .recv) error.WouldBlock else error.WouldBlock,
                @intFromEnum(linux.E.CONNREFUSED) => error.ConnectionRefused,
                @intFromEnum(linux.E.NOTCONN) => error.NotConnected,
                @intFromEnum(linux.E.NOENT) => if (task.req == .cancel) error.EntryNotFound else error.Unexpected,
                else => error.Unexpected,
            };

            task.result = switch (task.req) {
                .noop => .{ .noop = {} },
                .accept => .{ .accept = @errorCast(op_error.?) },
                .recv => .{ .recv = @errorCast(op_error.?) },
                .write => .{ .write = @errorCast(op_error.?) },
                .writev => .{ .writev = @errorCast(op_error.?) },
                .close => .{ .close = @errorCast(op_error.?) },
                .timer => .{ .timer = @errorCast(op_error.?) },
                .cancel => .{ .cancel = @errorCast(op_error.?) },
            };

            task.state = if (op_error) |err| (if (err == error.Canceled) .canceled else .complete) else .complete;

            self.in_flight.remove(task);
            if (task.state != .in_flight) {
                log.debug("Executing callback for task (ptr: {*}, req: {s})", .{ task, taskReqName(task.req) });
                task.callback(async_io, task) catch |cb_err| {
                    log.err("Callback for task (ptr: {*}, req: {s}) failed: {s}", .{ task, taskReqName(task.req), @errorName(cb_err) });
                };
            }
            async_io.resetTask(task);
            async_io.free_q.push(task);
            log.debug("Task (ptr: {*}, req: {s}) moved to free_q after error", .{ task, taskReqName(task.req) });
        } else {
            var success_result: Result = undefined;

            switch (task.req) {
                .noop => success_result = .noop,
                .accept => {
                    log.debug("Accept success, new FD: {d}", .{res});
                    success_result = .{ .accept = @intCast(res) };
                },
                .recv => {
                    log.debug("Recv success, bytes read: {d}", .{res});
                    log.debug("Raw recv data (FD: {d}, bytes: {d}): {x}", .{ task.req.recv.fd, cqe.res, task.req.recv.buffer[0..@intCast(cqe.res)] });
                    success_result = .{ .recv = @intCast(res) };
                },
                .write, .writev => {
                    log.debug("Write success, bytes written: {d}", .{res});
                    success_result = if (task.req == .write) .{ .write = @intCast(res) } else .{ .writev = @intCast(res) };
                },
                .close => {
                    log.debug("Close success", .{});
                    success_result = .{ .close = {} };
                },
                .timer => {
                    log.debug("Timer expired", .{});
                    success_result = .{ .timer = {} };
                },
                .cancel => {
                    log.debug("Cancel request completed successfully", .{});
                    success_result = .{ .cancel = {} };
                },
            }
            task.result = success_result;

            if (cqe.flags & linux.IORING_CQE_F_MORE != 0) {
                log.debug("Task (ptr: {*}, req: {s}) has MORE completions pending (flags={b})", .{ task, taskReqName(task.req), cqe.flags });
                task.state = .in_flight;
            } else {
                log.debug("Task (ptr: {*}, req: {s}) has no more completions (flags={b})", .{ task, taskReqName(task.req), cqe.flags });
                task.state = .complete;
                self.in_flight.remove(task);
                if (task.state != .in_flight) {
                    log.debug("Executing callback for task (ptr: {*}, req: {s})", .{ task, taskReqName(task.req) });
                    task.callback(async_io, task) catch |cb_err| {
                        log.err("Callback for task (ptr: {*}, req: {s}) failed: {s}", .{ task, taskReqName(task.req), @errorName(cb_err) });
                    };
                }
                async_io.resetTask(task);
                async_io.free_q.push(task);
                log.debug("Task (ptr: {*}, req: {s}) moved to free_q after completion", .{ task, taskReqName(task.req) });
            }
        }
    }

    /// Returns true if no tasks are in_flight.
    pub fn done(self: *IOUringBackend) bool {
        return self.in_flight.empty();
    }

    /// Returns the io_uring file descriptor for polling.
    pub fn pollableFd(self: *IOUringBackend) !posix.fd_t {
        if (self.ring.fd < 0) return error.InvalidFd;
        return self.ring.fd;
    }

    fn taskReqName(req: Request) []const u8 {
        return switch (req) {
            .noop => "noop",
            .accept => "accept",
            .recv => "recv",
            .write => "write",
            .writev => "writev",
            .close => "close",
            .timer => "timer",
            .cancel => "cancel",
        };
    }
};
