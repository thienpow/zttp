// zttp/src/async/io_uring.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;
const log = std.log.scoped(.iouring);

const Queue = @import("queue.zig").Intrusive;
const Task = @import("task.zig").Task;
const AsyncIoContext = @import("async.zig").AsyncIoContext;
const OperationType = @import("op_request.zig").OperationType;
const Request = @import("op_request.zig").Request;
const Result = @import("op_request.zig").Result;
const ResultError = @import("op_request.zig").ResultError;
const CancelError = @import("op_request.zig").CancelError;
const RecvError = @import("op_request.zig").RecvError;

pub const IOUringBackend = struct {
    ring: linux.IoUring,
    in_flight: Queue(Task, .in_flight) = .{},

    pub fn init(entries: u16) anyerror!IOUringBackend {
        var params = std.mem.zeroInit(linux.io_uring_params, .{
            .flags = linux.IORING_SETUP_CLAMP | linux.IORING_SETUP_SUBMIT_ALL,
        });

        log.debug("Initializing io_uring with {} entries", .{entries});
        const ring = try linux.IoUring.init_params(entries, &params);
        log.debug("io_uring initialized (FD: {d})", .{ring.fd});

        return .{ .ring = ring };
    }

    pub fn deinit(self: *IOUringBackend, gpa: Allocator) void {
        log.debug("IOUringBackend.deinit started", .{});

        while (self.in_flight.pop()) |task| {
            log.debug("IOUringBackend.deinit: Freeing in_flight task {any} (ptr: {*})", .{ task.req, task });
            gpa.destroy(task);
        }

        if (self.ring.fd >= 0) {
            log.debug("Deinitializing io_uring ring (FD: {d})", .{self.ring.fd});
            self.ring.deinit();
        }
        log.debug("IOUringBackend.deinit complete", .{});
    }

    pub fn submitAndWait(self: *IOUringBackend, submission_q: *Queue(Task, .in_flight)) anyerror!void {
        try self.prepSubmissionQueue(submission_q);

        const submitted_count = self.ring.sq_ready();

        if (submitted_count > 0) {
            log.debug("Submitting {} SQEs and waiting for 1 completion", .{submitted_count});
            _ = try self.ring.submit_and_wait(1);
        } else if (!self.in_flight.empty()) {
            log.debug("Submission queue empty, but {} in-flight tasks. Waiting for 1 existing completion...", .{self.in_flight.len()});
            _ = try self.ring.submit_and_wait(1);
        } else {
            log.debug("Submission queue empty and no in-flight tasks. Skipping wait.", .{});
        }
    }

    pub fn submit(self: *IOUringBackend, submission_q: *Queue(Task, .in_flight)) anyerror!void {
        try self.prepSubmissionQueue(submission_q);

        const submitted_count = self.ring.sq_ready();
        if (submitted_count > 0) {
            //log.debug("Submitting {} SQEs without waiting", .{submitted_count});
            _ = try self.ring.submit();
        } else {
            //log.debug("Submission queue empty, nothing to submit", .{});
        }
    }

    fn prepSubmissionQueue(self: *IOUringBackend, submission_q: *Queue(Task, .in_flight)) anyerror!void {
        //log.debug("prepSubmissionQueue: Processing submission_q ({} tasks)", .{submission_q.len()});
        while (submission_q.pop()) |task| {
            const sqe = self.ring.get_sqe() catch |err| {
                // if (err == error.SubmissionQueueFull) {
                //     submission_q.pushFront(task);
                //     log.warn("io_uring SQ full ({} ready), {any} (ptr: {*}) re-queued to front", .{ self.ring.sq_ready(), task.req, task });
                //     return;
                // }
                return err;
            };

            self.prepTask(sqe, task);
            self.in_flight.push(task);
            const fd_for_log = switch (task.req) {
                .accept => |fd| fd,
                .recv => |r| r.fd,
                .write => |w| w.fd,
                .writev => |wv| wv.fd,
                .close => |fd| fd,
                else => -1,
            };
            log.debug("Prepped SQE for task {any} (ptr: {*}, FD: {d}), moved from submission_q to in_flight", .{ task.req, task, fd_for_log });
        }
        //log.debug("prepSubmissionQueue: Finished processing submission_q. {} tasks now in_flight.", .{self.in_flight.len()});
    }

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
                sqe.addr = 0; // No sockaddr
                sqe.len = 0; // No sockaddr length
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
                log.debug("Prep SQE: writev (fd={d}, iovcnt={d})", .{ req.fd, req.vecs.len });
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
            .timer => |_| {
                log.warn("Prep SQE: timer (not fully implemented yet)", .{});
                sqe.opcode = linux.IORING_OP.NOP;
            },
            .cancel => |cancel_req| {
                log.warn("Prep SQE: cancel (not fully implemented yet)", .{});
                switch (cancel_req) {
                    .task => |task_to_cancel| {
                        log.debug("Prep SQE: cancel task {any} (ptr: {*})", .{ task_to_cancel.req, task_to_cancel });
                        sqe.opcode = linux.IORING_OP.ASYNC_CANCEL;
                        sqe.addr = @intFromPtr(task_to_cancel);
                    },
                }
            },
        }
    }

    pub fn reapCompletions(self: *IOUringBackend, ring: *AsyncIoContext) anyerror!void {
        //log.debug("reapCompletions started ({} in_flight)", .{self.in_flight.len()});
        var cqe_count: usize = 0;
        var cqes: [16]linux.io_uring_cqe = undefined;

        const num_cqes = try self.ring.copy_cqes(&cqes, 0);
        for (cqes[0..num_cqes]) |cqe| {
            cqe_count += 1;
            const task: *Task = @ptrFromInt(cqe.user_data);
            //log.debug("Reaping CQE for task type: {any} (ptr: {*}) with res={d}, flags={b}", .{ task.req, task, cqe.res, cqe.flags });

            const was_canceled_before_cqe = (task.state == .canceled);
            self.handleCompletion(ring, task, &cqe, was_canceled_before_cqe);
        }

        if (cqe_count > 0) {
            log.debug("Reaped {} completions", .{cqe_count});
        } else {
            //log.debug("No completions to reap", .{});
        }
    }

    fn handleCompletion(self: *IOUringBackend, ring: *AsyncIoContext, task: *Task, cqe: *const linux.io_uring_cqe, skip_callback: bool) void {
        const res = cqe.res;
        var op_error: ?anyerror = null;

        if (res < 0) {
            const errno = @as(u32, @intCast(-res));
            log.debug("io_uring operation {any} (ptr: {*}) failed with errno: {d}", .{ task.req, task, errno });
            op_error = switch (errno) {
                @intFromEnum(std.posix.E.CANCELED) => error.Canceled,
                @intFromEnum(std.posix.E.AGAIN) => error.Unexpected,
                @intFromEnum(std.posix.E.CONNRESET) => if (task.req == .recv) RecvError.ConnectionResetByPeer else error.Unexpected,
                @intFromEnum(std.posix.E.INVAL) => ResultError.Invalid,
                140 => if (builtin.target.os.tag != .linux) error.Unexpected else error.Unexpected, // WOULDBLOCK for non-Linux
                else => error.Unexpected,
            };

            task.result = switch (task.req) {
                .noop => blk: {
                    log.warn("NOP operation failed with error: {s}", .{errorName(op_error.?)});
                    break :blk .{ .noop = {} };
                },
                .accept => .{ .accept = @errorCast(op_error.?) },
                .recv => .{ .recv = @errorCast(op_error.?) },
                .write => .{ .write = @errorCast(op_error.?) },
                .writev => .{ .writev = @errorCast(op_error.?) },
                .close => .{ .close = @errorCast(op_error.?) },
                .timer => .{ .timer = @errorCast(op_error.?) },
                .cancel => .{ .cancel = @errorCast(op_error.?) },
            };

            task.state = .complete;

            // Safe removal - check if task is in the in_flight queue
            if (self.in_flight.hasItem(task)) {
                self.in_flight.remove(task);
            } else {
                log.warn("Task {*} ({any}) not found in in_flight queue during error cleanup", .{ task, task.req });
            }

            ring.free_q.push(task);
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
                log.debug("Task {any} (ptr: {*}) has MORE completions pending (flags={b})", .{ task.req, task, cqe.flags });
                task.state = .in_flight;
            } else {
                log.debug("Task {any} (ptr: {*}) has no more completions (flags={b}). Releasing.", .{ task.req, task, cqe.flags });
                task.state = .complete;

                // Safe removal - check if task is in the in_flight queue
                if (self.in_flight.hasItem(task)) {
                    self.in_flight.remove(task);
                } else {
                    log.warn("Task {*} ({any}) not found in in_flight queue during completion", .{ task, task.req });
                }

                ring.free_q.push(task);
            }
        }

        if (!skip_callback) {
            task.callback(ring, task.*) catch |cb_err| {
                log.err("Callback for task {any} (ptr: {*}) failed: {s}", .{ task.req, task, errorName(cb_err) });
            };
        } else {
            log.debug("Skipping callback for task {any} (ptr: {*}) due to skip_callback flag", .{ task.req, task });
        }
    }

    pub fn done(self: *IOUringBackend) bool {
        return self.in_flight.empty();
    }

    pub fn pollableFd(self: *IOUringBackend) !posix.fd_t {
        if (self.ring.fd < 0) return error.InvalidFd;
        return self.ring.fd;
    }

    fn errorName(err: anyerror) []const u8 {
        return @errorName(err);
    }
};
