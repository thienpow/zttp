const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const posix = std.posix;
const assert = std.debug.assert;
const log = std.log.scoped(.kqueue);

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

/// Backend for AsyncIo using kqueue (BSD/macOS).
/// Manages the kqueue instance and an in_flight queue of tasks.
/// Single-threaded: no mutex, as server is single-threaded.
pub const KqueueBackend = struct {
    kq: posix.fd_t,
    in_flight: Queue(Task, .queue) = .{},
    timer_counter: u64 = 0, // Unique identifier for timers

    /// Initializes a kqueue instance.
    pub fn init(_: u16) anyerror!KqueueBackend {
        if (builtin.os.tag != .macos and builtin.os.tag != .freebsd and builtin.os.tag != .netbsd and builtin.os.tag != .openbsd and builtin.os.tag != .dragonfly) {
            @compileError("Kqueue backend only supports BSD/macOS systems");
        }

        const kq = try posix.kqueue();
        return .{ .kq = kq };
    }

    /// Deinitializes the kqueue instance.
    /// Task deallocation is handled by AsyncIo.deinit.
    pub fn deinit(self: *KqueueBackend, _: Allocator) void {
        if (self.kq >= 0) {
            posix.close(self.kq);
            self.kq = -1;
        }
    }

    /// Submits tasks from submission_q and waits for at least one completion.
    /// Returns the number of tasks successfully prepped.
    pub fn submitAndWait(self: *KqueueBackend, submission_q: *Queue(Task, .queue)) anyerror!usize {
        const prepped_count = try self.prepSubmissionQueue(submission_q);
        if (prepped_count > 0 or !self.in_flight.empty()) {
            try self.reapCompletionsWait();
        }
        return prepped_count;
    }

    /// Submits tasks from submission_q without waiting.
    /// Returns the number of tasks successfully prepped.
    pub fn submit(self: *KqueueBackend, submission_q: *Queue(Task, .queue)) anyerror!usize {
        return try self.prepSubmissionQueue(submission_q);
    }

    /// Prepares tasks from submission_q, moving them to in_flight.
    /// Returns the number of tasks successfully prepped.
    fn prepSubmissionQueue(self: *KqueueBackend, submission_q: *Queue(Task, .queue)) anyerror!usize {
        var prepped_count: usize = 0;
        var changelist: [16]posix.Kevent = undefined;
        var change_idx: usize = 0;

        while (submission_q.pop()) |task| {
            if (change_idx >= changelist.len) {
                // Apply pending changes
                try self.applyChanges(changelist[0..change_idx]);
                change_idx = 0;
            }

            self.prepTask(&changelist[change_idx], task);
            change_idx += 1;
            self.in_flight.push(task);
            prepped_count += 1;
        }

        if (change_idx > 0) {
            try self.applyChanges(changelist[0..change_idx]);
        }

        return prepped_count;
    }

    /// Applies kevent changes to the kqueue.
    fn applyChanges(self: *KqueueBackend, changelist: []posix.Kevent) !void {
        _ = try posix.kevent(self.kq, changelist, &[_]posix.Kevent{}, null);
    }

    /// Prepares a kevent for a task based on its request type.
    fn prepTask(self: *KqueueBackend, kev: *posix.Kevent, task: *Task) void {
        kev.udata = @intFromPtr(task);
        kev.flags = posix.EV_ADD | posix.EV_ONESHOT;
        kev.fflags = 0;
        kev.data = 0;

        switch (task.req) {
            .noop => {
                // Use a user event for noop
                kev.ident = @intFromPtr(task);
                kev.filter = posix.EVFILT_USER;
                kev.fflags = posix.NOTE_TRIGGER;
            },
            .accept => |fd| {
                kev.ident = @intCast(fd);
                kev.filter = posix.EVFILT_READ;
            },
            .recv => |req| {
                kev.ident = @intCast(req.fd);
                kev.filter = posix.EVFILT_READ;
                kev.data = @intCast(req.buffer.len);
            },
            .write => |req| {
                kev.ident = @intCast(req.fd);
                kev.filter = posix.EVFILT_WRITE;
                kev.data = @intCast(req.buffer.len);
            },
            .writev => |req| {
                kev.ident = @intCast(req.fd);
                kev.filter = posix.EVFILT_WRITE;
                var total_len: usize = 0;
                for (req.vecs) |vec| {
                    total_len += vec.iov_len;
                }
                kev.data = @intCast(total_len);
            },
            .close => |fd| {
                // Close is handled immediately
                kev.ident = @intCast(fd);
                kev.filter = posix.EVFILT_USER;
                kev.fflags = posix.NOTE_TRIGGER;
            },
            .timer => |ts| {
                kev.ident = self.timer_counter;
                self.timer_counter += 1;
                kev.filter = posix.EVFILT_TIMER;
                kev.fflags = posix.NOTE_NSECONDS;
                kev.data = ts.nsec;
                if (ts.sec > 0) {
                    kev.data += ts.sec * 1_000_000_000;
                }
            },
            .cancel => |cancel_req| {
                switch (cancel_req) {
                    .task => |task_to_cancel| {
                        kev.ident = @intFromPtr(task_to_cancel);
                        kev.filter = posix.EVFILT_USER;
                        kev.fflags = posix.NOTE_TRIGGER;
                    },
                    .all => {
                        kev.ident = @intFromPtr(task);
                        kev.filter = posix.EVFILT_USER;
                        kev.fflags = posix.NOTE_TRIGGER;
                    },
                }
            },
        }
    }

    /// Reaps completed events and processes them.
    pub fn reapCompletions(self: *KqueueBackend, async_io: *AsyncIo) anyerror!void {
        var events: [16]posix.Kevent = undefined;
        const num_events = try posix.kevent(self.kq, &[_]posix.Kevent{}, &events, null);
        for (events[0..num_events]) |ev| {
            const task: *Task = @ptrFromInt(ev.udata);
            if (!self.in_flight.hasItem(task)) {
                log.err("Invalid task pointer {*}, udata={d} not in in_flight queue, skipping event", .{ task, ev.udata });
                continue;
            }
            self.handleCompletion(async_io, task, &ev);
        }
    }

    /// Reaps completions with a wait.
    fn reapCompletionsWait(self: *KqueueBackend) !void {
        var events: [16]posix.Kevent = undefined;
        const num_events = try posix.kevent(self.kq, &[_]posix.Kevent{}, &events, &.{ .sec = 0, .nsec = 100_000_000 }); // 100ms
        for (events[0..num_events]) |ev| {
            const task: *Task = @ptrFromInt(ev.udata);
            if (!self.in_flight.hasItem(task)) {
                log.err("Invalid task pointer {*}, udata={d} not in in_flight queue, skipping event", .{ task, ev.udata });
                continue;
            }
            self.handleCompletion(self.async_io, task, &ev);
        }
    }

    /// Processes a single kevent for a task.
    fn handleCompletion(self: *KqueueBackend, async_io: *AsyncIo, task: *Task, ev: *const posix.Kevent) void {
        var op_error: ?anyerror = null;
        var success_result: ?Result = null;

        if (ev.flags & posix.EV_ERROR != 0) {
            const errno = ev.data;
            op_error = switch (errno) {
                posix.E.BADF, posix.E.FAULT => if (task.req == .recv or task.req == .write or task.req == .writev) error.Unexpected else error.BadFileDescriptor,
                posix.E.CANCELED => error.Canceled,
                posix.E.CONNRESET => if (task.req == .recv) RecvError.ConnectionResetByPeer else error.ConnectionReset,
                posix.E.PIPE => if (task.req == .recv) error.Unexpected else error.BrokenPipe,
                posix.E.INVAL => error.InvalidArgument,
                posix.E.AGAIN => if (task.req == .recv) error.WouldBlock else error.WouldBlock,
                posix.E.CONNREFUSED => error.ConnectionRefused,
                posix.E.NOTCONN => error.NotConnected,
                posix.E.NOENT => if (task.req == .cancel) error.EntryNotFound else error.Unexpected,
                else => error.Unexpected,
            };
        } else {
            switch (task.req) {
                .noop => {
                    success_result = .{ .noop = {} };
                },
                .accept => {
                    var addr: posix.sockaddr = undefined;
                    var addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
                    const new_fd = posix.accept(task.req.accept, &addr, &addrlen) catch |err| {
                        op_error = mapPosixError(err);
                        return;
                    };
                    success_result = .{ .accept = new_fd };
                },
                .recv => |req| {
                    const bytes_read = posix.recv(req.fd, req.buffer, 0) catch |err| {
                        op_error = mapPosixError(err);
                        return;
                    };
                    success_result = .{ .recv = bytes_read };
                },
                .write => |req| {
                    const bytes_written = posix.write(req.fd, req.buffer, 0) catch |err| {
                        op_error = mapPosixError(err);
                        return;
                    };
                    success_result = .{ .write = bytes_written };
                },
                .writev => |req| {
                    const bytes_written = posix.writev(req.fd, req.vecs) catch |err| {
                        op_error = mapPosixError(err);
                        return;
                    };
                    success_result = .{ .writev = bytes_written };
                },
                .close => {
                    posix.close(task.req.close) catch |err| {
                        op_error = mapPosixError(err);
                        return;
                    };
                    success_result = .{ .close = {} };
                },
                .timer => {
                    success_result = .{ .timer = {} };
                },
                .cancel => {
                    if (task.req.cancel == .all) {
                        while (self.in_flight.pop()) |t| {
                            t.state = .canceled;
                            t.result = .{ .cancel = error.Canceled };
                            t.callback(async_io, t) catch |cb_err| {
                                log.err("Callback for canceled task (ptr: {*}, req: {s}) failed: {s}", .{ t, taskReqName(t.req), @errorName(cb_err) });
                            };
                            async_io.resetTask(t);
                            async_io.free_q.push(t);
                        }
                    } else if (task.req.cancel == .task) |t| {
                        if (self.in_flight.hasItem(t)) {
                            self.in_flight.remove(t);
                            t.state = .canceled;
                            t.result = .{ .cancel = error.Canceled };
                            t.callback(async_io, t) catch |cb_err| {
                                log.err("Callback for canceled task (ptr: {*}, req: {s}) failed: {s}", .{ t, taskReqName(t.req), @errorName(cb_err) });
                            };
                            async_io.resetTask(t);
                            async_io.free_q.push(t);
                        } else {
                            op_error = error.EntryNotFound;
                        }
                    }
                    success_result = .{ .cancel = {} };
                },
            }
        }

        task.result = if (op_error) |err| switch (task.req) {
            .noop => .{ .noop = {} },
            .accept => .{ .accept = @errorCast(err) },
            .recv => .{ .recv = @errorCast(err) },
            .write => .{ .write = @errorCast(err) },
            .writev => .{ .writev = @errorCast(err) },
            .close => .{ .close = @errorCast(err) },
            .timer => .{ .timer = @errorCast(err) },
            .cancel => .{ .cancel = @errorCast(err) },
        } else success_result.?;

        task.state = if (op_error) |err| (if (err == error.Canceled) .canceled else .complete) else .complete;

        self.in_flight.remove(task);
        task.callback(async_io, task) catch |cb_err| {
            log.err("Callback for task (ptr: {*}, req: {s}) failed: {s}", .{ task, taskReqName(task.req), @errorName(cb_err) });
        };
        async_io.resetTask(task);
        async_io.free_q.push(task);
    }

    /// Returns true if no tasks are in_flight.
    pub fn done(self: *KqueueBackend) bool {
        return self.in_flight.empty();
    }

    /// Returns the kqueue file descriptor for polling.
    pub fn pollableFd(self: *KqueueBackend) !posix.fd_t {
        if (self.kq < 0) return error.InvalidFd;
        return self.kq;
    }

    /// Maps POSIX errors to ResultError, RecvError, or CancelError.
    fn mapPosixError(err: anyerror) anyerror {
        return switch (err) {
            error.BadFileDescriptor, error.InvalidHandle => error.BadFileDescriptor,
            error.ConnectionRefused => error.ConnectionRefused,
            error.ConnectionResetByPeer => RecvError.ConnectionResetByPeer,
            error.BrokenPipe => error.BrokenPipe,
            error.WouldBlock => error.WouldBlock,
            error.NotConnected => error.NotConnected,
            error.InvalidArgument => error.InvalidArgument,
            error.ConnectionTimedOut => error.TimedOut,
            else => error.Unexpected,
        };
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
