// zttp/src/async/io_uring.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const posix = std.posix; // For posix types like fd_t
const linux = std.os.linux; // For io_uring types and functions
const assert = std.debug.assert;
const log = std.log.scoped(.iouring); // Use a scoped logger

const Queue = @import("queue.zig").Intrusive;
const Task = @import("task.zig").Task;
const AsyncIoContext = @import("async.zig").AsyncIoContext; // Import the renamed context
// Import renamed types from op_request.zig
const OperationType = @import("op_request.zig").OperationType;
const Request = @import("op_request.zig").Request;
const Result = @import("op_request.zig").Result;
const ResultError = @import("op_request.zig").ResultError;
const CancelError = @import("op_request.zig").CancelError;
const RecvError = @import("op_request.zig").RecvError;

/// The io_uring specific backend implementation.
pub const IOUringBackend = struct {
    ring: linux.IoUring, // The main io_uring ring struct provided by Zig's std library
    in_flight: Queue(Task, .in_flight) = .{}, // Tasks currently submitted to the kernel

    /// Initializes the io_uring backend.
    /// `entries` is the requested size of the ring (number of SQEs/CQEs).
    pub fn init(entries: u16) anyerror!IOUringBackend {
        // Use reasonable setup flags:
        // IORING_SETUP_SQPOLL: Enable kernel submission thread (optional, but can be good for throughput)
        // IORING_SETUP_CLAMP: Clamp entries to system supported max
        // IORING_SETUP_CQSIZE: Set the CQ size explicitly (optional, defaults to 2*entries)
        // IORING_SETUP_SUBMIT_ALL: Continue submitting even if one SQE fails
        // IORING_SETUP_COOP_TASKRUN: Don't interrupt user thread for task completion
        // IORING_SETUP_SINGLE_ISSUER: Only one thread will issue submissions (true for our main loop)
        var params = std.mem.zeroInit(linux.io_uring_params, .{
            //.flags = linux.IORING_SETUP_SQPOLL | linux.IORING_SETUP_CLAMP | linux.IORING_SETUP_SUBMIT_ALL | linux.IORING_SETUP_COOP_TASKRUN | linux.IORING_SETUP_SINGLE_ISSUER,
            // Start simpler without SQPOLL and COOP/SINGLE, add later if needed
            .flags = linux.IORING_SETUP_CLAMP | linux.IORING_SETUP_SUBMIT_ALL,
            // .cq_entries = entries * 2, // Example: set CQ size larger than SQ
        });

        // Initialize the io_uring ring
        log.debug("Initializing io_uring with {} entries", .{entries});
        const ring: linux.IoUring = try linux.IoUring.init_params(entries, &params);
        log.debug("io_uring initialized (FD: {d})", .{ring.fd});

        return .{ .ring = ring };
    }

    /// Deinitializes the io_uring backend.
    /// Frees any tasks remaining in the in_flight queue.
    pub fn deinit(self: *IOUringBackend, gpa: Allocator) void {
        log.debug("IOUringBackend.deinit started", .{});

        // Free any tasks remaining in the in_flight queue
        while (self.in_flight.pop()) |task| {
            log.debug("IOUringBackend.deinit: Freeing in_flight task {any} (ptr: {*})", .{ task.req, task });
            gpa.destroy(task);
        }

        if (self.ring.fd >= 0) {
            log.debug("Deinitializing io_uring ring (FD: {d})", .{self.ring.fd});
            self.ring.deinit(); // Call the standard library's deinit for the ring
        }
        log.debug("IOUringBackend.deinit complete", .{});
    }

    /// Submits tasks from the submission queue to io_uring and blocks
    /// until at least one completion is available, then reaps completions.
    pub fn submitAndWait(self: *IOUringBackend, submission_q: *Queue(Task, .in_flight)) anyerror!void {
        // Prep SQEs for tasks in the submission queue. This also moves tasks to backend.in_flight.
        self.prepSubmissionQueue(submission_q) catch |err| {
            log.err("Failed to prep submission queue: {}", .{err});
            // Error handling needs refinement, tasks might be partially moved/prepped.
            // For now, assume failure means no new SQEs are ready, but existing ones might be.
            return err;
        };

        // Submit and wait for at least 1 completion
        // The number of submissions is the count of tasks newly prepped (now in ring's SQ).
        const submitted_count = self.ring.sq_ready();

        if (submitted_count > 0) {
            log.debug("Submitting {} SQEs and waiting for 1 completion", .{submitted_count});
            // enter(to_submit, min_complete, flags)
            _ = try self.ring.enter(submitted_count, 1, linux.IORING_ENTER_GETEVENTS);
        } else if (!self.in_flight.empty()) {
            // Submission queue was empty, but there are tasks already in-flight.
            // We need to wait for one of *those* to complete.
            // Submit 0 new, wait for 1 completion from existing ops.
            log.debug("Submission queue empty, but {} in-flight tasks. Waiting for 1 existing completion...", .{self.in_flight.len()});
            _ = try self.ring.enter(0, 1, linux.IORING_ENTER_GETEVENTS); // Wait for 1 completion
        } else {
            // No tasks to submit, and no tasks in-flight. Nothing to wait for.
            log.debug("Submission queue empty and no in-flight tasks. Skipping wait.", .{});
            // If submitAndWait is called in this state, the main loop design might need review.
            // A common pattern is to only call submitAndWait when AsyncIoContext.done() is false.
        }

        // Completions are now available. The main loop calls reapCompletions next.
    }

    /// Submits tasks from the submission queue to io_uring without waiting.
    pub fn submit(self: *IOUringBackend, submission_q: *Queue(Task, .in_flight)) anyerror!void {
        // Prep SQEs for tasks in the submission queue. This also moves tasks to backend.in_flight.
        self.prepSubmissionQueue(submission_q) catch |err| {
            log.err("Failed to prep submission queue: {}", .{err});
            return err;
        };

        // Submit all ready SQEs
        const submitted_count = self.ring.sq_ready();
        if (submitted_count > 0) {
            log.debug("Submitting {} SQEs without waiting", .{submitted_count});
            // enter(to_submit, min_complete, flags) or submit()
            _ = try self.ring.enter(submitted_count, 0, 0); // submit() is often just a wrapper around enter(count, 0, 0)
        } else {
            log.debug("Submission queue empty, nothing to submit", .{});
        }
    }

    /// Prepares Submission Queue Entries (SQEs) from the provided submission queue.
    /// Successfully prepped tasks are moved from `submission_q` to `self.in_flight`.
    fn prepSubmissionQueue(self: *IOUringBackend, submission_q: *Queue(Task, .in_flight)) Allocator.Error!void {
        log.debug("prepSubmissionQueue: Processing submission_q ({} tasks)", .{submission_q.len()});
        // We pop tasks one by one. If get_sqe fails, we push the current task back
        // to the front of the submission queue and stop.
        while (submission_q.pop()) |task| {
            const sqe = self.ring.get_sqe();
            if (sqe == null) {
                // SQ is full. Push the task back to the front of the *original* submission queue.
                submission_q.pushFront(task);
                log.warn("io_uring SQ full ({} ready), {any} (ptr: {*}) re-queued to front", .{ self.ring.sq_ready(), task.req, task });
                // Stop processing the rest of the submission queue for this round.
                return; // Exit the function
            }

            // Successfully got an SQE. Prep it.
            // The task's state should already be .in_flight because it came from submission_q
            // (which has the .in_flight state constraint).
            self.prepTask(sqe.?, task);

            // Add the task to the backend's in-flight queue.
            // State is already .in_flight, which matches the in_flight queue's constraint.
            self.in_flight.push(task);
            // Log FD from task.req for relevant types, not task.userdata generally
            const fd_for_log = switch (task.req) {
                .accept => |fd| fd,
                .recv => |r| r.fd,
                .write => |w| w.fd,
                .writev => |wv| wv.fd,
                .close => |fd| fd,
                // Other ops don't have a primary FD related to the request itself
                else => -1, // Placeholder for non-FD ops
            };
            log.debug("Prepped SQE for task {any} (ptr: {*}, FD: {d}), moved from submission_q to in_flight", .{ task.req, task, fd_for_log });
        }
        log.debug("prepSubmissionQueue: Finished processing submission_q. {} tasks now in_flight.", .{self.in_flight.len()});
    }

    /// Prepares a single Submission Queue Entry (SQE) for a Task.
    fn prepTask(_: *IOUringBackend, sqe: *linux.io_uring_sqe, task: *Task) void {
        // Store the Task pointer in the SQE's user_data.
        // When the completion comes back, cqe.user_data will hold this value.
        sqe.user_data = @intFromPtr(task);

        switch (task.req) {
            .noop => {
                log.debug("Prep SQE: noop", .{});
                sqe.prep_nop();
            },
            .accept => |fd| {
                log.debug("Prep SQE: accept (fd={d})", .{fd});
                // For accept, we typically pass null for addr and addr_len for non-blocking accept
                // or if we'll get the address later. Using 0 flags for now.
                // To make it multishot (keep accepting), we'd add linux.IORING_F_ACCEPT_MULTISHot
                // but let's start simpler with one accept per SQE.
                sqe.prep_accept(fd, null, null, 0); // Pass addr and addr_len pointers if you want to get address immediately
                // Add task.req.accept_addr / task.req.accept_addr_len if you modify Request union
            },
            .recv => |req| {
                log.debug("Prep SQE: recv (fd={d}, len={d})", .{ req.fd, req.buffer.len });
                // Using prep_read which works for sockets too. recv/readv are also options.
                sqe.prep_read(req.fd, req.buffer.ptr, @intCast(req.buffer.len), 0); // Offset 0 for streams
            },
            .write => |req| {
                log.debug("Prep SQE: write (fd={d}, len={d})", .{ req.fd, req.buffer.len });
                // Using prep_write which works for sockets too. send/writev are also options.
                sqe.prep_write(req.fd, req.buffer.ptr, @intCast(req.buffer.len), 0); // Offset 0 for streams
            },
            .writev => |req| {
                log.debug("Prep SQE: writev (fd={d}, iovcnt={d})", .{ req.fd, req.vecs.len });
                // Use prep_writev for scatter/gather write
                sqe.prep_writev(req.fd, @ptrCast(req.vecs.ptr), @intCast(req.vecs.len), 0); // Offset 0 for streams
            },
            .close => |fd| {
                log.debug("Prep SQE: close (fd={d})", .{fd});
                sqe.prep_close(fd);
            },
            .timer => |ts| {
                // Timer implementation requires prep_timeout
                log.debug("Prep SQE: timer (sec={}, nsec={})", .{ ts.sec, ts.nsec });
                // Need a `struct timespec` variable to point to.
                // This struct needs to live until the completion.
                // Where to store it? It could be part of the Task's request union somehow,
                // or allocated separately and its pointer stored.
                // For now, let's submit a noop. Timer implementation is more involved.
                log.warn("Prep SQE: timer (not fully implemented yet)", .{});
                sqe.prep_nop(); // Submit a noop for now
            },
            .cancel => |cancel_req| {
                // Cancellation requires prep_cancel
                log.warn("Prep SQE: cancel (not fully implemented yet)", .{});
                switch (cancel_req) {
                    .task => |task_to_cancel| {
                        log.debug("Prep SQE: cancel task {any} (ptr: {*})", .{ task_to_cancel.req, task_to_cancel });
                        // prep_cancel takes the user_data of the SQE *being canceled*.
                        // This is the task pointer we stored earlier.
                        sqe.prep_cancel(@intFromPtr(task_to_cancel), 0);
                        // Note: Canceling might itself generate a CQE for the cancel task,
                        // AND/OR an error CQE for the canceled task.
                        // This logic needs careful handling in reapCompletions.
                        // For now, we submit the cancel request.
                    },
                    // Handle .all later
                }
            },
        }
    }

    /// Reaps and processes completed tasks from io_uring's Completion Queue (CQ).
    pub fn reapCompletions(self: *IOUringBackend, ring: *AsyncIoContext) anyerror!void {
        log.debug("reapCompletions started ({} in_flight)", .{self.in_flight.len()});
        var cqe_count: usize = 0;
        var iter = self.ring.peek_batch();
        while (iter.next()) |cqe| {
            cqe_count += 1;
            // Retrieve the original Task from user_data
            // Ensure the pointer is valid. If the task was canceled and freed early, this could be UB.
            // However, our task state/queue management tries to prevent this.
            const task: *Task = @ptrFromInt(cqe.user_data);
            log.debug("Reaping CQE for task type: {any} (ptr: {*}) with res={d}, flags={b}", .{ task.req, task, cqe.res, cqe.flags });

            // Check if the task was marked as canceled before its CQE arrived.
            // If state is .canceled, the cancel request handler marked it.
            // The cancel request handler (Task.cancel) is responsible for marking the task .canceled.
            // It's the cancel *completion* handler that might move the task to a synchronous queue.
            // Let's just check the task state here. If it's already .canceled, skip the original callback.
            const was_canceled_before_cqe = (task.state == .canceled);

            // Handle the completion result (sets task.result, updates task.state, potentially releases)
            self.handleCompletion(ring, task, cqe, was_canceled_before_cqe);

            // After processing, advance the CQ ring pointer. peek_batch handles this.
        }

        if (cqe_count > 0) {
            log.debug("Reaped {} completions", .{cqe_count});
        } else {
            log.debug("No completions to reap", .{});
        }
    }

    /// Translates a CQE result into the appropriate Task Result and handles callback/cleanup.
    /// `skip_callback`: if true, the task's main callback is not invoked (used for canceled tasks).
    fn handleCompletion(self: *IOUringBackend, ring: *AsyncIoContext, task: *Task, cqe: *linux.io_uring_cqe, skip_callback: bool) void {
        const res = cqe.res;
        var op_error: ?anyerror = null; // Store the error if any

        if (res < 0) {
            // Error occurred. Convert negative value to posix.E enum.
            const err = linux.E.fromInt(-res) catch {
                log.err("Unknown errno {} from io_uring for task {any} (ptr: {*})", .{ -res, task.req, task });
                op_error = error.Unexpected;
            };
            if (op_error == null) { // If conversion didn't already map to Unexpected
                log.debug("io_uring operation {any} (ptr: {*}) failed with errno: {s} ({d})", .{ task.req, task, @tagName(err), -res });
                // Map posix.E to our ResultError or specific errors
                op_error = switch (err) {
                    .ECANCELED => error.Canceled, // Use our ResultError.Canceled
                    .EAGAIN, .EWOULDBLOCK => {
                        log.err("Unexpected EAGAIN/EWOULDBLOCK for io_uring operation {any} (ptr: {*})", .{task.req});
                        error.Unexpected;
                    },
                    .ECONNRESET => {
                        // Specific error for recv
                        if (task.req == .recv) RecvError.ConnectionResetByPeer else error.Unexpected;
                    },
                    .EINVAL => ResultError.Invalid,
                    // Add more specific mappings if needed
                    else => error.Unexpected, // Map other errors to Unexpected
                };
            }

            // Set the error result based on the original request type
            task.result = switch (task.req) {
                // Need to cast the error to the correct union field type
                .noop => .{ .noop = @errorCast(op_error.?) }, // Noop doesn't typically error, but handle defensively
                .accept => .{ .accept = @errorCast(op_error.?) }, // Cast anyerror to ResultError!posix.fd_t's error set
                .recv => .{ .recv = @errorCast(op_error.?) }, // Cast anyerror to RecvError!usize's error set
                .write => .{ .write = @errorCast(op_error.?) }, // Cast anyerror to ResultError!usize's error set
                .writev => .{ .writev = @errorCast(op_error.?) }, // Cast anyerror to ResultError!usize's error set
                .close => .{ .close = @errorCast(op_error.?) }, // Cast anyerror to ResultError!void's error set
                .timer => .{ .timer = @errorCast(op_error.?) }, // Cast anyerror to ResultError!void's error set
                .cancel => .{ .cancel = @errorCast(op_error.?) }, // Cast anyerror to CancelError!void's error set
            };

            // For errors, the operation is complete.
            // Mark as complete and release.
            task.state = .complete;
            self.in_flight.remove(task); // Remove from the backend's in_flight queue
            ring.free_q.push(task); // Return to the AsyncIoContext's free_q

        } else {
            // Success result (res >= 0)
            var success_result: Result = undefined; // Declare result here

            switch (task.req) {
                .noop => success_result = .noop, // Noop result is just void success
                .accept => {
                    // For accept, res is the new file descriptor on success
                    log.debug("Accept success, new FD: {d}", .{res});
                    success_result = .{ .accept = @intCast(res) };
                },
                .recv => {
                    // For recv, res is the number of bytes read
                    log.debug("Recv success, bytes read: {d}", .{res});
                    success_result = .{ .recv = @intCast(res) };
                },
                .write, .writev => {
                    // For write/writev, res is the number of bytes written
                    log.debug("Write success, bytes written: {d}", .{res});
                    success_result = if (task.req == .write) .{ .write = @intCast(res) } else .{ .writev = @intCast(res) };
                },
                .close => {
                    // For close, res is typically 0 on success
                    log.debug("Close success", .{});
                    success_result = .{ .close = {} };
                },
                .timer => {
                    // For timers, res is 0 on success (timer expired)
                    log.debug("Timer expired", .{});
                    success_result = .{ .timer = {} };
                },
                .cancel => {
                    // For cancel, res is 0 on success (kernel operation was likely canceled or wasn't pending)
                    // Negative results were handled above.
                    log.debug("Cancel request completed successfully", .{});
                    success_result = .{ .cancel = {} };
                    // The task being canceled might get its own CQE with ECANCELED.
                    // Its state/release is handled by its own CQE processing.
                },
            }
            // Set the task's result
            task.result = success_result;

            // Mark the task state complete or in-flight based on io_uring flags.
            // If F_MORE is set, the operation is NOT fully completed,
            // so the task remains in the in_flight queue.
            // Otherwise, the task is fully complete and released.
            if (cqe.flags & linux.IORING_CQE_F_MORE != 0) {
                log.debug("Task {any} (ptr: {*}) has MORE completions pending (flags={b})", .{ task.req, task, cqe.flags });
                task.state = .in_flight; // Explicitly confirm state remains in_flight
                // Do not remove from self.in_flight or return to free_q yet
            } else {
                log.debug("Task {any} (ptr: {*}) has no more completions (flags={b}). Releasing.", .{ task.req, task });
                task.state = .complete; // Mark as complete
                self.in_flight.remove(task); // Remove from backend's in_flight queue
                ring.free_q.push(task); // Return to the AsyncIoContext's free_q
            }
        }

        // Call the completion callback unless skipped (e.g., due to cancellation processed elsewhere)
        if (!skip_callback) {
            task.callback(ring, task.*) catch |cb_err| { // Pass task.* to avoid mutable pointer issue if callback changes state
                log.err("Callback for task {any} (ptr: {*}) failed: {}", .{ task.req, task, cb_err });
                // Depending on the error, maybe log, or retry the callback, or shut down?
                // For now, just log and proceed. The task's state and result are already set.
            };
        } else {
            log.debug("Skipping callback for task {any} (ptr: {*}) due to skip_callback flag", .{ task.req, task });
            // If the original callback is skipped, the task is still handled (state, release)
            // but the user's direct response to the original operation completion is suppressed.
            // This is appropriate if a cancel handler is the primary responder.
        }
    }

    /// Checks if there are any tasks currently submitted to the kernel queues.
    /// This is a rough indicator of whether the backend is still busy.
    pub fn done(self: *IOUringBackend) bool {
        // Check if our internal in_flight queue is empty.
        // This queue should hold tasks that have been submitted but haven't
        // received their final completion CQE yet.
        return self.in_flight.empty();
        // Also checking ring.sq_ready() and ring.cq_ready() could be more precise
        // but in_flight should track everything we *expect* a completion for.
        // Let's rely on in_flight.empty() as the primary indicator for the backend.
    }

    /// Returns the file descriptor associated with the io_uring instance.
    /// This can be used by an external event loop (like poll/epoll) to wait
    /// for completions.
    pub fn pollableFd(self: *IOUringBackend) !posix.fd_t {
        if (self.ring.fd < 0) return error.InvalidFd;
        return self.ring.fd;
    }
};

// Error mapping helper (similar to ourio, but adapted for io_uring's res)
fn cqeResToE(result: i32) std.posix.E {
    // io_uring results are typically positive for success values,
    // or negative for kernel error numbers (-errno).
    if (result > -4096 and result < 0) { // Heuristic to distinguish errors from large positive values
        return @as(std.posix.E, @enumFromInt(-result));
    }
    return .SUCCESS; // Assume success if not a standard negative errno range
}
