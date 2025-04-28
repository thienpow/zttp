// zttp/src/async/task.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const AsyncIo = @import("async.zig").AsyncIo; // Renamed from Ring
const Context = @import("async.zig").Context;
const Request = @import("op_request.zig").Request;
const Result = @import("op_request.zig").Result;
const OperationType = @import("op_request.zig").OperationType; // Import the renamed enum

pub const Task = struct {
    userdata: ?*anyopaque = null, // User data pointer for the callback
    msg: u16 = 0, // User message/enum discriminator for the callback
    callback: *const fn (*AsyncIo, Task) anyerror!void, // Callback signature uses AsyncIo

    req: Request = .noop, // The definition of the asynchronous request
    result: ?Result = null, // The result of the operation once completed

    /// State for internal queue management (used by IntrusiveQueue)
    state: enum {
        free, // The task is available for a new operation
        in_flight, // The task has been submitted to the backend and is pending
        complete, // The backend completed the task, waiting for callback or cleanup (less used in this design)
        canceled, // The task was canceled
    } = .free,

    next: ?*Task = null, // Next pointer for IntrusiveQueue
    prev: ?*Task = null, // Previous pointer for IntrusiveQueue (if using doubly linked)

    /// Helper to cast the userdata pointer to a specific type.
    pub fn userdataCast(self: Task, comptime T: type) *T {
        return @ptrCast(@alignCast(self.userdata));
    }

    /// Helper to cast the msg field to an enum.
    pub fn msgToEnum(self: Task, comptime Enum: type) Enum {
        return @enumFromInt(self.msg);
    }

    /// Attempts to cancel this specific task.
    /// Returns a task representing the cancellation request itself.
    /// The original task's callback will be invoked with `error.Canceled` if successful.
    /// Requires the backend to support cancellation.
    ///
    /// This method will be implemented later, after the backend supports cancel.
    pub fn cancel(
        self: *Task, // The task to be canceled
        ring: *AsyncIo, // Uses AsyncIo
        ctx: Context, // Context for the cancellation *request's* completion
    ) Allocator.Error!*Task {
        // Create a new Task for the cancel request itself
        const cancel_req_task = try ring.getTask();
        cancel_req_task.* = .{
            .userdata = ctx.ptr,
            .msg = ctx.msg,
            .callback = ctx.cb,
            .req = .{ .cancel = .{ .task = self } }, // This request is to cancel `self`
            .state = .in_flight,
        };
        ring.submission_q.push(cancel_req_task);
        return cancel_req_task;
    }
};
