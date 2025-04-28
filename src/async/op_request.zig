// zttp/src/async/op_request.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const posix = std.posix;
const Task = @import("task.zig").Task;
const Timespec = @import("async.zig").Timespec; // Timespec definition is now in async.zig

/// Defines the type of asynchronous request.
pub const OperationType = enum { // Renamed from Op
    noop,
    accept,
    recv,
    write,
    writev,
    close,
    timer, // For future timer support
    cancel, // Request to cancel another task
};

/// Defines the possible result types for asynchronous operations.
/// The specific union field corresponds to the `OperationType` of the request.
pub const Result = union(OperationType) { // Union tag uses OperationType
    noop,
    accept: ResultError!posix.fd_t, // Result is the new client FD on success
    recv: RecvError!usize, // Result is number of bytes read on success
    write: ResultError!usize, // Result is number of bytes written on success
    writev: ResultError!usize, // Result is number of bytes written on success
    close: ResultError!void,
    timer: ResultError!void, // Timer expired successfully
    cancel: CancelError!void, // Cancellation request completed
};

/// Error set for asynchronous operation results.
pub const ResultError = error{
    /// The request parameters were invalid.
    Invalid,
    /// The operation was canceled before completion.
    Canceled,
    /// An unexpected system or I/O error occurred.
    Unexpected,
    /// The operation timed out.
    TimedOut,
};

/// Error set specifically for cancellation results.
pub const CancelError = ResultError || error{
    /// The task to be canceled was not found or not in a cancellable state.
    EntryNotFound,
    /// The cancellation request could not be processed.
    NotCanceled,
};

/// Error set specifically for receive operations.
pub const RecvError = ResultError || error{
    /// The connection was reset by the peer.
    ConnectionResetByPeer,
    /// The provided buffer was too small for the received data.
    BufferTooSmall, // May not be relevant for basic read/recv, but good to have.
};

/// Defines the parameters for an asynchronous request.
pub const Request = union(OperationType) { // Union tag uses OperationType
    noop,
    accept: posix.fd_t, // Server socket FD to accept on
    recv: struct {
        fd: posix.fd_t,
        buffer: []u8,
    },
    write: struct {
        fd: posix.fd_t,
        buffer: []const u8,
    },
    writev: struct {
        fd: posix.fd_t,
        vecs: []const posix.iovec_const,
    },
    close: posix.fd_t,
    timer: Timespec, // Duration for the timer
    cancel: union(enum) {
        task: *Task, // The specific task to cancel
        // Add .all later if needed
    },
};
