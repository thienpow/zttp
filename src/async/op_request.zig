// src/async/op_request.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const posix = std.posix;
const Task = @import("task.zig").Task;
const Timespec = @import("async.zig").Timespec;

/// Type of asynchronous request, corresponding to supported io_uring operations.
pub const OperationType = enum {
    /// No-op operation for testing or synchronization.
    noop,
    /// Accept a new connection on a server socket.
    accept,
    /// Receive data from a socket into a buffer.
    recv,
    /// Send data from a buffer over a socket.
    write,
    /// Send multiple buffers (scatter) over a socket.
    writev,
    /// Close a file descriptor.
    close,
    /// Set a timer to expire after a duration.
    timer,
    /// Cancel a specific task or all tasks.
    cancel,
};

/// Result of an asynchronous operation, tagged by the OperationType.
/// Each variant contains either a successful outcome or an error.
pub const Result = union(OperationType) {
    /// No-op completed successfully.
    noop: void,
    /// New client file descriptor on success, or error.
    accept: ResultError!posix.fd_t,
    /// Number of bytes read on success, or error.
    recv: RecvError!usize,
    /// Number of bytes written on success, or error.
    write: ResultError!usize,
    /// Number of bytes written on success, or error.
    writev: ResultError!usize,
    /// Close completed successfully, or error.
    close: ResultError!void,
    /// Timer expired successfully, or error.
    timer: ResultError!void,
    /// Cancellation request completed successfully, or error.
    cancel: CancelError!void,
};

/// Common errors for asynchronous operations.
pub const ResultError = error{
    /// Invalid request parameters (e.g., bad FD, buffer).
    Invalid,
    /// Operation was canceled before completion.
    Canceled,
    /// Unexpected system or I/O error.
    Unexpected,
    /// Operation timed out (e.g., no data received).
    TimedOut,
    /// Connection was reset by peer.
    ConnectionReset,
    /// Bad file descriptor.
    BadFileDescriptor,
    /// Invalid argument provided.
    InvalidArgument,
    /// Operation would block (e.g., non-blocking socket).
    WouldBlock,
    /// Connection refused by remote host.
    ConnectionRefused,
    /// Socket not connected.
    NotConnected,
    /// Broken pipe (write to closed connection).
    BrokenPipe,
};

/// Errors specific to cancellation operations.
pub const CancelError = ResultError || error{
    /// Task to cancel was not found or not cancellable.
    EntryNotFound,
    /// Cancellation request could not be processed.
    NotCanceled,
};

/// Errors specific to receive operations.
pub const RecvError = ResultError || error{
    /// Connection was reset by the peer during receive.
    ConnectionResetByPeer,
    /// Provided buffer was too small for received data.
    BufferTooSmall,
};

/// Parameters for an asynchronous request, tagged by OperationType.
pub const Request = union(OperationType) {
    /// No-op request (no parameters).
    noop: void,
    /// Server socket FD to accept a connection on.
    accept: posix.fd_t,
    /// Parameters for receiving data.
    recv: struct {
        fd: posix.fd_t, // Socket FD
        buffer: []u8, // Buffer to read into
    },
    /// Parameters for sending data.
    write: struct {
        fd: posix.fd_t, // Socket FD
        buffer: []const u8, // Buffer to write from
    },
    /// Parameters for scatter write.
    writev: struct {
        fd: posix.fd_t, // Socket FD
        vecs: []const posix.iovec_const, // I/O vectors
    },
    /// File descriptor to close.
    close: posix.fd_t,
    /// Duration for a timer.
    timer: Timespec,
    /// Cancellation target (specific task or all tasks).
    cancel: union(enum) {
        task: *Task, // Specific task to cancel
        all: void, // Cancel all in-flight tasks
    },
};
