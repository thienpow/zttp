// zttp/tests/async.zig
const std = @import("std");
const Async = @import("zttp").Async; // Import the main async module using its build system name

test "async module types compile" {
    // This test simply checks if the types can be defined without compilation errors.
    // It does not attempt to initialize or use the AsyncIoContext,
    // as the backend is currently a dummy.

    _ = Async.AsyncIoContext;
    _ = Async.Task;
    _ = Async.Request;
    _ = Async.Result;
    _ = Async.Context;
    _ = Async.OperationType;
    _ = Async.Timespec;
    _ = Async.ResultError;
    _ = Async.CancelError;
    _ = Async.RecvError;
    _ = Async.noopCallback; // Also test that the function pointer type is valid
}
