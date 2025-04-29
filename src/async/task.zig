// src/async/task.zig
const std = @import("std");
const AsyncIo = @import("async.zig").AsyncIo;
const Request = @import("op_request.zig").Request;
const Result = @import("op_request.zig").Result;
const Callback = @import("async.zig").Callback;

pub const TaskState = enum {
    free,
    in_flight,
    complete,
    canceled,
};

pub const QueueLinks = struct {
    next: ?*Task = null,
    prev: ?*Task = null,
};

pub const Task = struct {
    userdata: ?*anyopaque = null,
    msg: u16 = 0,
    callback: Callback,
    req: Request,
    result: ?Result = null,
    state: TaskState = .free,
    queue: QueueLinks = .{},
};
