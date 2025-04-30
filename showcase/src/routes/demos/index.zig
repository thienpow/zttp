// showcase/src/routes/demos/index.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.demos_index_handler);

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;

    ctx.set("logged_in", "false") catch |e| log.err("Failed to set logged_in: {any}", .{e});
    ctx.set("username", "Guest") catch |e| log.err("Failed to set username: {any}", .{e});
}
