// showcase/src/routes/demo/components/index.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.component_handler);

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;

    // Simulate logged in for layout consistency if needed
    ctx.set("logged_in", "true") catch |e| log.err("Failed to set logged_in: {any}", .{e});
    ctx.set("username", "CompViewer") catch |e| log.err("Failed to set username: {any}", .{e});
}
