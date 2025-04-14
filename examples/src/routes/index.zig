const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const message = if (ctx.get("request_id")) |rid|
        std.fmt.allocPrint(res.allocator, "Hello, World! Request ID: {s}", .{rid}) catch "Hello, World!"
    else
        "Hello, World!";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    std.log.info("Served GET hello endpoint", .{});
}

pub fn post(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const message = if (ctx.get("request_id")) |rid|
        std.fmt.allocPrint(res.allocator, "Posted! Request ID: {s}", .{rid}) catch "Posted!"
    else
        "Posted!";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    std.log.info("Served POST hello endpoint", .{});
}
