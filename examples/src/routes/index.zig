const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub const method = "GET";
pub const path = "/";

pub fn handler(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const message = if (ctx.get("request_id")) |rid|
        std.fmt.allocPrint(res.allocator, "Hello, World! Request ID: {s}", .{rid}) catch "Hello, World!"
    else
        "Hello, World!";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    std.log.info("Served hello endpoint", .{});
}
