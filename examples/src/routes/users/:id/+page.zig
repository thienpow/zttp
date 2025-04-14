// src/routes/users_id.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub const method = "GET";
pub const path = "/users/:id"; // Define a path with parameters

pub fn handler(req: *Request, res: *Response, ctx: *Context) void {
    _ = req;
    res.status = .ok;
    const user_id = ctx.get("id") orelse "unknown";
    const message = std.fmt.allocPrint(res.allocator, "User ID: {s}", .{user_id}) catch "Error";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    std.log.info("Served user endpoint with id: {s}", .{user_id});
}
