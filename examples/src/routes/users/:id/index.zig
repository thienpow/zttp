const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const user_id = ctx.get("id") orelse "unknown";
    const message = std.fmt.allocPrint(res.arena.allocator(), "User ID: {s}", .{user_id}) catch "Error";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    // std.log.info("Served GET user endpoint with id: {s}", .{user_id});
}

pub fn post(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const user_id = ctx.get("id") orelse "unknown";
    const message = std.fmt.allocPrint(res.arena.allocator(), "Posted for User ID: {s}", .{user_id}) catch "Error";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    //std.log.info("Served POST user endpoint with id: {s}", .{user_id});
}
