const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, _: *Context) void {
    res.status = .ok;
    res.setJson(.{ .message = "JSON API endpoint" }) catch return;
    std.log.info("Served GET JSON API endpoint", .{});
}

pub fn post(_: *Request, res: *Response, _: *Context) void {
    res.status = .ok;
    res.setJson(.{ .message = "Posted to JSON API endpoint" }) catch return;
    std.log.info("Served POST JSON API endpoint", .{});
}
