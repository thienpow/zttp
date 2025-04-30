// showcase/src/routes/demos/chat/index.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, _: *Context) void {
    res.status = .ok;
}
