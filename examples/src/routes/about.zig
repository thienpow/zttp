// zttp/examples/src/routes/about.zig
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    ctx.set("logged_in", "false") catch return; // Default assumption
}
