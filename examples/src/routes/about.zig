// zttp/examples/src/routes/about.zig
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    // Set context variables needed by the layout and this page
    //ctx.set("site_name", "My Awesome Site") catch return;
    //ctx.set("page_title", "About Us") catch return;
    // Assuming logged_in state might be needed by the layout's nav
    // In a real app, this would come from session/cookie check
    ctx.set("logged_in", "false") catch return; // Default assumption
    // Template rendering is handled by the server based on route config
}
