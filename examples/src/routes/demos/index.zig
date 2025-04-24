// zttp/examples/src/routes/demos/index.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.demos_index_handler);

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;

    // Set context variables primarily for layout consistency (nav bar)
    // These aren't strictly required by demos/index.zmx itself.
    ctx.set("logged_in", "false") catch |e| log.err("Failed to set logged_in: {any}", .{e}); // Assume guest for demo index
    ctx.set("username", "Guest") catch |e| log.err("Failed to set username: {any}", .{e});

    // Optional: Add a page-specific heading if desired, overriding layout default
    // ctx.set("page_heading", "ZTTP Live Demos") catch |e| log.err("Failed to set page_heading: {any}", .{e});

    // Template rendering (routes/demos/index.zmx) is handled by the server based on routing rules.
    log.debug("Served GET /demos index page.", .{});
}
