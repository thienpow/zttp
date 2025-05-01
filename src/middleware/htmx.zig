// src/middleware/htmx.zig
const std = @import("std");

const http = @import("../http/mod.zig");
pub const Request = http.Request;
pub const Response = http.Response;

const core = @import("../core/mod.zig");
pub const Context = core.Context;

pub fn htmx(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    // Check for HTMX request by inspecting the HX-Request header
    const is_htmx = if (req.headers.get("HX-Request")) |hx_request|
        std.mem.eql(u8, hx_request, "true")
    else
        false;

    // Set is_htmx in the context
    ctx.set("is_htmx", if (is_htmx) "true" else "false") catch {
        std.log.warn("Failed to set is_htmx in context", .{});
        return;
    };

    // Call the next handler
    next(req, res, ctx);
}
