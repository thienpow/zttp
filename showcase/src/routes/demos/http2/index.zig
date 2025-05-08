const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.http2_demo_handler);

pub fn get(req: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;

    // --- Set up common layout variables (assuming layout.zmx needs these) ---
    // Simulate logged in and username for layout nav consistency
    ctx.set("logged_in", "false") catch |e| log.err("Failed to set logged_in: {any}", .{e});
    ctx.set("username", "Guest") catch |e| log.err("Failed to set username: {any}", .{e});

    // --- HTTP/2 Specific Information ---
    // Pass the detected protocol version to the template
    ctx.set("request_protocol", req.version) catch |e| log.err("Failed to set request_protocol: {any}", .{e});

    // We don't need to explicitly handle Http2Connection here in the handler.
    // The ZTTP server automatically negotiates the protocol (HTTP/1.1 or HTTP/2).
    // By requesting this page, the browser *might* use HTTP/2 if the server
    // (configured in showcase/src/main.zig) supports it and the browser agrees.
    // The template will simply report which protocol version was received by this handler.
}
