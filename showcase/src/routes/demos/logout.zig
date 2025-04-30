// showcase/src/routes/logout.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, _: *Context) void {
    // In a real app: clear session/cookie
    std.log.info("Simulated logout.", .{});

    // Manually set redirect headers and status
    // Use .see_other now that it's defined in the enum
    res.status = .found; // HTTP 302
    res.setHeader("HX-Redirect", "/?logged_in=false") catch |err| {
        // Fallback if redirect fails
        std.log.err("Failed to set Location header for redirect after logout: {any}", .{err});
        res.status = .internal_server_error;
        // Clear potentially conflicting headers if setHeader failed partially
        // res.clearHeaders(); // Function doesn't exist - removed
        res.setHeader("Content-Type", "text/plain") catch {};
        res.setBody("Logout processed, but redirect failed.") catch {};
        return; // Exit after setting error response
    };

    // if hx-redirect not available
    res.setHeader("Location", "/?logged_in=false") catch |err| {
        std.log.err("Failed to set Location header: {any}", .{err});
        // Continue, as HX-Redirect is already set
    };

    res.setBody("Redirecting...") catch {};
}
