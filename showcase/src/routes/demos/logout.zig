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
    res.status = .see_other; // HTTP 303 See Other
    res.setHeader("Location", "/") catch |err| {
        // Fallback if redirect fails
        std.log.err("Failed to set Location header for redirect after logout: {any}", .{err});
        res.status = .internal_server_error;
        // Clear potentially conflicting headers if setHeader failed partially
        // res.clearHeaders(); // Function doesn't exist - removed
        res.setHeader("Content-Type", "text/plain") catch {};
        res.setBody("Logout processed, but redirect failed.") catch {};
        return; // Exit after setting error response
    };

    // Optionally set a minimal body for clients that don't follow redirects, though often not needed.
    // res.setBody("Redirecting...") catch {}; // Usually not necessary
}
