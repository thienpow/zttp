// zttp/examples/src/routes/profile/index.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    // --- Simulated Auth Check ---
    // In a real app, check session/cookie here.
    // We'll *assume* if someone hits this handler *after* login POST succeeded,
    // the context *might* be set appropriately *if we didn't redirect*.
    // Since our login POST renders index directly, accessing /profile requires
    // a manual setup or a proper session.
    // Let's PRETEND the user is logged in for demonstration purposes here.
    const is_logged_in = true; // FAKE IT for demonstration
    const username = "admin"; // FAKE IT

    if (!is_logged_in) {
        // If we had real auth check and it failed:
        res.redirect("/login", .see_other) catch |err| {
            std.log.err("Failed to redirect to login: {any}", .{err});
            res.status = .internal_server_error;
            res.setBody("Redirect to login failed.") catch {};
        };
        return;
    }

    // --- Render Profile Page ---
    res.status = .ok;
    // Set context for the profile page and its specific layout
    ctx.set("profile_user", username) catch return;
    ctx.set("user_email", "admin@example.com") catch return; // Example profile data
    // Template rendering (profile/index.zmx using profile/layout.zmx) is handled by the server
}
