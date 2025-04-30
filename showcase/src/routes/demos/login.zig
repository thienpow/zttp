// showcase/src/routes/login.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

// Handler to display the login form
pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    ctx.set("logged_in", "false") catch return; // Not logged in when viewing form
}

// Handler to process the login form submission
pub fn post(req: *Request, res: *Response, ctx: *Context) void {
    var username: ?[]const u8 = null;
    var password: ?[]const u8 = null;

    // Access req.form - parsing usually happens implicitly here if needed
    if (req.form) |form| {
        username = form.get("username");
        password = form.get("password");
    } else {
        // This block might be reached if content-type wasn't form-urlencoded/multipart
        // or if parsing failed internally when accessing req.form implicitly.
        std.log.warn("Login POST received without parsable form data.", .{});
        // Re-render login form with a generic error
        res.status = .bad_request;
        ctx.set("logged_in", "false") catch {};
        ctx.set("error_message", "Could not read form data.") catch {};
        // No setTemplatePath - let router render the default login.zmx
        return;
    }

    // Simulate authentication
    if (username) |u| {
        // Check username first
        if (std.mem.eql(u8, u, "admin")) {
            // Then check if password is not null and capture its value
            if (password) |p| {
                // Then compare the password value
                if (std.mem.eql(u8, p, "password")) {
                    // --- Login Success ---
                    std.log.info("Simulated login success for user: {s}", .{u});
                    ctx.set("logged_in", "true") catch {};
                    // Redirect to homepage after successful login
                    // Use .see_other now that it's defined in the enum
                    res.status = .found; // HTTP 302
                    res.setHeader("Location", "/?logged_in=true") catch |err| {
                        // Fallback if setting header fails
                        std.log.err("Failed to set Location header for redirect after login: {any}", .{err});
                        res.status = .internal_server_error;
                        // res.clearHeaders(); // Function doesn't exist - removed
                        res.setHeader("Content-Type", "text/plain") catch {};
                        res.setBody("Login successful, but redirect failed.") catch {};
                    };
                    // No need to set context for index page here, as we are redirecting.
                    // Flash messages would require session state.
                    return; // Important: exit after setting redirect
                }
            }
        }
    }

    // --- Login Failure ---
    std.log.warn("Simulated login failed for user: {?s}", .{username});
    res.status = .unauthorized;
    ctx.set("logged_in", "false") catch {};
    ctx.set("error_message", "Invalid username or password.") catch {}; // Error message for login form
    ctx.set("submitted_username", username orelse "") catch {}; // Re-fill username field
}
