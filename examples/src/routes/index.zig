// examples/src/routes/index.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.index_handler);

// Helper to safely set context with logging
fn setCtx(ctx: *Context, key: []const u8, value: []const u8) void {
    ctx.set(key, value) catch |err| {
        log.err("Failed to set context '{s}': {any}", .{ key, err });
    };
}

// Helper to get optional query param or default (still useful for demo login)
fn getQueryParam(req: *Request, key: []const u8, default_value: []const u8) []const u8 {
    return req.query.get(key) orelse default_value;
}

pub fn get(req: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;

    const is_logged_in = std.mem.eql(u8, getQueryParam(req, "logged_in", "false"), "true");
    setCtx(ctx, "logged_in", if (is_logged_in) "true" else "false");

    if (is_logged_in) {
        // Get username from query param, default to "User"
        const raw_username = getQueryParam(req, "username", "User");

        // Allocate the username onto the response arena so it persists for the template
        const dupe_result = res.allocator.dupe(u8, raw_username);
        if (dupe_result) |duped_username| {
            setCtx(ctx, "username", duped_username);
        } else |err| {
            log.err("Failed to allocate memory for username: {any}", .{err});
            setCtx(ctx, "username", "User"); // Fallback to default if alloc fails
        }
    }

    log.debug("Context set for GET /: logged_in={s}", .{
        ctx.get("logged_in") orelse "N/A",
    });
}
