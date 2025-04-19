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

// Helper to get optional query param or default
fn getQueryParam(req: *Request, key: []const u8, default_value: []const u8) []const u8 {
    // --- FIX: Assume req.query is non-optional based on compiler error ---
    // Directly access 'get' on req.query.
    // This relies on zttp ensuring req.query is always a valid (possibly empty) map.
    return req.query.get(key) orelse default_value;
}

pub fn get(req: *Request, res: *Response, ctx: *Context) void {
    log.info("Handling GET / request", .{});
    res.status = .ok;

    // --- Basic Page/Layout Info ---
    setCtx(ctx, "site_name", "zttp Demo Site");
    setCtx(ctx, "page_title", "Welcome Home");
    setCtx(ctx, "page_heading", "zttp Framework Demo");

    // --- Authentication Simulation (via query param for demo) ---
    const is_logged_in = std.mem.eql(u8, getQueryParam(req, "logged_in", "false"), "true");
    setCtx(ctx, "logged_in", if (is_logged_in) "true" else "false");

    // --- User Info (conditional on login status) ---
    var username: []const u8 = "Guest";
    if (is_logged_in) {
        const raw_username = getQueryParam(req, "username", "DemoUser");
        var decoded_buf: [128]u8 = undefined;

        if (raw_username.len > decoded_buf.len) {
            log.warn("Username query param too long for decoding buffer: '{s}'", .{raw_username});
            username = raw_username;
        } else {
            const original_len = raw_username.len;
            @memcpy(decoded_buf[0..original_len], raw_username);

            const decoded_slice: []u8 = std.Uri.percentDecodeInPlace(decoded_buf[0..original_len]);
            const decoding_successful = true; // Assuming success for demo

            if (decoding_successful) {
                const dupe_result = res.allocator.dupe(u8, decoded_slice);
                if (dupe_result) |duped_username| {
                    username = duped_username;
                } else |err| {
                    log.err("Failed to allocate memory for decoded username: {any}", .{err});
                    username = raw_username;
                }
            } else {
                log.warn("Failed to decode username query param '{s}' (assuming no error/change)", .{raw_username});
                username = raw_username;
            }
        }
    }
    setCtx(ctx, "username", username);

    // --- Data for Loops ---
    setCtx(ctx, "items", "[ \"Apples\", \"Bananas\", \"Oranges\" ]");

    // --- Other Demo Variables ---
    setCtx(ctx, "role", getQueryParam(req, "role", if (is_logged_in) "user" else "visitor"));
    setCtx(ctx, "show_details", getQueryParam(req, "show", "false"));
    setCtx(ctx, "theme", getQueryParam(req, "theme", "light"));

    log.debug("Context set for GET /: logged_in={s}, username={s}, role={s}", .{
        ctx.get("logged_in") orelse "N/A",
        ctx.get("username") orelse "N/A",
        ctx.get("role") orelse "N/A",
    });
}

pub fn post(req: *Request, res: *Response, ctx: *Context) void {
    log.info("Handling POST / request", .{});
    res.status = .ok;

    // --- Basic Page/Layout Info ---
    setCtx(ctx, "site_name", "zttp Demo Site");
    setCtx(ctx, "page_title", "POST Received");
    setCtx(ctx, "page_heading", "Form Submission");

    // --- Process Form Data ---
    var username: []const u8 = "Guest";
    var is_logged_in = false;
    var submitted_data = std.ArrayList(u8).init(res.allocator);
    defer submitted_data.deinit();

    if (req.form) |form| {
        const writer = submitted_data.writer();
        _ = writer.print("Received Form Data: ", .{}) catch {};
        var first = true;

        var it = form.iterator();
        while (it.next()) |entry| {
            if (!first) {
                _ = writer.print(", ", .{}) catch {};
            }
            // Assuming .key_ptr/.value_ptr based on previous iterations
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            _ = writer.print("{s}={s}", .{ key, value }) catch {};

            if (std.mem.eql(u8, key, "username")) {
                if (value.len > 0) {
                    const dupe_result = res.allocator.dupe(u8, value);
                    if (dupe_result) |duped_username| {
                        username = duped_username;
                    } else |err| {
                        log.err("Failed to allocate memory for form username: {any}", .{err});
                        username = "Guest";
                        is_logged_in = false;
                        break;
                    }
                    is_logged_in = (username.len > 0 and !std.mem.eql(u8, username, "Guest"));
                } else {
                    username = "Guest";
                    is_logged_in = false;
                }
            }
            first = false;
        }
    } else {
        log.warn("req.form is null in POST handler", .{});
        _ = submitted_data.writer().print("No form data received or parsed.", .{}) catch {};
    }

    setCtx(ctx, "logged_in", if (is_logged_in) "true" else "false");
    setCtx(ctx, "username", username);

    // --- FIX: Use explicit if/else for post_message dupe ---
    var post_msg_for_ctx: []const u8 = ""; // Variable to hold the final message
    const post_msg_dupe_result = res.allocator.dupe(u8, submitted_data.items);
    if (post_msg_dupe_result) |duped_msg| {
        post_msg_for_ctx = duped_msg; // Assign success result
    } else |err| {
        log.err("Failed to dupe post_message: {any}", .{err});
        post_msg_for_ctx = "Error creating POST message"; // Assign fallback
    }
    // Now assign the final value to the context
    setCtx(ctx, "post_message", post_msg_for_ctx);

    // --- Set other variables for POST response page ---
    setCtx(ctx, "items", "[]");
    setCtx(ctx, "role", if (is_logged_in) "user" else "visitor");
    setCtx(ctx, "show_details", "false");
    setCtx(ctx, "theme", "light");

    log.debug("Context set for POST /: logged_in={s}, username={s}", .{
        ctx.get("logged_in") orelse "N/A",
        ctx.get("username") orelse "N/A",
    });
}
