// zttp/examples/src/routes/demo/conditional.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.conditional_handler); // Scoped logger

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    log.info("Executing GET handler for /demo/conditional", .{});
    res.status = .ok;

    // --- Set up common layout variables (assuming layout.zmx needs these) ---
    log.debug("Setting common context vars...", .{});
    // ctx.set("site_name", "My Awesome Site") catch |e| log.err("Failed to set site_name: {any}", .{e});
    // Set page_title specifically for this page (as used in the template)
    ctx.set("page_title", "Demo") catch |e| log.err("Failed to set page_title: {any}", .{e});

    // --- Set up variables specifically for the conditional examples ---
    log.debug("Setting demo-specific context vars...", .{});

    // Example 1: Simple Truthiness & Else
    // For '#if user': Set 'user' to something truthy.
    // For '{{ user.name }}': Need 'user.name'. The current renderer/context likely
    // doesn't support nested lookups, so we might need to set "user.name" as the key.
    // Let's simulate a logged-in user for this example run.
    ctx.set("user", "true") catch |e| log.err("Failed to set user: {any}", .{e}); // For #if user check
    ctx.set("user.name", "Alice") catch |e| log.err("Failed to set user.name: {any}", .{e}); // For {{ user.name }}

    // Example 2: Equality, Inequality & ElseIf
    // Set 'status' to one of the tested values. Let's try "pending".
    ctx.set("status", "pending") catch |e| log.err("Failed to set status: {any}", .{e});

    // Example 3: Numeric Comparisons
    // Set 'item_count'. Let's try a value > 0 but <= 10.
    ctx.set("item_count", "7") catch |e| log.err("Failed to set item_count: {any}", .{e});

    // Example 4: Logical Operators (and/or)
    // Set 'is_admin' and 'has_special_permission'. Let's try admin=false, special=true
    ctx.set("is_admin", "false") catch |e| log.err("Failed to set is_admin: {any}", .{e});
    ctx.set("has_special_permission", "true") catch |e| log.err("Failed to set has_special_permission: {any}", .{e});

    // Example 5: Non-Empty Check
    // Set 'messages'. Let's give it a non-empty value.
    ctx.set("messages", "You have 1 unread notification.") catch |e| log.err("Failed to set messages: {any}", .{e});
    // If you wanted to test the #else branch, you would set:
    // ctx.set("messages", "") catch |e| log.err("Failed to set messages: {any}", .{e});

    // Example 6: Combined Conditions
    // Needs 'user.role' and 'is_override_active'. We already have 'user' set.
    // We set 'user.name' above, now set 'user.role'.
    // Again, assuming flat context, use "user.role" key. Let's make the user an editor.
    ctx.set("user.role", "editor") catch |e| log.err("Failed to set user.role: {any}", .{e});
    // Set 'is_override_active'. Let's set it to false to test the first part of the 'or'.
    ctx.set("is_override_active", "false") catch |e| log.err("Failed to set is_override_active: {any}", .{e});

    log.info("Finished setting context for /demo/conditional. Template rendering should follow.", .{});
    // Template rendering is handled by the server based on route config mapping
    // to index.zmx (or whatever the template file is actually named)
}
