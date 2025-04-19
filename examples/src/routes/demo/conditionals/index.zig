// zttp/examples/src/routes/demo/conditional.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.conditional_handler); // Scoped logger

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    log.info("Executing GET handler for /demo/conditionals", .{});
    res.status = .ok;

    // --- Set up common layout variables (assuming layout.zmx needs these) ---
    log.debug("Setting common context vars...", .{});
    ctx.set("site_name", "zttp Demos") catch |e| log.err("Failed to set site_name: {any}", .{e});
    ctx.set("page_title", "Conditional Logic Demo") catch |e| log.err("Failed to set page_title: {any}", .{e});
    // Add logged_in and username for layout nav consistency
    ctx.set("logged_in", "true") catch |e| log.err("Failed to set logged_in: {any}", .{e}); // Simulate logged in
    ctx.set("username", "DemoUser") catch |e| log.err("Failed to set username: {any}", .{e}); // Simulate username

    // --- Set up variables specifically for the conditional examples ---
    log.debug("Setting demo-specific context vars...", .{});

    // --- Existing Examples ---
    // Example 1: Simple Truthiness & Else
    ctx.set("user", "true") catch |e| log.err("Failed to set user: {any}", .{e});
    ctx.set("user.name", "Alice") catch |e| log.err("Failed to set user.name: {any}", .{e});

    // Example 2: Equality, Inequality & ElseIf
    ctx.set("status", "pending") catch |e| log.err("Failed to set status: {any}", .{e});

    // Example 3: Numeric Comparisons
    ctx.set("item_count", "7") catch |e| log.err("Failed to set item_count: {any}", .{e});

    // Example 4: Logical Operators (and/or)
    ctx.set("is_admin", "false") catch |e| log.err("Failed to set is_admin: {any}", .{e});
    ctx.set("has_special_permission", "true") catch |e| log.err("Failed to set has_special_permission: {any}", .{e});

    // Example 5: Non-Empty Check
    ctx.set("messages", "You have 1 unread notification.") catch |e| log.err("Failed to set messages: {any}", .{e});
    // ctx.set("messages", "") catch |e| log.err("Failed to set messages: {any}", .{e}); // To test the #else

    // --- New Enhanced Examples ---

    // Example 6: Variable vs. Variable Comparison
    ctx.set("user_role", "editor") catch |e| log.err("Failed to set user_role: {any}", .{e});
    ctx.set("required_role", "admin") catch |e| log.err("Failed to set required_role: {any}", .{e});
    // To test the #if branch:
    // ctx.set("user_role", "admin") catch |e| log.err("Failed to set user_role: {any}", .{e});
    // ctx.set("required_role", "admin") catch |e| log.err("Failed to set required_role: {any}", .{e});

    // Example 7: Greater Than or Equal / Less Than or Equal
    ctx.set("score", "85") catch |e| log.err("Failed to set score: {any}", .{e});
    ctx.set("passing_score", "70") catch |e| log.err("Failed to set passing_score: {any}", .{e});
    ctx.set("max_score", "100") catch |e| log.err("Failed to set max_score: {any}", .{e});

    // Example 8: Logical Operator Precedence/Grouping
    ctx.set("permission_a", "true") catch |e| log.err("Failed to set permission_a: {any}", .{e});
    ctx.set("permission_b", "false") catch |e| log.err("Failed to set permission_b: {any}", .{e});
    ctx.set("emergency_override", "true") catch |e| log.err("Failed to set emergency_override: {any}", .{e});

    // Example 9: Single Quotes in Literals & General Inequality
    ctx.set("user_preference", "dark") catch |e| log.err("Failed to set user_preference: {any}", .{e});
    // To test the #else branch:
    // ctx.set("user_preference", "light") catch |e| log.err("Failed to set user_preference: {any}", .{e});

    log.info("Finished setting context for /demo/conditionals. Template rendering should follow.", .{});
}
