// zttp/examples/src/routes/demo/conditional.zig
const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const log = std.log.scoped(.conditional_handler); // Scoped logger

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    log.info("Executing GET handler for /demo/conditional", .{}); // Log entry point
    res.status = .ok;

    // --- Set up common layout variables ---
    log.debug("Setting common context vars...", .{});
    ctx.set("site_name", "My Awesome Site") catch |e| log.err("Failed to set site_name: {any}", .{e});
    ctx.set("page_title", "Conditional Logic Demo") catch |e| log.err("Failed to set page_title: {any}", .{e});
    ctx.set("logged_in", "false") catch |e| log.err("Failed to set logged_in: {any}", .{e});

    // --- Set up variables specifically for the demo ---
    log.debug("Setting demo-specific context vars...", .{});
    ctx.set("is_active", "true") catch |e| log.err("Failed to set is_active: {any}", .{e});
    ctx.set("user_role", "admin") catch |e| log.err("Failed to set user_role: {any}", .{e});
    ctx.set("item_count", "7") catch |e| log.err("Failed to set item_count: {any}", .{e});
    ctx.set("max_items", "10") catch |e| log.err("Failed to set max_items: {any}", .{e});
    ctx.set("empty_var", "") catch |e| log.err("Failed to set empty_var: {any}", .{e});
    ctx.set("status_code", "404") catch |e| log.err("Failed to set status_code: {any}", .{e});

    // Variable for the #while loop demo
    ctx.set("loop_counter", "0") catch |e| log.err("Failed to set loop_counter: {any}", .{e});
    ctx.set("loop_limit", "3") catch |e| log.err("Failed to set loop_limit: {any}", .{e});

    log.info("Finished setting context for /demo/conditional. Template rendering should follow.", .{});
    // Template rendering is handled by the server based on route config mapping
    // to conditional_demo.zmx
}
