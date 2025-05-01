// src/middleware.zig
const std = @import("std");

const http = @import("../http/mod.zig");
pub const Request = http.Request;
pub const Response = http.Response;

const core = @import("../core/mod.zig");
pub const Context = core.Context;
const Server = core.Server;

const router = @import("../core/router.zig");
const HandlerFn = router.HandlerFn;
const MiddlewareFn = router.MiddlewareFn;
const NextFn = router.NextFn;
const utils = @import("../utils.zig");

pub const MiddlewareContext = struct {
    middlewares: []const MiddlewareFn,
    index: usize,
    server: *Server,
    final_handler: *HandlerFn,
};

pub fn executeChain(req: *Request, res: *Response, ctx: *Context, middleware_ctx: *MiddlewareContext, final_handler: HandlerFn) !void {
    if (middleware_ctx.middlewares.len == 0) {
        final_handler(req, res, ctx);
        return;
    }

    // Store middleware_ctx address in ctx
    const context_addr_str = try std.fmt.allocPrint(ctx.allocator, "{x}", .{@intFromPtr(middleware_ctx)});
    try ctx.set("middleware_context", context_addr_str);

    // Update final_handler in middleware_ctx
    middleware_ctx.final_handler.* = final_handler;

    // Start the middleware chain
    const mw = middleware_ctx.middlewares[0];
    middleware_ctx.index = 1;
    mw(req, res, ctx, callNextMiddleware);
}

pub fn callNextMiddleware(req: *Request, res: *Response, ctx: *Context) void {
    const context_addr_str = ctx.get("middleware_context") orelse {
        std.log.err("Middleware context address not found in Ctx.", .{});
        utils.sendError(undefined, ctx.allocator, .internal_server_error, "Middleware Context Missing");
        return;
    };

    const context_ptr_addr = std.fmt.parseInt(usize, context_addr_str, 16) catch |err| {
        std.log.err("Failed to parse middleware context address '{s}': {any}", .{ context_addr_str, err });
        utils.sendError(undefined, ctx.allocator, .internal_server_error, "Invalid Middleware Context Address");
        return;
    };
    const context_ptr = @as(*MiddlewareContext, @ptrFromInt(context_ptr_addr));

    if (context_ptr.index < context_ptr.middlewares.len) {
        const mw = context_ptr.middlewares[context_ptr.index];
        context_ptr.index += 1;
        mw(req, res, ctx, callNextMiddleware);
    } else {
        context_ptr.final_handler.* = context_ptr.server.router.getHandler(req.method, req.path, ctx) orelse utils.notFound;
        context_ptr.final_handler.*(req, res, ctx);
    }
}
