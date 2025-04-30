const std = @import("std");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const HandlerFn = @import("router.zig").HandlerFn;
const MiddlewareFn = @import("router.zig").MiddlewareFn;
const NextFn = @import("router.zig").NextFn;
const Server = @import("server.zig").Server;
const utils = @import("utils.zig");

pub const MiddlewareContext = struct {
    middlewares: []const MiddlewareFn,
    index: usize,
    server: *Server,
    final_handler: *HandlerFn,
};

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
    }
}
