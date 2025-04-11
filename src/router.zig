const std = @import("std");
const Request = @import("http/request.zig").Request;
const Response = @import("http/response.zig").Response;

pub const Handler = fn (*Request, *Response) void;

pub const Router = struct {
    allocator: std.mem.Allocator,
    routes: std.StringHashMap(Handler),

    pub fn init(allocator: std.mem.Allocator) Router {
        var router = Router{
            .allocator = allocator,
            .routes = std.StringHashMap(Handler).init(allocator),
        };

        // Import generated routes if available
        @import("logging.zig").log("Initializing router with generated routes", .{});
        if (@import("std").meta.hasFn(@import("generated_routes.zig"), "registerRoutes")) {
            @import("generated_routes.zig").registerRoutes(&router);
        } else {
            @import("logging.zig").log("No generated routes found; using empty router", .{});
        }

        return router;
    }

    pub fn deinit(self: *Router) void {
        var it = self.routes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.routes.deinit();
    }

    pub fn addRoute(self: *Router, path: []const u8, handler: Handler) !void {
        const path_dup = try self.allocator.dupe(u8, path);
        try self.routes.put(path_dup, handler);
    }

    pub fn dispatch(self: *Router, req: Request, res: *Response) void {
        if (self.routes.get(req.path)) |handler| {
            handler(&req, res);
        } else {
            res.status = 404;
            res.setBody("Not Found") catch @import("logging.zig").log("Failed to set 404 body", .{});
        }
    }
};
