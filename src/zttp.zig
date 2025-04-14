// src/zttp.zig
const std = @import("std");
pub const Server = @import("server.zig").Server;
pub const ThreadPool = @import("pool.zig").ThreadPool;
pub const Request = @import("request.zig").Request;
pub const Response = @import("response.zig").Response;
pub const Context = @import("context.zig").Context;
pub const MiddlewareFn = @import("router.zig").MiddlewareFn;
pub const HandlerFn = @import("router.zig").HandlerFn;
pub const NextFn = @import("router.zig").NextFn;
pub const Router = @import("router.zig").Router;

pub const ServerOptions = struct {
    port: u16 = 8080,
    min_threads: usize = 2,
    max_threads: usize = 8,
    max_tasks: usize = 100,
    adaptive_scaling: bool = true,
};

pub const Route = struct {
    module_name: []const u8,
    method: []const u8,
    path: []const u8,
    handler: HandlerFn,
};

fn loggingMiddleware(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    const request_id = std.fmt.allocPrint(ctx.allocator, "{d}", .{std.time.nanoTimestamp()}) catch "unknown";
    ctx.set("request_id", request_id) catch return;
    std.log.info("{s} {s} {s}", .{ req.method, req.path, request_id });
    next(req, res, ctx);
}

pub fn createServer(
    allocator: std.mem.Allocator,
    options: ServerOptions,
) !*ServerBundle {
    const pool_options = ThreadPool.Options{
        .min_threads = options.min_threads,
        .max_threads = options.max_threads,
        .max_tasks = options.max_tasks,
        .adaptive_scaling = options.adaptive_scaling,
    };

    var pool = try allocator.create(ThreadPool);
    pool.* = try ThreadPool.init(allocator, pool_options);
    errdefer {
        pool.deinit();
        allocator.destroy(pool);
    }

    try pool.startWorkers(options.min_threads);

    var server = try allocator.create(Server);
    server.* = Server.init(allocator, options.port, pool);
    errdefer {
        server.deinit();
        allocator.destroy(server);
    }

    const bundle = try allocator.create(ServerBundle);
    bundle.* = ServerBundle{
        .allocator = allocator,
        .server = server,
        .pool = pool,
        .options = options,
    };

    // Add default logging middleware
    try bundle.use(loggingMiddleware);

    return bundle;
}

pub const ServerBundle = struct {
    allocator: std.mem.Allocator,
    server: *Server,
    pool: *ThreadPool,
    options: ServerOptions,

    pub fn start(self: *ServerBundle, start_thread: bool) !void {
        if (start_thread) {
            const thread = try std.Thread.spawn(.{}, startServerThread, .{self});
            _ = thread;
        } else {
            try self.server.start();
        }
    }

    pub fn deinit(self: *ServerBundle) void {
        self.server.deinit();
        self.pool.deinit();
        self.allocator.destroy(self.server);
        self.allocator.destroy(self.pool);
        self.allocator.destroy(self);
    }

    pub fn route(self: *ServerBundle, method: []const u8, path: []const u8, handler: HandlerFn) !void {
        try self.server.route(method, path, handler);
    }

    pub fn use(self: *ServerBundle, middleware: MiddlewareFn) !void {
        try self.server.use(middleware);
    }

    pub fn loadRoutes(self: *ServerBundle, comptime getRoutesFn: fn (std.mem.Allocator) anyerror![]const Route) !void {
        const routes = try getRoutesFn(self.allocator);
        defer {
            for (routes) |r| {
                self.allocator.free(r.module_name);
                self.allocator.free(r.method);
                self.allocator.free(r.path);
            }
            self.allocator.free(routes);
        }

        if (routes.len == 0) {
            std.log.warn("No routes loaded", .{});
        }

        for (routes) |r| {
            std.log.info("Registering route: {s} {s}", .{ r.method, r.path });
            try self.server.route(r.method, r.path, r.handler);
        }
    }
};

fn startServerThread(bundle: *ServerBundle) void {
    bundle.server.start() catch |err| {
        std.log.err("Failed to start server: {}", .{err});
    };
}
