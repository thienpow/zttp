// zttp/src/zttp.zig
const std = @import("std");

pub const Middleware = @import("middleware/mod.zig");
pub const Request = @import("request.zig").Request;
pub const HttpMethod = @import("request.zig").HttpMethod;
pub const Response = @import("response.zig").Response;
pub const Context = @import("context.zig").Context;
pub const WebSocket = @import("websocket.zig").WebSocket;
pub const ThreadPool = @import("pool.zig").ThreadPool;
pub const Server = @import("server.zig").Server;
pub const Async = @import("async/async.zig");
pub const AsyncContext = Async.Context;

const router = @import("router.zig");
const MiddlewareFn = router.MiddlewareFn;
const HandlerFn = router.HandlerFn;
const NextFn = router.NextFn;
const Router = router.Router;
pub const WebSocketHandlerFn = router.WebSocketHandlerFn;

const cache = @import("template/cache.zig");

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,
};

pub const Route = struct {
    module_name: []const u8,
    method: HttpMethod,
    path: []const u8,
    handler: ?HandlerFn = null,
    ws_handler: ?WebSocketHandlerFn = null,
};

pub const Template = struct {
    name: []const u8,
    buffer: []const u8,
};

pub fn createServer(
    allocator: std.mem.Allocator,
    server_options: Server.Options,
) !*ServerBundle {
    var pool = try allocator.create(ThreadPool);
    pool.* = try ThreadPool.init(allocator);
    errdefer {
        pool.deinit();
        allocator.destroy(pool);
    }

    try pool.startWorkers(8);

    var server = try allocator.create(Server);
    server.* = try Server.init(allocator, server_options);
    errdefer {
        server.deinit();
        allocator.destroy(server);
    }

    const bundle = try allocator.create(ServerBundle);
    bundle.* = ServerBundle{
        .allocator = allocator,
        .server = server,
        .pool = pool,
        .server_options = server_options,
    };

    return bundle;
}

pub const ServerBundle = struct {
    allocator: std.mem.Allocator,
    server: *Server,
    pool: *ThreadPool,
    server_options: Server.Options,

    pub fn start(self: *ServerBundle, start_thread: bool) !void {
        if (start_thread) {
            const thread = try std.Thread.spawn(.{}, startServerThread, .{self});
            _ = thread;
        } else {
            try self.server.start();
        }

        while (true) {
            std.time.sleep(1_000_000_000);
        }
    }

    pub fn deinit(self: *ServerBundle) void {
        self.server.deinit();
        self.pool.deinit();
    }

    pub fn route(self: *ServerBundle, method: HttpMethod, path: []const u8, handler: HandlerFn) !void {
        try self.server.route("", method, path, handler, null);
    }

    pub fn use(self: *ServerBundle, middleware: MiddlewareFn) !void {
        try self.server.use(middleware);
    }

    pub fn loadRoutes(self: *ServerBundle, comptime getRoutesFn: fn (std.mem.Allocator) anyerror![]const Route) !void {
        const routes = try getRoutesFn(self.allocator);
        if (routes.len == 0) {
            std.log.warn("No routes loaded", .{});
        }

        for (routes) |r| {
            try self.server.route(r.module_name, r.method, r.path, r.handler, r.ws_handler);
        }
    }

    pub fn loadTemplates(self: *ServerBundle, comptime getTemplatesFn: fn (std.mem.Allocator) anyerror![]const Template) !void {
        const templates = try getTemplatesFn(self.allocator);

        if (templates.len == 0) {
            std.log.warn("No templates loaded", .{});
        }

        try cache.initTemplateCache(self.allocator, @intCast(templates.len));

        for (templates) |t| {
            _ = try cache.putTokenizedTemplate(t.name, t.buffer);
        }
    }
};

fn startServerThread(bundle: *ServerBundle) void {
    bundle.server.start() catch |err| {
        std.log.err("Failed to start server: {}", .{err});
    };
}
