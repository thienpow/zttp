// src/zttp.zig
const std = @import("std");

pub const Middleware = @import("middleware/mod.zig");
pub const Request = @import("request.zig").Request;
pub const Response = @import("response.zig").Response;
pub const Context = @import("context.zig").Context;

const Server = @import("server.zig").Server;
const ThreadPool = @import("pool.zig").ThreadPool;

const router = @import("router.zig");
const MiddlewareFn = router.MiddlewareFn;
const HandlerFn = router.HandlerFn;
const NextFn = router.NextFn;
const Router = router.Router;

const cache = @import("template/cache.zig");

pub const HttpMethod = enum {
    get,
    post,
    put,
    delete,
    patch,
    head,
    options,
    trace,
};

pub const ServerOptions = struct {
    port: u16 = 8080,
    min_threads: usize = 2,
    max_threads: usize = 8,
    max_tasks: usize = 100,
    adaptive_scaling: bool = true,
};

pub const Route = struct {
    module_name: []const u8,
    method: HttpMethod,
    path: []const u8,
    handler: HandlerFn,
};

pub const Template = struct {
    name: []const u8,
    buffer: []const u8,
};

pub fn createServer(
    parent_allocator: std.mem.Allocator,
    options: ServerOptions,
) !*ServerBundle {
    var arena = std.heap.ArenaAllocator.init(parent_allocator);
    const alloc = arena.allocator();

    const pool_options = ThreadPool.Options{
        .min_threads = options.min_threads,
        .max_threads = options.max_threads,
        .max_tasks = options.max_tasks,
        .adaptive_scaling = options.adaptive_scaling,
    };

    var pool = try alloc.create(ThreadPool);
    pool.* = try ThreadPool.init(parent_allocator, pool_options); // Use parent_allocator
    errdefer {
        pool.deinit();
        alloc.destroy(pool);
    }

    try pool.startWorkers(options.min_threads);

    var server = try alloc.create(Server);
    server.* = Server.init(parent_allocator, options.port, pool); // Use parent_allocator
    errdefer {
        server.deinit();
        alloc.destroy(server);
    }

    const bundle = try alloc.create(ServerBundle);
    bundle.* = ServerBundle{
        .arena = arena,
        .server = server,
        .pool = pool,
        .options = options,
    };

    return bundle;
}

pub const ServerBundle = struct {
    arena: std.heap.ArenaAllocator,
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

        while (true) {
            std.time.sleep(1_000_000_000);
        }
    }

    pub fn deinit(self: *ServerBundle) void {
        self.server.deinit();
        self.pool.deinit();
        self.arena.deinit();
    }

    pub fn route(self: *ServerBundle, method: HttpMethod, path: []const u8, handler: HandlerFn) !void {
        try self.server.route("", method, path, handler); // Empty module_name as per router.zig
    }

    pub fn use(self: *ServerBundle, middleware: MiddlewareFn) !void {
        try self.server.use(middleware);
    }

    pub fn loadRoutes(self: *ServerBundle, comptime getRoutesFn: fn (std.mem.Allocator) anyerror![]const Route) !void {
        const routes = try getRoutesFn(self.arena.allocator());
        if (routes.len == 0) {
            std.log.warn("No routes loaded", .{});
        }

        for (routes) |r| {
            try self.server.route(r.module_name, r.method, r.path, r.handler);
        }
    }

    pub fn loadTemplates(self: *ServerBundle, comptime getTemplatesFn: fn (std.mem.Allocator) anyerror![]const Template) !void {
        const templates = try getTemplatesFn(self.arena.allocator());

        if (templates.len == 0) {
            std.log.warn("No templates loaded", .{});
        }

        // Initialize the template cache with capacity for all templates
        try cache.initTemplateCache(self.arena.allocator(), @intCast(templates.len));

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
