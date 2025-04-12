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

pub fn createServer(
    allocator: std.mem.Allocator,
    options: ServerOptions,
    comptime router_init_fn: ?fn (server: *Server) anyerror!void,
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

    if (router_init_fn) |init_fn| {
        try init_fn(server);
    }

    const bundle = try allocator.create(ServerBundle);
    bundle.* = ServerBundle{
        .allocator = allocator,
        .server = server,
        .pool = pool,
    };

    return bundle;
}

pub const ServerBundle = struct {
    allocator: std.mem.Allocator,
    server: *Server,
    pool: *ThreadPool,

    pub fn start(self: *ServerBundle, start_thread: bool) !void {
        if (start_thread) {
            const thread = try std.Thread.spawn(.{}, startServerThread, .{self.server});
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
};

fn startServerThread(server: *Server) void {
    server.start() catch |err| {
        std.log.err("Failed to start server: {}", .{err});
    };
}

pub fn example() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const options = ServerOptions{
        .port = 3000,
        .min_threads = 4,
        .max_threads = 16,
    };

    const server_bundle = try createServer(allocator, options, setupRoutes);
    defer server_bundle.deinit();

    try server_bundle.use(loggingMiddleware);
    try server_bundle.start(false);
}

fn setupRoutes(server: *Server) !void {
    try server.route("GET", "/", handleRoot);
    try server.route("GET", "/hello", handleHello);
    try server.route("POST", "/data", handleData);
}

fn handleRoot(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    res.setHeader("Content-Type", "text/plain") catch return;
    if (ctx.get("request_id")) |rid| {
        res.setBody(try std.fmt.allocPrint(res.allocator, "Welcome to ZTTP! Request ID: {s}", .{rid})) catch return;
    } else {
        res.setBody("Welcome to ZTTP!") catch return;
    }
}

fn handleHello(_: *Request, res: *Response, _: *Context) void {
    res.status = .ok;
    res.setHeader("Content-Type", "text/plain") catch return;
    res.setBody("Hello, World!") catch return;
}

fn handleData(req: *Request, res: *Response, _: *Context) void {
    res.status = .ok;
    res.setHeader("Content-Type", "application/json") catch return;
    if (req.json) |json| {
        res.setJson(json) catch return;
    } else if (req.form) |form| {
        var obj = std.json.ObjectMap.init(res.allocator);
        defer obj.deinit();
        var it = form.iterator();
        while (it.next()) |entry| {
            try obj.put(entry.key_ptr.*, .{ .string = entry.value_ptr.* });
        }
        res.setJson(obj) catch return;
    } else {
        res.status = .bad_request;
        res.setBody("Expected JSON or form data") catch return;
    }
}

fn loggingMiddleware(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    const request_id = std.fmt.allocPrint(ctx.allocator, "{d}", .{std.time.nanoTimestamp()}) catch "unknown";
    ctx.set("request_id", request_id) catch return;
    std.log.info("{s} {s} {s}", .{ req.method, req.path, request_id });
    next(req, res, ctx);
}
