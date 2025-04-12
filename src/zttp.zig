// zttp.zig - Main library file
const std = @import("std");
pub const Server = @import("server.zig").Server;
pub const ThreadPool = @import("pool.zig").ThreadPool;
pub const Request = @import("http.zig").Request;
pub const Response = @import("http.zig").Response;

/// ServerOptions provides configuration for the HTTP server
pub const ServerOptions = struct {
    port: u16 = 8080,
    min_threads: usize = 2,
    max_threads: usize = 8,
    max_tasks: usize = 100,
    adaptive_scaling: bool = true,
};

/// Creates and starts an HTTP server with the given options
/// This is a convenience function that sets up both the server and thread pool
pub fn createServer(
    allocator: std.mem.Allocator,
    options: ServerOptions,
    comptime router_init_fn: ?fn (server: *Server) anyerror!void,
) !*ServerBundle {
    // Create the thread pool
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

    // Start the worker threads
    try pool.startWorkers(options.min_threads);

    // Create the server
    var server = try allocator.create(Server);
    server.* = Server.init(allocator, options.port, pool);
    errdefer {
        server.deinit();
        allocator.destroy(server);
    }

    // Setup router if a router init function was provided
    if (router_init_fn) |init_fn| {
        try init_fn(server);
    }

    // Create the bundle that holds both the server and pool
    const bundle = try allocator.create(ServerBundle);
    bundle.* = ServerBundle{
        .allocator = allocator,
        .server = server,
        .pool = pool,
    };

    return bundle;
}

/// ServerBundle holds both the server and thread pool to manage their lifecycle
pub const ServerBundle = struct {
    allocator: std.mem.Allocator,
    server: *Server,
    pool: *ThreadPool,

    /// Start the server (non-blocking if start_thread is true)
    pub fn start(self: *ServerBundle, start_thread: bool) !void {
        if (start_thread) {
            const thread = try std.Thread.spawn(.{}, startServerThread, .{self.server});
            _ = thread;
        } else {
            try self.server.start();
        }
    }

    /// Clean up all resources
    pub fn deinit(self: *ServerBundle) void {
        self.server.deinit();
        self.pool.deinit();
        self.allocator.destroy(self.server);
        self.allocator.destroy(self.pool);
        self.allocator.destroy(self);
    }

    /// Add a route to the server
    pub fn route(self: *ServerBundle, path: []const u8, handler: fn (*Request, *Response) void) !void {
        try self.server.route(path, handler);
    }
};

/// Helper function to start the server in a separate thread
fn startServerThread(server: *Server) void {
    server.start() catch |err| {
        std.log.err("Failed to start server: {}", .{err});
    };
}

/// Simple example usage
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

    try server_bundle.start(false); // Start in current thread
}

fn setupRoutes(server: *Server) !void {
    try server.route("/", handleRoot);
    try server.route("/hello", handleHello);
}

fn handleRoot(req: *Request, res: *Response) void {
    _ = req;
    res.status = .ok;
    _ = res.setHeader("Content-Type", "text/plain") catch return;
    _ = res.setBody("Welcome to ZTTP!") catch return;
}

fn handleHello(req: *Request, res: *Response) void {
    _ = req;
    res.status = .ok;
    _ = res.setHeader("Content-Type", "text/plain") catch return;
    _ = res.setBody("Hello, World!") catch return;
}
