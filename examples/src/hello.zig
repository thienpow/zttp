const std = @import("std");
const zttp = @import("zttp");
const Server = zttp.Server;
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;
const ServerOptions = zttp.ServerOptions;
const Route = zttp.Route;

var bundle_ptr_static: ?*zttp.ServerBundle = null;

fn loggingMiddleware(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    const request_id = std.fmt.allocPrint(ctx.allocator, "{d}", .{std.time.nanoTimestamp()}) catch "unknown";
    ctx.set("request_id", request_id) catch return;
    std.log.info("{s} {s} {s}", .{ req.method, req.path, request_id });
    next(req, res, ctx);
}

fn bundleMiddleware(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    if (bundle_ptr_static) |bundle| {
        const ptr_str = std.fmt.allocPrint(ctx.allocator, "{x}", .{@intFromPtr(bundle)}) catch return;
        defer ctx.allocator.free(ptr_str);
        ctx.set("server_bundle", ptr_str) catch return;
    } else {
        std.log.err("Bundle pointer not initialized in middleware", .{});
    }
    next(req, res, ctx);
}

// Fallback handler for unknown routes
fn fallbackHandler(req: *Request, res: *Response, ctx: *Context) void {
    _ = req;
    _ = ctx;
    res.status = .not_found;
    res.setBody("Route not found") catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
}

// Thread function to scan routes and load them
fn scanAndLoadRoutes(allocator: std.mem.Allocator, bundle: *zttp.ServerBundle) void {
    std.log.info("Starting route scanning in separate thread", .{});
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var routes = std.ArrayList(Route).init(arena_alloc);
    defer routes.deinit();

    // Open routes directory
    const routes_dir = std.fs.cwd().openDir("src/routes", .{ .iterate = true }) catch |err| {
        std.log.warn("Failed to open routes directory 'src/routes': {}. Server will run without routes.", .{err});
        return;
    };

    var walker = routes_dir.walk(arena_alloc) catch |err| {
        std.log.err("Failed to walk routes directory: {}", .{err});
        return;
    };
    defer walker.deinit();

    // Scan for .zig files and match against known routes
    while (walker.next() catch null) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".zig")) continue;
        const route_name = entry.path[0 .. entry.path.len - 4]; // e.g., "api/json"

        // Get route from known modules
        const route = getRouteForFile(route_name, arena_alloc) catch |err| {
            std.log.warn("Failed to process route {s}: {}", .{ route_name, err });
            continue;
        };
        if (route) |r| {
            routes.append(r) catch {
                std.log.err("Failed to append route for {s}", .{route_name});
                continue;
            };
            std.log.info("Found route: {s} {s}", .{ r.method, r.path });
        } else {
            std.log.warn("No route definition for {s}, using fallback", .{route_name});
            const fallback_path = std.fmt.allocPrint(arena_alloc, "/{s}", .{route_name}) catch continue;
            routes.append(Route{
                .module_name = route_name,
                .method = "GET",
                .path = fallback_path,
                .handler = fallbackHandler,
            }) catch continue;
        }
    }

    if (routes.items.len == 0) {
        std.log.warn("No valid routes found in routes/ directory", .{});
        return;
    }

    // Load routes into the server
    bundle.loadRoutes(routes.items) catch |err| {
        std.log.err("Failed to load routes: {}", .{err});
    };
    std.log.info("Finished loading {} routes", .{routes.items.len});
}

// Known route modules (compile-time registry)
const RouteModule = struct {
    name: []const u8,
    method: []const u8,
    path: []const u8,
    handler: zttp.HandlerFn,
};

const known_routes = [_]RouteModule{
    .{
        .name = "get_hello",
        .method = @import("routes/get_hello.zig").method,
        .path = @import("routes/get_hello.zig").path,
        .handler = @import("routes/get_hello.zig").handler,
    },
    .{
        .name = "api/json",
        .method = @import("routes/api/json.zig").method,
        .path = @import("routes/api/json.zig").path,
        .handler = @import("routes/api/json.zig").handler,
    },
};

// Helper to map file names to route structs
fn getRouteForFile(name: []const u8, allocator: std.mem.Allocator) !?Route {
    for (known_routes) |route| {
        if (std.mem.eql(u8, name, route.name)) {
            return Route{
                .module_name = try allocator.dupe(u8, route.name),
                .method = try allocator.dupe(u8, route.method),
                .path = try allocator.dupe(u8, route.path),
                .handler = route.handler,
            };
        }
    }
    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const options = ServerOptions{
        .port = 8080,
        .min_threads = 2,
        .max_threads = 8,
        .max_tasks = 100,
    };

    // Create server bundle
    var bundle = try zttp.createServer(allocator, options, &.{});
    defer bundle.deinit();

    try bundle.use(loggingMiddleware);
    try bundle.use(bundleMiddleware);

    // Store bundle for middleware
    bundle_ptr_static = bundle;
    defer bundle_ptr_static = null;

    // Start server in a separate thread
    std.log.info("Starting server on :8080", .{});
    const server_thread = try std.Thread.spawn(.{}, serverThreadFn, .{bundle});
    _ = server_thread;

    // Start route scanning in another thread
    const route_thread = try std.Thread.spawn(.{}, scanAndLoadRoutes, .{ allocator, bundle });
    _ = route_thread;

    // Keep main thread alive
    while (true) {
        std.time.sleep(1_000_000_000); // Sleep 1 second
    }
}

fn serverThreadFn(bundle: *zttp.ServerBundle) void {
    bundle.start(false) catch |err| {
        std.log.err("Server failed: {}", .{err});
    };
}
