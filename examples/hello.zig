const std = @import("std");
const zttp = @import("zttp");
const Server = zttp.Server;
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;
const ServerOptions = zttp.ServerOptions;

// Store bundle_ptr statically, safe since it's constant for the server lifetime
var bundle_ptr_static: ?[]const u8 = null;

fn hello(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const message = if (ctx.get("request_id")) |rid|
        std.fmt.allocPrint(res.allocator, "Hello, World! Request ID: {s}", .{rid}) catch "Hello, World!"
    else
        "Hello, World!";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    std.log.info("Served hello endpoint", .{});
}

fn jsonEndpoint(req: *Request, res: *Response, _: *Context) void {
    const name = req.query.get("name") orelse "Guest";
    const json = std.fmt.allocPrint(
        req.allocator,
        "{{\"message\": \"Hello, {s}!\"}}",
        .{name},
    ) catch {
        res.status = .internal_server_error;
        res.setBody("Failed to generate JSON") catch return;
        return;
    };
    defer req.allocator.free(json);

    res.status = .ok;
    res.setBody(json) catch return;
    res.setHeader("Content-Type", "application/json") catch return;
    std.log.info("Served JSON endpoint for name: {s}", .{name});
}

const AsyncTask = struct {
    allocator: std.mem.Allocator,
    delay_ms: u64,
    bundle: *zttp.ServerBundle,

    fn process(self: AsyncTask, result: *zttp.ThreadPool.TaskResult) void {
        std.time.sleep(self.delay_ms * std.time.ns_per_ms);

        const msg = std.fmt.allocPrint(
            self.allocator,
            "Async task completed after {d}ms",
            .{self.delay_ms},
        ) catch {
            result.success = false;
            return;
        };

        result.payload = @constCast(msg.ptr);
        result.payload_size = msg.len;
        result.success = true;
    }
};

fn asyncEndpoint(_: *Request, res: *Response, ctx: *Context) void {
    const bundle_ptr = ctx.get("server_bundle") orelse {
        res.status = .internal_server_error;
        res.setBody("Server bundle not initialized") catch return;
        std.log.err("Server bundle not initialized", .{});
        return;
    };
    const bundle = @as(*zttp.ServerBundle, @ptrFromInt(
        std.fmt.parseInt(usize, bundle_ptr, 16) catch {
            res.status = .internal_server_error;
            res.setBody("Invalid server bundle") catch return;
            return;
        },
    ));

    const task = AsyncTask{
        .allocator = res.allocator,
        .delay_ms = 1000,
        .bundle = bundle,
    };

    const task_id = bundle.pool.schedule(
        AsyncTask.process,
        task,
        null,
        5,
        null,
        0,
        0,
        null,
        null,
    ) catch |err| {
        res.status = .internal_server_error;
        res.setBody("Failed to schedule task") catch return;
        std.log.err("Failed to schedule async task: {}", .{err});
        return;
    };

    std.log.info("Scheduled async task ID: {d}", .{task_id});

    const success = bundle.pool.waitForTask(task_id, 2 * std.time.ns_per_s) catch |err| {
        res.status = .internal_server_error;
        res.setBody("Failed to wait for task") catch return;
        std.log.err("Failed to wait for async task {d}: {}", .{ task_id, err });
        return;
    };

    if (!success) {
        res.status = .internal_server_error;
        res.setBody("Async task failed or timed out") catch return;
        std.log.warn("Async task {d} failed or timed out", .{task_id});
        return;
    }

    const status = bundle.pool.getTaskStatus(task_id);
    if (status != null and status.? == .Completed) {
        const message = "Async task completed successfully!";
        res.setBody(message) catch return;
        res.status = .ok;
        res.setHeader("Content-Type", "text/plain") catch return;
        std.log.info("Async task {d} completed successfully", .{task_id});
    } else {
        res.status = .internal_server_error;
        res.setBody("No result from async task") catch return;
        std.log.warn("Async task {d} returned no result", .{task_id});
    }
}

fn loggingMiddleware(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    const request_id = std.fmt.allocPrint(ctx.allocator, "{d}", .{std.time.nanoTimestamp()}) catch "unknown";
    ctx.set("request_id", request_id) catch return;
    std.log.info("{s} {s} {s}", .{ req.method, req.path, request_id });
    next(req, res, ctx);
}

fn bundleMiddleware(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    if (bundle_ptr_static) |ptr| {
        ctx.set("server_bundle", ptr) catch return;
    } else {
        std.log.err("Bundle pointer not initialized in middleware", .{});
    }
    next(req, res, ctx);
}

fn userHandler(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const user_id = ctx.get("id") orelse "unknown";
    const message = std.fmt.allocPrint(res.allocator, "User ID: {s}", .{user_id}) catch "Error";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    std.log.info("Served user endpoint with id: {s}", .{user_id});
}

fn setupRoutes(server: *Server) !void {
    try server.use(loggingMiddleware);
    try server.route("GET", "/", hello);
    try server.route("GET", "/json", jsonEndpoint);
    try server.route("GET", "/async", asyncEndpoint);
    try server.route("GET", "/users/:id", userHandler); // New route
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

    var bundle = try zttp.createServer(allocator, options, setupRoutes);
    defer bundle.deinit();

    const bundle_ptr = try std.fmt.allocPrint(allocator, "{x}", .{@intFromPtr(bundle)});
    defer allocator.free(bundle_ptr);

    bundle_ptr_static = bundle_ptr;
    defer bundle_ptr_static = null;

    try bundle.use(bundleMiddleware);

    std.log.info("Starting server on :8080", .{});
    try bundle.start(false);
}
