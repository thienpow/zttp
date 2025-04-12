const std = @import("std");
const zttp = @import("zttp");
const Server = zttp.Server;
const ThreadPool = zttp.ThreadPool;
const Request = zttp.Request;
const Response = zttp.Response;

// Global ThreadPool, initialized in main
var pool: ?ThreadPool = null;

fn hello(_: *Request, res: *Response) void {
    res.status = .ok;
    res.setBody("Hello, World!") catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
    std.log.info("Served hello endpoint", .{});
}

fn jsonEndpoint(req: *Request, res: *Response) void {
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
    task_id: u64 = 0, // Store task ID for waiting

    fn process(self: AsyncTask, result: *ThreadPool.TaskResult) void {
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

    fn deinit(self: AsyncTask, result: *ThreadPool.TaskResult) void {
        if (result.payload != null and result.payload_size > 0) {
            const ptr: [*]u8 = @ptrCast(result.payload.?);
            self.allocator.free(ptr[0..result.payload_size]);
        }
    }
};

fn asyncEndpoint(_: *Request, res: *Response) void {
    if (pool == null) {
        res.status = .internal_server_error;
        res.setBody("Thread pool not initialized") catch return;
        std.log.err("Thread pool not initialized", .{});
        return;
    }

    var task = AsyncTask{
        .allocator = res.allocator,
        .delay_ms = 1000,
    };
    const task_id = pool.?.schedule(
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
    task.task_id = task_id;
    std.log.info("Scheduled async task ID: {d}", .{task_id});

    // Wait for task completion
    const success = pool.?.waitForTask(task_id, 2 * std.time.ns_per_s) catch |err| {
        res.status = .internal_server_error;
        res.setBody("Failed to wait for task") catch return;
        std.log.err("Failed to wait for async task {d}: {}", .{ task_id, err });
        return;
    };

    var result = ThreadPool.TaskResult{};
    defer task.deinit(&result);

    if (!success) {
        res.status = .internal_server_error;
        res.setBody("Async task failed or timed out") catch return;
        std.log.warn("Async task {d} failed or timed out", .{task_id});
        return;
    }

    if (result.payload != null and result.payload_size > 0) {
        const msg: []const u8 = @as([*]const u8, @ptrCast(result.payload.?))[0..result.payload_size];
        res.setBody(msg) catch return;
        res.status = .ok;
        res.setHeader("Content-Type", "text/plain") catch return;
        std.log.info("Async task {d} completed successfully", .{task_id});
    } else {
        res.status = .internal_server_error;
        res.setBody("No result from async task") catch return;
        std.log.warn("Async task {d} returned no result", .{task_id});
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize global pool
    pool = try ThreadPool.init(allocator, .{
        .min_threads = 2,
        .max_threads = 8,
        .max_tasks = 100,
    });
    defer if (pool) |*p| p.deinit();
    try pool.?.startWorkers(2);

    var server = Server.init(allocator, 8080, &pool.?);
    defer server.deinit();

    try server.route("/", hello);
    try server.route("/json", jsonEndpoint);
    try server.route("/async", asyncEndpoint);

    std.log.info("Starting server on :8080", .{});
    try server.start();
}
