const std = @import("std");
const zttp = @import("zttp");
const Server = zttp.Server;
const Request = zttp.Request;
const Response = zttp.Response;
const ServerOptions = zttp.ServerOptions;

// Store the server bundle as a global variable
// This avoids needing to modify Request to add a context field
var server_bundle: ?*zttp.ServerBundle = null;

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

fn asyncEndpoint(_: *Request, res: *Response) void {
    if (server_bundle == null) {
        res.status = .internal_server_error;
        res.setBody("Server bundle not initialized") catch return;
        std.log.err("Server bundle not initialized", .{});
        return;
    }

    const task = AsyncTask{
        .allocator = res.allocator,
        .delay_ms = 1000,
    };

    const task_id = server_bundle.?.pool.schedule(
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

    // Wait for task completion
    const success = server_bundle.?.pool.waitForTask(task_id, 2 * std.time.ns_per_s) catch |err| {
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

    const status = server_bundle.?.pool.getTaskStatus(task_id);
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

// Setup routes for the server
fn setupRoutes(server: *Server) !void {
    try server.route("/", hello);
    try server.route("/json", jsonEndpoint);
    try server.route("/async", asyncEndpoint);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create server with the new integrated API
    const options = ServerOptions{
        .port = 8080,
        .min_threads = 2,
        .max_threads = 8,
        .max_tasks = 100,
    };

    var bundle = try zttp.createServer(allocator, options, setupRoutes);
    defer bundle.deinit();

    // Store the bundle in the global variable
    server_bundle = bundle;
    defer server_bundle = null;

    std.log.info("Starting server on :8080", .{});
    try bundle.start(false); // Run in the main thread
}
