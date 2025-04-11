const std = @import("std");
const zttp = @import("zttp");
const Server = zttp.Server;
const ThreadPool = zttp.ThreadPool;

// Global thread pool that will be used by handlers
var global_pool: *ThreadPool = undefined;

// Simple hello world handler function
fn helloHandler(req: *Server.Request, res: *Server.Response) void {
    std.debug.print("Received request for path: {s}\n", .{req.path});

    res.setHeader("Content-Type", "text/html") catch |err| {
        std.debug.print("Error setting header: {}\n", .{err});
        return;
    };

    res.setBody("<html><body><h1>Hello, World!</h1><p>Welcome to our Zig HTTP server.</p></body></html>") catch |err| {
        std.debug.print("Error setting body: {}\n", .{err});
        return;
    };
}

// Structure to hold the task parameters and results
const AsyncTaskData = struct {
    client_id: u32,
    allocator: std.mem.Allocator,
    result_message: ?[]const u8 = null,

    pub fn deinit(self: *AsyncTaskData) void {
        if (self.result_message) |msg| {
            self.allocator.free(msg);
        }
    }
};

// Function that will be executed in the thread pool
fn processingTask(data: AsyncTaskData, result: *ThreadPool.TaskResult) void {
    std.debug.print("Starting async processing for client: {d}\n", .{data.client_id});

    // Simulate complex processing
    std.time.sleep(3 * std.time.ns_per_s);

    // Create result message that could be stored in a database or message queue
    const result_msg = std.fmt.allocPrint(data.allocator, "Processed data for client {d} at timestamp: {d}", .{ data.client_id, std.time.timestamp() }) catch {
        result.success = false;
        return;
    };

    // Store result where it could be retrieved later
    std.debug.print("Task completed with result: {s}\n", .{result_msg});
    data.allocator.free(result_msg);

    result.success = true;
}

// Request counter to simulate different client IDs
var request_counter = std.atomic.Value(u32).init(0);

// Handler that schedules work on the thread pool
fn asyncHandler(req: *Server.Request, res: *Server.Response) void {
    _ = req; // Unused in this example

    // Generate a unique client ID
    const client_id = request_counter.fetchAdd(1, .monotonic);

    // Create task data
    const task_data = AsyncTaskData{
        .client_id = client_id,
        .allocator = res.allocator,
    };

    // Schedule the task on the thread pool
    _ = global_pool.schedule(
        processingTask,
        task_data,
        null, // No result storage
        5, // Priority
        null, // No timeout
        0, // No retries
        0, // No retry delay
        null, // No dependencies
        null, // No dependency timeout
    ) catch |err| {
        std.debug.print("Failed to schedule task: {}\n", .{err});
        res.status = 500;
        res.setBody("Failed to schedule async task") catch return;
        return;
    };

    // Send response
    res.setHeader("Content-Type", "text/plain") catch return;
    res.setBody(std.fmt.allocPrint(res.allocator, "Started async task for client {d}. Check server logs for completion.", .{client_id}) catch "Started async task") catch return;

    std.debug.print("Queued async task for client {d}\n", .{client_id});
}

pub fn main() !void {
    // Create an allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize the thread pool
    const pool_options = ThreadPool.Options{
        .min_threads = 2,
        .max_threads = 4,
        .max_tasks = 50,
    };

    var pool = try ThreadPool.init(allocator, pool_options);
    defer pool.deinit();

    // Start the worker threads
    try pool.startWorkers(2);

    // Make the pool available globally
    global_pool = &pool;

    // Create a server
    var server = Server.init(allocator, 8080);
    defer server.deinit();

    // Add routes
    try server.addRoute("/", helloHandler);
    try server.addRoute("/async", asyncHandler);

    // Start the server (this will block)
    std.debug.print("Starting server on port 8080\n", .{});
    try server.start();
}
