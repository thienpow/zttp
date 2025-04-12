const std = @import("std");
const http = @import("http.zig");
const ThreadPool = @import("pool.zig").ThreadPool;

pub const Server = struct {
    allocator: std.mem.Allocator,
    listener: ?std.net.Server,
    port: u16,
    running: bool,
    router: http.Router,
    pool: *ThreadPool,

    pub fn init(allocator: std.mem.Allocator, port: u16, pool: *ThreadPool) Server {
        return .{
            .allocator = allocator,
            .listener = null,
            .port = port,
            .running = false,
            .router = http.Router.init(allocator),
            .pool = pool,
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener) |*listener| {
            listener.deinit();
        }
        self.router.deinit();
    }

    pub fn route(self: *Server, path: []const u8, handler: http.HandlerFn) !void {
        try self.router.add(path, handler);
    }

    pub fn start(self: *Server) !void {
        if (self.running) return error.AlreadyRunning;

        const address = try std.net.Address.parseIp("0.0.0.0", self.port);
        self.listener = try address.listen(.{ .reuse_address = true });
        self.running = true;

        std.log.info("Server listening on 0.0.0.0:{d}", .{self.port});

        while (self.running) {
            const conn = self.listener.?.accept() catch |err| {
                std.log.err("Failed to accept connection: {}", .{err});
                continue;
            };
            const task_id = try self.pool.schedule(
                handleConnection,
                ConnectionTask{ .server = self, .conn = conn },
                null,
                5,
                null,
                0,
                0,
                null,
                null,
            );
            std.log.debug("Scheduled connection handling task: {d}", .{task_id});
        }
    }

    const ConnectionTask = struct {
        server: *Server,
        conn: std.net.Server.Connection,
    };

    fn handleConnection(task: ConnectionTask, result: *ThreadPool.TaskResult) void {
        defer task.conn.stream.close();
        var arena = std.heap.ArenaAllocator.init(task.server.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        var buffer: [16384]u8 = undefined;
        const bytes_read = task.conn.stream.read(&buffer) catch |err| {
            std.log.err("Failed to read request: {}", .{err});
            result.success = false;
            return;
        };
        if (bytes_read == 0) {
            result.success = true;
            return;
        }

        var req = http.Request.parse(alloc, buffer[0..bytes_read]) catch |err| {
            std.log.err("Failed to parse request: {}", .{err});
            sendError(task.conn.stream, alloc, .bad_request, "Invalid Request");
            result.success = false;
            return;
        };
        var res = http.Response.init(alloc);

        res.setHeader("Server", "zig-http/0.1") catch {
            sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
            result.success = false;
            return;
        };

        const keep_alive = req.isKeepAlive();
        if (keep_alive) {
            res.setHeader("Connection", "keep-alive") catch {};
        } else {
            res.setHeader("Connection", "close") catch {};
        }

        const handler = task.server.router.find(req.path) orelse notFound;
        handler(&req, &res);

        res.send(task.conn.stream) catch |err| {
            std.log.err("Failed to send response: {}", .{err});
            result.success = false;
            return;
        };

        result.success = true;
    }

    fn sendError(stream: std.net.Stream, alloc: std.mem.Allocator, status: http.StatusCode, msg: []const u8) void {
        var res = http.Response.init(alloc);
        defer res.deinit();
        res.status = status;
        res.setBody(msg) catch return;
        res.setHeader("Content-Type", "text/plain") catch return;
        res.send(stream) catch return;
    }

    fn notFound(_: *http.Request, res: *http.Response) void {
        res.status = .not_found;
        res.body = "Not Found";
        res.setHeader("Content-Type", "text/plain") catch return;
    }
};

pub fn initServer(allocator: std.mem.Allocator, port: u16, pool: *ThreadPool) Server {
    return Server.init(allocator, port, pool);
}
