// zttp/src/server.zig
const std = @import("std");
const Context = @import("context.zig").Context;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const StatusCode = @import("response.zig").StatusCode;
const ThreadPool = @import("pool.zig").ThreadPool;
const HandlerFn = @import("router.zig").HandlerFn;
const MiddlewareFn = @import("router.zig").MiddlewareFn;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const Router = @import("router.zig").Router;
const HttpMethod = @import("zttp.zig").HttpMethod;
const Template = @import("template/main.zig");
const WebSocket = @import("websocket.zig").WebSocket;
const Async = @import("async/async.zig");
const AsyncIoContext = Async.AsyncIoContext;
const Task = Async.Task;
const AsyncContext = Async.Context;
const ResultError = Async.ResultError;
const Connection = @import("connection.zig");
const BackendType = @import("async/async.zig").BackendType;

const log = std.log.scoped(.server);

pub const Server = struct {
    allocator: std.mem.Allocator,
    listener: ?std.net.Server,
    async_ctx: ?*AsyncIoContext,
    options: Options,
    running: std.atomic.Value(bool),
    router: Router,
    pool: *ThreadPool,
    websockets: std.ArrayList(WebSocket),

    pub const Options = struct {
        port: u16 = 8088,
        thread_pool_options: ThreadPool.Options = .{},
        websocket_options: WebSocket.Options = .{},
        async_ring_entries: u16 = 256,
        backend_type: BackendType = .io_uring,
    };

    pub fn init(allocator: std.mem.Allocator, options: Options, pool: *ThreadPool) !Server {
        var server = Server{
            .allocator = allocator,
            .listener = null,
            .async_ctx = null,
            .options = options,
            .running = std.atomic.Value(bool).init(false),
            .router = Router.init(allocator),
            .pool = pool,
            .websockets = std.ArrayList(WebSocket).init(allocator),
        };

        server.async_ctx = try allocator.create(AsyncIoContext);
        server.async_ctx.?.* = try AsyncIoContext.init(allocator, options.async_ring_entries, options.backend_type);
        std.log.debug("Server.init: AsyncIoContext initialized with backend={any}", .{options.backend_type});

        return server;
    }

    pub fn deinit(self: *Server) void {
        self.running.store(false, .release);

        for (self.websockets.items) |*ws| {
            ws.close();
        }
        self.websockets.deinit();

        if (self.async_ctx) |ctx| {
            ctx.deinit();
            self.allocator.destroy(ctx);
            self.async_ctx = null;
        }

        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }

        self.router.deinit();
    }

    pub fn route(self: *Server, module_name: []const u8, method: HttpMethod, path: []const u8, handler: ?HandlerFn, ws_handler: ?WebSocketHandlerFn) !void {
        try self.router.add(module_name, method, path, handler, ws_handler);
    }

    pub fn use(self: *Server, middleware: MiddlewareFn) !void {
        try self.router.use(middleware);
    }

    fn handleAcceptCompletion(async_ctx: *AsyncIoContext, task: Task) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(task.userdata));
        const result = task.result orelse return error.NoResult;

        const new_fd = result.accept catch |err| {
            log.err("Async accept failed: {}", .{err});

            // Make sure we schedule a new accept task before returning
            _ = try async_ctx.accept(server.listener.?.stream.handle, AsyncContext{
                .ptr = server,
                .cb = handleAcceptCompletion,
                .msg = 0,
            });
            return;
        };

        log.info("Accepted new connection (FD: {})", .{new_fd});

        const stream = std.net.Stream{ .handle = new_fd };
        const connection_task = Connection.ConnectionTask{
            .server = server,
            .conn = std.net.Server.Connection{
                .stream = stream,
                .address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 0),
            },
        };

        // Schedule the connection handling in the thread pool with proper error handling
        _ = server.pool.schedule(
            Connection.handleConnection,
            connection_task,
            null,
            5,
            null,
            0,
            0,
            null,
            null,
        ) catch |err| {
            log.err("Failed to schedule connection handling: {}", .{err});
            // Close the connection if we can't handle it
            std.posix.close(new_fd);
            log.debug("Closed connection FD: {d} after scheduling error", .{new_fd});
        };

        // Always schedule the next accept task, regardless of connection handling success
        _ = try async_ctx.accept(server.listener.?.stream.handle, AsyncContext{
            .ptr = server,
            .cb = handleAcceptCompletion,
            .msg = 0,
        });
    }

    pub fn start(self: *Server) !void {
        if (self.running.load(.acquire)) return error.AlreadyRunning;

        self.running.store(true, .release);

        if (self.options.backend_type == .dummy) {
            std.log.debug("Server.start: Running with dummy backend", .{});
            // Simulate server loop without listener
            while (self.running.load(.acquire)) {
                if (self.async_ctx) |ctx| {
                    ctx.submit() catch |err| {
                        std.log.err("Dummy submit failed: {}", .{err});
                        continue;
                    };
                    ctx.reapCompletions() catch |err| {
                        std.log.err("Dummy reap completions failed: {}", .{err});
                        continue;
                    };
                }
                std.time.sleep(10_000_000); // 10ms sleep to avoid tight loop
            }
            std.log.info("Server main loop stopped (dummy backend)", .{});
            return;
        }

        const address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, self.options.port);
        self.listener = try address.listen(.{ .reuse_address = true });
        const listen_fd = self.listener.?.stream.handle;
        std.log.info("Server listening on 0.0.0.0:{d} (FD: {})", .{ self.options.port, listen_fd });

        if (self.async_ctx == null) {
            std.log.err("Server.start: AsyncIoContext not initialized", .{});
            return error.InvalidState;
        }

        _ = try self.async_ctx.?.accept(listen_fd, AsyncContext{
            .ptr = self,
            .cb = handleAcceptCompletion,
            .msg = 0,
        });
        std.log.debug("Initial async accept task submitted", .{});

        while (self.running.load(.acquire) or !self.async_ctx.?.done()) {
            //std.log.debug("Server loop: running={any}, async_ctx.done={any}", .{ self.running.load(.acquire), self.async_ctx.?.done() });
            if (self.async_ctx) |ctx| {
                ctx.submit() catch |err| {
                    std.log.err("Submit failed: {}", .{err});
                    continue;
                };
                ctx.reapCompletions() catch |err| {
                    std.log.err("Reap completions failed: {}", .{err});
                    continue;
                };

                const poll_fd = ctx.pollableFd() catch |err| {
                    std.log.err("Pollable FD error: {}", .{err});
                    continue;
                };
                var pollfds = [1]std.posix.pollfd{.{ .fd = poll_fd, .events = std.posix.POLL.IN, .revents = 0 }};
                const poll_timeout_ms = 0;

                _ = std.posix.poll(&pollfds, poll_timeout_ms) catch |err| {
                    std.log.err("Poll error: {}", .{err});
                    continue;
                };
            }
        }

        std.log.info("Server main loop stopped", .{});
    }
};
