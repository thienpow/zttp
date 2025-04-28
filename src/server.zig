// src/server.zig
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
const AsyncIo = Async.AsyncIo;
const Task = Async.Task;
const AsyncContext = Async.Context;
const ResultError = Async.ResultError;
const Connection = @import("connection.zig");

const log = std.log.scoped(.server);

pub const Server = struct {
    allocator: std.mem.Allocator,
    listener: ?std.net.Server,
    async_io: ?*AsyncIo,
    options: Options,
    running: std.atomic.Value(bool),
    router: Router,
    pool: *ThreadPool,
    websockets: std.ArrayList(WebSocket),
    websocket_fds: std.AutoHashMap(std.posix.fd_t, void),

    pub const Options = struct {
        port: u16 = 8088,
        thread_pool_options: ThreadPool.Options = .{},
        websocket_options: WebSocket.Options = .{},
        async_ring_entries: u16 = 256,
    };

    pub fn init(allocator: std.mem.Allocator, options: Options, pool: *ThreadPool) !Server {
        var server = Server{
            .allocator = allocator,
            .listener = null,
            .async_io = null,
            .options = options,
            .running = std.atomic.Value(bool).init(false),
            .router = Router.init(allocator),
            .pool = pool,
            .websockets = std.ArrayList(WebSocket).init(allocator),
            .websocket_fds = std.AutoHashMap(std.posix.fd_t, void).init(allocator),
        };

        server.async_io = try allocator.create(AsyncIo);
        errdefer allocator.destroy(server.async_io.?);
        server.async_io.?.* = try AsyncIo.init(allocator, options.async_ring_entries);

        return server;
    }

    pub fn deinit(self: *Server) void {
        self.running.store(false, .release);

        for (self.websockets.items) |*ws| {
            ws.close();
        }
        self.websockets.deinit();
        self.websocket_fds.deinit();

        if (self.async_io) |ctx| {
            ctx.deinit();
            self.allocator.destroy(ctx);
            self.async_io = null;
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

    fn handleAcceptCompletion(async_io: *AsyncIo, task: Task) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(task.userdata));
        const result = task.result orelse return error.NoResult;

        const new_fd = result.accept catch |err| {
            log.err("Async accept failed: {}", .{err});
            _ = try async_io.accept(server.listener.?.stream.handle, AsyncContext{
                .ptr = server,
                .cb = handleAcceptCompletion,
                .msg = 0,
            });
            return;
        };

        log.info("Accepted new connection (FD: {})", .{new_fd});

        const is_websocket = server.websocket_fds.contains(new_fd);
        std.log.debug("FD: {d} is_websocket: {any}", .{ new_fd, is_websocket });

        const stream = std.net.Stream{ .handle = new_fd };
        const connection_task = Connection.ConnectionTask{
            .server = server,
            .conn = std.net.Server.Connection{
                .stream = stream,
                .address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 0),
            },
        };

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
            log.err("Failed to schedule connection handling (FD: {d}): {any}", .{ new_fd, err });
            std.posix.close(new_fd);
            log.debug("Closed connection FD: {d} after scheduling error", .{new_fd});
        };

        _ = try async_io.accept(server.listener.?.stream.handle, AsyncContext{
            .ptr = server,
            .cb = handleAcceptCompletion,
            .msg = 0,
        });
    }

    pub fn start(self: *Server) !void {
        if (self.running.load(.acquire)) return error.AlreadyRunning;

        self.running.store(true, .release);

        const address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, self.options.port);
        self.listener = try address.listen(.{ .reuse_address = true });
        const listen_fd = self.listener.?.stream.handle;
        std.log.info("Server listening on 0.0.0.0:{d} (FD: {})", .{ self.options.port, listen_fd });

        if (self.async_io == null) {
            std.log.err("Server.start: AsyncIo not initialized", .{});
            return error.InvalidState;
        }

        _ = try self.async_io.?.accept(listen_fd, AsyncContext{
            .ptr = self,
            .cb = handleAcceptCompletion,
            .msg = 0,
        });
        std.log.debug("Initial async accept task submitted", .{});

        while (self.running.load(.acquire) or !self.async_io.?.done()) {
            //std.log.debug("Server loop: running={any}, async_io.done={any}", .{ self.running.load(.acquire), self.async_io.?.done() });
            if (self.async_io) |ctx| {
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
