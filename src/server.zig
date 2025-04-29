const std = @import("std");
const Allocator = std.mem.Allocator;
const AsyncIo = @import("async/async.zig").AsyncIo;
const Task = @import("async/task.zig").Task;
const Router = @import("router.zig").Router;
const HttpMethod = @import("request.zig").HttpMethod;
const HandlerFn = @import("router.zig").HandlerFn;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const MiddlewareFn = @import("router.zig").MiddlewareFn;
const WebSocket = @import("websocket.zig").WebSocket;
const Connection = @import("connection.zig").Connection;
const log = std.log.scoped(.server);

pub const Server = struct {
    allocator: Allocator,
    listener: ?std.net.Server,
    async_io: ?*AsyncIo,
    options: Options,
    running: std.atomic.Value(bool),
    router: Router,
    websockets: std.ArrayList(WebSocket),
    websocket_fds: std.AutoHashMap(std.posix.fd_t, void),
    connections: std.AutoHashMap(std.posix.fd_t, *Connection),

    pub const Options = struct {
        port: u16 = 8088,
        websocket_options: WebSocket.Options = .{},
        async_ring_entries: u16 = 1024, // Increased for browser workloads
        max_connections: usize = 100, // Limit concurrent connections
    };

    pub fn init(allocator: Allocator, options: Options) !Server {
        var server = Server{
            .allocator = allocator,
            .listener = null,
            .async_io = null,
            .options = options,
            .running = std.atomic.Value(bool).init(false),
            .router = Router.init(allocator),
            .websockets = std.ArrayList(WebSocket).init(allocator),
            .websocket_fds = std.AutoHashMap(std.posix.fd_t, void).init(allocator),
            .connections = std.AutoHashMap(std.posix.fd_t, *Connection).init(allocator),
        };

        server.async_io = try allocator.create(AsyncIo);
        server.async_io.?.* = try AsyncIo.init(allocator, options.async_ring_entries);

        const address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, options.port);
        server.listener = try address.listen(.{ .reuse_address = true });
        return server;
    }

    pub fn deinit(self: *Server) void {
        self.running.store(false, .release);

        // Close all active connections
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.asyncClose() catch |err| {
                log.err("Failed to close connection FD {d}: {}", .{ entry.key_ptr.*, err });
            };
        }
        self.connections.deinit();

        // Clean up WebSocket connections
        for (self.websockets.items) |*ws| {
            ws.close(.{});
        }
        self.websockets.deinit();
        self.websocket_fds.deinit();

        // Clean up async_io and listener
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

    pub fn start(self: *Server) !void {
        self.running.store(true, .release);
        log.info("Server starting on port {d}", .{self.options.port});

        // Schedule initial accept
        const listener_fd = self.listener.?.stream.handle;
        log.debug("Scheduling initial accept for listener FD: {d}", .{listener_fd});
        const accept_task = self.async_io.?.accept(listener_fd, .{
            .ptr = self,
            .cb = handleAcceptCompletion,
        }) catch |err| {
            log.err("Failed to schedule initial accept: {s}", .{@errorName(err)});
            return err;
        };
        log.debug("Initial accept task scheduled (ptr: {*})", .{accept_task});

        // Main event loop
        var pollfds = [_]std.posix.pollfd{.{ .fd = try self.async_io.?.pollableFd(), .events = std.posix.POLL.IN, .revents = 0 }};
        const poll_timeout_ms = 10; // Small timeout to reduce CPU usage

        while (self.running.load(.acquire) or !self.async_io.?.done()) {
            const ctx = self.async_io.?;
            ctx.submit() catch |err| {
                log.err("Submit failed: {}, continuing event loop", .{err});
                continue;
            };

            _ = std.posix.poll(&pollfds, poll_timeout_ms) catch |err| {
                log.err("Poll failed: {}", .{err});
                continue;
            };

            if (pollfds[0].revents & std.posix.POLL.IN != 0) {
                ctx.reapCompletions() catch |err| {
                    log.err("Reap completions failed: {}", .{err});
                };
            }
        }

        log.info("Server stopped", .{});
    }

    // Register a route with HTTP or WebSocket handler
    pub fn route(self: *Server, module_name: []const u8, method: HttpMethod, path: []const u8, handler: ?HandlerFn, ws_handler: ?WebSocketHandlerFn) !void {
        try self.router.add(module_name, method, path, handler, ws_handler);
    }

    // Add middleware to the router
    pub fn use(self: *Server, middleware: MiddlewareFn) !void {
        try self.router.use(middleware);
    }

    fn handleAcceptCompletion(async_io: *AsyncIo, task: *Task) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(task.userdata));
        const result = task.result orelse return error.NoResult;

        log.debug("Handling accept completion, task ptr: {*}, userdata: {x}", .{ task, @intFromPtr(task.userdata) });

        const new_fd = result.accept catch |err| {
            log.err("Async accept failed: {}", .{err});
            task.userdata = null; // Clean task before reuse
            _ = async_io.accept(server.listener.?.stream.handle, .{
                .ptr = server,
                .cb = handleAcceptCompletion,
            }) catch |accept_err| {
                log.err("Failed to schedule next accept: {s}", .{@errorName(accept_err)});
                return accept_err;
            };
            return;
        };

        if (server.connections.count() >= server.options.max_connections) {
            log.warn("Max connections reached, closing FD {d}", .{new_fd});
            std.posix.close(new_fd);
            task.userdata = null; // Clean task before reuse
            _ = async_io.accept(server.listener.?.stream.handle, .{
                .ptr = server,
                .cb = handleAcceptCompletion,
            }) catch |accept_err| {
                log.err("Failed to schedule next accept: {s}", .{@errorName(accept_err)});
                return accept_err;
            };
            return;
        }

        log.info("Accepted new connection (FD: {d})", .{new_fd});

        const stream = std.net.Stream{ .handle = new_fd };
        const conn = std.net.Server.Connection{
            .stream = stream,
            .address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 0),
        };

        const connection = Connection.init(server, conn, server.allocator) catch |err| {
            log.err("Failed to initialize connection for FD {d}: {s}", .{ new_fd, @errorName(err) });
            std.posix.close(new_fd);
            task.userdata = null; // Clean task before reuse
            _ = async_io.accept(server.listener.?.stream.handle, .{
                .ptr = server,
                .cb = handleAcceptCompletion,
            }) catch |accept_err| {
                log.err("Failed to schedule next accept: {s}", .{@errorName(accept_err)});
                return accept_err;
            };
            return;
        };
        try server.connections.put(new_fd, connection);

        task.userdata = null; // Clean task before scheduling next accept
        log.debug("Cleared task userdata for ptr: {*}, scheduling next accept", .{task});

        _ = async_io.accept(server.listener.?.stream.handle, .{
            .ptr = server,
            .cb = handleAcceptCompletion,
        }) catch |accept_err| {
            log.err("Failed to schedule next accept: {s}", .{@errorName(accept_err)});
            return accept_err;
        };
    }
};
