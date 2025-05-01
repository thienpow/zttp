const std = @import("std");
const Allocator = std.mem.Allocator;

const Router = @import("router.zig").Router;
const HandlerFn = @import("router.zig").HandlerFn;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const MiddlewareFn = @import("router.zig").MiddlewareFn;

const AsyncIo = @import("../async/async.zig").AsyncIo;
const Task = @import("../async/task.zig").Task;

const HttpMethod = @import("../http/request.zig").HttpMethod;

const websocket = @import("../websocket/mod.zig");
const Connection = @import("connection.zig").Connection;

const log = std.log.scoped(.server);

pub const Server = struct {
    allocator: Allocator,
    listener: ?std.net.Server,
    async_io: ?*AsyncIo,
    options: Options,
    running: std.atomic.Value(bool),
    router: Router,
    websocket_fds: std.AutoHashMap(std.posix.fd_t, void),
    connections: std.AutoHashMap(std.posix.fd_t, *Connection),

    pub const Options = struct {
        port: u16 = 8088,
        websocket_options: websocket.WebSocket.Options = .{},
        async_ring_entries: u16 = 1024, // Increased for browser workloads
        max_connections: usize = 100, // Limit concurrent connections
        header_read_timeout_ms: u64 = 1000,
    };

    pub fn init(allocator: Allocator, options: Options) !Server {
        var server = Server{
            .allocator = allocator,
            .listener = null,
            .async_io = null,
            .options = options,
            .running = std.atomic.Value(bool).init(false),
            .router = Router.init(allocator),
            .websocket_fds = std.AutoHashMap(std.posix.fd_t, void).init(allocator),
            .connections = std.AutoHashMap(std.posix.fd_t, *Connection).init(allocator),
        };

        server.async_io = try allocator.create(AsyncIo);
        server.async_io.?.* = try AsyncIo.init(allocator, options.async_ring_entries);

        const address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, options.port);
        const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
        errdefer std.posix.close(socket);

        // Set SO_REUSEADDR
        try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

        // Set SO_REUSEPORT if available
        const reuse_port_supported = @hasDecl(std.posix.SO, "REUSEPORT");
        if (reuse_port_supported) {
            try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
            log.info("SO_REUSEPORT enabled for socket on port {d}", .{options.port});
        } else {
            log.warn("SO_REUSEPORT not supported on this platform, multiple servers may fail to bind", .{});
        }

        try std.posix.bind(socket, &address.any, address.getOsSockLen());
        try std.posix.listen(socket, 128);
        server.listener = std.net.Server{
            .stream = .{ .handle = socket },
            .listen_address = address,
        };

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

        // Clean up WebSocket FDs
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

        // Schedule initial accept
        const listener_fd = self.listener.?.stream.handle;
        const accept_task = self.async_io.?.accept(listener_fd, .{
            .ptr = self,
            .cb = handleAcceptCompletion,
        }) catch |err| {
            log.err("Failed to schedule initial accept: {s}", .{@errorName(err)});
            return err;
        };

        _ = accept_task;

        // Main event loop
        var pollfds = [_]std.posix.pollfd{.{ .fd = try self.async_io.?.pollableFd(), .events = std.posix.POLL.IN, .revents = 0 }};
        const poll_timeout_ms = 10; // Small timeout to reduce CPU usage

        log.info("Server started on port {d}", .{self.options.port});
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

        _ = async_io.accept(server.listener.?.stream.handle, .{
            .ptr = server,
            .cb = handleAcceptCompletion,
        }) catch |accept_err| {
            log.err("Failed to schedule next accept: {s}", .{@errorName(accept_err)});
            return accept_err;
        };
    }
};
