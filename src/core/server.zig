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

const http2 = @import("../http2/mod.zig");

const log = std.log.scoped(.server);

pub const Server = struct {
    allocator: Allocator,
    tcp_listener: ?std.net.Server, // Renamed for clarity
    udp_socket: ?std.posix.fd_t, // New UDP socket for QUIC
    async_io: ?*AsyncIo,
    options: Options,
    running: std.atomic.Value(bool),
    router: Router,
    websocket_fds: std.AutoHashMap(std.posix.fd_t, void),
    connections: std.AutoHashMap(std.posix.fd_t, *Connection),

    pub const Options = struct {
        app_context_ptr: *anyopaque,
        port: u16 = 8088,
        async_ring_entries: u16 = 1024,
        max_connections: usize = 100,
        header_read_timeout_ms: u64 = 1000,
        websocket: websocket.WebSocket.Options = .{},
        http2_settings: http2.Settings = .{},
        enable_http3: bool = false, // New option to toggle HTTP/3
    };

    pub fn init(allocator: Allocator, options: Options) !Server {
        var server = Server{
            .allocator = allocator,
            .tcp_listener = null,
            .udp_socket = null,
            .async_io = null,
            .options = options,
            .running = std.atomic.Value(bool).init(false),
            .router = Router.init(allocator),
            .websocket_fds = std.AutoHashMap(std.posix.fd_t, void).init(allocator),
            .connections = std.AutoHashMap(std.posix.fd_t, *Connection).init(allocator),
        };

        server.async_io = try allocator.create(AsyncIo);
        server.async_io.?.* = try AsyncIo.init(allocator, options.async_ring_entries);

        // TCP socket setup (existing)
        const address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, options.port);
        const tcp_socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
        errdefer std.posix.close(tcp_socket);

        try std.posix.setsockopt(tcp_socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        const reuse_port_supported = @hasDecl(std.posix.SO, "REUSEPORT");
        if (reuse_port_supported) {
            try std.posix.setsockopt(tcp_socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
            log.info("SO_REUSEPORT enabled for TCP socket on port {d}", .{options.port});
        } else {
            log.warn("SO_REUSEPORT not supported, multiple servers may fail to bind", .{});
        }

        try std.posix.bind(tcp_socket, &address.any, address.getOsSockLen());
        try std.posix.listen(tcp_socket, 128);
        server.tcp_listener = std.net.Server{
            .stream = .{ .handle = tcp_socket },
            .listen_address = address,
        };

        // UDP socket setup for QUIC/HTTP/3
        if (options.enable_http3) {
            const udp_socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
            errdefer std.posix.close(udp_socket);

            try std.posix.setsockopt(udp_socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
            if (reuse_port_supported) {
                try std.posix.setsockopt(udp_socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
                log.info("SO_REUSEPORT enabled for UDP socket on port {d}", .{options.port});
            }

            try std.posix.bind(udp_socket, &address.any, address.getOsSockLen());
            server.udp_socket = udp_socket;
            log.info("UDP socket created for QUIC/HTTP/3 on port {d}", .{options.port});
        }

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

        // Clean up async_io, TCP listener, and UDP socket
        if (self.async_io) |ctx| {
            ctx.deinit();
            self.allocator.destroy(ctx);
            self.async_io = null;
        }

        if (self.tcp_listener) |*listener| {
            listener.deinit();
            self.tcp_listener = null;
        }

        if (self.udp_socket) |udp_fd| {
            std.posix.close(udp_fd);
            self.udp_socket = null;
        }

        self.router.deinit();
    }

    pub fn start(self: *Server) !void {
        self.running.store(true, .release);

        // Schedule initial TCP accept
        const listener_fd = self.tcp_listener.?.stream.handle;
        const accept_task = self.async_io.?.accept(listener_fd, .{
            .ptr = self,
            .cb = handleAcceptCompletion,
        }) catch |err| {
            log.err("Failed to schedule initial TCP accept: {s}", .{@errorName(err)});
            return err;
        };
        _ = accept_task;

        // Schedule initial UDP recv for QUIC if enabled
        if (self.options.enable_http3 and self.udp_socket != null) {
            const buffer = try self.allocator.alloc(u8, 1500); // Buffer for QUIC packets
            errdefer self.allocator.free(buffer);
            const udp_task = self.async_io.?.recv(self.udp_socket.?, buffer, .{
                .ptr = self,
                .cb = handleQuicReadCompletion,
            }) catch |err| {
                self.allocator.free(buffer);
                log.err("Failed to schedule initial QUIC recv: {s}", .{@errorName(err)});
                return err;
            };
            _ = udp_task;
        }

        // Main event loop
        var pollfds = [_]std.posix.pollfd{
            .{ .fd = try self.async_io.?.pollableFd(), .events = std.posix.POLL.IN, .revents = 0 },
        };
        const poll_timeout_ms = 10;

        log.info("Server started on port {d} (TCP: HTTP/1.1, HTTP/2; UDP: HTTP/3 = {any})", .{ self.options.port, self.options.enable_http3 });
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
        // Advertise HTTP/3 support via Alt-Svc header for TCP responses
        // if (self.options.enable_http3) {
        //     const alt_svc_handler = struct {
        //         fn altSvcHandler(_: *Connection, _: []const u8, _: HttpMethod, _: []const u8) !void {
        //             // Add Alt-Svc header to responses
        //             try _.response.headers.append("Alt-Svc", "h3=\":443\"; ma=3600");
        //         }
        //     }.altSvcHandler;
        //     try self.router.use(alt_svc_handler);
        // }
    }

    // Add middleware to the router
    pub fn use(self: *Server, middleware: MiddlewareFn) !void {
        try self.router.use(middleware);
    }

    fn handleAcceptCompletion(async_io: *AsyncIo, task: *Task) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(task.userdata));
        const result = task.result orelse return error.NoResult;

        const new_fd = result.accept catch |err| {
            log.err("Async TCP accept failed: {}", .{err});
            task.userdata = null;
            _ = async_io.accept(server.tcp_listener.?.stream.handle, .{
                .ptr = server,
                .cb = handleAcceptCompletion,
            }) catch |accept_err| {
                log.err("Failed to schedule next TCP accept: {s}", .{@errorName(accept_err)});
                return accept_err;
            };
            return;
        };

        if (server.connections.count() >= server.options.max_connections) {
            log.warn("Max connections reached, closing TCP FD {d}", .{new_fd});
            std.posix.close(new_fd);
            task.userdata = null;
            _ = async_io.accept(server.tcp_listener.?.stream.handle, .{
                .ptr = server,
                .cb = handleAcceptCompletion,
            }) catch |accept_err| {
                log.err("Failed to schedule next TCP accept: {s}", .{@errorName(accept_err)});
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
            log.err("Failed to initialize TCP connection for FD {d}: {s}", .{ new_fd, @errorName(err) });
            std.posix.close(new_fd);
            task.userdata = null;
            _ = async_io.accept(server.tcp_listener.?.stream.handle, .{
                .ptr = server,
                .cb = handleAcceptCompletion,
            }) catch |accept_err| {
                log.err("Failed to schedule next TCP accept: {s}", .{@errorName(accept_err)});
                return accept_err;
            };
            return;
        };
        try server.connections.put(new_fd, connection);

        task.userdata = null;

        _ = async_io.accept(server.tcp_listener.?.stream.handle, .{
            .ptr = server,
            .cb = handleAcceptCompletion,
        }) catch |accept_err| {
            log.err("Failed to schedule next TCP accept: {s}", .{@errorName(accept_err)});
            return accept_err;
        };
    }

    fn handleQuicReadCompletion(async_io: *AsyncIo, task: *Task) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(task.userdata));
        const result = task.result orelse return error.NoResult;

        // Free the buffer after use
        if (task.req == .recv) {
            server.allocator.free(task.req.recv.buffer);
        }

        const bytes_received = result.recv catch |err| {
            log.err("Async QUIC recv failed: {}", .{err});
            task.userdata = null;
            const buffer = try server.allocator.alloc(u8, 1500);
            _ = async_io.recv(server.udp_socket.?, buffer, .{
                .ptr = server,
                .cb = handleQuicReadCompletion,
            }) catch |read_err| {
                server.allocator.free(buffer);
                log.err("Failed to schedule next QUIC recv: {s}", .{@errorName(read_err)});
                return read_err;
            };
            return;
        };

        if (bytes_received == 0) {
            log.debug("Empty QUIC packet received, ignoring", .{});
            task.userdata = null;
            const buffer = try server.allocator.alloc(u8, 1500);
            _ = async_io.recv(server.udp_socket.?, buffer, .{
                .ptr = server,
                .cb = handleQuicReadCompletion,
            }) catch |read_err| {
                server.allocator.free(buffer);
                log.err("Failed to schedule next QUIC recv: {s}", .{@errorName(read_err)});
                return read_err;
            };
            return;
        }

        if (server.connections.count() >= server.options.max_connections) {
            log.warn("Max connections reached, ignoring QUIC packet", .{});
            task.userdata = null;
            const buffer = try server.allocator.alloc(u8, 1500);
            _ = async_io.recv(server.udp_socket.?, buffer, .{
                .ptr = server,
                .cb = handleQuicReadCompletion,
            }) catch |read_err| {
                server.allocator.free(buffer);
                log.err("Failed to schedule next QUIC recv: {s}", .{@errorName(read_err)});
                return read_err;
            };
            return;
        }

        // Use the UDP socket FD for QUIC connection
        const quic_fd = server.udp_socket.?;

        // Create a connection for the QUIC packet
        // Assume Connection.init processes the packet via http2 module
        const stream = std.net.Stream{ .handle = quic_fd };
        const conn = std.net.Server.Connection{
            .stream = stream,
            .address = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 0),
        };

        const connection = Connection.init(server, conn, server.allocator) catch |err| {
            log.err("Failed to initialize QUIC connection for FD {d}: {s}", .{ quic_fd, @errorName(err) });
            task.userdata = null;
            const buffer = try server.allocator.alloc(u8, 1500);
            _ = async_io.recv(server.udp_socket.?, buffer, .{
                .ptr = server,
                .cb = handleQuicReadCompletion,
            }) catch |read_err| {
                server.allocator.free(buffer);
                log.err("Failed to schedule next QUIC recv: {s}", .{@errorName(read_err)});
                return read_err;
            };
            return;
        };

        // Store the connection (keyed by FD, but QUIC may need connection ID)
        try server.connections.put(quic_fd, connection);

        task.userdata = null;

        // Schedule next recv
        const buffer = try server.allocator.alloc(u8, 1500);
        _ = async_io.recv(server.udp_socket.?, buffer, .{
            .ptr = server,
            .cb = handleQuicReadCompletion,
        }) catch |read_err| {
            server.allocator.free(buffer);
            log.err("Failed to schedule next QUIC recv: {s}", .{@errorName(read_err)});
            return read_err;
        };
    }
};
