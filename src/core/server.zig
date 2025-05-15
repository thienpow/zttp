// src/core/server.zig
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
const tls = @import("tls.zig");

const log = std.log.scoped(.server);

pub const Server = struct {
    allocator: Allocator,
    tcp_listener: ?std.net.Server,
    udp_socket: ?std.posix.fd_t,
    async_io: ?*AsyncIo,
    options: Options,
    running: std.atomic.Value(bool),
    router: Router,
    websocket_fds: std.AutoHashMap(std.posix.fd_t, void),
    connections: std.AutoHashMap(std.posix.fd_t, *Connection),
    tls_ctx: ?*tls.TlsContext,

    pub const Options = struct {
        app_context_ptr: *anyopaque,
        port: u16 = 8080,
        async_ring_entries: u16 = 1024,
        max_connections: usize = 100,
        header_read_timeout_ms: u64 = 1000,
        websocket: websocket.WebSocket.Options = .{},
        http2_settings: http2.Settings = .{},
        enable_http3: bool = false,
        tls: ?tls.CertConfig = null,
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
            .tls_ctx = null,
        };

        if (options.tls) |tls_config| {
            const protocol_count: usize = if (options.enable_http3) 3 else 2;
            const protocols = try allocator.alloc(tls.Protocol, protocol_count);
            defer allocator.free(protocols);
            protocols[0] = .http1;
            protocols[1] = .h2;
            if (options.enable_http3) {
                protocols[2] = .h3;
                log.info("HTTP/3 enabled, protocol count: {d}", .{protocol_count});
            }

            const cert_config = tls.CertConfig{
                .cert_file = tls_config.cert_file,
                .key_file = tls_config.key_file,
            };

            server.tls_ctx = try allocator.create(tls.TlsContext);
            errdefer {
                if (server.tls_ctx) |ctx| {
                    ctx.deinit();
                    allocator.destroy(ctx);
                }
            }
            if (server.tls_ctx) |ctx| {
                ctx.* = try tls.TlsContext.init(allocator, cert_config, protocols);
            } else {
                return error.TlsContextAllocationFailed;
            }
            log.info("TLS enabled with cert: {s}, key: {s}", .{ tls_config.cert_file, tls_config.key_file });
        }

        server.async_io = try allocator.create(AsyncIo);
        server.async_io.?.* = try AsyncIo.init(allocator, options.async_ring_entries);

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

        var it = self.connections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.asyncClose() catch |err| {
                log.err("Failed to close connection FD {d}: {}", .{ entry.key_ptr.*, err });
            };
        }
        self.connections.deinit();

        self.websocket_fds.deinit();

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

        const listener_fd = self.tcp_listener.?.stream.handle;
        const accept_task = self.async_io.?.accept(listener_fd, .{
            .ptr = self,
            .cb = handleAcceptCompletion,
        }) catch |err| {
            log.err("Failed to schedule initial TCP accept: {s}", .{@errorName(err)});
            return err;
        };
        _ = accept_task;

        if (self.options.enable_http3 and self.udp_socket != null) {
            const buffer = try self.allocator.alloc(u8, 1500);
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

    pub fn route(self: *Server, module_name: []const u8, method: HttpMethod, path: []const u8, handler: ?HandlerFn, ws_handler: ?WebSocketHandlerFn) !void {
        try self.router.add(module_name, method, path, handler, ws_handler);
    }

    pub fn use(self: *Server, middleware: MiddlewareFn) !void {
        try self.router.use(middleware);
    }

    fn handleAcceptCompletion(async_io: *AsyncIo, task: *Task) anyerror!void {
        const server: *Server = @ptrCast(@alignCast(task.userdata));
        const result = task.result orelse return error.NoResult;

        const new_fd = result.accept catch |err| {
            log.err("Async TCP accept failed: {}", .{err});
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
            _ = async_io.accept(server.tcp_listener.?.stream.handle, .{
                .ptr = server,
                .cb = handleAcceptCompletion,
            }) catch |accept_err| {
                log.err("Failed to schedule next TCP accept: {s}", .{@errorName(accept_err)});
                return accept_err;
            };
            return;
        }

        var tls_conn: ?*tls.TlsConnection = null;
        var negotiated_protocol = Connection.Protocol.http1;

        if (server.tls_ctx) |tls_context| {
            tls_conn = try tls_context.createConnection(new_fd);
            errdefer {
                if (tls_conn) |tconn| tconn.deinit();
            }

            tls_conn.?.handshake() catch |err| {
                if (err == error.WouldBlock) {
                    log.debug("TLS handshake would block on FD {d}, closing connection", .{new_fd});
                } else {
                    log.err("TLS handshake failed on FD {d}: {s}", .{ new_fd, @errorName(err) });
                }
                _ = async_io.accept(server.tcp_listener.?.stream.handle, .{
                    .ptr = server,
                    .cb = handleAcceptCompletion,
                }) catch |accept_err| {
                    log.err("Failed to schedule next TCP accept: {s}", .{@errorName(accept_err)});
                    return accept_err;
                };
                return;
            };

            negotiated_protocol = try tls_conn.?.getNegotiatedProtocol();
            log.info("TLS handshake complete on FD {d}, negotiated protocol: {s}", .{ new_fd, @tagName(negotiated_protocol) });
        } else {
            log.info("TCP connection accepted on FD {d} (No TLS)", .{new_fd});
        }

        const connection = Connection.init(server, new_fd, server.allocator, tls_conn, negotiated_protocol, null) catch |err| {
            log.err("Failed to initialize connection for FD {d}: {s}", .{ new_fd, @errorName(err) });
            if (tls_conn == null) {
                std.posix.close(new_fd);
            }
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

        if (task.req == .recv) {
            server.allocator.free(task.req.recv.buffer);
        }

        const bytes_received = result.recv catch |err| {
            log.err("Async QUIC recv failed: {}", .{err});
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

        const quic_fd = server.udp_socket.?;

        const connection = Connection.init(server, quic_fd, server.allocator, null, Connection.Protocol.http3, null) catch |err| {
            log.err("Failed to initialize QUIC connection for FD {d}: {s}", .{ quic_fd, @errorName(err) });
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

        try server.connections.put(quic_fd, connection);

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
