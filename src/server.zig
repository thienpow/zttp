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

const Connection = @import("connection.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    listener: ?std.net.Server,
    options: Options,
    running: bool,
    router: Router,
    pool: *ThreadPool,
    websockets: std.ArrayList(WebSocket),

    pub const Options = struct {
        port: u16 = 8088,
        thread_pool_options: ThreadPool.Options = .{},
        websocket_options: WebSocket.Options = .{},
    };

    pub fn init(allocator: std.mem.Allocator, options: Options, pool: *ThreadPool) Server {
        return .{
            .allocator = allocator,
            .listener = null,
            .options = options,
            .running = false,
            .router = Router.init(allocator),
            .pool = pool,
            .websockets = std.ArrayList(WebSocket).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        for (self.websockets.items) |*ws| {
            ws.close();
        }
        self.websockets.deinit();
        if (self.listener) |*listener| {
            listener.deinit();
        }
        self.router.deinit();
    }

    pub fn route(self: *Server, module_name: []const u8, method: HttpMethod, path: []const u8, handler: ?HandlerFn, ws_handler: ?WebSocketHandlerFn) !void {
        try self.router.add(module_name, method, path, handler, ws_handler);
    }

    pub fn use(self: *Server, middleware: MiddlewareFn) !void {
        try self.router.use(middleware);
    }

    pub fn start(self: *Server) !void {
        if (self.running) return error.AlreadyRunning;

        const address = try std.net.Address.parseIp("0.0.0.0", self.options.port);
        self.listener = try address.listen(.{ .reuse_address = true });
        self.running = true;

        std.log.info("Server listening on 0.0.0.0:{d}", .{self.options.port});

        while (self.running) {
            const conn = self.listener.?.accept() catch |err| {
                std.log.err("Failed to accept connection: {}", .{err});
                continue;
            };
            const task_id = try self.pool.schedule(
                Connection.handleConnection,
                Connection.ConnectionTask{ .server = self, .conn = conn },
                null,
                5,
                null,
                0,
                0,
                null,
                null,
            );
            _ = task_id;
        }
    }
};
