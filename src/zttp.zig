// src/zttp.zig
const std = @import("std");

const http = @import("http/mod.zig");
pub const HttpMethod = http.HttpMethod;
pub const Request = http.Request;
pub const Response = http.Response;

const core = @import("core/mod.zig");
pub const Context = core.Context;
pub const Server = core.Server;
pub const middleware = @import("middleware/mod.zig");

const router = @import("core/router.zig");
const MiddlewareFn = router.MiddlewareFn;
const HandlerFn = router.HandlerFn;
const NextFn = router.NextFn;
const Router = router.Router;
const WebSocketHandlerFn = router.WebSocketHandlerFn;

const Async = @import("async/async.zig");
pub const AsyncContext = Async.AsyncContext;

const websocket = @import("websocket/mod.zig");
pub const WebSocket = websocket.WebSocket;

const cache = @import("template/cache.zig");
const db_mod = @import("db/mod.zig");

pub const db = db_mod;

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,
};

pub const Route = struct {
    module_name: []const u8,
    method: HttpMethod,
    path: []const u8,
    handler: ?HandlerFn = null,
    ws_handler: ?WebSocketHandlerFn = null,
};

pub const Template = struct {
    name: []const u8,
    buffer: []const u8,
};

pub fn createServer(
    allocator: std.mem.Allocator,
    server_options: Server.Options,
    num_servers: usize,
) !*ServerBundle {
    if (num_servers == 0) {
        return error.InvalidServerCount;
    }

    var servers = try allocator.alloc(*Server, num_servers);
    errdefer {
        for (servers) |server| {
            server.deinit();
            allocator.destroy(server);
        }
        allocator.free(servers);
    }

    for (0..num_servers) |i| {
        servers[i] = try allocator.create(Server);
        servers[i].* = try Server.init(allocator, server_options); // Same port for all
    }

    const bundle = try allocator.create(ServerBundle);
    bundle.* = ServerBundle{
        .allocator = allocator,
        .servers = servers,
        .server_options = server_options,
    };

    return bundle;
}

pub const ServerBundle = struct {
    allocator: std.mem.Allocator,
    servers: []*Server,
    server_options: Server.Options,

    pub fn start(self: *ServerBundle) !void {
        var threads = try self.allocator.alloc(std.Thread, self.servers.len);
        errdefer self.allocator.free(threads);

        for (0..self.servers.len) |i| {
            threads[i] = try std.Thread.spawn(.{}, startServerThread, .{ self, i });
        }

        while (true) {
            std.time.sleep(1_000_000_000);
        }
    }

    pub fn deinit(self: *ServerBundle) void {
        for (self.servers) |server| {
            server.deinit();
            self.allocator.destroy(server);
        }
        self.allocator.free(self.servers);
        self.allocator.destroy(self);
    }

    pub fn route(self: *ServerBundle, method: HttpMethod, path: []const u8, handler: HandlerFn) !void {
        for (self.servers) |server| {
            try server.route("", method, path, handler, null);
        }
    }

    pub fn use(self: *ServerBundle, middlewareFn: MiddlewareFn) !void {
        for (self.servers) |server| {
            try server.use(middlewareFn);
        }
    }

    pub fn loadRoutes(self: *ServerBundle, comptime getRoutesFn: fn (std.mem.Allocator) anyerror![]const Route) !void {
        const routes = try getRoutesFn(self.allocator);
        if (routes.len == 0) {
            std.log.warn("No routes loaded", .{});
        }

        for (self.servers) |server| {
            for (routes) |r| {
                try server.route(r.module_name, r.method, r.path, r.handler, r.ws_handler);
            }
        }
    }

    pub fn loadTemplates(self: *ServerBundle, comptime getTemplatesFn: fn (std.mem.Allocator) anyerror![]const Template) !void {
        const templates = try getTemplatesFn(self.allocator);

        if (templates.len == 0) {
            std.log.warn("No templates loaded", .{});
        }

        try cache.initTemplateCache(self.allocator, @intCast(templates.len));

        for (templates) |t| {
            _ = try cache.putTokenizedTemplate(t.name, t.buffer);
        }
    }
};

fn startServerThread(bundle: *ServerBundle, server_index: usize) void {
    bundle.servers[server_index].start() catch |err| {
        std.log.err("Failed to start server {d} on port {d}: {}", .{ server_index, bundle.server_options.port, err });
    };
}
