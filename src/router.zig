const std = @import("std");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const WebSocket = @import("websocket.zig").WebSocket;
const HttpMethod = @import("zttp.zig").HttpMethod;

pub const HandlerFn = *const fn (*Request, *Response, *Context) void;
pub const MiddlewareFn = *const fn (*Request, *Response, *Context, NextFn) void;
pub const NextFn = *const fn (*Request, *Response, *Context) void;
pub const WebSocketHandlerFn = *const fn (ws: *WebSocket, data: []const u8, ctx: *Context) void;

pub const Router = struct {
    routes: std.ArrayList(Route),
    middlewares: std.ArrayList(MiddlewareFn),
    allocator: std.mem.Allocator,

    const Route = struct {
        path: []const u8,
        handler: ?HandlerFn = null,
        ws_handler: ?WebSocketHandlerFn = null,
        method: HttpMethod,
        is_parametrized: bool,
        param_names: [][]const u8,
        is_wildcard: bool,
    };

    pub fn init(allocator: std.mem.Allocator) Router {
        return .{
            .routes = std.ArrayList(Route).init(allocator),
            .middlewares = std.ArrayList(MiddlewareFn).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Router) void {
        for (self.routes.items) |route| {
            self.allocator.free(route.path);
            for (route.param_names) |param| {
                self.allocator.free(param);
            }
            self.allocator.free(route.param_names);
        }
        self.routes.deinit();
        self.middlewares.deinit();
    }

    pub fn add(self: *Router, module_name: []const u8, method: HttpMethod, path: []const u8, handler: ?HandlerFn, ws_handler: ?WebSocketHandlerFn) !void {
        if (path.len == 0 or path[0] != '/') return error.InvalidPath;
        if (handler == null and ws_handler == null) return error.NoHandler;

        var param_names = std.ArrayList([]const u8).init(self.allocator);
        var is_parametrized = false;
        var is_wildcard = false;

        // Check for wildcard
        if (std.mem.endsWith(u8, path, "/*")) {
            is_wildcard = true;
        } else {
            // Parse path segments for parameters
            var segments = std.mem.splitScalar(u8, path, '/');
            while (segments.next()) |segment| {
                if (segment.len > 0 and segment[0] == ':') {
                    is_parametrized = true;
                    const param_name = try self.allocator.dupe(u8, segment[1..]);
                    try param_names.append(param_name);
                }
            }
        }

        const path_owned = try self.allocator.dupe(u8, path);

        try self.routes.append(.{
            .path = path_owned,
            .handler = handler,
            .ws_handler = if (std.mem.eql(u8, module_name, "websocket")) ws_handler else null,
            .method = method,
            .is_parametrized = is_parametrized,
            .param_names = try param_names.toOwnedSlice(),
            .is_wildcard = is_wildcard,
        });
    }

    pub fn use(self: *Router, middleware: MiddlewareFn) !void {
        try self.middlewares.append(middleware);
    }

    fn matchRoute(route: Route, method: HttpMethod, path: []const u8, ctx: *Context) ?struct { handler: ?HandlerFn, ws_handler: ?WebSocketHandlerFn } {
        if (route.method != method) return null;

        if (route.is_wildcard) {
            // Match prefix up to '/*'
            const prefix = route.path[0 .. route.path.len - 2]; // Remove '/*'
            if (std.mem.startsWith(u8, path, prefix)) {
                // Trim leading '/' from suffix, if present
                var suffix = path[prefix.len..];
                if (suffix.len > 0 and suffix[0] == '/') {
                    suffix = suffix[1..];
                }
                const suffix_owned = ctx.allocator.dupe(u8, suffix) catch {
                    std.log.err("Failed to allocate wildcard suffix", .{});
                    return null;
                };
                ctx.set("wildcard", suffix_owned) catch {
                    std.log.err("Failed to set wildcard", .{});
                    ctx.allocator.free(suffix_owned);
                    return null;
                };
                return .{ .handler = route.handler, .ws_handler = route.ws_handler };
            }
            return null;
        }

        if (!route.is_parametrized) {
            // Static route: exact match
            if (std.mem.eql(u8, route.path, path)) {
                return .{ .handler = route.handler, .ws_handler = route.ws_handler };
            }
            return null;
        }

        // Parameterized route: match segments
        var route_segments = std.mem.splitScalar(u8, route.path, '/');
        var path_segments = std.mem.splitScalar(u8, path, '/');
        var param_index: usize = 0;
        var match = true;

        while (route_segments.next()) |route_seg| {
            const path_seg = path_segments.next() orelse {
                match = false;
                break;
            };

            if (route_seg.len == 0 and path_seg.len == 0) {
                continue;
            }

            if (route_seg[0] == ':') {
                if (param_index < route.param_names.len) {
                    // Store parameter in Context
                    const param_name = route.param_names[param_index];
                    const param_value = ctx.allocator.dupe(u8, path_seg) catch {
                        std.log.err("Failed to allocate param value for {s}", .{param_name});
                        match = false;
                        break;
                    };
                    ctx.set(param_name, param_value) catch {
                        std.log.err("Failed to set param {s}", .{param_name});
                        ctx.allocator.free(param_value);
                        match = false;
                        break;
                    };
                    param_index += 1;
                } else {
                    match = false;
                    break;
                }
            } else if (!std.mem.eql(u8, route_seg, path_seg)) {
                match = false;
                break;
            }
        }

        // Ensure no extra path segments
        if (path_segments.next() != null) {
            match = false;
        }

        // Check if all parameters were set
        if (match and param_index != route.param_names.len) {
            match = false;
        }

        if (match) {
            return .{ .handler = route.handler, .ws_handler = route.ws_handler };
        }

        // Clear any parameters if no match
        for (0..param_index) |i| {
            if (i < route.param_names.len) {
                if (ctx.get(route.param_names[i])) |val| {
                    ctx.allocator.free(val);
                    _ = ctx.data.remove(route.param_names[i]);
                }
            }
        }
        return null;
    }

    pub fn getHandler(self: *Router, method: HttpMethod, path: []const u8, ctx: *Context) ?HandlerFn {
        for (self.routes.items) |route| {
            if (matchRoute(route, method, path, ctx)) |result| {
                return result.handler;
            }
        }
        return null;
    }

    pub fn getWebSocketHandler(self: *Router, method: HttpMethod, path: []const u8, ctx: *Context) ?WebSocketHandlerFn {
        for (self.routes.items) |route| {
            if (matchRoute(route, method, path, ctx)) |result| {
                return result.ws_handler;
            }
        }
        return null;
    }

    pub fn getMiddlewares(self: *Router) []const MiddlewareFn {
        return self.middlewares.items;
    }
};
