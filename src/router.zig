// src/router.zig
const std = @import("std");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;

pub const HandlerFn = *const fn (*Request, *Response, *Context) void;
pub const MiddlewareFn = *const fn (*Request, *Response, *Context, NextFn) void;
pub const NextFn = *const fn (*Request, *Response, *Context) void;

pub const Router = struct {
    routes: std.ArrayList(Route),
    middlewares: std.ArrayList(MiddlewareFn),
    allocator: std.mem.Allocator,

    const Route = struct {
        path: []const u8,
        handler: HandlerFn,
        method: []const u8,
        is_parametrized: bool,
        param_names: [][]const u8,
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
            self.allocator.free(route.method);
            for (route.param_names) |param| {
                self.allocator.free(param);
            }
            self.allocator.free(route.param_names);
        }
        self.routes.deinit();
        self.middlewares.deinit();
    }

    pub fn add(self: *Router, method: []const u8, path: []const u8, handler: HandlerFn) !void {
        if (path.len == 0 or path[0] != '/') return error.InvalidPath;
        if (!@import("request.zig").isValidMethod(method)) return error.InvalidMethod;

        var param_names = std.ArrayList([]const u8).init(self.allocator);
        var is_parametrized = false;

        // Parse path segments for parameters
        var segments = std.mem.splitScalar(u8, path, '/');
        while (segments.next()) |segment| {
            if (segment.len > 0 and segment[0] == ':') {
                is_parametrized = true;
                const param_name = try self.allocator.dupe(u8, segment[1..]);
                try param_names.append(param_name);
            }
        }

        const path_owned = try self.allocator.dupe(u8, path);
        const method_owned = try self.allocator.dupe(u8, method);
        try self.routes.append(.{
            .path = path_owned,
            .handler = handler,
            .method = method_owned,
            .is_parametrized = is_parametrized,
            .param_names = try param_names.toOwnedSlice(), // Use try to handle error
        });
    }

    pub fn use(self: *Router, middleware: MiddlewareFn) !void {
        try self.middlewares.append(middleware);
    }

    pub fn find(self: *Router, method: []const u8, path: []const u8, ctx: *Context) ?HandlerFn {
        for (self.routes.items) |route| {
            if (!std.mem.eql(u8, route.method, method)) continue;

            if (!route.is_parametrized) {
                // Static route: exact match
                if (std.mem.eql(u8, route.path, path)) {
                    return route.handler;
                }
            } else {
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
                                // Allocation failed, treat as no match
                                match = false;
                                break;
                            };
                            ctx.set(param_name, param_value) catch {
                                // Setting context failed, free value and treat as no match
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

                if (match) {
                    return route.handler;
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
            }
        }
        return null;
    }

    pub fn getMiddlewares(self: *Router) []const MiddlewareFn {
        return self.middlewares.items;
    }
};
