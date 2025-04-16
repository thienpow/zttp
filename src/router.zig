const std = @import("std");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const HttpMethod = @import("zttp.zig").HttpMethod;

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
        method: HttpMethod,
        is_parametrized: bool,
        param_names: [][]const u8,
        is_wildcard: bool,
        template: ?[]const u8 = null,
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
            if (route.template) |tpl| {
                self.allocator.free(tpl);
            }
        }
        self.routes.deinit();
        self.middlewares.deinit();
    }

    pub fn add(self: *Router, module_name: []const u8, method: HttpMethod, path: []const u8, handler: HandlerFn, template_path: []const u8) !void {
        _ = module_name;

        if (path.len == 0 or path[0] != '/') return error.InvalidPath;

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

        var template: ?[]const u8 = null;
        const file = std.fs.cwd().openFile(template_path, .{}) catch null;
        if (file) |f| {
            defer f.close();
            const stat = try f.stat();
            const buffer = try self.allocator.alloc(u8, stat.size);
            _ = try f.readAll(buffer);
            template = buffer;
        } else {
            //std.log.warn("Template file not found for module: {s}", .{template_path});
        }

        try self.routes.append(.{
            .path = path_owned,
            .handler = handler,
            .method = method,
            .is_parametrized = is_parametrized,
            .param_names = try param_names.toOwnedSlice(),
            .is_wildcard = is_wildcard,
            .template = template,
        });
    }

    pub fn use(self: *Router, middleware: MiddlewareFn) !void {
        try self.middlewares.append(middleware);
    }

    pub fn getHandler(self: *Router, method: HttpMethod, path: []const u8, ctx: *Context) ?HandlerFn {
        for (self.routes.items) |route| {
            if (route.method != method) continue;

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
                        continue;
                    };
                    ctx.set("wildcard", suffix_owned) catch {
                        std.log.err("Failed to set wildcard", .{});
                        ctx.allocator.free(suffix_owned);
                        continue;
                    };
                    //std.log.debug("Wildcard route {s} matched, suffix: {s}", .{ route.path, suffix });
                    return route.handler;
                }
                continue;
            }

            if (!route.is_parametrized) {
                // Static route: exact match
                if (std.mem.eql(u8, route.path, path)) {
                    //std.log.debug("Static route {s} matched", .{route.path});
                    return route.handler;
                }
            } else {
                // Parameterized route: match segments
                var route_segments = std.mem.splitScalar(u8, route.path, '/');
                var path_segments = std.mem.splitScalar(u8, path, '/');
                var param_index: usize = 0;
                var match = true;

                //std.log.debug("Matching route {s} against path {s}", .{ route.path, path });

                while (route_segments.next()) |route_seg| {
                    const path_seg = path_segments.next() orelse {
                        //std.log.debug("Path too short for route {s}", .{route.path});
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
                            //std.log.debug("Set param {s} = {s}", .{ param_name, param_value });
                            param_index += 1;
                        } else {
                            //std.log.debug("Too many params for route {s}", .{route.path});
                            match = false;
                            break;
                        }
                    } else if (!std.mem.eql(u8, route_seg, path_seg)) {
                        //std.log.debug("Segment mismatch: {s} != {s}", .{ route_seg, path_seg });
                        match = false;
                        break;
                    }
                }

                // Ensure no extra path segments
                if (path_segments.next() != null) {
                    //std.log.debug("Path too long for route {s}", .{route.path});
                    match = false;
                }

                // Check if all parameters were set
                if (match and param_index != route.param_names.len) {
                    //std.log.debug("Not enough params for route {s}, got {d}, expected {d}", .{ route.path, param_index, route.param_names.len });
                    match = false;
                }

                if (match) {
                    //std.log.debug("Route {s} matched", .{route.path});
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
        //std.log.debug("No route matched for {s} {s}", .{ @tagName(method), path });
        return null;
    }

    pub fn getTemplate(self: *Router, method: HttpMethod, path: []const u8) ?[]const u8 {
        for (self.routes.items) |route| {
            if (route.method != method) continue;

            // For non-parameterized routes, simple direct comparison
            if (!route.is_parametrized and !route.is_wildcard) {
                if (std.mem.eql(u8, route.path, path)) {
                    return route.template;
                }
                continue;
            }

            // For wildcard routes
            if (route.is_wildcard) {
                const prefix = route.path[0 .. route.path.len - 2]; // Remove '/*'
                if (std.mem.startsWith(u8, path, prefix)) {
                    return route.template;
                }
                continue;
            }

            // For parameterized routes
            var route_segments = std.mem.splitScalar(u8, route.path, '/');
            var path_segments = std.mem.splitScalar(u8, path, '/');
            var match = true;

            while (route_segments.next()) |route_seg| {
                const path_seg = path_segments.next() orelse {
                    match = false;
                    break;
                };

                if (route_seg.len == 0 and path_seg.len == 0) {
                    continue;
                }

                // For parameter segments, just continue matching
                if (route_seg.len > 0 and route_seg[0] == ':') {
                    continue;
                } else if (!std.mem.eql(u8, route_seg, path_seg)) {
                    match = false;
                    break;
                }
            }

            // Check if path has extra segments
            if (path_segments.next() != null) {
                match = false;
            }

            if (match) {
                return route.template;
            }
        }

        return null;
    }

    pub fn getMiddlewares(self: *Router) []const MiddlewareFn {
        return self.middlewares.items;
    }
};
