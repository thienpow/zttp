// Auto-generated by routegen.zig
const std = @import("std");
const zttp = @import("zttp");

pub const Route = zttp.Route;

pub fn getRoutes(allocator: std.mem.Allocator) ![]const Route {
    var routes = std.ArrayList(Route).init(allocator);
    errdefer {
        for (routes.items) |r| {
            allocator.free(r.module_name);
            allocator.free(r.method);
            allocator.free(r.path);
        }
        routes.deinit();
    }
    if (@hasDecl(@import("routes/get_hello.zig"), "handler") and
        @hasDecl(@import("routes/get_hello.zig"), "method") and
        @hasDecl(@import("routes/get_hello.zig"), "path")) {
        try routes.append(Route{
            .module_name = try allocator.dupe(u8, "get_hello"),
            .method = try allocator.dupe(u8, @import("routes/get_hello.zig").method),
            .path = try allocator.dupe(u8, @import("routes/get_hello.zig").path),
            .handler = @import("routes/get_hello.zig").handler,
        });
    }
    if (@hasDecl(@import("routes/users_id.zig"), "handler") and
        @hasDecl(@import("routes/users_id.zig"), "method") and
        @hasDecl(@import("routes/users_id.zig"), "path")) {
        try routes.append(Route{
            .module_name = try allocator.dupe(u8, "users_id"),
            .method = try allocator.dupe(u8, @import("routes/users_id.zig").method),
            .path = try allocator.dupe(u8, @import("routes/users_id.zig").path),
            .handler = @import("routes/users_id.zig").handler,
        });
    }
    if (@hasDecl(@import("routes/api/json.zig"), "handler") and
        @hasDecl(@import("routes/api/json.zig"), "method") and
        @hasDecl(@import("routes/api/json.zig"), "path")) {
        try routes.append(Route{
            .module_name = try allocator.dupe(u8, "json"),
            .method = try allocator.dupe(u8, @import("routes/api/json.zig").method),
            .path = try allocator.dupe(u8, @import("routes/api/json.zig").path),
            .handler = @import("routes/api/json.zig").handler,
        });
    }
    return routes.toOwnedSlice();
}