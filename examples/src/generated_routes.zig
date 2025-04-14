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
    if (@hasDecl(@import("routes/index.zig"), "handler") and
        @hasDecl(@import("routes/index.zig"), "method") and
        @hasDecl(@import("routes/index.zig"), "path")) {
        try routes.append(Route{
            .module_name = try allocator.dupe(u8, "index"),
            .method = try allocator.dupe(u8, @import("routes/index.zig").method),
            .path = try allocator.dupe(u8, @import("routes/index.zig").path),
            .handler = @import("routes/index.zig").handler,
        });
    }
    if (@hasDecl(@import("routes/users/:id/+page.zig"), "handler") and
        @hasDecl(@import("routes/users/:id/+page.zig"), "method") and
        @hasDecl(@import("routes/users/:id/+page.zig"), "path")) {
        try routes.append(Route{
            .module_name = try allocator.dupe(u8, "+page"),
            .method = try allocator.dupe(u8, @import("routes/users/:id/+page.zig").method),
            .path = try allocator.dupe(u8, @import("routes/users/:id/+page.zig").path),
            .handler = @import("routes/users/:id/+page.zig").handler,
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