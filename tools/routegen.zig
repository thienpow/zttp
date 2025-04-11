const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const routes_dir = "src/routes/";
    const output_file = "src/generated_routes.zig";

    var dir = try std.fs.cwd().openDir(routes_dir, .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    var routes = std.ArrayList(struct { path: []const u8, module: []const u8 }).init(allocator);
    defer routes.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zig")) continue;
        const route_name = entry.name[0 .. entry.name.len - 4];
        const path = try std.fmt.allocPrint(allocator, "/{s}", .{route_name});
        defer allocator.free(path);
        try routes.append(.{ .path = try allocator.dupe(u8, path), .module = try allocator.dupe(u8, route_name) });
    }

    // Generate the file
    var file = try std.fs.cwd().createFile(output_file, .{});
    defer file.close();

    var writer = file.writer();
    try writer.writeAll(
        \\const std = @import("std");
        \\const Router = @import("router.zig").Router;
        \\const Request = @import("http/request.zig").Request;
        \\const Response = @import("http/response.zig").Response;
        \\
        \\pub fn registerRoutes(router: *Router) void {
    );

    for (routes.items) |route| {
        try writer.print(
            \\    router.addRoute("{s}", @import("{s}").handler) catch |err| {{
            \\        @import("logging.zig").log("Failed to add route {s}: {{}}", .{{err}});
            \\    }};
            \\
        , .{ route.path, route.module, route.path });
    }

    try writer.writeAll(
        \\}
    );

    std.debug.print("Generated {s} with {} routes\n", .{ output_file, routes.items.len });
}
