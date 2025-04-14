// tools/routegen.zig
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 3) {
        std.debug.print("Usage: {s} <routes_dir> <output_file>\n", .{args[0]});
        std.process.exit(1);
    }

    const routes_dir = args[1];
    const output_file = args[2];

    std.debug.print("Generating routes from {s} to {s}\n", .{ routes_dir, output_file });
    try generateRoutes(allocator, routes_dir, output_file);
}

pub fn generateRoutes(allocator: std.mem.Allocator, routes_dir_path: []const u8, output_file: []const u8) !void {
    var dir = std.fs.cwd().openDir(routes_dir_path, .{ .iterate = true }) catch |err| {
        std.debug.print("Warning: Failed to open {s}: {}. Generating empty routes.\n", .{ routes_dir_path, err });
        var file = try std.fs.cwd().createFile(output_file, .{});
        defer file.close();
        try file.writeAll(
            \\// Auto-generated by routegen.zig
            \\const std = @import("std");
            \\const zttp = @import("zttp");
            \\
            \\pub const Route = zttp.Route;
            \\
            \\pub fn getRoutes(allocator: std.mem.Allocator) ![]const Route {
            \\    _ = allocator;
            \\    return &[_]Route{};
            \\}
        );
        std.debug.print("Generated empty {s}\n", .{output_file});
        return;
    };
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    var routes = std.ArrayList(struct {
        module: []const u8,
        import_path: []const u8,
        path: []const u8,
        method: []const u8,
    }).init(allocator);
    defer {
        for (routes.items) |r| {
            allocator.free(r.module);
            allocator.free(r.import_path);
            allocator.free(r.path);
            allocator.free(r.method);
        }
        routes.deinit();
    }

    while (try walker.next()) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const module_name = entry.basename[0 .. entry.basename.len - 4];

        // Create import path correctly - just use the full path from walker
        const import_path = try allocator.dupe(u8, entry.path);

        // Build URL route path
        var path_buf = std.ArrayList(u8).init(allocator);
        defer path_buf.deinit();

        try path_buf.appendSlice("/");

        // Add directory path components to URL route, but without the .zig file extension
        if (entry.path.len > 0) {
            // Strip .zig from the path for URL construction
            const path_without_ext = if (std.mem.endsWith(u8, entry.path, ".zig"))
                entry.path[0 .. entry.path.len - 4]
            else
                entry.path;

            var iter = std.mem.splitScalar(u8, path_without_ext, '/');
            while (iter.next()) |component| {
                if (component.len == 0) continue;
                try path_buf.appendSlice(component);
                try path_buf.appendSlice("/");
            }
        }

        // The last component should be replaced with the transformed module name
        // First, remove the last slash if present
        if (path_buf.items.len > 0 and path_buf.items[path_buf.items.len - 1] == '/') {
            _ = path_buf.pop();
        }

        // For the path, we want to transform underscores to slashes
        try path_buf.appendSlice("/");
        for (module_name) |c| {
            try path_buf.append(if (c == '_') '/' else c);
        }

        const route_path = try path_buf.toOwnedSlice();

        try routes.append(.{
            .module = try allocator.dupe(u8, module_name),
            .import_path = import_path,
            .path = route_path,
            .method = try allocator.dupe(u8, "GET"), // Default, overridden in generated code
        });
        std.debug.print("Found route: {s} ({s}) [import: routes/{s}]\n", .{ route_path, module_name, import_path });
    }

    var file = try std.fs.cwd().createFile(output_file, .{});
    defer file.close();

    var writer = file.writer();
    try writer.writeAll(
        \\// Auto-generated by routegen.zig
        \\const std = @import("std");
        \\const zttp = @import("zttp");
        \\
        \\pub const Route = zttp.Route;
        \\
        \\pub fn getRoutes(allocator: std.mem.Allocator) ![]const Route {
        \\    var routes = std.ArrayList(Route).init(allocator);
        \\    errdefer {
        \\        for (routes.items) |r| {
        \\            allocator.free(r.module_name);
        \\            allocator.free(r.method);
        \\            allocator.free(r.path);
        \\        }
        \\        routes.deinit();
        \\    }
        \\
    );

    for (routes.items) |route| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try buf.writer().writeAll(
            \\    if (@hasDecl(@import("routes/
        );
        try buf.appendSlice(route.import_path);
        try buf.appendSlice(
            \\"), "handler") and
            \\        @hasDecl(@import("routes/
        );
        try buf.appendSlice(route.import_path);
        try buf.appendSlice(
            \\"), "method") and
            \\        @hasDecl(@import("routes/
        );
        try buf.appendSlice(route.import_path);
        try buf.appendSlice(
            \\"), "path")) {
            \\        try routes.append(Route{
            \\            .module_name = try allocator.dupe(u8, "
        );
        try buf.appendSlice(route.module);
        try buf.appendSlice(
            \\"),
            \\            .method = try allocator.dupe(u8, @import("routes/
        );
        try buf.appendSlice(route.import_path);
        try buf.appendSlice(
            \\").method),
            \\            .path = try allocator.dupe(u8, @import("routes/
        );
        try buf.appendSlice(route.import_path);
        try buf.appendSlice(
            \\").path),
            \\            .handler = @import("routes/
        );
        try buf.appendSlice(route.import_path);
        try buf.appendSlice(
            \\").handler,
            \\        });
            \\    }
            \\
        );
        try writer.writeAll(buf.items);
    }

    try writer.writeAll(
        \\    return routes.toOwnedSlice();
        \\}
    );

    std.debug.print("Generated {s} with {} routes\n", .{ output_file, routes.items.len });
}
