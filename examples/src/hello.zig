// examples/src/hello.zig
const std = @import("std");
const zttp = @import("zttp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const options = zttp.ServerOptions{
        .port = 8080,
    };

    var bundle = try zttp.createServer(allocator, options);
    defer bundle.deinit();

    // Add default logging middleware
    try bundle.use(zttp.Middleware.Logger.log);

    // Load user routes
    try bundle.loadRoutes(@import("generated_routes.zig").getRoutes);

    std.log.info("Starting server on :8080", .{});
    try bundle.start(true);
}
