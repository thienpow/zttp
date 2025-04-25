// examples/src/routes/ws.zig
const std = @import("std");
const zttp = @import("zttp");

pub fn ws(wsk: *zttp.WebSocket, message: []const u8, _: *const zttp.Context) void {
    std.log.info("Received WebSocket message: {s}", .{message});
    wsk.sendMessage("Hello, client!") catch |err| {
        std.log.err("Failed to send WebSocket message: {}", .{err});
    };
}
