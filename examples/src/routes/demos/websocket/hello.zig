// examples/src/routes/demos/websocket/hello.zig
const std = @import("std");
const zttp = @import("zttp");

pub fn ws(wsk: *zttp.WebSocket, message: []const u8, ctx: *zttp.Context) void {
    std.log.info("WS message received: {s}", .{message});

    // Debug Context pointer
    std.log.debug("Context pointer: {*}", .{ctx});

    // Basic WebSocket functionality that doesn't use context
    var response_buffer: [256]u8 = undefined;
    const formatted_response = std.fmt.bufPrint(&response_buffer, "Echo: '{s}' (len={d}). WebSockets working!", .{
        message,
        message.len,
    }) catch {
        wsk.sendMessage("Error formatting response") catch {};
        return;
    };

    // Try some safe operations to diagnose context issues
    std.log.debug("Attempting to access context data...", .{});

    // Print the context contents for debugging
    std.log.debug("Context data count: {d}", .{ctx.data.count()});

    // Send response before attempting potentially problematic operations
    wsk.sendMessage(formatted_response) catch |err| {
        std.log.err("Failed to send WebSocket message: {}", .{err});
        return;
    };

    // Now try a controlled set operation - this might reveal the issue
    std.log.debug("Attempting context.set operation...", .{});

    // Try using set and catch any errors
    ctx.set("test_key", "test_value") catch |err| {
        std.log.err("Context set failed: {s}", .{@errorName(err)});
        return;
    };

    std.log.debug("Context set operation succeeded", .{});
    std.log.debug("WebSocket handler completed successfully", .{});
}
