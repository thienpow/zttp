// examples/src/routes/demos/websocket/hello.zig
const std = @import("std");
const zttp = @import("zttp");
const WebSocket = zttp.WebSocket;
const Context = zttp.Context;
const AsyncContext = zttp.AsyncContext;

pub fn ws(wsk: *WebSocket, message: []const u8, ctx: *Context, async_ctx: AsyncContext) void {
    _ = ctx; // Unused
    std.log.info("WS message received: {s}", .{message});
    // Echo the exact input
    wsk.sendMessageAsync(message, async_ctx) catch |err| {
        std.log.err("Failed to send WebSocket message: {any}", .{err});
        wsk.close();
    };
}
