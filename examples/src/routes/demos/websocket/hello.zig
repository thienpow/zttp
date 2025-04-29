// examples/src/routes/demos/websocket/hello.zig
const std = @import("std");
const zttp = @import("zttp");
const WebSocket = zttp.WebSocket;
const Context = zttp.Context;
const AsyncContext = zttp.AsyncContext;

pub fn ws(wsk: *WebSocket, message: []const u8, ctx: *Context, async_ctx: AsyncContext) void {
    _ = ctx;
    std.log.info("WS message received: {s}", .{message});
    if (std.mem.eql(u8, message, "ping")) {
        wsk.sendMessageAsync("pong", async_ctx) catch |err| {
            std.log.err("Failed to send WebSocket message: {any}", .{err});
            wsk.close(async_ctx);
        };
    } else {
        std.log.warn("Unexpected message: {x}", .{message});
        wsk.sendMessageAsync("unknown", async_ctx) catch |err| {
            std.log.err("Failed to send WebSocket message: {any}", .{err});
            wsk.close(async_ctx);
        };
    }
}
