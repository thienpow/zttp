// zttp/examples/src/routes/demos/chat/ws.zig
const std = @import("std");
const zttp = @import("zttp");

const log = std.log.scoped(.chat_ws_handler);
pub const is_chat = true;

pub fn ws(wsk: *zttp.WebSocket, message: []const u8, _: *const zttp.Context) void {
    log.info("WS Handler received raw message on FD {d}: {s}", .{ wsk.socket, message });
}
