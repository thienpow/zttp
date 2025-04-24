const std = @import("std");
const Allocator = std.mem.Allocator;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;

pub const WebSocket = struct {
    socket: std.posix.fd_t,
    allocator: Allocator,
    is_open: bool,

    pub fn init(socket: std.posix.fd_t, allocator: Allocator) WebSocket {
        return .{ .socket = socket, .allocator = allocator, .is_open = true };
    }

    pub fn handleHandshake(req: *const Request, res: *Response) !bool {
        // Check WebSocket upgrade headers
        if (!std.mem.eql(u8, req.headers.get("Upgrade") orelse "", "websocket")) return false;
        if (!std.mem.eql(u8, req.headers.get("Connection") orelse "", "Upgrade")) return false;
        if (!std.mem.eql(u8, req.headers.get("Sec-WebSocket-Version") orelse "", "13")) return false;

        const key = req.headers.get("Sec-WebSocket-Key") orelse return error.InvalidWebSocketKey;

        // Compute Sec-WebSocket-Accept
        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var concat_buf: [128]u8 = undefined;
        const concat = try std.fmt.bufPrint(&concat_buf, "{s}{s}", .{ key, magic });
        var sha1_hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(concat, &sha1_hash, .{});
        var accept_buf: [32]u8 = undefined;
        const accept_key = std.base64.standard.Encoder.encode(&accept_buf, &sha1_hash);

        // Set response headers
        res.status = 101;
        try res.headers.put("Upgrade", "websocket");
        try res.headers.put("Connection", "Upgrade");
        try res.headers.put("Sec-WebSocket-Accept", accept_key);
        return true;
    }

    pub fn sendMessage(self: *WebSocket, message: []const u8) !void {
        if (!self.is_open) return error.ConnectionClosed;
        // Send text frame (opcode 0x1, FIN bit set)
        var frame: [4096]u8 = undefined;
        frame[0] = 0x81; // FIN + Text frame
        if (message.len <= 125) {
            frame[1] = @as(u8, @intCast(message.len));
            @memcpy(frame[2 .. 2 + message.len], message);
            _ = try std.posix.send(self.socket, frame[0 .. 2 + message.len], 0); // Discard return value
        } else {
            // Handle larger payloads if needed
            return error.PayloadTooLarge;
        }
    }

    pub fn close(self: *WebSocket) void {
        if (self.is_open) {
            const close_frame = [_]u8{ 0x88, 0x00 }; // Close frame
            _ = std.posix.send(self.socket, &close_frame, 0) catch {}; // Discard return value
            std.posix.close(self.socket);
            self.is_open = false;
        }
    }
};
