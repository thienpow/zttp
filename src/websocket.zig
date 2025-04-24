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

    pub fn readBlocking(self: *WebSocket, buffer: []u8) !usize {
        if (!self.is_open) return error.WebSocketClosed;

        const bytes_read = try std.posix.read(self.socket, buffer);
        if (bytes_read == 0) {
            // Connection closed by peer
            self.is_open = false;
            return 0;
        }
        return bytes_read;
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

    pub fn sendFrame(self: *WebSocket, opcode: u8, payload: []const u8) !void {
        if (!self.is_open) return error.WebSocketClosed;

        // Construct WebSocket frame: FIN=1, RSV=0, opcode, payload length, payload
        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();

        // Header: FIN=1, RSV=0, opcode
        try frame.append(0x80 | (opcode & 0x0F));

        // Payload length
        if (payload.len <= 125) {
            try frame.append(@intCast(payload.len));
        } else if (payload.len <= 0xFFFF) {
            try frame.append(126);
            try frame.appendSlice(&[_]u8{
                @intCast((payload.len >> 8) & 0xFF),
                @intCast(payload.len & 0xFF),
            });
        } else {
            try frame.append(127);
            try frame.appendSlice(&[_]u8{
                @intCast((payload.len >> 56) & 0xFF),
                @intCast((payload.len >> 48) & 0xFF),
                @intCast((payload.len >> 40) & 0xFF),
                @intCast((payload.len >> 32) & 0xFF),
                @intCast((payload.len >> 24) & 0xFF),
                @intCast((payload.len >> 16) & 0xFF),
                @intCast((payload.len >> 8) & 0xFF),
                @intCast(payload.len & 0xFF),
            });
        }

        // Payload
        try frame.appendSlice(payload);

        // Send frame
        _ = try std.posix.send(self.socket, frame.items, 0);
    }

    pub fn sendMessage(self: *WebSocket, message: []const u8) !void {
        // Delegate to sendFrame with text frame opcode (0x1)
        try self.sendFrame(0x1, message);
    }

    pub fn close(self: *WebSocket) void {
        if (self.is_open) {
            const close_frame = [_]u8{ 0x88, 0x00 }; // Close frame (FIN=1, opcode=0x8, no payload)
            _ = std.posix.send(self.socket, &close_frame, 0) catch {};
            std.posix.close(self.socket);
            self.is_open = false;
            self.socket = -1; // Mark as invalid to prevent double-close
        }
    }
};
