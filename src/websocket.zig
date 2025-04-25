const std = @import("std");
const Allocator = std.mem.Allocator;
const Context = @import("context.zig").Context;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const ThreadPool = @import("pool.zig").ThreadPool;
const Server = @import("server.zig").Server;

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

pub const WebSocketTask = struct {
    server: *Server,
    ws: *WebSocket,
    ctx: *Context,
    handler: WebSocketHandlerFn,
};

pub fn handleWebSocket(task_ptr: *WebSocketTask, result: *ThreadPool.TaskResult) void {
    const task = task_ptr.*;
    const alloc = task.server.allocator;

    var ctx_deinit_done = false;
    defer if (!ctx_deinit_done) task.ctx.deinit();

    var ws_close_done = false;
    defer if (!ws_close_done) task.ws.close();

    defer alloc.destroy(task_ptr);

    defer {
        var found = false;
        for (task.server.websockets.items, 0..) |*server_ws, i| {
            if (server_ws.socket == task.ws.socket) {
                _ = task.server.websockets.swapRemove(i);
                found = true;
                // std.log.info("Removed WebSocket (FD: {d}) from server list.", .{task.ws.socket});
                break;
            }
        }
        if (!found) {
            std.log.warn("WebSocket (FD: {d}) already removed from server list?", .{task.ws.socket});
        }

        ctx_deinit_done = true;
        ws_close_done = true;
    }

    // std.log.info("WebSocket handler started for socket FD: {d}", .{task.ws.socket});

    var read_buffer: [4096]u8 = undefined;

    while (task.ws.is_open) {
        const header_bytes_read = task.ws.readBlocking(read_buffer[0..2]) catch |err| {
            std.log.err("WebSocket read error (header): {any}. Closing connection FD: {d}", .{ err, task.ws.socket });
            break;
        };

        if (header_bytes_read == 0) {
            // std.log.info("WebSocket connection closed by peer (FD: {d}).", .{task.ws.socket});
            break;
        }
        if (header_bytes_read < 2) {
            std.log.warn("Incomplete WebSocket frame header received ({d} bytes). Closing FD: {d}", .{ header_bytes_read, task.ws.socket });
            break;
        }

        const fin_bit = (read_buffer[0] >> 7) & 1;
        const rsv_bits = (read_buffer[0] >> 4) & 7;
        const opcode = read_buffer[0] & 0x0F;
        const mask_bit = (read_buffer[1] >> 7) & 1;
        const payload_len_short = read_buffer[1] & 0x7F;

        if (rsv_bits != 0) {
            std.log.warn("WebSocket frame received with non-zero RSV bits ({b}). Closing FD: {d}", .{ rsv_bits, task.ws.socket });
            break;
        }
        if (mask_bit == 0) {
            std.log.warn("WebSocket frame received from client without mask bit set. Closing FD: {d}", .{task.ws.socket});
            break;
        }

        var payload_len: u64 = 0;
        var mask_key: [4]u8 = undefined;
        var current_read_offset: usize = 2;

        if (payload_len_short <= 125) {
            payload_len = payload_len_short;
        } else if (payload_len_short == 126) {
            var len_buffer: [2]u8 = undefined;
            if (task.ws.readBlocking(&len_buffer) catch |err| {
                std.log.warn("WebSocket read error (16-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                break;
            } != 2) {
                std.log.warn("Incomplete WebSocket frame (16-bit length). Closing FD: {d}", .{task.ws.socket});
                break;
            }
            payload_len = std.mem.readInt(u16, &len_buffer, .big);
            current_read_offset += 2;
        } else {
            var len_buffer: [8]u8 = undefined;
            if (task.ws.readBlocking(&len_buffer) catch |err| {
                std.log.warn("WebSocket read error (64-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                break;
            } != 8) {
                std.log.warn("Incomplete WebSocket frame (64-bit length). Closing FD: {d}", .{task.ws.socket});
                break;
            }
            payload_len = std.mem.readInt(u64, &len_buffer, .big);
            current_read_offset += 8;
        }

        if (task.ws.readBlocking(read_buffer[current_read_offset .. current_read_offset + 4]) catch |err| {
            std.log.warn("WebSocket read error (mask key): {any}. Closing FD: {d}", .{ err, task.ws.socket });
            break;
        } != 4) {
            std.log.warn("Incomplete WebSocket frame (mask key). Closing FD: {d}", .{task.ws.socket});
            break;
        }
        @memcpy(&mask_key, read_buffer[current_read_offset .. current_read_offset + 4]);
        current_read_offset += 4;

        if (opcode >= 0x8) {
            if (payload_len > 125) {
                std.log.warn("Control frame received with payload > 125 bytes. Closing FD: {d}", .{task.ws.socket});
                break;
            }
            if (fin_bit == 0) {
                std.log.warn("Control frame received fragmented (FIN=0). Closing FD: {d}", .{task.ws.socket});
                break;
            }

            const control_payload = alloc.alloc(u8, @intCast(payload_len)) catch {
                std.log.err("Failed to allocate buffer for control frame payload. Closing FD: {d}", .{task.ws.socket});
                break;
            };
            defer alloc.free(control_payload);

            if (task.ws.readBlocking(control_payload) catch |err| {
                std.log.warn("WebSocket read error (control payload): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                break;
            } != control_payload.len) {
                std.log.warn("Incomplete WebSocket control frame payload. Closing FD: {d}", .{task.ws.socket});
                break;
            }
            for (control_payload, 0..) |*byte, j| {
                byte.* ^= mask_key[j % 4];
            }

            switch (opcode) {
                0x8 => {
                    // std.log.info("WebSocket Close frame received. Closing connection FD: {d}", .{task.ws.socket});
                    task.ws.close();
                    break;
                },
                0x9 => {
                    // std.log.debug("WebSocket Ping frame received. Sending Pong. FD: {d}", .{task.ws.socket});
                    task.ws.sendFrame(0xA, control_payload) catch |err| {
                        std.log.err("Failed to send WebSocket Pong frame: {any}. Closing FD: {d}", .{ err, task.ws.socket });
                        break;
                    };
                },
                0xA => {
                    // std.log.debug("WebSocket Pong frame received. FD: {d}", .{task.ws.socket});
                },
                else => {
                    std.log.warn("Unknown control frame opcode received: {x}. Closing FD: {d}", .{ opcode, task.ws.socket });
                    break;
                },
            }
            if (!task.ws.is_open) break;
            continue;
        }

        if (opcode != 0x1 and opcode != 0x2) {
            std.log.warn("Unsupported data frame opcode received: {x}. Closing FD: {d}", .{ opcode, task.ws.socket });
            break;
        }

        const max_payload: u64 = 1024 * 1024;
        if (payload_len > max_payload) {
            std.log.warn("WebSocket payload too large ({d} bytes). Closing FD: {d}", .{ payload_len, task.ws.socket });
            break;
        }
        if (payload_len == 0) {
            if (opcode == 0x1) {
                task.handler(task.ws, "", task.ctx);
            } else {
                // std.log.debug("Received empty binary frame. Ignoring. FD: {d}", .{task.ws.socket});
            }
            continue;
        }

        const payload_buffer = alloc.alloc(u8, @intCast(payload_len)) catch |err| {
            std.log.err("Failed to allocate buffer for WebSocket payload ({d} bytes): {any}. Closing FD: {d}", .{ payload_len, err, task.ws.socket });
            break;
        };
        defer alloc.free(payload_buffer);

        if (task.ws.readBlocking(payload_buffer) catch |err| {
            std.log.warn("WebSocket read error (payload): {any}. Closing FD: {d}", .{ err, task.ws.socket });
            break;
        } != payload_buffer.len) {
            std.log.warn("Incomplete WebSocket payload received. Closing FD: {d}", .{task.ws.socket});
            break;
        }

        for (payload_buffer, 0..) |*byte, j| {
            byte.* ^= mask_key[j % 4];
        }

        if (opcode == 0x1) {
            task.handler(task.ws, payload_buffer, task.ctx);
        } else {
            // std.log.debug("Received binary frame ({d} bytes). Ignoring. FD: {d}", .{ payload_buffer.len, task.ws.socket });
        }
    }

    // std.log.info("WebSocket handler finished for FD: {d}", .{task.ws.socket});
    result.success = true;
}
