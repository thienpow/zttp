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
    options: Options,

    pub const Options = struct {
        blocking: bool = true,
        poll_timeout_ms: i32 = 1000,
        retry_sleep_ns: u64 = 10 * std.time.ns_per_ms,
        max_payload_size: u64 = 1024 * 1024,
        read_buffer_size: usize = 4096,
    };

    pub fn init(socket: std.posix.fd_t, allocator: Allocator, options: Options) WebSocket {
        // Set socket to non-blocking mode if needed
        if (!options.blocking) {
            const flags = std.posix.fcntl(socket, std.posix.F.GETFL, 0) catch |err| {
                std.log.err("Failed to get socket flags: {any}", .{err});
                return .{ .socket = socket, .allocator = allocator, .is_open = true, .options = options };
            };
            const O_NONBLOCK = 0x800;
            if (flags & O_NONBLOCK == 0) {
                _ = std.posix.fcntl(socket, std.posix.F.SETFL, flags | O_NONBLOCK) catch |err| {
                    std.log.err("Failed to set socket to non-blocking: {any}", .{err});
                };
            } else {
                std.log.debug("Socket (FD: {d}) already in non-blocking mode", .{socket});
            }
        }
        return .{
            .socket = socket,
            .allocator = allocator,
            .is_open = true,
            .options = options,
        };
    }

    pub fn read(self: *WebSocket, buffer: []u8) !?usize {
        if (!self.is_open) return error.WebSocketClosed;

        if (self.options.blocking) {
            const bytes_read = try std.posix.read(self.socket, buffer);
            if (bytes_read == 0) {
                self.is_open = false;
                return null;
            }
            return bytes_read;
        } else {
            var pollfd = [1]std.posix.pollfd{.{ .fd = self.socket, .events = std.posix.POLL.IN, .revents = 0 }};
            const poll_result = try std.posix.poll(&pollfd, self.options.poll_timeout_ms);
            if (poll_result == 0) {
                return null;
            }

            if (pollfd[0].revents & std.posix.POLL.IN != 0) {
                const bytes_read = std.posix.read(self.socket, buffer) catch |err| switch (err) {
                    error.WouldBlock => return null,
                    else => return err,
                };
                if (bytes_read == 0) {
                    self.is_open = false;
                    return null;
                }
                return bytes_read;
            } else if (pollfd[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR) != 0) {
                std.log.debug("Poll error: revents={b}", .{pollfd[0].revents});
                self.is_open = false;
                return null;
            }
            return null;
        }
    }

    pub fn sendFrame(self: *WebSocket, opcode: u8, payload: []const u8) !void {
        if (!self.is_open) return error.WebSocketClosed;

        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();

        try frame.append(0x80 | (opcode & 0x0F));

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

        try frame.appendSlice(payload);

        var total_sent: usize = 0;
        while (total_sent < frame.items.len) {
            const sent = std.posix.send(self.socket, frame.items[total_sent..], 0) catch |err| switch (err) {
                error.WouldBlock => {
                    var pollfd = [1]std.posix.pollfd{.{ .fd = self.socket, .events = std.posix.POLL.OUT, .revents = 0 }};
                    _ = try std.posix.poll(&pollfd, self.options.poll_timeout_ms);
                    continue;
                },
                else => return err,
            };
            total_sent += sent;
        }
    }

    pub fn sendMessage(self: *WebSocket, message: []const u8) !void {
        try self.sendFrame(0x1, message);
    }

    pub fn close(self: *WebSocket) void {
        if (self.is_open) {
            const close_frame = [_]u8{ 0x88, 0x00 };
            _ = std.posix.send(self.socket, &close_frame, 0) catch {};
            std.posix.close(self.socket);
            self.is_open = false;
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
        const socket_fd = task.ws.socket;
        for (task.server.websockets.items, 0..) |*server_ws, i| {
            if (server_ws.socket == socket_fd) {
                _ = task.server.websockets.swapRemove(i);
                found = true;
                break;
            }
        }
        if (!found) {
            std.log.warn("WebSocket (FD: {d}) already removed from server list?", .{socket_fd});
        }

        ctx_deinit_done = true;
        ws_close_done = true;
        std.log.info("WebSocket handler finished for FD: {d}", .{socket_fd});
    }

    var read_buffer = alloc.alloc(u8, task.ws.options.read_buffer_size) catch |err| {
        std.log.err("Failed to allocate read buffer: {any}", .{err});
        task.ws.close();
        return;
    };
    defer alloc.free(read_buffer);
    var frame_buffer = std.ArrayList(u8).init(alloc);
    defer frame_buffer.deinit();

    while (task.ws.is_open) {
        while (frame_buffer.items.len < 2) {
            const bytes_read = task.ws.read(read_buffer[0..]) catch |err| {
                std.log.err("WebSocket read error (header): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                task.ws.close();
                break;
            };
            if (bytes_read == null or bytes_read.? == 0) {
                if (task.ws.is_open) {
                    if (task.ws.options.blocking) {
                        std.log.info("WebSocket connection closed by peer (FD: {d}).", .{task.ws.socket});
                        task.ws.close();
                        break;
                    }
                    std.time.sleep(task.ws.options.retry_sleep_ns);
                    continue;
                }
                break;
            }
            frame_buffer.appendSlice(read_buffer[0..bytes_read.?]) catch |err| {
                std.log.err("Failed to append to frame buffer (header): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                task.ws.close();
                break;
            };
            std.log.debug("Frame buffer after header read (FD: {d}): {x}", .{ task.ws.socket, frame_buffer.items });
        }
        if (!task.ws.is_open or frame_buffer.items.len < 2) break;

        std.log.debug("Received frame header (FD: {d}): {x}", .{ task.ws.socket, frame_buffer.items[0..2] });

        const fin_bit = (frame_buffer.items[0] >> 7) & 1;
        const rsv_bits = (frame_buffer.items[0] >> 4) & 7;
        const opcode = frame_buffer.items[0] & 0x0F;
        const mask_bit = (frame_buffer.items[1] >> 7) & 1;
        const payload_len_short = frame_buffer.items[1] & 0x7F;

        if (rsv_bits != 0) {
            std.log.warn("WebSocket frame received with non-zero RSV bits ({b}). Closing FD: {d}", .{ rsv_bits, task.ws.socket });
            task.ws.close();
            break;
        }
        if (mask_bit == 0) {
            std.log.warn("WebSocket frame received from client without mask bit set. Closing FD: {d}", .{task.ws.socket});
            task.ws.close();
            break;
        }

        var payload_len: u64 = 0;
        var mask_key: [4]u8 = undefined;
        var header_size: usize = 2;

        if (payload_len_short <= 125) {
            payload_len = payload_len_short;
        } else if (payload_len_short == 126) {
            header_size = 4;
            while (frame_buffer.items.len < header_size) {
                const bytes_read = task.ws.read(read_buffer[0..]) catch |err| {
                    std.log.warn("WebSocket read error (16-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                    task.ws.close();
                    break;
                };
                if (bytes_read == null or bytes_read.? == 0) {
                    if (task.ws.is_open and !task.ws.options.blocking) {
                        std.time.sleep(task.ws.options.retry_sleep_ns);
                        continue;
                    }
                    task.ws.close();
                    break;
                }
                frame_buffer.appendSlice(read_buffer[0..bytes_read.?]) catch |err| {
                    std.log.err("Failed to append to frame buffer (16-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                    task.ws.close();
                    break;
                };
                std.log.debug("Frame buffer after extended length read (FD: {d}): {x}", .{ task.ws.socket, frame_buffer.items });
            }
            if (!task.ws.is_open or frame_buffer.items.len < header_size) break;
            payload_len = std.mem.readInt(u16, frame_buffer.items[2..4], .big);
        } else {
            header_size = 10;
            while (frame_buffer.items.len < header_size) {
                const bytes_read = task.ws.read(read_buffer[0..]) catch |err| {
                    std.log.warn("WebSocket read error (64-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                    task.ws.close();
                    break;
                };
                if (bytes_read == null or bytes_read.? == 0) {
                    if (task.ws.is_open and !task.ws.options.blocking) {
                        std.time.sleep(task.ws.options.retry_sleep_ns);
                        continue;
                    }
                    task.ws.close();
                    break;
                }
                frame_buffer.appendSlice(read_buffer[0..bytes_read.?]) catch |err| {
                    std.log.err("Failed to append to frame buffer (64-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                    task.ws.close();
                    break;
                };
                std.log.debug("Frame buffer after extended length read (FD: {d}): {x}", .{ task.ws.socket, frame_buffer.items });
            }
            if (!task.ws.is_open or frame_buffer.items.len < header_size) break;
            payload_len = std.mem.readInt(u64, frame_buffer.items[2..10], .big);
        }

        header_size += 4;
        while (frame_buffer.items.len < header_size) {
            const bytes_read = task.ws.read(read_buffer[0..]) catch |err| {
                std.log.warn("WebSocket read error (mask key): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                task.ws.close();
                break;
            };
            if (bytes_read == null or bytes_read.? == 0) {
                if (task.ws.is_open and !task.ws.options.blocking) {
                    std.time.sleep(task.ws.options.retry_sleep_ns);
                    continue;
                }
                task.ws.close();
                break;
            }
            frame_buffer.appendSlice(read_buffer[0..bytes_read.?]) catch |err| {
                std.log.err("Failed to append to frame buffer (mask key): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                task.ws.close();
                break;
            };
            std.log.debug("Frame buffer after mask key read (FD: {d}): {x}", .{ task.ws.socket, frame_buffer.items });
        }
        if (!task.ws.is_open or frame_buffer.items.len < header_size) break;
        @memcpy(&mask_key, frame_buffer.items[header_size - 4 .. header_size]);
        std.log.debug("Mask key (FD: {d}): {x}", .{ task.ws.socket, mask_key });

        while (frame_buffer.items.len < header_size + payload_len) {
            const bytes_read = task.ws.read(read_buffer[0..]) catch |err| {
                std.log.warn("WebSocket read error (payload): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                task.ws.close();
                break;
            };
            if (bytes_read == null or bytes_read.? == 0) {
                if (task.ws.is_open and !task.ws.options.blocking) {
                    std.time.sleep(task.ws.options.retry_sleep_ns);
                    continue;
                }
                task.ws.close();
                break;
            }
            frame_buffer.appendSlice(read_buffer[0..bytes_read.?]) catch |err| {
                std.log.err("Failed to append to frame buffer (payload): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                task.ws.close();
                break;
            };
            std.log.debug("Frame buffer after payload read (FD: {d}): {x}", .{ task.ws.socket, frame_buffer.items });
        }
        if (!task.ws.is_open) break;

        const payload_buffer = alloc.alloc(u8, @intCast(payload_len)) catch |err| {
            std.log.err("Failed to allocate buffer for WebSocket payload ({d} bytes): {any}. Closing FD: {d}", .{ payload_len, err, task.ws.socket });
            task.ws.close();
            break;
        };
        defer alloc.free(payload_buffer);

        @memcpy(payload_buffer[0..payload_len], frame_buffer.items[header_size .. header_size + payload_len]);

        std.log.debug("Raw payload before unmasking (FD: {d}, opcode: {x}, len: {d}): {x}", .{ task.ws.socket, opcode, payload_buffer.len, payload_buffer });

        for (payload_buffer, 0..) |*byte, j| {
            byte.* ^= mask_key[j % 4];
        }

        std.log.debug("Received payload (FD: {d}, opcode: {x}, len: {d}): {x}", .{ task.ws.socket, opcode, payload_buffer.len, payload_buffer });

        if (payload_buffer.len == 4) {
            var expected: [4]u8 = [4]u8{ 'p', 'i', 'n', 'g' };
            for (expected[0..], 0..) |*byte, j| {
                byte.* ^= mask_key[j % 4];
            }
            std.log.debug("Expected masked 'ping' payload (FD: {d}): {x}", .{ task.ws.socket, expected });
        }

        if (opcode >= 0x8) {
            if (payload_len > 125) {
                std.log.warn("Control frame received with payload > 125 bytes. Closing FD: {d}", .{task.ws.socket});
                task.ws.close();
                break;
            }
            if (fin_bit == 0) {
                std.log.warn("Control frame received fragmented (FIN=0). Closing FD: {d}", .{task.ws.socket});
                task.ws.close();
                break;
            }

            switch (opcode) {
                0x8 => {
                    std.log.info("WebSocket Close frame received. Closing connection FD: {d}", .{task.ws.socket});
                    task.ws.close();
                    break;
                },
                0x9 => {
                    std.log.debug("WebSocket Ping frame received. Sending Pong. FD: {d}", .{task.ws.socket});
                    task.ws.sendFrame(0xA, payload_buffer) catch |err| {
                        std.log.err("Failed to send WebSocket Pong frame: {any}. Closing FD: {d}", .{ err, task.ws.socket });
                        task.ws.close();
                        break;
                    };
                },
                0xA => {
                    std.log.debug("WebSocket Pong frame received. FD: {d}", .{task.ws.socket});
                },
                else => {
                    std.log.warn("Unknown control frame opcode received: {x}. Closing FD: {d}", .{ opcode, task.ws.socket });
                    task.ws.close();
                    break;
                },
            }
            if (!task.ws.is_open) break;
            frame_buffer.clearAndFree();
            continue;
        }

        if (opcode != 0x1 and opcode != 0x2) {
            std.log.warn("Unsupported data frame opcode received: {x}. Closing FD: {d}", .{ opcode, task.ws.socket });
            task.ws.close();
            break;
        }

        if (payload_len > task.ws.options.max_payload_size) {
            std.log.warn("WebSocket payload too large ({d} bytes). Closing FD: {d}", .{ payload_len, task.ws.socket });
            task.ws.close();
            break;
        }

        if (opcode == 0x1) {
            if (!std.unicode.utf8ValidateSlice(payload_buffer)) {
                std.log.warn("Invalid UTF-8 in text frame. Closing FD: {d}", .{task.ws.socket});
                const close_frame = [_]u8{ 0x03, 0xEF };
                task.ws.sendFrame(0x8, &close_frame) catch |err| {
                    std.log.err("Failed to send close frame: {any}. Closing FD: {d}", .{ err, task.ws.socket });
                };
                task.ws.close();
                break;
            }
            std.log.debug("Calling WebSocket handler for FD: {d}", .{task.ws.socket});
            task.handler(task.ws, payload_buffer, task.ctx);
        } else {
            std.log.debug("Received binary frame ({d} bytes). Ignoring. FD: {d}", .{ payload_buffer.len, task.ws.socket });
        }

        frame_buffer.clearAndFree();
    }

    result.success = true;
}
