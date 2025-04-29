// src/websocket.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const Context = @import("context.zig").Context;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const ThreadPool = @import("pool.zig").ThreadPool;
const Server = @import("server.zig").Server;
const AsyncIo = @import("async/async.zig").AsyncIo;
const AsyncContext = @import("async/async.zig").Context;
const Task = @import("async/task.zig").Task;

/// WebSocket connection over a socket, using async I/O.
pub const WebSocket = struct {
    socket: std.posix.fd_t,
    allocator: Allocator,
    is_open: bool,
    options: Options,
    async_io: *AsyncIo,

    pub const Options = struct {
        max_payload_size: u64 = 1024 * 1024,
        read_buffer_size: usize = 4096,
    };

    /// Initializes a WebSocket over the given socket.
    pub fn init(socket: std.posix.fd_t, allocator: Allocator, options: Options, async_io: *AsyncIo) WebSocket {
        return .{
            .socket = socket,
            .allocator = allocator,
            .is_open = true,
            .options = options,
            .async_io = async_io,
        };
    }

    /// Schedules an async read into the buffer.
    pub fn readAsync(self: *WebSocket, buffer: []u8, ctx: AsyncContext) !void {
        if (!self.is_open) {
            std.log.err("Attempted to read from closed WebSocket (FD: {d})", .{self.socket});
            return error.WebSocketClosed;
        }
        if (self.socket <= 0) {
            std.log.err("Invalid socket FD: {d}", .{self.socket});
            return error.InvalidSocket;
        }
        std.log.debug("Scheduling recv for FD: {d}, buffer size: {d}", .{ self.socket, buffer.len });
        _ = try self.async_io.recv(self.socket, buffer, ctx);
    }

    /// Sends a WebSocket frame asynchronously.
    pub fn sendFrameAsync(self: *WebSocket, opcode: u8, payload: []const u8, ctx: AsyncContext) !void {
        if (!self.is_open) {
            std.log.debug("Attempted to send frame on closed WebSocket (FD: {d})", .{self.socket});
            return error.WebSocketClosed;
        }

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
        std.log.debug("Sending frame (FD: {d}, opcode: {x}, payload_len: {d}): {x}", .{ self.socket, opcode, payload.len, frame.items });
        if (opcode == 0x1) {
            std.log.debug("Sending payload as string (FD: {d}): {s}", .{ self.socket, payload });
        }

        _ = try self.async_io.write(self.socket, frame.items, ctx);
    }

    /// Sends a text message asynchronously.
    pub fn sendMessageAsync(self: *WebSocket, message: []const u8, ctx: AsyncContext) !void {
        try self.sendFrameAsync(0x1, message, ctx);
    }

    /// Marks the WebSocket as closed and submits an async close task.
    pub fn close(self: *WebSocket, ctx: AsyncContext) void {
        if (!self.is_open) {
            std.log.debug("WebSocket already closed (FD: {d})", .{self.socket});
            return;
        }

        std.log.debug("Initiating async close for WebSocket (FD: {d})", .{self.socket});
        self.is_open = false;

        if (self.socket > 0) {
            _ = self.async_io.close(self.socket, ctx) catch |err| {
                std.log.err("Failed to submit async close for FD: {d}: {any}", .{ self.socket, err });
            };
        }
    }
};

/// Manages a WebSocket connection, including state machine and frame processing.
/// State transitions:
/// - reading_header: Reading the first 2 bytes of a frame.
/// - reading_extended_length: Reading extended payload length (2 or 8 bytes).
/// - reading_mask_key: Reading the 4-byte masking key.
/// - reading_payload: Reading the payload data.
/// - processing_frame: Processing a complete frame.
/// - closed: Connection is closed, no further reads.
pub const WebSocketConnection = struct {
    server: *Server,
    ws: *WebSocket,
    ctx: *Context,
    handler: WebSocketHandlerFn,
    allocator: Allocator,
    state: State,
    frame_buffer: std.ArrayList(u8),
    payload_buffer: ?[]u8,
    payload_len: u64,
    mask_key: [4]u8,
    header_size: usize,

    pub const State = enum {
        reading_header,
        reading_extended_length,
        reading_mask_key,
        reading_payload,
        processing_frame,
        closed,
    };

    /// Initializes a WebSocket connection and starts reading.
    pub fn init(server: *Server, ws: *WebSocket, ctx: *Context, handler: WebSocketHandlerFn, allocator: Allocator) !*WebSocketConnection {
        const conn = try allocator.create(WebSocketConnection);
        errdefer allocator.destroy(conn);

        conn.* = .{
            .server = server,
            .ws = ws,
            .ctx = ctx,
            .handler = handler,
            .allocator = allocator,
            .state = .reading_header,
            .frame_buffer = std.ArrayList(u8).init(allocator),
            .payload_buffer = null,
            .payload_len = 0,
            .mask_key = undefined,
            .header_size = 2,
        };

        try conn.startReading();
        return conn;
    }

    /// Deinitializes the connection, freeing resources.
    pub fn deinit(self: *WebSocketConnection) void {
        if (self.payload_buffer) |buf| {
            self.allocator.free(buf);
        }
        self.frame_buffer.deinit();
        self.allocator.destroy(self);
    }

    /// Starts the async read loop.
    pub fn startReading(self: *WebSocketConnection) !void {
        try self.readNext();
    }

    fn readNext(self: *WebSocketConnection) !void {
        if (!self.ws.is_open or self.state == .closed) {
            std.log.debug("Skipping readNext on closed WebSocket (FD: {d}, state: {s})", .{ self.ws.socket, @tagName(self.state) });
            return;
        }

        if (self.ws.socket <= 0) {
            std.log.err("Invalid socket FD: {d}", .{self.ws.socket});
            return error.InvalidSocket;
        }

        var buffer_size: usize = self.ws.options.read_buffer_size;
        switch (self.state) {
            .reading_header => buffer_size = 2,
            .reading_extended_length => buffer_size = if (self.header_size == 4) 2 else 8,
            .reading_mask_key => buffer_size = 4,
            .reading_payload => buffer_size = @min(self.payload_len, self.ws.options.read_buffer_size),
            .processing_frame, .closed => return,
        }

        // Allocate task
        const task = self.ws.async_io.getTask() catch |err| {
            std.log.err("Failed to get task for WebSocket read (FD: {d}): {s}", .{ self.ws.socket, @errorName(err) });
            self.state = .closed;
            self.ws.close(.{ .ptr = self, .cb = closeCompletionCallback });
            return error.TaskAllocationFailed;
        };

        // Allocate temporary buffer for recv
        const buf = try self.allocator.alloc(u8, buffer_size);
        task.* = .{
            .userdata = self,
            .callback = handleWebSocketCompletion,
            .req = .{ .recv = .{ .fd = self.ws.socket, .buffer = buf } },
        };
        std.log.debug("Task allocated for readNext (ptr: {*}, FD: {d}, state: {s}, buffer_size: {d}, buf_ptr: {*})", .{ task, self.ws.socket, @tagName(self.state), buffer_size, buf.ptr });
        self.ws.async_io.submission_q.push(task);
    }
};

/// Handles completion of WebSocket read tasks.
fn handleWebSocketCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    const bytes_read = result.recv catch |err| {
        std.log.err("WebSocket read error (state: {s}, FD: {d}): {any}", .{ @tagName(conn.state), conn.ws.socket, err });
        conn.state = .closed;
        if (conn.ws.is_open) {
            conn.ws.close(AsyncContext{
                .ptr = conn,
                .cb = closeCompletionCallback,
            });
        }
        conn.allocator.free(task.req.recv.buffer); // Free buffer
        return;
    };

    if (bytes_read == 0) {
        std.log.info("WebSocket connection closed by peer (FD: {d})", .{conn.ws.socket});
        conn.state = .closed;
        if (conn.ws.is_open) {
            conn.ws.close(AsyncContext{
                .ptr = conn,
                .cb = closeCompletionCallback,
            });
        }
        conn.allocator.free(task.req.recv.buffer); // Free buffer
        return;
    }

    // Log the raw recv buffer
    std.log.debug("Received {d} bytes (FD: {d}, state: {s}): {x}", .{ bytes_read, conn.ws.socket, @tagName(conn.state), task.req.recv.buffer[0..bytes_read] });
    // Append the received data to frame_buffer
    try conn.frame_buffer.appendSlice(task.req.recv.buffer[0..bytes_read]);
    conn.allocator.free(task.req.recv.buffer); // Free buffer
    std.log.debug("Full frame buffer (FD: {d}, state: {s}): {x}", .{ conn.ws.socket, @tagName(conn.state), conn.frame_buffer.items });

    switch (conn.state) {
        .reading_header => {
            if (bytes_read >= 2) {
                const opcode = conn.frame_buffer.items[0] & 0x0F;
                const fin_bit = (conn.frame_buffer.items[0] >> 7) & 1;
                const payload_len_short = conn.frame_buffer.items[1] & 0x7F;
                const mask_bit = (conn.frame_buffer.items[1] >> 7) & 1;

                // Validate header
                if (conn.frame_buffer.items[0] == 0xaa and conn.frame_buffer.items[1] == 0xaa) {
                    std.log.warn("Invalid header received (FD: {d}): {x}", .{ conn.ws.socket, conn.frame_buffer.items[0..2] });
                    try sendProtocolError(conn, "Invalid header");
                    return;
                }

                if (opcode == 0 or (opcode > 0x2 and opcode < 0x8) or opcode > 0xA) {
                    std.log.warn("Invalid opcode {x} received (FD: {d})", .{ opcode, conn.ws.socket });
                    try sendProtocolError(conn, "Invalid opcode");
                    return;
                }
                if (fin_bit == 0 and opcode < 0x8) {
                    std.log.warn("Fragmented frame received (FD: {d})", .{conn.ws.socket});
                    try sendProtocolError(conn, "Fragmented frames not supported");
                    return;
                }
                if (payload_len_short == 126) {
                    conn.header_size = 4;
                    conn.state = .reading_extended_length;
                } else if (payload_len_short == 127) {
                    conn.header_size = 10;
                    conn.state = .reading_extended_length;
                } else {
                    conn.payload_len = payload_len_short;
                    if (mask_bit == 0) {
                        std.log.warn("Unmasked frame received (FD: {d})", .{conn.ws.socket});
                        try sendProtocolError(conn, "Unmasked frame received");
                        return;
                    }
                    conn.header_size = 6;
                    conn.state = .reading_mask_key;
                }
                if (conn.state != .closed) {
                    try conn.readNext();
                }
            } else {
                std.log.warn("Incomplete header received (FD: {d}, bytes: {d})", .{ conn.ws.socket, bytes_read });
                try conn.readNext();
            }
        },
        .reading_extended_length => {
            if (conn.frame_buffer.items.len >= conn.header_size) {
                const len_bytes = conn.frame_buffer.items[2..conn.header_size];
                if (conn.header_size == 4) {
                    conn.payload_len = @as(u16, len_bytes[0]) << 8 | len_bytes[1];
                } else { // header_size == 10
                    conn.payload_len = @as(u64, len_bytes[0]) << 56 |
                        @as(u64, len_bytes[1]) << 48 |
                        @as(u64, len_bytes[2]) << 40 |
                        @as(u64, len_bytes[3]) << 32 |
                        @as(u64, len_bytes[4]) << 24 |
                        @as(u64, len_bytes[5]) << 16 |
                        @as(u64, len_bytes[6]) << 8 |
                        len_bytes[7];
                }
                if (conn.payload_len > conn.ws.options.max_payload_size) {
                    try sendMessageTooBig(conn);
                    return;
                }
                const mask_bit = (conn.frame_buffer.items[1] >> 7) & 1;
                if (mask_bit == 0) {
                    std.log.warn("Unmasked frame received (FD: {d})", .{conn.ws.socket});
                    try sendProtocolError(conn, "Unmasked frame received");
                    return;
                }
                conn.state = .reading_mask_key;
                if (conn.state != .closed) {
                    try conn.readNext();
                }
            } else {
                std.log.warn("Incomplete extended length received (FD: {d}, bytes: {d})", .{ conn.ws.socket, conn.frame_buffer.items.len });
                try conn.readNext();
            }
        },
        .reading_mask_key => {
            if (conn.frame_buffer.items.len >= conn.header_size) {
                @memcpy(&conn.mask_key, conn.frame_buffer.items[conn.header_size - 4 .. conn.header_size]);
                // Validate mask key
                if (std.mem.eql(u8, &conn.mask_key, &[_]u8{ 0xaa, 0xaa, 0xaa, 0xaa })) {
                    std.log.warn("Suspicious mask key (FD: {d}): {x}", .{ conn.ws.socket, conn.mask_key });
                    try sendProtocolError(conn, "Invalid mask key");
                    return;
                }
                std.log.debug("Mask key (FD: {d}): {x}", .{ conn.ws.socket, conn.mask_key });
                conn.state = .reading_payload;
                if (conn.state != .closed) {
                    try conn.readNext();
                }
            } else {
                std.log.warn("Incomplete mask key received (FD: {d}, bytes: {d})", .{ conn.ws.socket, conn.frame_buffer.items.len });
                try conn.readNext();
            }
        },
        .reading_payload => {
            if (conn.frame_buffer.items.len >= conn.header_size + conn.payload_len) {
                conn.state = .processing_frame;
                try processWebSocketFrame(conn);
                conn.frame_buffer.clearRetainingCapacity();
                conn.header_size = 2;
                conn.payload_len = 0;
                conn.state = .reading_header;
                if (conn.state != .closed) {
                    try conn.readNext();
                }
            } else {
                std.log.debug("Partial payload received (FD: {d}, received: {d}, expected: {d})", .{ conn.ws.socket, conn.frame_buffer.items.len - conn.header_size, conn.payload_len });
                try conn.readNext();
            }
        },
        .processing_frame, .closed => {},
    }
}

/// Sends a protocol error close frame and initiates async close.
fn sendProtocolError(conn: *WebSocketConnection, msg: []const u8) !void {
    std.log.warn("{s} on FD: {d}", .{ msg, conn.ws.socket });
    if (!conn.ws.is_open or conn.state == .closed) {
        std.log.debug("Skipping protocol error send on closed WebSocket (FD: {d})", .{conn.ws.socket});
        conn.state = .closed;
        return;
    }
    const close_frame = [_]u8{ 0x03, 0xEA }; // Protocol error (1002)
    try conn.ws.sendFrameAsync(0x8, &close_frame, AsyncContext{
        .ptr = conn,
        .cb = writeCompletionCallback,
    });
    conn.state = .closed;
    conn.ws.close(AsyncContext{
        .ptr = conn,
        .cb = closeCompletionCallback,
    });
}

/// Sends a message too big close frame and initiates async close.
fn sendMessageTooBig(conn: *WebSocketConnection) !void {
    std.log.warn("Payload length ({d}) exceeds max_payload_size ({d}) on FD: {d}", .{ conn.payload_len, conn.ws.options.max_payload_size, conn.ws.socket });
    if (!conn.ws.is_open or conn.state == .closed) {
        std.log.debug("Skipping message too big send on closed WebSocket (FD: {d})", .{conn.ws.socket});
        conn.state = .closed;
        return;
    }
    const close_frame = [_]u8{ 0x03, 0xF1 }; // Message Too Big (1009)
    try conn.ws.sendFrameAsync(0x8, &close_frame, AsyncContext{
        .ptr = conn,
        .cb = writeCompletionCallback,
    });
    conn.state = .closed;
    conn.ws.close(AsyncContext{
        .ptr = conn,
        .cb = closeCompletionCallback,
    });
}

/// Processes a complete WebSocket frame.
fn processWebSocketFrame(conn: *WebSocketConnection) !void {
    const frame = conn.frame_buffer.items;
    const fin_bit = (frame[0] >> 7) & 1;
    const rsv_bits = (frame[0] >> 4) & 7;
    const opcode = frame[0] & 0x0F;

    std.log.debug("Processing frame (FD: {d}, opcode: {x}, fin: {d}, payload_len: {d})", .{ conn.ws.socket, opcode, fin_bit, conn.payload_len });

    if (rsv_bits != 0) {
        try sendProtocolError(conn, "Non-zero RSV bits");
        return;
    }

    // Allocate or resize payload_buffer
    if (conn.payload_buffer == null or conn.payload_buffer.?.len < conn.payload_len) {
        if (conn.payload_buffer) |buf| {
            conn.allocator.free(buf);
        }
        conn.payload_buffer = try conn.allocator.alloc(u8, @intCast(conn.payload_len));
    }

    const payload_start = conn.header_size;
    const raw_payload = frame[payload_start .. payload_start + conn.payload_len];
    @memcpy(conn.payload_buffer.?[0..conn.payload_len], raw_payload);
    for (conn.payload_buffer.?, 0..) |*byte, i| {
        byte.* ^= conn.mask_key[i % 4];
    }
    std.log.debug("Unmasked payload (FD: {d}): {x}", .{ conn.ws.socket, conn.payload_buffer.? });
    if (opcode == 0x1) {
        std.log.debug("Unmasked payload as string (FD: {d}): {s}", .{ conn.ws.socket, conn.payload_buffer.? });
    }

    const ctx = AsyncContext{
        .ptr = conn,
        .cb = writeCompletionCallback,
    };

    if (opcode >= 0x8) {
        if (conn.payload_len > 125 or fin_bit == 0) {
            try sendProtocolError(conn, "Invalid control frame");
            return;
        }
        switch (opcode) {
            0x8 => {
                std.log.info("Close frame received (FD: {d})", .{conn.ws.socket});
                if (conn.ws.is_open and conn.state != .closed) {
                    try conn.ws.sendFrameAsync(0x8, conn.payload_buffer.?, ctx);
                    conn.state = .closed;
                    conn.ws.close(AsyncContext{
                        .ptr = conn,
                        .cb = closeCompletionCallback,
                    });
                }
            },
            0x9 => if (conn.ws.is_open and conn.state != .closed) {
                try conn.ws.sendFrameAsync(0xA, conn.payload_buffer.?, ctx);
            },
            0xA => std.log.debug("Pong frame received (FD: {d})", .{conn.ws.socket}),
            else => try sendProtocolError(conn, "Unknown control opcode"),
        }
    } else if (opcode == 0x1) {
        if (!std.unicode.utf8ValidateSlice(conn.payload_buffer.?)) {
            std.log.warn("Invalid UTF-8 in text frame (FD: {d}): {x}", .{ conn.ws.socket, conn.payload_buffer.? });
            if (conn.ws.is_open and conn.state != .closed) {
                const close_frame = [_]u8{ 0x03, 0xEF }; // Invalid data (1007)
                try conn.ws.sendFrameAsync(0x8, &close_frame, ctx);
                conn.state = .closed;
                conn.ws.close(AsyncContext{
                    .ptr = conn,
                    .cb = closeCompletionCallback,
                });
            }
            return;
        }
        conn.handler(conn.ws, conn.payload_buffer.?, conn.ctx, ctx);
    } else {
        try sendProtocolError(conn, "Unsupported opcode");
    }
}

/// Handles completion of write tasks.
fn writeCompletionCallback(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    const bytes_written = result.write catch |err| {
        std.log.err("Write error (FD: {d}): {any}", .{ conn.ws.socket, err });
        conn.state = .closed;
        if (conn.ws.is_open) {
            conn.ws.close(AsyncContext{
                .ptr = conn,
                .cb = closeCompletionCallback,
            });
        }
        return;
    };

    std.log.debug("Write completed (FD: {d}, bytes: {d})", .{ conn.ws.socket, bytes_written });
}

/// Handles completion of async close tasks.
fn closeCompletionCallback(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    _ = result.close catch |err| {
        std.log.err("Close error (FD: {d}): {any}", .{ conn.ws.socket, err });
    };

    std.log.debug("Async close completed for FD: {d}", .{conn.ws.socket});
    conn.state = .closed;

    // Perform final cleanup
    _ = conn.server.websocket_fds.remove(conn.ws.socket);
    for (conn.server.websockets.items, 0..) |*ws, i| {
        if (ws.socket == conn.ws.socket) {
            _ = conn.server.websockets.swapRemove(i);
            break;
        }
    }
    conn.deinit(); // Includes ctx.deinit()
    conn.allocator.destroy(conn.ctx); // Free ctx
    task.userdata = null;
}

/// Thread pool handler for WebSocket connections.
pub fn handleWebSocket(conn: *WebSocketConnection, result: *ThreadPool.TaskResult) void {
    std.log.debug("Starting WebSocket handler for FD: {d}", .{conn.ws.socket});
    if (!conn.ws.is_open) {
        std.log.err("WebSocket not open for FD: {d}", .{conn.ws.socket});
        result.success = false;
        return;
    }

    result.success = true;
}
