// src/websocket.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const Context = @import("context.zig").Context;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const Server = @import("server.zig").Server;
const AsyncIo = @import("async/async.zig").AsyncIo;
const AsyncContext = @import("async/async.zig").Context;
const Task = @import("async/task.zig").Task;

const log = std.log.scoped(.websocket);

/// WebSocket connection over a socket, using async I/O.
pub const WebSocket = struct {
    socket: std.posix.fd_t,
    allocator: Allocator,
    is_open: bool,
    options: Options,
    async_io: *AsyncIo,

    pub const Options = struct {
        max_payload_size: u64 = 1024 * 1024, // 1MB
        read_buffer_size: usize = 4096,
    };

    /// Initializes a WebSocket over the given socket.
    pub fn init(socket: std.posix.fd_t, allocator: Allocator, options: Options, async_io: *AsyncIo) WebSocket {
        log.debug("WebSocket.init: FD: {d}", .{socket});
        return .{
            .socket = socket,
            .allocator = allocator,
            .is_open = true,
            .options = options,
            .async_io = async_io,
        };
    }

    /// Deinitializes the WebSocket, freeing resources.
    pub fn deinit(self: *WebSocket) void {
        log.debug("WebSocket.deinit: FD: {d}", .{self.socket});
        // No dynamic resources to free in WebSocket struct
    }

    /// Schedules an async read into the buffer.
    pub fn readAsync(self: *WebSocket, buffer: []u8, ctx: AsyncContext) !void {
        if (!self.is_open) {
            log.err("Attempted to read from closed WebSocket (FD: {d})", .{self.socket});
            return error.WebSocketClosed;
        }
        if (self.socket <= 0) {
            log.err("Invalid socket FD: {d}", .{self.socket});
            return error.InvalidSocket;
        }
        log.debug("Scheduling recv for FD: {d}, buffer size: {d}", .{ self.socket, buffer.len });
        _ = try self.async_io.recv(self.socket, buffer, ctx);
    }

    /// Sends a WebSocket frame asynchronously.
    pub fn sendFrameAsync(self: *WebSocket, opcode: u8, payload: []const u8, ctx: AsyncContext) !void {
        if (!self.is_open) {
            log.debug("Attempted to send frame on closed WebSocket (FD: {d})", .{self.socket});
            return error.WebSocketClosed;
        }

        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();

        // FIN bit (1) and opcode
        try frame.append(0x80 | (opcode & 0x0F));

        // Payload length
        if (payload.len <= 125) {
            try frame.append(@intCast(payload.len));
        } else if (payload.len <= 0xFFFF) {
            try frame.append(126);
            try frame.writer().writeInt(u16, @intCast(payload.len), .big);
        } else {
            try frame.append(127);
            try frame.writer().writeInt(u64, payload.len, .big);
        }

        // Payload
        try frame.appendSlice(payload);

        //log.debug("Sending frame (FD: {d}, opcode: {x}, payload_len: {d}): {x}", .{ self.socket, opcode, payload.len, frame.items });
        if (opcode == 0x1) {
            log.debug("Sending payload as string (FD: {d}): {s}", .{ self.socket, payload });
        }

        const frame_data = try self.allocator.dupe(u8, frame.items);
        errdefer self.allocator.free(frame_data);

        _ = try self.async_io.write(self.socket, frame_data, ctx);
    }

    /// Sends a text message asynchronously.
    pub fn sendMessageAsync(self: *WebSocket, message: []const u8, ctx: AsyncContext) !void {
        try self.sendFrameAsync(0x1, message, ctx);
    }

    /// Marks the WebSocket as closed and submits an async close task.
    pub fn close(self: *WebSocket, ctx: AsyncContext) void {
        if (!self.is_open) {
            log.debug("WebSocket already closed (FD: {d})", .{self.socket});
            return;
        }

        log.debug("Initiating async close for WebSocket (FD: {d})", .{self.socket});
        self.is_open = false;

        if (self.socket > 0) {
            _ = self.async_io.close(self.socket, ctx) catch |err| {
                log.err("Failed to submit async close for FD: {d}: {any}", .{ self.socket, err });
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
/// - closed: Connection is closed, no further reads.
pub const WebSocketConnection = struct {
    server: *Server,
    ws: WebSocket, // Owned, not a pointer
    ctx: *Context,
    handler: WebSocketHandlerFn,
    allocator: Allocator,
    state: State,
    frame_buffer: std.ArrayList(u8),
    payload_buffer: std.ArrayList(u8),
    mask_key: ?[4]u8,
    opcode: u8,
    fin: bool,
    payload_len: u64,
    header_size: usize,

    pub const State = enum {
        reading_header,
        reading_extended_length,
        reading_mask_key,
        reading_payload,
        closed,
    };

    /// Initializes a WebSocket connection and starts reading.
    pub fn init(server: *Server, ws: WebSocket, ctx: *Context, handler: WebSocketHandlerFn, allocator: Allocator) !*WebSocketConnection {
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
            .payload_buffer = std.ArrayList(u8).init(allocator),
            .mask_key = null,
            .opcode = 0,
            .fin = false,
            .payload_len = 0,
            .header_size = 2,
        };

        log.debug("WebSocketConnection.init: FD: {d}", .{ws.socket});
        try conn.readNext();
        return conn;
    }

    /// Deinitializes the connection, freeing resources.
    pub fn deinit(self: *WebSocketConnection) void {
        log.debug("WebSocketConnection.deinit: FD: {d}", .{self.ws.socket});
        self.frame_buffer.deinit();
        self.payload_buffer.deinit();
        self.ws.deinit();
        self.allocator.destroy(self);
    }

    /// Starts the async read loop.
    pub fn startReading(self: *WebSocketConnection) !void {
        try self.readNext();
    }

    /// Schedules the next async read based on the current state.
    fn readNext(self: *WebSocketConnection) !void {
        if (!self.ws.is_open or self.state == .closed) {
            log.debug("Skipping readNext on closed WebSocket (FD: {d}, state: {s})", .{
                self.ws.socket, @tagName(self.state),
            });
            return;
        }

        if (self.ws.socket <= 0) {
            log.err("Invalid socket FD: {d}", .{self.ws.socket});
            self.state = .closed;
            return error.InvalidSocket;
        }

        const buffer_size: usize = switch (self.state) {
            .reading_header => 2,
            .reading_extended_length => if (self.header_size == 8) 2 else 8,
            .reading_mask_key => 4,
            .reading_payload => @min(self.payload_len, self.ws.options.read_buffer_size),
            .closed => return,
        };

        const task = try self.ws.async_io.getTask();
        const buf = try self.allocator.alloc(u8, buffer_size);
        task.* = .{
            .userdata = self,
            .callback = handleReadCompletion,
            .req = .{ .recv = .{ .fd = self.ws.socket, .buffer = buf } },
        };
        self.ws.async_io.submission_q.push(task);
        log.debug("Task allocated for readNext (ptr: {*}, FD: {d}, state: {s}, buffer_size: {d}, buf_ptr: {*})", .{
            task, self.ws.socket, @tagName(self.state), buffer_size, buf.ptr,
        });
    }

    /// Sends a protocol error close frame and initiates async close.
    fn sendProtocolError(self: *WebSocketConnection, msg: []const u8) !void {
        log.warn("{s} on FD: {d}", .{ msg, self.ws.socket });
        if (!self.ws.is_open or self.state == .closed) {
            log.debug("Skipping protocol error send on closed WebSocket (FD: {d})", .{self.ws.socket});
            return;
        }

        var close_payload = std.ArrayList(u8).init(self.allocator);
        defer close_payload.deinit();
        try close_payload.writer().writeInt(u16, 1002, .big); // Protocol error (1002)

        try self.ws.sendFrameAsync(0x8, close_payload.items, AsyncContext{
            .ptr = self,
            .cb = handleWriteCompletion,
        });
        self.state = .closed;
        self.ws.close(AsyncContext{
            .ptr = self,
            .cb = handleCloseCompletion,
        });
    }

    /// Sends a message too big close frame and initiates async close.
    fn sendMessageTooBig(self: *WebSocketConnection) !void {
        log.warn("Payload length ({d}) exceeds max_payload_size ({d}) on FD: {d}", .{
            self.payload_len, self.ws.options.max_payload_size, self.ws.socket,
        });
        if (!self.ws.is_open or self.state == .closed) {
            log.debug("Skipping message too big send on closed WebSocket (FD: {d})", .{self.ws.socket});
            return;
        }

        var close_payload = std.ArrayList(u8).init(self.allocator);
        defer close_payload.deinit();
        try close_payload.writer().writeInt(u16, 1009, .big); // Message Too Big (1009)

        try self.ws.sendFrameAsync(0x8, close_payload.items, AsyncContext{
            .ptr = self,
            .cb = handleWriteCompletion,
        });
        self.state = .closed;
        self.ws.close(AsyncContext{
            .ptr = self,
            .cb = handleCloseCompletion,
        });
    }

    /// Processes a complete WebSocket frame.
    fn processFrame(self: *WebSocketConnection) !void {
        const frame = self.frame_buffer.items;
        self.fin = (frame[0] & 0x80) != 0;
        const rsv_bits = (frame[0] >> 4) & 0x07;
        self.opcode = frame[0] & 0x0F;

        log.debug("Processing frame (FD: {d}, opcode: {x}, fin: {d}, payload_len: {d})", .{
            self.ws.socket, self.opcode, @intFromBool(self.fin), self.payload_len,
        });

        if (rsv_bits != 0) {
            try self.sendProtocolError("Non-zero RSV bits");
            return;
        }

        if (!self.fin and self.opcode < 0x8) {
            try self.sendProtocolError("Fragmented frames not supported");
            return;
        }

        const payload_start = self.header_size;
        const raw_payload = frame[payload_start .. payload_start + self.payload_len];
        try self.payload_buffer.resize(@intCast(self.payload_len));
        @memcpy(self.payload_buffer.items, raw_payload);

        if (self.mask_key) |mask| {
            for (self.payload_buffer.items, 0..) |*byte, i| {
                byte.* ^= mask[i % 4];
            }
        }

        //log.debug("Unmasked payload (FD: {d}): {x}", .{ self.ws.socket, self.payload_buffer.items });
        if (self.opcode == 0x1) {
            //log.debug("Unmasked payload as string (FD: {d}): {s}", .{ self.ws.socket, self.payload_buffer.items });
            log.info("WS message received: {s}", .{self.payload_buffer.items});
        }

        const ctx = AsyncContext{
            .ptr = self,
            .cb = handleWriteCompletion,
        };

        if (self.opcode >= 0x8) { // Control frames
            if (self.payload_len > 125) {
                try self.sendProtocolError("Invalid control frame length");
                return;
            }

            switch (self.opcode) {
                0x8 => { // Close
                    log.info("Close frame received (FD: {d})", .{self.ws.socket});
                    if (self.ws.is_open and self.state != .closed) {
                        var close_payload = std.ArrayList(u8).init(self.allocator);
                        defer close_payload.deinit();
                        try close_payload.writer().writeInt(u16, 1000, .big); // Normal closure (1000)
                        try self.ws.sendFrameAsync(0x8, close_payload.items, ctx);
                        self.state = .closed;
                        self.ws.close(AsyncContext{
                            .ptr = self,
                            .cb = handleCloseCompletion,
                        });
                    }
                },
                0x9 => { // Ping
                    if (self.ws.is_open and self.state != .closed) {
                        try self.ws.sendFrameAsync(0xA, self.payload_buffer.items, ctx);
                        self.state = .reading_header;
                        self.frame_buffer.clearAndFree();
                        self.payload_buffer.clearRetainingCapacity();
                        self.mask_key = null;
                        self.opcode = 0;
                        self.payload_len = 0;
                        self.header_size = 2;
                        try self.readNext();
                    }
                },
                0xA => { // Pong
                    log.debug("Pong frame received (FD: {d})", .{self.ws.socket});
                    self.state = .reading_header;
                    self.frame_buffer.clearAndFree();
                    self.payload_buffer.clearRetainingCapacity();
                    self.mask_key = null;
                    self.opcode = 0;
                    self.payload_len = 0;
                    self.header_size = 2;
                    try self.readNext();
                },
                else => try self.sendProtocolError("Unknown control opcode"),
            }
        } else if (self.opcode == 0x1 or self.opcode == 0x2) { // Data frames
            if (self.opcode == 0x1 and !std.unicode.utf8ValidateSlice(self.payload_buffer.items)) {
                log.warn("Invalid UTF-8 in text frame (FD: {d}): {x}", .{
                    self.ws.socket, self.payload_buffer.items,
                });
                var close_payload = std.ArrayList(u8).init(self.allocator);
                defer close_payload.deinit();
                try close_payload.writer().writeInt(u16, 1007, .big); // Invalid data (1007)
                try self.ws.sendFrameAsync(0x8, close_payload.items, ctx);
                self.state = .closed;
                self.ws.close(AsyncContext{
                    .ptr = self,
                    .cb = handleCloseCompletion,
                });
                return;
            }

            log.debug("Calling WebSocket handler for FD: {d}, data: {s}", .{
                self.ws.socket, self.payload_buffer.items,
            });
            try self.handler(&self.ws, self.payload_buffer.items, self.ctx, ctx);
            log.debug("WebSocket handler completed for FD: {d}", .{self.ws.socket});

            self.state = .reading_header;
            self.frame_buffer.clearAndFree();
            self.payload_buffer.clearRetainingCapacity();
            self.mask_key = null;
            self.opcode = 0;
            self.payload_len = 0;
            self.header_size = 2;
            try self.readNext();
        } else {
            try self.sendProtocolError("Unsupported opcode");
        }
    }
};

/// Handles completion of async read tasks.
fn handleReadCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    const bytes_read = result.recv catch |err| {
        log.err("WebSocket read error (state: {s}, FD: {d}): {any}", .{
            @tagName(conn.state), conn.ws.socket, err,
        });
        conn.state = .closed;
        if (conn.ws.is_open) {
            conn.ws.close(AsyncContext{
                .ptr = conn,
                .cb = handleCloseCompletion,
            });
        }
        conn.allocator.free(task.req.recv.buffer);
        task.userdata = null;
        return;
    };

    if (bytes_read == 0) {
        log.info("WebSocket connection closed by peer (FD: {d})", .{conn.ws.socket});
        conn.state = .closed;
        if (conn.ws.is_open) {
            conn.ws.close(AsyncContext{
                .ptr = conn,
                .cb = handleCloseCompletion,
            });
        }
        conn.allocator.free(task.req.recv.buffer);
        task.userdata = null;
        return;
    }

    //log.debug("Received {d} bytes (FD: {d}, state: {s}): {x}", .{ bytes_read, conn.ws.socket, @tagName(conn.state), task.req.recv.buffer[0..bytes_read] });
    try conn.frame_buffer.appendSlice(task.req.recv.buffer[0..bytes_read]);
    conn.allocator.free(task.req.recv.buffer);
    //log.debug("Full frame buffer (FD: {d}, state: {s}): {x}", .{ conn.ws.socket, @tagName(conn.state), conn.frame_buffer.items });

    switch (conn.state) {
        .reading_header => {
            log.debug("Processing header (FD: {d}, buffer_len: {d})", .{ conn.ws.socket, conn.frame_buffer.items.len });
            if (conn.frame_buffer.items.len >= 2) {
                const header = conn.frame_buffer.items[0..2];
                conn.fin = (header[0] & 0x80) != 0;
                conn.opcode = header[0] & 0x0F;
                const mask_bit = (header[1] & 0x80) != 0;
                conn.payload_len = @as(u64, header[1] & 0x7F);

                log.debug("Header parsed (FD: {d}, fin: {d}, opcode: {x}, payload_len: {d}, mask_bit: {d})", .{
                    conn.ws.socket, @intFromBool(conn.fin), conn.opcode, conn.payload_len, @intFromBool(mask_bit),
                });
                if (!mask_bit) {
                    log.err("Unmasked frame received (FD: {d})", .{conn.ws.socket});
                    try conn.sendProtocolError("Unmasked frame received");
                    return;
                }

                if (conn.payload_len == 126) {
                    conn.header_size = 8; // 2 (header) + 2 (ext len) + 4 (mask)
                    conn.state = .reading_extended_length;
                } else if (conn.payload_len == 127) {
                    conn.header_size = 14; // 2 (header) + 8 (ext len) + 4 (mask)
                    conn.state = .reading_extended_length;
                } else {
                    conn.header_size = 6; // 2 (header) + 4 (mask)
                    conn.state = .reading_mask_key;
                }
                log.debug("Transitioning to state: {s} (FD: {d})", .{ @tagName(conn.state), conn.ws.socket });
                try conn.readNext();
            }
        },
        .reading_extended_length => {
            log.debug("Reading extended length (FD: {d}, buffer_len: {d})", .{ conn.ws.socket, conn.frame_buffer.items.len });
            // Define required_len as a variable to be set at runtime
            var required_len: usize = undefined;
            if (conn.payload_len == 126) {
                required_len = 4; // 2 (header) + 2 (ext len)
            } else { // payload_len == 127
                required_len = 10; // 2 (header) + 8 (ext len)
            }
            if (conn.frame_buffer.items.len >= required_len) {
                const len_bytes = conn.frame_buffer.items[2..required_len];
                if (conn.payload_len == 126) { // header_size == 8
                    if (len_bytes.len < 2) {
                        log.err("Incomplete extended length (FD: {d}): {x}", .{ conn.ws.socket, len_bytes });
                        try conn.sendProtocolError("Incomplete extended length");
                        return;
                    }
                    const fixed_len_bytes: *const [2]u8 = len_bytes[0..2];
                    conn.payload_len = std.mem.readInt(u16, fixed_len_bytes, .big);
                    log.debug("Parsed extended length (FD: {d}): {d}", .{ conn.ws.socket, conn.payload_len });
                } else { // payload_len == 127, header_size == 14
                    if (len_bytes.len < 8) {
                        log.err("Incomplete extended length (FD: {d}): {x}", .{ conn.ws.socket, len_bytes });
                        try conn.sendProtocolError("Incomplete extended length");
                        return;
                    }
                    const fixed_len_bytes: *const [8]u8 = len_bytes[0..8];
                    conn.payload_len = std.mem.readInt(u64, fixed_len_bytes, .big);
                    log.debug("Parsed extended length (FD: {d}): {d}", .{ conn.ws.socket, conn.payload_len });
                }
                if (conn.payload_len > conn.ws.options.max_payload_size) {
                    log.err("Payload length {d} exceeds max_payload_size {d} (FD: {d})", .{
                        conn.payload_len, conn.ws.options.max_payload_size, conn.ws.socket,
                    });
                    try conn.sendMessageTooBig();
                    return;
                }
                conn.state = .reading_mask_key;
                log.debug("Transitioning to state: {s} (FD: {d})", .{ @tagName(conn.state), conn.ws.socket });
                try conn.readNext();
            }
        },
        .reading_mask_key => {
            log.debug("Reading mask key (FD: {d}, buffer_len: {d})", .{ conn.ws.socket, conn.frame_buffer.items.len });
            if (conn.frame_buffer.items.len >= conn.header_size) {
                const mask_slice = conn.frame_buffer.items[conn.header_size - 4 .. conn.header_size];
                if (mask_slice.len == 4) {
                    conn.mask_key = mask_slice[0..4].*;
                    log.debug("Mask key (FD: {d}): {x}", .{ conn.ws.socket, conn.mask_key.? });
                    conn.state = .reading_payload;
                    try conn.readNext();
                } else {
                    try conn.sendProtocolError("Incomplete mask key");
                    return;
                }
            }
        },
        .reading_payload => {
            log.debug("Reading payload (FD: {d}, buffer_len: {d}, expected_len: {d})", .{
                conn.ws.socket, conn.frame_buffer.items.len, conn.header_size + conn.payload_len,
            });
            if (conn.frame_buffer.items.len >= conn.header_size + conn.payload_len) {
                try conn.processFrame();
            } else {
                try conn.readNext();
            }
        },
        .closed => {
            log.debug("Connection closed, ignoring read (FD: {d})", .{conn.ws.socket});
        },
    }

    task.userdata = null;
}

/// Handles completion of async write tasks.
fn handleWriteCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    const bytes_written = result.write catch |err| {
        log.err("Write error (FD: {d}): {any}", .{ conn.ws.socket, err });
        conn.state = .closed;
        if (conn.ws.is_open) {
            conn.ws.close(AsyncContext{
                .ptr = conn,
                .cb = handleCloseCompletion,
            });
        }
        return;
    };

    log.debug("-Done Writing frame to client completed (FD: {d}, bytes: {d})", .{ conn.ws.socket, bytes_written });
    conn.allocator.free(task.req.write.buffer);
    task.userdata = null;
}

/// Handles completion of async close tasks.
fn handleCloseCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    const socket = conn.ws.socket; // Store socket for logging
    _ = result.close catch |err| {
        log.err("Close error (FD: {d}): {any}", .{ socket, err });
    };

    log.debug("Async close completed for FD: {d}", .{socket});
    conn.state = .closed;

    // Remove WebSocket from server *before* deinit
    _ = conn.server.websocket_fds.remove(socket);

    // Deinit connection (includes WebSocket cleanup)
    conn.deinit();

    task.userdata = null;
}
