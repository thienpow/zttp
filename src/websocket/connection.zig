const std = @import("std");
const Allocator = std.mem.Allocator;
const WebSocket = @import("websocket.zig").WebSocket;
const WebSocketTransport = @import("transport.zig").WebSocketTransport;
const Context = @import("../context.zig").Context;
const WebSocketHandlerFn = @import("../router.zig").WebSocketHandlerFn;
const Server = @import("../server.zig").Server;
const AsyncIo = @import("../async/async.zig").AsyncIo;
const AsyncContext = @import("../async/async.zig").Context;
const Task = @import("../async/task.zig").Task;

const log = std.log.scoped(.websocket_connection);

/// Manages a WebSocket connection, including state machine and frame processing.
/// State transitions:
/// - reading_header: Reading the first 2 bytes of a frame.
/// - reading_extended_length: Reading extended payload length (2 or 8 bytes).
/// - reading_mask_key: Reading the 4-byte masking key.
/// - reading_payload: Reading the payload data.
/// - closed: Connection is closed, no further reads.
pub const WebSocketConnection = struct {
    server: *Server,
    ws: *WebSocket,
    transport: *WebSocketTransport,
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
    pub fn init(server: *Server, ws: *WebSocket, transport: *WebSocketTransport, ctx: *Context, handler: WebSocketHandlerFn, allocator: Allocator) !*WebSocketConnection {
        const conn = try allocator.create(WebSocketConnection);
        errdefer allocator.destroy(conn);

        conn.* = .{
            .server = server,
            .ws = ws,
            .transport = transport,
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

        try conn.readNext();
        return conn;
    }

    /// Deinitializes the connection, freeing resources.
    pub fn deinit(self: *WebSocketConnection) void {
        self.frame_buffer.deinit();
        self.payload_buffer.deinit();
        self.ws.deinit();
        self.transport.deinit();
        self.allocator.destroy(self);
    }

    /// Schedules the next async read based on the current state.
    fn readNext(self: *WebSocketConnection) !void {
        if (self.state == .closed) {
            return;
        }

        const buffer_size: usize = switch (self.state) {
            .reading_header => 2,
            .reading_extended_length => if (self.header_size == 8) 2 else 8,
            .reading_mask_key => 4,
            .reading_payload => @min(self.payload_len, self.ws.options.read_buffer_size),
            .closed => return,
        };

        const task = try self.ws.transport.async_io.getTask();
        const buf = try self.allocator.alloc(u8, buffer_size);
        task.* = .{
            .userdata = self,
            .callback = handleReadCompletion,
            .req = .{ .recv = .{ .fd = self.transport.fd, .buffer = buf } },
        };
        self.ws.transport.async_io.submission_q.push(task);
    }

    /// Sends a protocol error close frame and initiates async close.
    fn sendProtocolError(self: *WebSocketConnection, msg: []const u8) !void {
        log.warn("{s} on FD: {d}", .{ msg, self.transport.fd });
        if (!self.ws.is_open or self.state == .closed) {
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
            self.payload_len, self.ws.options.max_payload_size, self.transport.fd,
        });
        if (!self.ws.is_open or self.state == .closed) {
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
                    log.info("Close frame received (FD: {d})", .{self.transport.fd});
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
                        try self.ws.sendPongAsync(self.payload_buffer.items, ctx);
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
                    self.transport.fd, self.payload_buffer.items,
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

            try self.handler(self.ws, self.payload_buffer.items, self.ctx, ctx);

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

    /// Sends a Ping frame asynchronously.
    pub fn sendPingAsync(self: *WebSocketConnection, payload: []const u8, ctx: AsyncContext) !void {
        if (!self.ws.is_open or self.state == .closed) {
            log.warn("Attempted to send ping on closed connection (FD: {d})", .{self.transport.fd});
            return error.WebSocketClosed;
        }
        try self.ws.sendPingAsync(payload, ctx);
    }

    /// Sends an unsolicited Pong frame asynchronously.
    pub fn sendPongAsync(self: *WebSocketConnection, payload: []const u8, ctx: AsyncContext) !void {
        if (!self.ws.is_open or self.state == .closed) {
            log.warn("Attempted to send pong on closed connection (FD: {d})", .{self.transport.fd});
            return error.WebSocketClosed;
        }
        try self.ws.sendPongAsync(payload, ctx);
    }
};

/// Handles completion of async read tasks.
fn handleReadCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    const bytes_read = result.recv catch |err| {
        log.err("WebSocket read error (state: {s}, FD: {d}): {any}", .{
            @tagName(conn.state), conn.transport.fd, err,
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
        log.info("WebSocket connection closed by peer (FD: {d})", .{conn.transport.fd});
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

    try conn.frame_buffer.appendSlice(task.req.recv.buffer[0..bytes_read]);
    conn.allocator.free(task.req.recv.buffer);

    switch (conn.state) {
        .reading_header => {
            if (conn.frame_buffer.items.len >= 2) {
                const header = conn.frame_buffer.items[0..2];
                conn.fin = (header[0] & 0x80) != 0;
                conn.opcode = header[0] & 0x0F;
                const mask_bit = (header[1] & 0x80) != 0;
                conn.payload_len = @as(u64, header[1] & 0x7F);

                if (!mask_bit) {
                    log.err("Unmasked frame received (FD: {d})", .{conn.transport.fd});
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
                try conn.readNext();
            }
        },
        .reading_extended_length => {
            var required_len: usize = undefined;
            if (conn.payload_len == 126) {
                required_len = 4; // 2 (header) + 2 (ext len)
            } else { // payload_len == 127
                required_len = 10; // 2 (header) + 8 (ext len)
            }
            if (conn.frame_buffer.items.len >= required_len) {
                const len_bytes = conn.frame_buffer.items[2..required_len];
                if (conn.payload_len == 126) {
                    if (len_bytes.len < 2) {
                        log.err("Incomplete extended length (FD: {d}): {x}", .{ conn.transport.fd, len_bytes });
                        try conn.sendProtocolError("Incomplete extended length");
                        return;
                    }
                    const fixed_len_bytes: *const [2]u8 = len_bytes[0..2];
                    conn.payload_len = std.mem.readInt(u16, fixed_len_bytes, .big);
                } else {
                    if (len_bytes.len < 8) {
                        log.err("Incomplete extended length (FD: {d}): {x}", .{ conn.transport.fd, len_bytes });
                        try conn.sendProtocolError("Incomplete extended length");
                        return;
                    }
                    const fixed_len_bytes: *const [8]u8 = len_bytes[0..8];
                    conn.payload_len = std.mem.readInt(u64, fixed_len_bytes, .big);
                }
                if (conn.payload_len > conn.ws.options.max_payload_size) {
                    log.err("Payload length {d} exceeds max_payload_size {d} (FD: {d})", .{
                        conn.payload_len, conn.ws.options.max_payload_size, conn.transport.fd,
                    });
                    try conn.sendMessageTooBig();
                    return;
                }
                conn.state = .reading_mask_key;
                try conn.readNext();
            }
        },
        .reading_mask_key => {
            if (conn.frame_buffer.items.len >= conn.header_size) {
                const mask_slice = conn.frame_buffer.items[conn.header_size - 4 .. conn.header_size];
                if (mask_slice.len == 4) {
                    conn.mask_key = mask_slice[0..4].*;
                    conn.state = .reading_payload;
                    try conn.readNext();
                } else {
                    try conn.sendProtocolError("Incomplete mask key");
                    return;
                }
            }
        },
        .reading_payload => {
            if (conn.frame_buffer.items.len >= conn.header_size + conn.payload_len) {
                try conn.processFrame();
            } else {
                try conn.readNext();
            }
        },
        .closed => {},
    }

    task.userdata = null;
}

/// Handles completion of async write tasks.
fn handleWriteCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    _ = result.write catch |err| {
        log.err("Write error (FD: {d}): {any}", .{ conn.transport.fd, err });
        conn.state = .closed;
        if (conn.ws.is_open) {
            conn.ws.close(AsyncContext{
                .ptr = conn,
                .cb = handleCloseCompletion,
            });
        }
        return;
    };

    conn.allocator.free(task.req.write.buffer);
    task.userdata = null;
}

/// Handles completion of async close tasks.
fn handleCloseCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *WebSocketConnection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    const socket = conn.transport.fd;
    _ = result.close catch |err| {
        log.err("Close error (FD: {d}): {any}", .{ socket, err });
    };

    conn.state = .closed;

    _ = conn.server.websocket_fds.remove(socket);

    conn.deinit();

    task.userdata = null;
}
