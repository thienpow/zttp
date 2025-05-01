// src/websocket/websocket.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const WebSocketTransport = @import("transport.zig").WebSocketTransport;
const AsyncContext = @import("../async/async.zig").Context;

const log = std.log.scoped(.websocket);

/// High-level WebSocket protocol implementation.
/// Manages frame construction, ping/pong, and protocol state.
/// Depends on WebSocketTransport for I/O.
pub const WebSocket = struct {
    allocator: Allocator,
    transport: *WebSocketTransport,
    is_open: bool,
    options: Options,

    pub const Options = struct {
        /// Maximum payload size for incoming frames (in bytes).
        max_payload_size: u64 = 1024 * 1024, // 1MB
        /// Buffer size for reading data from the socket (in bytes).
        read_buffer_size: usize = 4096,
        /// Whether to support fragmented frames (not supported by default).
        support_fragmented_frames: bool = false,
        /// Initial capacity for the frame buffer (in bytes).
        frame_buffer_initial_capacity: usize = 4096,
        /// Initial capacity for the payload buffer (in bytes).
        payload_buffer_initial_capacity: usize = 4096,
        /// Custom close code for application-specific closures (null for protocol defaults).
        custom_close_code: ?u16 = null,
    };

    /// Initializes a WebSocket with a transport layer.
    pub fn init(transport: *WebSocketTransport, allocator: Allocator, options: Options) !*WebSocket {
        const ws = try allocator.create(WebSocket);
        errdefer allocator.destroy(ws);
        ws.* = .{
            .allocator = allocator,
            .transport = transport,
            .is_open = true,
            .options = options,
        };
        return ws;
    }

    /// Deinitializes the WebSocket, freeing resources.
    pub fn deinit(self: *WebSocket) void {
        self.allocator.destroy(self);
    }

    /// Sends a WebSocket frame asynchronously.
    pub fn sendFrameAsync(self: *WebSocket, opcode: u8, payload: []const u8, ctx: AsyncContext) !void {
        if (!self.is_open) {
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

        const frame_data = try self.allocator.dupe(u8, frame.items);
        errdefer self.allocator.free(frame_data);

        try self.transport.writeAsync(frame_data, ctx);
    }

    /// Sends a text message asynchronously.
    pub fn sendMessageAsync(self: *WebSocket, message: []const u8, ctx: AsyncContext) !void {
        try self.sendFrameAsync(0x1, message, ctx);
    }

    /// Sends a ping frame asynchronously.
    pub fn sendPingAsync(self: *WebSocket, payload: []const u8, ctx: AsyncContext) !void {
        if (payload.len > 125) {
            log.err("Ping payload exceeds max control frame size (125 bytes) ({d} > 125)", .{payload.len});
            return error.InvalidPayloadSize;
        }
        try self.sendFrameAsync(0x9, payload, ctx);
    }

    /// Sends a pong frame asynchronously.
    pub fn sendPongAsync(self: *WebSocket, payload: []const u8, ctx: AsyncContext) !void {
        if (payload.len > 125) {
            log.err("Pong payload exceeds max control frame size (125 bytes) ({d} > 125)", .{payload.len});
            return error.InvalidPayloadSize;
        }
        try self.sendFrameAsync(0xA, payload, ctx);
    }

    /// Closes the WebSocket connection.
    pub fn close(self: *WebSocket, ctx: AsyncContext) void {
        if (!self.is_open) {
            return;
        }
        self.is_open = false;
        self.transport.close(ctx);
    }
};
