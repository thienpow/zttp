const std = @import("std");
const Allocator = std.mem.Allocator;
const WebSocketTransport = @import("transport.zig").WebSocketTransport;
const AsyncContext = @import("../async/async.zig").Context;

const log = std.log.scoped(.websocket);

/// High-level WebSocket protocol implementation.
/// Manages frame construction, ping/pong, close handshake, extensions, and protocol state.
/// Depends on WebSocketTransport for I/O.
pub const WebSocket = struct {
    allocator: Allocator,
    transport: *WebSocketTransport,
    is_open: bool,
    options: Options,
    extensions: Extensions,
    close_status: ?CloseStatus,
    fragment_state: FragmentState,

    pub const Options = struct {
        max_payload_size: u64 = 1024 * 1024, // 1MB
        read_buffer_size: usize = 4096,
        support_fragmented_frames: bool = true,
        frame_buffer_initial_capacity: usize = 4096,
        payload_buffer_initial_capacity: usize = 4096,
        custom_close_code: ?u16 = null,
        enable_permessage_deflate: bool = false,
        min_deflate_size: usize = 256, // Minimum payload size for compression
    };

    pub const Extensions = struct {
        permessage_deflate: bool = false,
        rsv1_used: bool = false, // For permessage-deflate
    };

    pub const CloseStatus = struct {
        code: u16,
        reason: ?[]u8,
    };

    pub const FragmentState = struct {
        opcode: ?u8 = null,
        buffer: std.ArrayList(u8),

        fn init(allocator: Allocator) FragmentState {
            return .{
                .buffer = std.ArrayList(u8).init(allocator),
            };
        }

        fn deinit(self: *FragmentState) void {
            self.buffer.deinit();
        }

        pub fn reset(self: *FragmentState) void {
            self.opcode = null;
            self.buffer.clearAndFree();
        }
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
            .extensions = .{
                .permessage_deflate = options.enable_permessage_deflate,
            },
            .close_status = null,
            .fragment_state = FragmentState.init(allocator),
        };
        return ws;
    }

    /// Deinitializes the WebSocket, freeing resources.
    pub fn deinit(self: *WebSocket) void {
        self.fragment_state.deinit();
        if (self.close_status) |status| {
            if (status.reason) |reason| {
                self.allocator.free(reason);
            }
        }
        self.allocator.destroy(self);
    }

    /// Applies permessage-deflate compression if enabled.
    fn compressPayload(self: *WebSocket, payload: []const u8) ![]u8 {
        if (!self.extensions.permessage_deflate or payload.len < self.options.min_deflate_size) {
            return self.allocator.dupe(u8, payload);
        }

        var compressed = std.ArrayList(u8).init(self.allocator);
        defer compressed.deinit();

        var compressor = try std.compress.zlib.compressor(compressed.writer(), .{});
        _ = try compressor.write(payload);
        try compressor.finish();

        // Remove zlib trailer (4 bytes) for permessage-deflate
        if (compressed.items.len >= 4) {
            compressed.shrinkAndFree(compressed.items.len - 4);
        }

        return compressed.toOwnedSlice();
    }

    /// Decompresses permessage-deflate payload if enabled.
    pub fn decompressPayload(self: *WebSocket, payload: []const u8) ![]u8 {
        if (!self.extensions.permessage_deflate or !self.extensions.rsv1_used) {
            return self.allocator.dupe(u8, payload);
        }

        var decompressed = std.ArrayList(u8).init(self.allocator);
        defer decompressed.deinit();

        // Append zlib trailer (0x00 0x00 0xFF 0xFF) for decompression
        var input = std.ArrayList(u8).init(self.allocator);
        defer input.deinit();
        try input.appendSlice(payload);
        try input.appendSlice(&[_]u8{ 0x00, 0x00, 0xFF, 0xFF });

        var in_stream = std.io.fixedBufferStream(input.items);
        var decompressor = std.compress.zlib.decompressor(in_stream.reader());
        try decompressor.decompress(decompressed.writer());

        return decompressed.toOwnedSlice();
    }

    /// Sends a WebSocket frame asynchronously.
    pub fn sendFrameAsync(self: *WebSocket, opcode: u8, payload: []const u8, ctx: AsyncContext, is_compressed: bool) !void {
        if (!self.is_open) {
            return error.WebSocketClosed;
        }

        const final_payload = if (is_compressed) try self.compressPayload(payload) else try self.allocator.dupe(u8, payload);
        defer self.allocator.free(final_payload);

        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();

        // FIN bit (1), RSV1 for compression, and opcode
        var first_byte: u8 = 0x80 | (opcode & 0x0F);
        if (is_compressed and self.extensions.permessage_deflate) {
            first_byte |= 0x40; // Set RSV1 for permessage-deflate
        }
        try frame.append(first_byte);

        // Payload length
        if (final_payload.len <= 125) {
            try frame.append(@intCast(final_payload.len));
        } else if (final_payload.len <= 0xFFFF) {
            try frame.append(126);
            try frame.writer().writeInt(u16, @intCast(final_payload.len), .big);
        } else {
            try frame.append(127);
            try frame.writer().writeInt(u64, final_payload.len, .big);
        }

        // Payload
        try frame.appendSlice(final_payload);

        const frame_data = try self.allocator.dupe(u8, frame.items);
        errdefer self.allocator.free(frame_data);

        try self.transport.writeAsync(frame_data, ctx);
    }

    /// Sends a text message asynchronously.
    pub fn sendMessageAsync(self: *WebSocket, message: []const u8, ctx: AsyncContext) !void {
        try self.sendFrameAsync(0x1, message, ctx, self.extensions.permessage_deflate);
    }

    /// Sends a ping frame asynchronously.
    pub fn sendPingAsync(self: *WebSocket, payload: []const u8, ctx: AsyncContext) !void {
        if (payload.len > 125) {
            log.err("Ping payload exceeds max control frame size (125 bytes) ({d} > 125)", .{payload.len});
            return error.InvalidPayloadSize;
        }
        try self.sendFrameAsync(0x9, payload, ctx, false);
    }

    /// Sends a pong frame asynchronously.
    pub fn sendPongAsync(self: *WebSocket, payload: []const u8, ctx: AsyncContext) !void {
        if (payload.len > 125) {
            log.err("Pong payload exceeds max control frame size (125 bytes) ({d} > 125)", .{payload.len});
            return error.InvalidPayloadSize;
        }
        try self.sendFrameAsync(0xA, payload, ctx, false);
    }

    /// Initiates a proper close handshake.
    pub fn close(self: *WebSocket, ctx: AsyncContext) void {
        if (!self.is_open) {
            return;
        }

        var close_payload = std.ArrayList(u8).init(self.allocator);
        defer close_payload.deinit();

        const close_code = self.options.custom_close_code orelse 1000; // Normal closure
        self.close_status = .{ .code = close_code, .reason = null };

        close_payload.writer().writeInt(u16, close_code, .big) catch |err| {
            log.err("Failed to write close code: {any}", .{err});
            self.is_open = false;
            self.transport.close(ctx);
            return;
        };

        self.sendFrameAsync(0x8, close_payload.items, ctx, false) catch |err| {
            log.err("Failed to send close frame: {any}", .{err});
            self.is_open = false;
            self.transport.close(ctx);
            return;
        };

        self.is_open = false;
    }

    /// Sends a close frame with code and reason.
    pub fn sendCloseFrame(self: *WebSocket, code: u16, reason: ?[]const u8, ctx: AsyncContext) !void {
        if (!self.is_open) {
            return error.WebSocketClosed;
        }

        var close_payload = std.ArrayList(u8).init(self.allocator);
        defer close_payload.deinit();

        try close_payload.writer().writeInt(u16, code, .big);
        if (reason) |r| {
            try close_payload.appendSlice(r);
        }

        self.close_status = .{
            .code = code,
            .reason = if (reason) |r| try self.allocator.dupe(u8, r) else null,
        };

        try self.sendFrameAsync(0x8, close_payload.items, ctx, false);
        self.is_open = false;
    }
};
