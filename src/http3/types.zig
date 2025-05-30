// src/http3/types.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const settings = @import("settings.zig");
pub const Settings = settings.Settings;
pub const Http3Error = @import("error.zig").Http3Error;

/// HTTP/3 Frame Types (RFC 9114 Section 7.2)
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    priority = 0x02, // PRIORITY frame (RFC 9218)
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05, // PUSH_PROMISE frame
    ping = 0x06, // PING frame
    goaway = 0x07,
    window_update = 0x08, // WINDOW_UPDATE frame
    continuation = 0x09, // CONTINUATION frame
    max_push_id = 0x0D,
    duplicate_push = 0x0E,
    webtransport_stream = 0x41,

    // WebTransport frames (draft-ietf-webtrans-http3)
    webtransport_bi = 0x54, // WebTransport bidirectional stream
    webtransport_uni = 0x58, // WebTransport unidirectional stream

    reserved,

    pub fn fromInt(value: u64) FrameType {
        return switch (value) {
            0x00 => .data,
            0x01 => .headers,
            0x02 => .priority,
            0x03 => .cancel_push,
            0x04 => .settings,
            0x05 => .push_promise,
            0x06 => .ping,
            0x07 => .goaway,
            0x08 => .window_update,
            0x09 => .continuation,
            0x0D => .max_push_id,
            0x0E => .duplicate_push,
            0x41 => .webtransport_stream,
            0x54 => .webtransport_bi,
            0x58 => .webtransport_uni,
            else => .reserved,
        };
    }
};

/// Represents a single HTTP/3 frame (RFC 9114 Section 7.2)
pub const Frame = union(FrameType) {
    data: struct {
        payload: []const u8,
        fin: bool = false, // End of stream flag
        padding_length: ?u8 = null, // Optional padding length
        padding: []const u8 = &[_]u8{}, // Padding bytes
    },
    headers: struct {
        encoded_block: []const u8,
        priority: ?Priority = null,
        padding_length: ?u8 = null, // Optional padding length
        padding: []const u8 = &[_]u8{}, // Padding bytes
    },
    priority: Priority,
    cancel_push: struct { push_id: u64 },
    settings: Settings,
    push_promise: struct {
        push_id: u64,
        encoded_headers: []const u8,
        padding_length: ?u8 = null, // Optional padding length
        padding: []const u8 = &[_]u8{}, // Padding bytes
    },
    ping: struct {
        opaque_data: [8]u8, // 8 bytes of opaque data
    },
    goaway: struct {
        stream_id: u64,
        error_code: u64 = 0,
    },
    window_update: struct {
        window_size_increment: u64,
    },
    continuation: struct {
        encoded_block: []const u8,
        end_headers: bool = false,
    },
    max_push_id: struct { push_id: u64 },
    duplicate_push: struct { push_id: u64 },
    webtransport_stream: struct {},
    webtransport_bi: struct {
        session_id: u64,
    },
    webtransport_uni: struct {
        session_id: u64,
    },
    reserved: struct {
        frame_type: u64,
        payload: []const u8,
    },

    /// Deinitializes the frame, freeing any owned payload memory
    pub fn deinit(self: Frame, allocator: Allocator) void {
        switch (self) {
            .data => |f| {
                allocator.free(f.payload);
                if (f.padding.len > 0) allocator.free(f.padding);
            },
            .headers => |f| {
                allocator.free(f.encoded_block);
                if (f.padding.len > 0) allocator.free(f.padding);
            },
            .push_promise => |f| {
                allocator.free(f.encoded_headers);
                if (f.padding.len > 0) allocator.free(f.padding);
            },
            .continuation => |f| allocator.free(f.encoded_block),
            .reserved => |f| allocator.free(f.payload),
            else => {},
        }
    }

    /// Returns the frame type as a u64 value
    pub fn getType(self: Frame) u64 {
        return switch (self) {
            .data => 0x00,
            .headers => 0x01,
            .priority => 0x02,
            .cancel_push => 0x03,
            .settings => 0x04,
            .push_promise => 0x05,
            .ping => 0x06,
            .goaway => 0x07,
            .window_update => 0x08,
            .continuation => 0x09,
            .max_push_id => 0x0D,
            .duplicate_push => 0x0E,
            .webtransport_stream => 0x41,
            .webtransport_bi => 0x54,
            .webtransport_uni => 0x58,
            .reserved => |f| f.frame_type,
        };
    }

    /// Calculates the total frame size including padding
    pub fn getTotalSize(self: Frame) u64 {
        const base_size = switch (self) {
            .data => |f| f.payload.len,
            .headers => |f| f.encoded_block.len,
            .priority => 1, // Single byte
            .cancel_push, .max_push_id, .duplicate_push => 8, // Variable length integer
            .settings => |s| s.getEncodedSize(),
            .push_promise => |f| 8 + f.encoded_headers.len, // 8 bytes for push_id
            .ping => 8, // Fixed 8 bytes
            .goaway => |f| if (f.error_code == 0) 8 else 16,
            .window_update => 8,
            .continuation => |f| f.encoded_block.len,
            .webtransport_stream => 0,
            .webtransport_bi => 8, // session_id
            .webtransport_uni => 8, // session_id
            .reserved => |f| f.payload.len,
        };

        const padding_size = switch (self) {
            .data => |f| if (f.padding_length) |len| @as(u64, len) + 1 else 0, // +1 for padding length field
            .headers => |f| if (f.padding_length) |len| @as(u64, len) + 1 else 0,
            .push_promise => |f| if (f.padding_length) |len| @as(u64, len) + 1 else 0,
            else => 0,
        };

        return base_size + padding_size;
    }

    /// Checks if the frame has padding
    pub fn hasPadding(self: Frame) bool {
        return switch (self) {
            .data => |f| f.padding_length != null,
            .headers => |f| f.padding_length != null,
            .push_promise => |f| f.padding_length != null,
            else => false,
        };
    }
};

/// HTTP/3 Priority information (RFC 9218)
pub const Priority = struct {
    urgency: u3 = 3, // 0-7, where 0 is highest priority
    incremental: bool = false,
};

/// HTTP/3 Stream Types (RFC 9114 Section 6)
pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    encoder = 0x02, // QPACK encoder stream
    decoder = 0x03, // QPACK decoder stream
    request = 0x04, // HTTP request/response stream
    webtransport = 0x54, // WebTransport stream

    pub fn fromInt(value: u64) StreamType {
        return switch (value) {
            0x00 => .control,
            0x01 => .push,
            0x02 => .encoder,
            0x03 => .decoder,
            0x04 => .request,
            0x54 => .webtransport,
            else => .control, // Default fallback
        };
    }
};

/// HTTP/3 Connection State
pub const ConnectionState = enum {
    idle,
    connecting,
    connected,
    goaway_sent,
    goaway_received,
    closing,
    closed,
};

/// HTTP/3 Stream State
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset_local,
    reset_remote,
};
