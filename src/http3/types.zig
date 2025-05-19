// src/http3/types.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

const settings = @import("settings.zig");
pub const Settings = settings.Settings;

/// HTTP/3 Error Types
pub const Http3Error = error{
    FrameError,
    NeedMoreData,
    InvalidVli,
};

/// HTTP/3 Frame Types (RFC 9114 Section 7.2)
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    goaway = 0x07,
    max_push_id = 0x0D,
    duplicate_push = 0x0E,
    webtransport_stream = 0x41,
    reserved,
};

/// Represents a single HTTP/3 frame (RFC 9114 Section 7.2)
pub const Frame = union(FrameType) {
    data: struct { payload: []const u8 },
    headers: struct { encoded_block: []const u8 },
    cancel_push: struct { push_id: u64 },
    settings: Settings,
    goaway: struct { stream_id: u64 },
    max_push_id: struct { push_id: u64 },
    duplicate_push: struct { push_id: u64 },
    webtransport_stream: struct {},
    reserved: struct { payload: []const u8 },

    /// Deinitializes the frame, freeing any owned payload memory
    pub fn deinit(self: Frame, allocator: Allocator) void {
        switch (self) {
            .data => |f| allocator.free(f.payload),
            .headers => |f| allocator.free(f.encoded_block),
            ._ => |f| allocator.free(f.payload),
            else => {},
        }
    }
};

/// HTTP/3 Stream Types (RFC 9114 Section 6)
pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    encoder = 0x02,
    decoder = 0x03,
    request = 0x04,
};
