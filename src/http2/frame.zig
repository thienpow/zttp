// src/http2/frame.zig - HTTP/2 frame definitions and handling
const std = @import("std");

// HTTP/2 Frame Types
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

// HTTP/2 Frame Header (9 bytes)
pub const FrameHeader = struct {
    length: u24,
    type: FrameType,
    flags: u8,
    stream_id: u31,

    pub fn read(reader: anytype) !FrameHeader {
        var buf: [9]u8 = undefined;
        try reader.readNoEof(&buf);
        const length = (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | @as(u24, buf[2]);
        const frame_type: FrameType = @enumFromInt(buf[3]);
        const flags = buf[4];
        const stream_id = (@as(u31, buf[5] & 0x7F) << 24) | (@as(u31, buf[6]) << 16) | (@as(u31, buf[7]) << 8) | @as(u31, buf[8]);
        return .{
            .length = length,
            .type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        };
    }

    pub fn write(self: FrameHeader, writer: anytype) !void {
        var buf: [9]u8 = undefined;
        buf[0] = @intCast((self.length >> 16) & 0xFF);
        buf[1] = @intCast((self.length >> 8) & 0xFF);
        buf[2] = @intCast(self.length & 0xFF);
        buf[3] = @intFromEnum(self.type);
        buf[4] = self.flags;
        buf[5] = @intCast((self.stream_id >> 24) & 0x7F);
        buf[6] = @intCast((self.stream_id >> 16) & 0xFF);
        buf[7] = @intCast((self.stream_id >> 8) & 0xFF);
        buf[8] = @intCast(self.stream_id & 0xFF);
        try writer.writeAll(&buf);
    }
};

// Frame flags constants could be defined here
pub const HeadersFlags = struct {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
};

pub const DataFlags = struct {
    pub const END_STREAM: u8 = 0x1;
    pub const PADDED: u8 = 0x8;
};

pub const SettingsFlags = struct {
    pub const ACK: u8 = 0x1;
};
