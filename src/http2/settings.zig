const std = @import("std");
const Allocator = std.mem.Allocator;

// HTTP/2 Setting identifiers
pub const SettingId = struct {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
};

// HTTP/2 Settings
pub const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 0xFFFFFFFF,

    pub fn readPayload(_: Allocator, payload: []const u8) !Settings {
        var settings = Settings{};
        if (payload.len % 6 != 0) return error.InvalidSettingsPayload;
        var i: usize = 0;
        while (i < payload.len) : (i += 6) {
            if (i + 6 > payload.len) return error.InvalidSettingsPayload;
            const id = (@as(u16, payload[i]) << 8) | @as(u16, payload[i + 1]);
            const value = (@as(u32, payload[i + 2]) << 24) | (@as(u32, payload[i + 3]) << 16) |
                (@as(u32, payload[i + 4]) << 8) | @as(u32, payload[i + 5]);
            switch (id) {
                SettingId.HEADER_TABLE_SIZE => settings.header_table_size = value,
                SettingId.ENABLE_PUSH => {
                    if (value > 1) return error.InvalidSettingsValue;
                    settings.enable_push = value == 1;
                },
                SettingId.MAX_CONCURRENT_STREAMS => settings.max_concurrent_streams = value,
                SettingId.INITIAL_WINDOW_SIZE => {
                    if (value > 0x7FFFFFFF) return error.InvalidSettingsValue;
                    settings.initial_window_size = value;
                },
                SettingId.MAX_FRAME_SIZE => {
                    if (value < 16384 or value > 16777215) return error.InvalidSettingsValue;
                    settings.max_frame_size = value;
                },
                SettingId.MAX_HEADER_LIST_SIZE => settings.max_header_list_size = value,
                else => {}, // Ignore unknown settings
            }
        }
        return settings;
    }

    pub fn writePayload(self: Settings, allocator: Allocator) ![]u8 {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        const settings = [_]struct { id: u16, value: u32 }{
            .{ .id = SettingId.HEADER_TABLE_SIZE, .value = self.header_table_size },
            .{ .id = SettingId.ENABLE_PUSH, .value = if (self.enable_push) 1 else 0 },
            .{ .id = SettingId.MAX_CONCURRENT_STREAMS, .value = self.max_concurrent_streams },
            .{ .id = SettingId.INITIAL_WINDOW_SIZE, .value = self.initial_window_size },
            .{ .id = SettingId.MAX_FRAME_SIZE, .value = self.max_frame_size },
            .{ .id = SettingId.MAX_HEADER_LIST_SIZE, .value = self.max_header_list_size },
        };
        for (settings) |s| {
            try buf.append(@intCast((s.id >> 8) & 0xFF));
            try buf.append(@intCast(s.id & 0xFF));
            try buf.append(@intCast((s.value >> 24) & 0xFF));
            try buf.append(@intCast((s.value >> 16) & 0xFF));
            try buf.append(@intCast((s.value >> 8) & 0xFF));
            try buf.append(@intCast(s.value & 0xFF));
        }
        return try buf.toOwnedSlice();
    }
};
