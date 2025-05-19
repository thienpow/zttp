// src/http3/settings.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const varint = @import("varint.zig"); // Assumes a module for variable-length integer encoding/decoding

/// HTTP/3 SETTINGS Parameters
/// Defined in RFC 9114 Section 7.2.4
pub const Settings = struct {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x1)
    qpack_max_table_capacity: u64 = 0,
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x6)
    max_field_section_size: u64 = 0,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x7)
    qpack_blocked_streams: u64 = 0,

    /// Helper to get a setting value by its identifier.
    pub fn get(self: *const Settings, id: u64) ?u64 {
        return switch (id) {
            0x1 => self.qpack_max_table_capacity,
            0x6 => self.max_field_section_size,
            0x7 => self.qpack_blocked_streams,
            else => null,
        };
    }

    /// Parses the payload of a SETTINGS frame into a Settings struct.
    /// Assumes the payload is a sequence of (identifier, value) pairs encoded as variable-length integers.
    pub fn parse(allocator: Allocator, payload: []const u8) !Settings {
        var settings = Settings{};
        var offset: usize = 0;

        while (offset < payload.len) {
            // Decode identifier
            const id_result = try varint.decode(payload[offset..]);
            offset += id_result.bytes_read;
            const id = id_result.value;

            // Decode value
            const value_result = try varint.decode(payload[offset..]);
            offset += value_result.bytes_read;
            const value = value_result.value;

            // Assign to appropriate field
            switch (id) {
                0x1 => settings.qpack_max_table_capacity = value,
                0x6 => settings.max_field_section_size = value,
                0x7 => settings.qpack_blocked_streams = value,
                // Ignore unknown settings for forward compatibility
                else => continue,
            }
        }

        _ = allocator; // Allocator may be used for dynamic settings in the future
        return settings;
    }

    /// Serializes a Settings struct into a buffer for the SETTINGS frame payload.
    pub fn serialize(allocator: Allocator, settings: Settings) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();

        // Serialize non-zero settings
        if (settings.qpack_max_table_capacity > 0) {
            try varint.encode(0x1, &buffer);
            try varint.encode(settings.qpack_max_table_capacity, &buffer);
        }
        if (settings.max_field_section_size > 0) {
            try varint.encode(0x6, &buffer);
            try varint.encode(settings.max_field_section_size, &buffer);
        }
        if (settings.qpack_blocked_streams > 0) {
            try varint.encode(0x7, &buffer);
            try varint.encode(settings.qpack_blocked_streams, &buffer);
        }

        return buffer.toOwnedSlice();
    }
};
