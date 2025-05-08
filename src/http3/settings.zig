// src/http3/settings.zig

const std = @import("std");
const Allocator = std.mem.Allocator;

/// HTTP/3 SETTINGS Parameters
/// Defined in RFC 9114 Section 7.2.4
pub const Settings = struct {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x1)
    /// The maximum capacity of the QPACK dynamic table.
    qpack_max_table_capacity: u64 = 0,
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x6)
    /// The maximum size of the field section (sum of name and value lengths) in a set of headers.
    max_field_section_size: u64 = 0,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x7)
    /// The maximum number of streams that can be blocked by the QPACK encoder stream.
    qpack_blocked_streams: u64 = 0,

    // Other settings defined in RFC 9114:
    // SETTINGS_ENABLE_PUSH (0x3) - Implicitly enabled by default in servers. Value is 0 or 1.
    // SETTINGS_EXCLUDE_VERSIONS (0x8) - list of versions to exclude
    // SETTINGS_GREASE_TABLE (0x0A) - used for greasing (interoperability testing)

    // Note: Default values for HTTP/3 settings are typically 0, but client/server
    // implementations negotiate actual values via the SETTINGS frame.

    /// Helper to get a setting value by its identifier.
    pub fn get(self: *const Settings, id: u64) ?u64 {
        // Unimplemented: Placeholder for looking up settings by ID.
        _ = self;
        _ = id;
        return null;
    }

    /// Parses the payload of a SETTINGS frame into a Settings struct.
    /// Assumes the payload is a sequence of (identifier, value) pairs encoded as variable-length integers.
    pub fn parse(allocator: Allocator, payload: []const u8) !Settings {
        _ = allocator; // Unused for now
        _ = payload; // Unused for now
        @compileError("Unimplemented: HTTP/3 SETTINGS parsing");
    }

    /// Serializes a Settings struct into a buffer for the SETTINGS frame payload.
    pub fn serialize(allocator: Allocator, settings: Settings) ![]u8 {
        _ = allocator; // Unused for now
        _ = settings; // Unused for now
        @compileError("Unimplemented: HTTP/3 SETTINGS serialization");
    }
};