// src/http2/hpack/static_table.zig - HPACK static table implementation
const std = @import("std");

// HPACK static table entry
pub const StaticTableEntry = struct {
    name: []const u8,
    value: []const u8,
};

// HPACK static table implementation
pub const StaticTable = struct {
    // Static table entries as defined in RFC 7541 Appendix A
    entries: []const StaticTableEntry,

    pub fn init() StaticTable {
        return .{ .entries = &static_entries };
    }

    // Find a full header (name + value) in the static table
    pub fn findHeaderIndex(self: StaticTable, name: []const u8, value: []const u8) ?usize {
        for (self.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i + 1; // 1-based indexing as per spec
            }
        }
        return null;
    }

    // Find a header name in the static table
    pub fn findNameIndex(self: StaticTable, name: []const u8) ?usize {
        for (self.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return i + 1; // 1-based indexing as per spec
            }
        }
        return null;
    }
};

// Static table entries as defined in RFC 7541 Appendix A
// The complete table has 61 entries, showing the first few here
const static_entries = [_]StaticTableEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    // ... remaining entries would be added here
};
