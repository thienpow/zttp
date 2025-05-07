// src/http2/hpack/mod.zig - HPACK header compression module entry point
const std = @import("std");
const Allocator = std.mem.Allocator;

// Import submodules
const static_table_module = @import("static_table.zig");
const dynamic_table_module = @import("dynamic_table.zig");
const encoding = @import("encoding.zig");

// Export the HPACK components
pub const StaticTable = static_table_module.StaticTable;
pub const DynamicTable = dynamic_table_module.DynamicTable;
pub const readInteger = encoding.readInteger;
pub const writeInteger = encoding.writeInteger;
pub const readString = encoding.readString;
pub const writeString = encoding.writeString;

// Named struct for headers to avoid anonymous struct type mismatches
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

// Main HPACK implementation
pub const HPACK = struct {
    dynamic_table: DynamicTable,
    static_table: StaticTable,

    pub fn init(allocator: Allocator, max_table_size: usize) HPACK {
        return .{
            .dynamic_table = DynamicTable.init(allocator, max_table_size),
            .static_table = StaticTable.init(),
        };
    }

    pub fn deinit(self: *HPACK) void {
        self.dynamic_table.deinit();
    }

    pub fn encode(self: *HPACK, headers: std.ArrayList(Header), writer: anytype) !void {
        for (headers.items) |header| {
            // Simplified: Encode as literal header with indexing
            var name_index: ?usize = null;
            var value_index: ?usize = null;

            // Check static table
            value_index = self.static_table.findHeaderIndex(header.name, header.value);
            if (value_index == null) {
                name_index = self.static_table.findNameIndex(header.name);
            }

            if (value_index) |idx| {
                // Indexed header field
                try writeInteger(writer, idx, 7, 0x80);
            } else {
                // Literal header field
                if (name_index) |n_idx| {
                    // Literal with indexed name
                    try writeInteger(writer, n_idx, 6, 0x40);
                    try writeString(writer, header.value);
                } else {
                    // Literal with new name
                    try writeInteger(writer, 0, 6, 0x40);
                    try writeString(writer, header.name);
                    try writeString(writer, header.value);
                }
                // Add to dynamic table if space allows
                try self.dynamic_table.add(header.name, header.value);
            }
        }
    }

    pub fn decode(self: *HPACK, reader: anytype, allocator: Allocator) !std.ArrayList(Header) {
        var headers = std.ArrayList(Header).init(allocator);
        errdefer {
            for (headers.items) |h| {
                allocator.free(h.name);
                allocator.free(h.value);
            }
            headers.deinit();
        }

        while (true) {
            const first_byte = reader.readByte() catch |err| {
                if (err == error.EndOfStream) break;
                return err;
            };
            if (first_byte & 0x80 == 0x80) {
                // Indexed Header Field
                const index = try readInteger(reader, first_byte, 7);
                const header = try self.getHeader(index, allocator);
                try headers.append(.{ .name = header.name, .value = header.value });
            } else if (first_byte & 0x40 == 0x40) {
                // Literal Header Field with Incremental Indexing
                const name_index = try readInteger(reader, first_byte, 6);
                var name: []const u8 = undefined;
                if (name_index == 0) {
                    name = try readString(reader, allocator);
                } else {
                    name = try self.getHeaderName(name_index, allocator);
                }
                const value = try readString(reader, allocator);
                try headers.append(.{ .name = name, .value = value });
                try self.dynamic_table.add(name, value);
            } else {
                // Other cases (e.g., without indexing, dynamic table size update)
                return error.UnsupportedHPACKOperation;
            }
        }
        return headers;
    }

    fn getHeader(self: *HPACK, index: usize, allocator: Allocator) !Header {
        if (index == 0) return error.InvalidHeaderIndex;

        // Check static table first
        if (index <= self.static_table.entries.len) {
            const entry = self.static_table.entries[index - 1];
            return .{
                .name = try allocator.dupe(u8, entry.name),
                .value = try allocator.dupe(u8, entry.value),
            };
        }

        // Then check dynamic table
        const dynamic_index = index - self.static_table.entries.len;
        return self.dynamic_table.getHeader(dynamic_index, allocator);
    }

    fn getHeaderName(self: *HPACK, index: usize, allocator: Allocator) ![]const u8 {
        if (index == 0) return error.InvalidHeaderIndex;

        // Check static table first
        if (index <= self.static_table.entries.len) {
            return try allocator.dupe(u8, self.static_table.entries[index - 1].name);
        }

        // Then check dynamic table
        const dynamic_index = index - self.static_table.entries.len;
        return self.dynamic_table.getHeaderName(dynamic_index, allocator);
    }
};
