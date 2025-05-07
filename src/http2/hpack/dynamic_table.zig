// src/http2/hpack/dynamic_table.zig - HPACK dynamic table implementation
const std = @import("std");
const Allocator = std.mem.Allocator;

// Import header definition
const Header = @import("mod.zig").Header;

// Define the header entry struct for the dynamic table
const HeaderEntry = struct {
    name: []const u8,
    value: []const u8,
};

// HPACK dynamic table implementation
pub const DynamicTable = struct {
    entries: std.ArrayList(HeaderEntry),
    size: usize, // Current size in bytes
    max_size: usize, // Maximum size in bytes
    allocator: Allocator,

    pub fn init(allocator: Allocator, max_size: usize) DynamicTable {
        return .{
            .entries = std.ArrayList(HeaderEntry).init(allocator),
            .size = 0,
            .max_size = max_size,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DynamicTable) void {
        // Free all stored header names and values
        for (self.entries.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.entries.deinit();
    }

    // Calculate size of an entry (name + value + 32 bytes overhead as per spec)
    fn entrySize(name: []const u8, value: []const u8) usize {
        return name.len + value.len + 32;
    }

    // Add a new header to the dynamic table
    pub fn add(self: *DynamicTable, name: []const u8, value: []const u8) !void {
        const entry_size = entrySize(name, value);

        // Evict entries if necessary to maintain size constraints
        self.evictEntries(entry_size);

        // Check if the entry fits in the table
        if (entry_size <= self.max_size) {
            // Make copies of the name and value
            const name_copy = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(name_copy);

            const value_copy = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(value_copy);

            // Insert at the beginning (for LIFO behavior)
            try self.entries.insert(0, .{
                .name = name_copy,
                .value = value_copy,
            });

            self.size += entry_size;
        }
    }

    // Evict entries to make room for a new entry
    fn evictEntries(self: *DynamicTable, needed_size: usize) void {
        // Remove entries from the end until we have enough space
        while (self.size + needed_size > self.max_size and self.entries.items.len > 0) {
            const last_idx = self.entries.items.len - 1;
            const last = self.entries.items[last_idx];
            const last_size = entrySize(last.name, last.value);

            // Remove the entry
            _ = self.entries.pop();

            // Free the memory
            self.allocator.free(last.name);
            self.allocator.free(last.value);

            // Update the size
            self.size -= last_size;
        }
    }

    // Update the maximum size of the dynamic table
    pub fn updateMaxSize(self: *DynamicTable, new_max_size: usize) void {
        self.max_size = new_max_size;
        // Evict entries if necessary to comply with new size
        self.evictEntries(0);
    }

    // Get a header at the specified index
    pub fn getHeader(self: DynamicTable, index: usize, allocator: Allocator) !Header {
        if (index == 0 or index > self.entries.items.len) {
            return error.InvalidHeaderIndex;
        }

        const entry = self.entries.items[index - 1];
        return .{
            .name = try allocator.dupe(u8, entry.name),
            .value = try allocator.dupe(u8, entry.value),
        };
    }

    // Get a header name at the specified index
    pub fn getHeaderName(self: DynamicTable, index: usize, allocator: Allocator) ![]const u8 {
        if (index == 0 or index > self.entries.items.len) {
            return error.InvalidHeaderIndex;
        }

        return try allocator.dupe(u8, self.entries.items[index - 1].name);
    }

    // Find a full header (name + value) in the dynamic table
    pub fn findHeaderIndex(self: DynamicTable, name: []const u8, value: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                return i + 1; // 1-based indexing
            }
        }
        return null;
    }

    // Find a header name in the dynamic table
    pub fn findNameIndex(self: DynamicTable, name: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                return i + 1; // 1-based indexing
            }
        }
        return null;
    }
};
