const std = @import("std");

/// HeaderMap for storing multiple header values per key with case-insensitive keys.
pub const HeaderMap = struct {
    map: std.StringHashMap(std.ArrayList([]const u8)),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HeaderMap {
        return .{
            .map = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HeaderMap) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const values = entry.value_ptr.*;
            for (values.items) |value| {
                self.allocator.free(value);
            }
            values.deinit();
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit();
    }

    pub fn put(self: *HeaderMap, name: []const u8, value: []const u8) !void {
        const lowercased = try std.ascii.allocLowerString(self.allocator, name);
        errdefer self.allocator.free(lowercased);

        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        var entry = try self.map.getOrPut(lowercased);
        if (entry.found_existing) {
            self.allocator.free(lowercased);
            try entry.value_ptr.append(value_copy);
        } else {
            var list = std.ArrayList([]const u8).init(self.allocator);
            try list.append(value_copy);
            entry.value_ptr.* = list;
        }
    }

    pub fn append(self: *HeaderMap, name: []const u8, value: []const u8) !void {
        const lowercased = try std.ascii.allocLowerString(self.allocator, name);
        errdefer self.allocator.free(lowercased);

        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        var entry = try self.map.getOrPut(lowercased);
        if (entry.found_existing) {
            self.allocator.free(lowercased);
        }

        if (!entry.found_existing) {
            entry.value_ptr.* = std.ArrayList([]const u8).init(self.allocator);
        }

        try entry.value_ptr.append(value_copy);
    }

    pub fn get(self: *const HeaderMap, name: []const u8) ?[]const u8 {
        const lowercased = std.ascii.allocLowerString(self.allocator, name) catch return null;
        defer self.allocator.free(lowercased);

        if (self.map.get(lowercased)) |values| {
            if (values.items.len > 0) {
                return values.items[0];
            }
        }
        return null;
    }

    pub fn getAll(self: *const HeaderMap, name: []const u8) ?[]const []const u8 {
        const lowercased = std.ascii.allocLowerString(self.allocator, name) catch return null;
        defer self.allocator.free(lowercased);

        if (self.map.get(lowercased)) |values| {
            return values.items;
        }
        return null;
    }

    pub fn contains(self: *const HeaderMap, name: []const u8) bool {
        const lowercased = std.ascii.allocLowerString(self.allocator, name) catch return false;
        defer self.allocator.free(lowercased);
        return self.map.contains(lowercased);
    }
};
