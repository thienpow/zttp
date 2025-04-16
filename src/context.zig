// src/context.zig
const std = @import("std");

pub const Context = struct {
    allocator: std.mem.Allocator,
    data: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) Context {
        return .{
            .allocator = allocator,
            .data = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Context) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.data.deinit();
    }

    pub fn set(self: *Context, key: []const u8, value: []const u8) !void {
        if (self.data.get(key)) |old| self.allocator.free(old);
        try self.data.put(
            try self.allocator.dupe(u8, key),
            try self.allocator.dupe(u8, value),
        );
    }

    pub fn get(self: *Context, key: []const u8) ?[]const u8 {
        return self.data.get(key);
    }

    pub fn existsAndTrue(self: *Context, key: []const u8) bool {
        if (self.get(key)) |value| {
            if (value.len == 0) return false;
            if (std.mem.eql(u8, value, "false")) return false;
            if (std.mem.eql(u8, value, "0")) return false;
            if (std.mem.eql(u8, value, "null")) return false;
            return true;
        }
        return false;
    }

    pub fn setOwned(self: *Context, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        try self.data.put(key_copy, value);
    }

    pub fn remove(self: *Context, key: []const u8) bool {
        if (self.data.fetchRemove(key)) |removed_entry| {
            self.allocator.free(removed_entry.key);
            self.allocator.free(removed_entry.value);
            return true;
        }
        return false;
    }
};
