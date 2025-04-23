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
        self.data.deinit();
        // No individual free calls; rely on arena.deinit() if using ArenaAllocator
    }

    pub fn set(self: *Context, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy); // Safe for non-arena allocators
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        // Remove old entry without freeing (arena will handle cleanup)
        _ = self.data.remove(key);
        try self.data.put(key_copy, value_copy);
    }

    pub fn setOwned(self: *Context, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        // Remove old entry without freeing
        _ = self.data.remove(key);
        try self.data.put(key_copy, value);
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

    pub fn remove(self: *Context, key: []const u8) bool {
        return self.data.remove(key); // No free; arena handles cleanup
    }
};
