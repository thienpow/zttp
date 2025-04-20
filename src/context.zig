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
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        // Use 'try' to handle potential errors from fetchPut
        const maybe_old_entry = try self.data.fetchPut(key_copy, value_copy);

        // Now check the optional result
        if (maybe_old_entry) |old_entry| {
            // Free the PREVIOUS key and value that were replaced
            self.allocator.free(old_entry.key);
            self.allocator.free(old_entry.value);
        }
    }

    pub fn setOwned(self: *Context, key: []const u8, value: []const u8) !void {
        // 'value' is already owned by the caller, 'key' needs duplication.
        const key_copy = try self.allocator.dupe(u8, key);
        // If key duplication or put fails, free the key_copy.
        // The caller still owns 'value' if put fails.
        errdefer self.allocator.free(key_copy);

        // Use 'try' to handle potential errors from fetchPut
        const maybe_old_entry = try self.data.fetchPut(key_copy, value);

        // Now check the optional result
        if (maybe_old_entry) |old_entry| {
            // Free the PREVIOUS key and value
            self.allocator.free(old_entry.key);
            self.allocator.free(old_entry.value);
            // 'value' passed in is now owned by the map upon successful put.
        }
        // If fetchPut fails (e.g. OOM), key_copy is freed by errdefer.
        // The original 'value' is NOT freed here, ownership remains with caller on error.
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
        // fetchRemove returns ?KV (no error), so this is correct.
        if (self.data.fetchRemove(key)) |removed_entry| {
            self.allocator.free(removed_entry.key);
            self.allocator.free(removed_entry.value);
            return true;
        }
        return false;
    }
};
