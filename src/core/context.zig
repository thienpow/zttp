// src/core/context.zig
const std = @import("std");
const http = @import("../http/mod.zig");
const Request = http.Request;
const Response = http.Response;

pub const Context = struct {
    allocator: std.mem.Allocator,
    data: std.StringHashMap([]const u8),
    app_context_ptr: ?*anyopaque,
    req: Request,
    res: Response,

    pub fn init(allocator: std.mem.Allocator, app_context_ptr: ?*anyopaque, req: Request, res: Response) Context {
        return .{
            .allocator = allocator,
            .data = std.StringHashMap([]const u8).init(allocator),
            .app_context_ptr = app_context_ptr,
            .req = req,
            .res = res,
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

        if (self.data.fetchRemove(key)) |old_entry| {
            self.allocator.free(old_entry.key);
            self.allocator.free(old_entry.value);
        }
        try self.data.put(key_copy, value_copy);
    }

    pub fn setOwned(self: *Context, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        if (self.data.fetchRemove(key)) |old_entry| {
            self.allocator.free(old_entry.key);
            self.allocator.free(old_entry.value);
        }
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
        if (self.data.fetchRemove(key)) |removed_entry| {
            self.allocator.free(removed_entry.key);
            self.allocator.free(removed_entry.value);
            return true;
        }
        return false;
    }

    pub fn getApp(self: *Context, comptime T: type) ?*T {
        // Safety: This cast is inherently unsafe; the caller must ensure
        // the pointer is actually of type T. If the pointer is null,
        // or the type T is incorrect, behavior is undefined.
        // We return an optional pointer to indicate if app_context_ptr was null.
        if (self.app_context_ptr) |ptr| {
            return @ptrCast(@alignCast(ptr));
        }
        return null;
    }
};
