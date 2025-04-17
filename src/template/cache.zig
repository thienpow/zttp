const std = @import("std");

var layout_cache: ?std.StringHashMap([]const u8) = null;
var cache_mutex: std.Thread.Mutex = .{};
var cache_allocator: ?std.mem.Allocator = null;

pub fn initTemplateCache(allocator: std.mem.Allocator) !void {
    cache_mutex.lock();
    defer cache_mutex.unlock();

    if (layout_cache != null) return;
    cache_allocator = allocator;
    layout_cache = std.StringHashMap([]const u8).init(allocator);
    std.debug.print("Template cache initialized with allocator {any}\n", .{allocator});
}

pub fn deinitTemplateCache() void {
    cache_mutex.lock();
    defer cache_mutex.unlock();

    if (layout_cache) |*cache| {
        std.debug.print("Deinitializing template cache...\n", .{});
        cache.deinit();
        layout_cache = null;
        cache_allocator = null;
        std.debug.print("Template cache deinitialized.\n", .{});
    }
}

pub fn getCache() ?*std.StringHashMap([]const u8) {
    return if (layout_cache) |*cache| cache else null;
}

pub fn getCacheAllocator() ?std.mem.Allocator {
    return cache_allocator;
}

pub fn accessCache(
    comptime operation: enum { get, put },
    key: []const u8,
    value: ?[]const u8,
) !?[]const u8 {
    cache_mutex.lock();
    defer cache_mutex.unlock();

    const cache = getCache() orelse return error.CacheNotInitialized;

    switch (operation) {
        .get => return cache.get(key),
        .put => {
            if (value == null) return error.InvalidValue;
            try cache.put(key, value.?);
            return null;
        },
    }
}
