const std = @import("std");

var template_cache: ?std.StringHashMap([]const u8) = null;
var cache_mutex: std.Thread.Mutex = .{};
var cache_allocator: ?std.mem.Allocator = null;

pub fn initTemplateCache(allocator: std.mem.Allocator, capacity: u32) !void {
    cache_mutex.lock();
    defer cache_mutex.unlock();

    // Clear existing cache if it exists
    if (template_cache) |*cache| {
        cache.deinit();
        template_cache = null;
        cache_allocator = null;
    }

    cache_allocator = allocator;
    template_cache = std.StringHashMap([]const u8).init(allocator);
    try template_cache.?.ensureTotalCapacity(capacity);
}

pub fn deinitTemplateCache() void {
    cache_mutex.lock();
    defer cache_mutex.unlock();

    if (template_cache) |*cache| {
        cache.deinit();
        template_cache = null;
        cache_allocator = null;
    }
}

pub fn getCache() ?*std.StringHashMap([]const u8) {
    return if (template_cache) |*cache| cache else null;
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

    const cache = getCache() orelse {
        return error.CacheNotInitialized;
    };
    const allocator = cache_allocator orelse {
        return error.CacheNotInitialized;
    };

    switch (operation) {
        .get => {

            // Remove leading and trailing slashes from the key
            const trimmed = std.mem.trim(u8, key, "/");

            // Handle root path
            if (trimmed.len == 0) {
                const index_key = "index";

                if (cache.get(index_key)) |template| {
                    return template;
                } else {
                    return null;
                }
            }

            // Try the trimmed path directly
            if (cache.get(trimmed)) |template| {
                return template;
            }

            // Append "/index" for directory-like paths
            var name_buf = std.ArrayList(u8).init(allocator);
            defer name_buf.deinit();
            try name_buf.appendSlice(trimmed);
            if (!std.mem.endsWith(u8, trimmed, "/index") and !std.mem.endsWith(u8, trimmed, "/layout")) {
                try name_buf.appendSlice("/index");
            }
            const template_name = try name_buf.toOwnedSlice();
            defer allocator.free(template_name);

            if (cache.get(template_name)) |template| {
                return template;
            } else {
                return null;
            }
        },
        .put => {
            if (value == null) {
                return error.InvalidValue;
            }
            try cache.put(key, value.?);
            return null;
        },
    }
}
