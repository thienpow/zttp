// src/template/cache.zig
const std = @import("std");
const types = @import("types.zig");
const parser = @import("parser.zig"); // Need this for tokenize

// Use RwLock instead of Mutex for better concurrency
var template_cache: ?std.StringHashMap(CachedTemplateData) = null;
var cache_rwlock: std.Thread.RwLock = .{};
var cache_allocator: ?std.mem.Allocator = null; // Allocator for the HashMap and the Arenas

// Reinstate ArenaAllocator in the cached data structure
pub const CachedTemplateData = struct {
    arena: std.heap.ArenaAllocator, // Owns memory for this entry's tokens
    tokens: std.ArrayList(types.Token), // Allocated using the arena
};

pub fn initTemplateCache(allocator: std.mem.Allocator, capacity: u32) !void {
    cache_rwlock.lock();
    defer cache_rwlock.unlock();

    // Deinit previous cache if it exists
    if (template_cache) |*cache| {
        var it = cache.valueIterator();
        while (it.next()) |cached_data| {
            // Deinit the arena associated with each old entry
            cached_data.arena.deinit();
        }
        cache.deinit();
        // Don't nullify here, overwritten below
    }

    cache_allocator = allocator;
    template_cache = std.StringHashMap(CachedTemplateData).init(allocator);
    try template_cache.?.ensureTotalCapacity(capacity);
    errdefer template_cache = null; // Ensure consistent state on error
}

pub fn deinitTemplateCache() void {
    cache_rwlock.lock();
    defer cache_rwlock.unlock();

    if (template_cache) |*cache| {
        var it = cache.valueIterator();
        while (it.next()) |cached_data| {
            // Deinit the arena associated with each entry
            cached_data.arena.deinit();
        }
        cache.deinit(); // Deinit the hashmap itself
        template_cache = null;
        cache_allocator = null;
    }
}

// getCache might be used for introspection, protect with read lock
pub fn getCache() ?*std.StringHashMap(CachedTemplateData) {
    cache_rwlock.lockShared();
    defer cache_rwlock.unlockShared();
    return if (template_cache) |*cache| cache else null;
}

// getCacheAllocator usually doesn't need locking
pub fn getCacheAllocator() ?std.mem.Allocator {
    return cache_allocator;
}

pub fn putTokenizedTemplate(key: []const u8, raw_content: []const u8) !void {
    cache_rwlock.lock(); // Need exclusive access to modify
    defer cache_rwlock.unlock();

    const cache: *std.StringHashMap(CachedTemplateData) = &(template_cache orelse return error.CacheNotInitialized);
    const allocator = cache_allocator orelse return error.CacheNotInitialized; // Allocator for map keys and arenas

    // Use fetchRemove to handle existing entries correctly
    if (cache.fetchRemove(key)) |removed_entry| {
        std.log.warn("Replacing cached template: {s}", .{removed_entry.key});
        // Deinit the OLD arena from the REMOVED entry
        removed_entry.value.arena.deinit();
        // Free the key owned by the map
        allocator.free(removed_entry.key);
    }

    // --- Create NEW Arena for this template's tokens ---
    var entry_arena = std.heap.ArenaAllocator.init(allocator);
    // If init fails, error propagates.

    // --- Tokenize using the NEW Arena's allocator ---
    // If tokenize fails, ensure the newly created arena is cleaned up
    const tokens = try parser.tokenize(entry_arena.allocator(), raw_content);
    errdefer entry_arena.deinit(); // Cleanup arena if subsequent steps fail

    // --- Create the data structure to cache ---
    const cached_data = CachedTemplateData{
        .arena = entry_arena, // Moves ownership of the arena
        .tokens = tokens, // Moves ownership of the token list
    };

    // --- Duplicate the key for the cache to own ---
    const key_copy = try allocator.dupe(u8, key);
    // If key duplication fails, arena is cleaned up by errdefer above. Add key cleanup.
    errdefer allocator.free(key_copy);

    // --- Put the NEW entry in the cache ---
    // Use 'try' to propagate potential OOM from put
    try cache.put(key_copy, cached_data);
    // If put fails, key_copy and entry_arena are cleaned up by their errdefers.

    std.log.debug("Cached {s}", .{key_copy});
}

pub fn getTokens(key: []const u8) !?*const std.ArrayList(types.Token) {
    cache_rwlock.lockShared(); // Acquire READ lock
    defer cache_rwlock.unlockShared(); // Release read lock when done

    const cache = template_cache orelse return error.CacheNotInitialized;

    const trimmed = std.mem.trim(u8, key, "/");

    // --- Lookup Logic ---
    // Function to perform the actual lookup inside the lock
    const findEntry = struct { // Use an anonymous struct to scope the function
        fn lookup(c: *const std.StringHashMap(CachedTemplateData), k: []const u8) ?*const std.ArrayList(types.Token) {
            if (c.getPtr(k)) |entry_ptr| {
                return &entry_ptr.tokens;
            }
            return null;
        }
    }.lookup;

    // Handle root path ("/" -> "index")
    if (trimmed.len == 0) {
        if (findEntry(&cache, "index")) |tokens_ptr| return tokens_ptr;
        std.log.debug("Cache miss for root path ('index')", .{});
        return null;
    }

    // 1. Try the trimmed path directly
    if (findEntry(&cache, trimmed)) |tokens_ptr| return tokens_ptr;
    std.log.debug("Cache miss for trimmed path: {s}", .{trimmed});

    // 2. If not found, try appending "/index"
    if (!std.mem.endsWith(u8, trimmed, "/index")) {
        // Use stack allocation for the lookup key
        var name_buf_array: [1024]u8 = undefined; // Stack buffer
        var fba = std.heap.FixedBufferAllocator.init(&name_buf_array);
        var name_buf = std.ArrayList(u8).init(fba.allocator());
        defer name_buf.deinit(); // Clean up ArrayList (no memory is actually freed, since it's stack-allocated)

        try name_buf.appendSlice(trimmed);
        try name_buf.appendSlice("/index");
        const index_key_lookup = name_buf.items;

        if (findEntry(&cache, index_key_lookup)) |tokens_ptr| return tokens_ptr;
    } else {
        std.log.debug("Skipping append /index because path already ends with it: {s}", .{trimmed});
    }

    // 3. If neither worked, return null
    return null;
}
