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

pub fn preloadLayoutTemplates() !void {
    // Ensure cache is initialized
    if (layout_cache == null) return error.CacheNotInitialized;
    const allocator = getCacheAllocator() orelse return error.AllocatorNotAvailable;

    // Base directory to search from
    const base_dir = "src/routes";

    // Open base directory
    var dir = try std.fs.cwd().openDir(base_dir, .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    // Iterate through files and load only layout.zmx files
    while (try walker.next()) |entry| {
        if (entry.kind == .file and std.mem.eql(u8, std.fs.path.basename(entry.path), "layout.zmx")) {
            // Create the exact path key that renderTemplate will use
            const full_path_key = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_dir, entry.path });
            defer allocator.free(full_path_key);

            // Read the file content
            var file_path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const file_path = try std.fmt.bufPrint(&file_path_buf, "{s}/{s}", .{ base_dir, entry.path });

            const file_content = try std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize));
            defer allocator.free(file_content);

            // Cache the content with persistent allocations
            const persistent_key = try allocator.dupe(u8, full_path_key);
            errdefer allocator.free(persistent_key);

            const persistent_value = try allocator.dupe(u8, file_content);
            errdefer allocator.free(persistent_value);

            // Store in cache using exact format expected by renderTemplate
            _ = try accessCache(.put, persistent_key, persistent_value);
            std.debug.print("Preloaded layout template: {s}\n", .{persistent_key});
        }
    }
}

// Helper function to read file contents
fn readFileToString(dir: std.fs.Dir, path: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    const file = try dir.openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    const content = try allocator.alloc(u8, stat.size);
    const bytes_read = try file.readAll(content);

    if (bytes_read != stat.size) {
        allocator.free(content);
        return error.IncompleteRead;
    }

    return content;
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
