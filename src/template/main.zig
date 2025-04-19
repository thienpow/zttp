// src/template.main.zig
const std = @import("std");
const cache = @import("cache.zig");
const parser = @import("parser.zig");
const renderer = @import("renderer.zig");
const types = @import("types.zig");
pub const Context = @import("../context.zig").Context;
pub const TemplateError = types.TemplateError;

const template_base_dir = "src/routes";

pub const initTemplateCache = cache.initTemplateCache;
pub const deinitTemplateCache = cache.deinitTemplateCache;

pub fn renderTemplate(
    allocator: std.mem.Allocator,
    template_content: []const u8,
    ctx: *Context,
) ![]const u8 {
    // Check if the request is from HTMX
    const is_htmx = if (ctx.get("is_htmx")) |value|
        std.mem.eql(u8, value, "true")
    else
        false;

    var content_tokens = try parser.tokenize(allocator, template_content);
    defer content_tokens.deinit();

    var layout_rel_path: ?[]const u8 = null;
    var first_real_token_index: ?usize = null;

    for (content_tokens.items, 0..) |tok, idx| {
        switch (tok) {
            .text => |t| {
                if (std.mem.indexOfNone(u8, t, " \t\n\r") != null) {
                    first_real_token_index = idx;
                    break;
                }
            },
            .extends => |path| {
                if (idx == 0 or first_real_token_index == null) {
                    layout_rel_path = path;
                    first_real_token_index = idx;
                    break;
                } else {
                    return TemplateError.ExtendsMustBeFirst;
                }
            },
            else => {
                first_real_token_index = idx;
                break;
            },
        }
    }

    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();

    // If it's an HTMX request, skip layout rendering and render only the template content
    if (is_htmx) {
        //std.debug.print("HTMX request detected, rendering template without layout...\n", .{});
        //std.debug.print("Template content: '{s}'\n", .{template_content});

        // Filter out extends and handle blocks appropriately
        var render_start_idx: usize = 0;
        const render_end_idx: usize = content_tokens.items.len;

        // Reset the existing first_real_token_index instead of declaring a new one
        first_real_token_index = null;

        for (content_tokens.items, 0..) |tok, idx| {
            switch (tok) {
                .text => |t| {
                    if (std.mem.indexOfNone(u8, t, " \t\n\r") != null) {
                        first_real_token_index = idx;
                        break;
                    }
                },
                .extends => {
                    // Skip extends for HTMX
                    first_real_token_index = idx;
                    render_start_idx = idx + 1; // Start rendering after extends
                    break;
                },
                else => {
                    first_real_token_index = idx;
                    break;
                },
            }
        }

        // Use the existing output variable instead of declaring a new one
        // output is already defined in the outer scope and initialized

        try renderer.renderTokens(
            allocator,
            content_tokens.items,
            render_start_idx,
            render_end_idx,
            ctx,
            &output,
            null,
        );
        return output.toOwnedSlice();
    }

    // Existing layout rendering logic for non-HTMX requests
    if (layout_rel_path) |layout_path_from_tag| {
        //std.debug.print("Template extends layout: '{s}'\n", .{layout_path_from_tag});

        var path_join_buf: [std.fs.max_path_bytes]u8 = undefined;
        var path_fba = std.heap.FixedBufferAllocator.init(&path_join_buf);

        const resolved_layout_path = std.fs.path.join(path_fba.allocator(), &.{
            template_base_dir,
            layout_path_from_tag,
        }) catch {
            return TemplateError.PathResolutionError;
        };

        var layout_content: []const u8 = undefined;

        // Check cache for layout
        const maybe_cached = try cache.accessCache(.get, resolved_layout_path, null);

        if (maybe_cached) |cached_content| {
            layout_content = cached_content;
            std.debug.print("Retrieved layout '{s}' from cache\n", .{resolved_layout_path});
        } else {
            std.debug.print("Layout '{s}' not found in cache, loading from file...\n", .{resolved_layout_path});
            var loaded_content: []u8 = undefined;
            loaded_content = std.fs.cwd().readFileAlloc(allocator, resolved_layout_path, std.math.maxInt(usize)) catch |e| {
                std.debug.print("Error loading layout file '{s}': {any}\n", .{ resolved_layout_path, e });
                if (e == error.FileNotFound or e == error.NotDir or e == error.IsDir) return TemplateError.LayoutNotFound;
                return e;
            };
            defer allocator.free(loaded_content);

            // Cache the loaded content
            const cache_alloc = cache.getCacheAllocator() orelse return TemplateError.OutOfMemory;

            const persistent_key = try cache_alloc.dupe(u8, resolved_layout_path);
            errdefer cache_alloc.free(persistent_key);

            const persistent_value = try cache_alloc.dupe(u8, loaded_content);

            // Store in cache
            _ = try cache.accessCache(.put, persistent_key, persistent_value);
            layout_content = persistent_value;
            std.debug.print("Cached layout '{s}' using cache allocator {any}\n", .{ persistent_key, cache_alloc });
        }

        var block_content_map = std.StringHashMap([]const u8).init(allocator);
        defer {
            var it = block_content_map.valueIterator();
            while (it.next()) |value_ptr| allocator.free(value_ptr.*);
            block_content_map.deinit();
        }

        var capture_block_name: ?[]const u8 = null;
        var capture_block_start_idx: usize = 0;
        var capture_block_depth: u32 = 0;

        for (content_tokens.items, 0..) |token, idx| {
            if (first_real_token_index != null and idx == first_real_token_index.?) {
                if (content_tokens.items[idx] == .extends) {
                    continue;
                }
            }

            switch (token) {
                .block_start => |name| {
                    if (capture_block_depth == 0) {
                        capture_block_name = name;
                        capture_block_start_idx = idx + 1;
                        std.debug.print("Capturing block: {s}\n", .{name});
                    }
                    capture_block_depth += 1;
                },
                .endblock_stmt => {
                    if (capture_block_depth == 0) return TemplateError.MissingEndblock;
                    capture_block_depth -= 1;
                    if (capture_block_depth == 0 and capture_block_name != null) {
                        std.debug.print("Finished capturing block: {s}\n", .{capture_block_name.?});
                        var block_output = std.ArrayList(u8).init(allocator);
                        try renderer.renderTokens(
                            allocator,
                            content_tokens.items,
                            capture_block_start_idx,
                            idx,
                            ctx,
                            &block_output,
                            null,
                        );

                        try block_content_map.put(capture_block_name.?, try block_output.toOwnedSlice());
                        capture_block_name = null;
                    }
                },
                .extends => {
                    if (idx != first_real_token_index.?) {
                        return TemplateError.NestedExtendsNotSupported;
                    }
                },
                else => if (capture_block_name == null and capture_block_depth == 0) {
                    if (token == .text) {
                        if (std.mem.indexOfNone(u8, token.text, " \t\n\r") != null) {
                            std.debug.print("Warning: Content found outside of block in child template: '{s}'\n", .{token.text});
                        }
                    } else {
                        std.debug.print("Warning: Non-text/non-block tag found outside of block in child template: {any}\n", .{token});
                    }
                },
            }
        }

        if (capture_block_depth != 0) return TemplateError.MissingEndblock;

        var layout_tokens = try parser.tokenize(allocator, layout_content);
        defer layout_tokens.deinit();

        for (layout_tokens.items) |lt| {
            if (lt == .extends) return TemplateError.NestedExtendsNotSupported;
        }

        std.debug.print("Rendering layout '{s}' with injected blocks...\n", .{resolved_layout_path});
        try renderer.renderTokens(
            allocator,
            layout_tokens.items,
            0,
            layout_tokens.items.len,
            ctx,
            &output,
            &block_content_map,
        );
    } else {
        std.debug.print("Rendering standalone template...\n", .{});
        try renderer.renderTokens(
            allocator,
            content_tokens.items,
            0,
            content_tokens.items.len,
            ctx,
            &output,
            null,
        );
    }

    return output.toOwnedSlice();
}
