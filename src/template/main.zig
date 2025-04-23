// src/template/main.zig
const std = @import("std");
pub const cache = @import("cache.zig");
const parser = @import("parser.zig");
const renderer = @import("renderer.zig");
const types = @import("types.zig");
pub const Context = @import("../context.zig").Context;
pub const TemplateError = types.TemplateError;

pub fn renderTemplate(
    allocator: std.mem.Allocator,
    path: []const u8,
    ctx: *Context,
) !?[]const u8 {
    const tokens_ptr = cache.getTokens(path) catch |err| {
        std.log.err("Failed to lookup template tokens {s}: {}", .{ path, err });
        return null;
    };

    const cached_tokens = tokens_ptr orelse return null;

    // Check if the request is from HTMX
    const is_htmx = if (ctx.get("is_htmx")) |value|
        std.mem.eql(u8, value, "true")
    else
        false;

    //std.log.debug("Rendering template: {s}, is_htmx: {}", .{ path, is_htmx });

    const content_tokens = cached_tokens.*;

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
            .extends => |p| {
                if (idx == 0 or first_real_token_index == null) {
                    layout_rel_path = p;
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

    // If it's an HTMX request, skip layout rendering and render only the content block
    if (is_htmx) {
        // Find the content block to render, skipping #extends and other tokens
        var render_start_idx: ?usize = null;
        var render_end_idx: ?usize = null;
        var block_depth: u32 = 0;
        var found_content_block = false;

        for (content_tokens.items, 0..) |tok, idx| {
            if (first_real_token_index != null and idx < first_real_token_index.?) {
                continue;
            }
            switch (tok) {
                .extends => continue, // Skip #extends
                .block_start => |name| {
                    if (std.mem.eql(u8, name, "content") and block_depth == 0) {
                        render_start_idx = idx + 1;
                        found_content_block = true;
                    }
                    block_depth += 1;
                },
                .endblock_stmt => {
                    if (block_depth == 0) {
                        std.log.err("Invalid template: #endblock without matching #block in {s}", .{path});
                        return TemplateError.MissingEndblock;
                    }
                    block_depth -= 1;
                    if (found_content_block and block_depth == 0) {
                        render_end_idx = idx;
                        break;
                    }
                },
                else => if (block_depth == 0 and found_content_block == false) {
                    //std.log.debug("Skipping token before content block: {any}", .{tok});
                },
            }
        }

        if (!found_content_block or render_start_idx == null or render_end_idx == null) {
            std.log.err("No content block found in template {s} for HTMX", .{path});
            return TemplateError.NoContentBlock;
        }

        //std.log.debug("HTMX render: start_idx={d}, end_idx={d}", .{ render_start_idx.?, render_end_idx.? });

        try renderer.renderTokens(
            allocator,
            content_tokens.items,
            render_start_idx.?,
            render_end_idx.?,
            ctx,
            &output,
            null,
            0, // Top-level render for HTMX
        );
        return try output.toOwnedSlice();
    }

    // Non-HTMX request: Handle layout rendering or direct template rendering
    if (layout_rel_path) |layout_path_from_tag| {
        const layout_tokens_ptr = try cache.getTokens(layout_path_from_tag);
        const layout_tokens_list = layout_tokens_ptr orelse return TemplateError.LayoutNotFound;

        //std.log.debug("Loading layout: {s}", .{layout_path_from_tag});

        var block_content_map = std.StringHashMap([]const u8).init(allocator);
        defer {
            var it = block_content_map.valueIterator();
            while (it.next()) |value_ptr| allocator.free(value_ptr.*);
            block_content_map.deinit();
        }

        var capture_block_name: ?[]const u8 = null;
        var capture_block_start_idx: usize = 0;
        var capture_block_depth: u32 = 0;

        // Capture block content, skipping #extends explicitly
        for (content_tokens.items, 0..) |token, idx| {
            if (first_real_token_index != null and idx < first_real_token_index.?) {
                continue;
            }
            switch (token) {
                .extends => continue,
                .block_start => |name| {
                    if (capture_block_depth == 0) {
                        capture_block_name = name;
                        capture_block_start_idx = idx + 1;
                    }
                    capture_block_depth += 1;
                },
                .endblock_stmt => {
                    if (capture_block_depth == 0) return TemplateError.MissingEndblock;
                    capture_block_depth -= 1;
                    if (capture_block_depth == 0 and capture_block_name != null) {
                        //std.log.debug("Capturing block: {s}, start_idx={d}, end_idx={d}", .{ capture_block_name.?, capture_block_start_idx, idx });

                        var block_output = std.ArrayList(u8).init(allocator);
                        try renderer.renderTokens(
                            allocator,
                            content_tokens.items,
                            capture_block_start_idx,
                            idx,
                            ctx,
                            &block_output,
                            null,
                            0,
                        );
                        try block_content_map.put(capture_block_name.?, try block_output.toOwnedSlice());
                        capture_block_name = null;
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

        //std.log.debug("Rendering layout with {d} blocks", .{block_content_map.count()});

        try renderer.renderTokens(
            allocator,
            layout_tokens_list.*.items,
            0,
            layout_tokens_list.*.items.len,
            ctx,
            &output,
            &block_content_map,
            0,
        );
    } else {
        //std.log.debug("Rendering template directly: {s}", .{path});

        try renderer.renderTokens(
            allocator,
            content_tokens.items,
            0,
            content_tokens.items.len,
            ctx,
            &output,
            null,
            0,
        );
    }

    return try output.toOwnedSlice();
}
