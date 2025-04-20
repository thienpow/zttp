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

    // If it's an HTMX request, skip layout rendering and render only the template content
    if (is_htmx) {
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
        return try output.toOwnedSlice();
    }

    // Existing layout rendering logic for non-HTMX requests
    if (layout_rel_path) |layout_path_from_tag| {
        const layout_tokens_ptr = try cache.getTokens(layout_path_from_tag);
        const layout_tokens_list = layout_tokens_ptr orelse return TemplateError.LayoutNotFound;

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
                    }
                    capture_block_depth += 1;
                },
                .endblock_stmt => {
                    if (capture_block_depth == 0) return TemplateError.MissingEndblock;
                    capture_block_depth -= 1;
                    if (capture_block_depth == 0 and capture_block_name != null) {
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

        try renderer.renderTokens(
            allocator,
            layout_tokens_list.*.items,
            0,
            layout_tokens_list.*.items.len,
            ctx,
            &output,
            &block_content_map,
        );
    } else {
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

    return try output.toOwnedSlice();
}
