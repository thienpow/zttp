// zttp/src/template.zig
const std = @import("std");
pub const Context = @import("context.zig").Context;

const template_base_dir = "src/routes";

pub const TemplateError = error{
    InvalidSyntax,
    MissingEndif,
    MissingEndfor,
    MissingEndwhile,
    MissingEndblock,
    FileNotFound,
    LayoutNotFound,
    OutOfMemory,
    UnclosedTag,
    InvalidCollection,
    InvalidSetExpression,
    WhileLoopOverflow,
    ExtendsMustBeFirst,
    BlockNameMismatch,
    NestedExtendsNotSupported,
    PathResolutionError,
    ParseIntError,
};

const Condition = union(enum) {
    simple: []const u8,
    non_empty: []const u8,
    equals: struct { var_name: []const u8, value: []const u8 },
};

const SetStmtPayload = struct {
    var_name: []const u8,
    value: []const u8,
};

const Token = union(enum) {
    text: []const u8,
    variable: []const u8,
    if_start: Condition,
    elseif_stmt: Condition,
    else_stmt,
    endif_stmt,
    for_start: struct { var_name: []const u8, collection: []const u8 },
    endfor_stmt,
    while_start: []const u8,
    endwhile_stmt,
    set_stmt: SetStmtPayload,
    extends: []const u8,
    block_start: []const u8,
    endblock_stmt,
};

// Helper to find the end of a directive line, skipping trailing newline(s)
fn findEndOfDirective(content: []const u8, start_pos: usize) usize {
    var current_pos = start_pos;
    while (current_pos < content.len and content[current_pos] != '\n' and content[current_pos] != '\r') {
        current_pos += 1;
    }
    // Consume the newline character(s) if present
    if (current_pos < content.len) {
        if (content[current_pos] == '\r') {
            current_pos += 1;
            if (current_pos < content.len and content[current_pos] == '\n') {
                current_pos += 1;
            }
        } else if (content[current_pos] == '\n') {
            current_pos += 1;
        }
    }
    return current_pos;
}

// Helper to get the content of a directive line (trimmed)
fn getDirectiveContent(content: []const u8, tag_start_pos: usize, tag_len: usize) []const u8 {
    const content_start = tag_start_pos + tag_len;
    var content_end = content_start;
    while (content_end < content.len and content[content_end] != '\n' and content[content_end] != '\r') {
        content_end += 1;
    }
    return std.mem.trim(u8, content[content_start..content_end], " \t");
}

fn parseCondition(content: []const u8) TemplateError!Condition {
    const trimmed = std.mem.trim(u8, content, " \t");
    // Check for non-empty comparison first: var != ""
    if (std.mem.indexOf(u8, trimmed, " != ")) |ne_pos| {
        const var_name = std.mem.trim(u8, trimmed[0..ne_pos], " \t");
        const right = std.mem.trim(u8, trimmed[ne_pos + 4 ..], " \t");
        // Allow var != "" or var != ''
        if ((std.mem.eql(u8, right, "\"\"") or std.mem.eql(u8, right, "''")) and var_name.len > 0) {
            return .{ .non_empty = var_name };
        }
    }
    // Check for equality comparison: var == "value" or var == 'value'
    else if (std.mem.indexOf(u8, trimmed, " == ")) |eq_pos| {
        const var_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
        const right = std.mem.trim(u8, trimmed[eq_pos + 4 ..], " \t");
        if (right.len >= 2 and ((right[0] == '"' and right[right.len - 1] == '"') or (right[0] == '\'' and right[right.len - 1] == '\''))) {
            const value = right[1 .. right.len - 1];
            if (var_name.len > 0) {
                return .{ .equals = .{ .var_name = var_name, .value = value } };
            }
        }
    }

    if (trimmed.len == 0) return TemplateError.InvalidSyntax;
    // Default to simple truthiness check
    return .{ .simple = trimmed };
}

// --- Tokenizer ---
fn tokenize(allocator: std.mem.Allocator, template: []const u8) !std.ArrayList(Token) {
    var tokens = std.ArrayList(Token).init(allocator);
    errdefer tokens.deinit();

    var pos: usize = 0;
    var first_tag_found = false;

    while (pos < template.len) {
        const remaining = template[pos..];

        if (std.mem.startsWith(u8, remaining, "{{")) {
            first_tag_found = true;
            const start = pos + 2;
            const end_offset = std.mem.indexOf(u8, template[start..], "}}") orelse return TemplateError.UnclosedTag;
            const var_name = std.mem.trim(u8, template[start .. start + end_offset], " \t");
            if (var_name.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .variable = var_name });
            pos = start + end_offset + 2;
        } else if (std.mem.startsWith(u8, remaining, "#if ")) {
            first_tag_found = true;
            const condition_str = getDirectiveContent(template, pos, 4);
            const condition = try parseCondition(condition_str);
            try tokens.append(.{ .if_start = condition });
            pos = findEndOfDirective(template, pos + 4);
        } else if (std.mem.startsWith(u8, remaining, "#elseif ")) {
            first_tag_found = true;
            const condition_str = getDirectiveContent(template, pos, 8);
            const condition = try parseCondition(condition_str);
            try tokens.append(.{ .elseif_stmt = condition });
            pos = findEndOfDirective(template, pos + 8);
        } else if (std.mem.startsWith(u8, remaining, "#else")) {
            const line_content = getDirectiveContent(template, pos, 5);
            if (line_content.len > 0) return TemplateError.InvalidSyntax;
            first_tag_found = true;
            try tokens.append(.else_stmt);
            pos = findEndOfDirective(template, pos + 5);
        } else if (std.mem.startsWith(u8, remaining, "#endif")) {
            const line_content = getDirectiveContent(template, pos, 6);
            if (line_content.len > 0) return TemplateError.InvalidSyntax;
            first_tag_found = true;
            try tokens.append(.endif_stmt);
            pos = findEndOfDirective(template, pos + 6);
        } else if (std.mem.startsWith(u8, remaining, "#for ")) {
            first_tag_found = true;
            const content = getDirectiveContent(template, pos, 5);
            const in_pos = std.mem.indexOf(u8, content, " in ") orelse return TemplateError.InvalidSyntax;
            const var_name = std.mem.trim(u8, content[0..in_pos], " \t");
            const collection = std.mem.trim(u8, content[in_pos + 4 ..], " \t");
            if (var_name.len == 0 or collection.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .for_start = .{ .var_name = var_name, .collection = collection } });
            pos = findEndOfDirective(template, pos + 5);
        } else if (std.mem.startsWith(u8, remaining, "#endfor")) {
            const line_content = getDirectiveContent(template, pos, 7);
            if (line_content.len > 0) return TemplateError.InvalidSyntax;
            first_tag_found = true;
            try tokens.append(.endfor_stmt);
            pos = findEndOfDirective(template, pos + 7);
        } else if (std.mem.startsWith(u8, remaining, "#while ")) {
            first_tag_found = true;
            const condition = getDirectiveContent(template, pos, 7);
            if (condition.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .while_start = condition });
            pos = findEndOfDirective(template, pos + 7);
        } else if (std.mem.startsWith(u8, remaining, "#endwhile")) {
            const line_content = getDirectiveContent(template, pos, 9);
            if (line_content.len > 0) return TemplateError.InvalidSyntax;
            first_tag_found = true;
            try tokens.append(.endwhile_stmt);
            pos = findEndOfDirective(template, pos + 9);
        } else if (std.mem.startsWith(u8, remaining, "#set ")) {
            first_tag_found = true;
            const content = getDirectiveContent(template, pos, 5);
            const eq_pos = std.mem.indexOf(u8, content, "=") orelse return TemplateError.InvalidSetExpression;
            const var_name = std.mem.trim(u8, content[0..eq_pos], " \t");
            const value = std.mem.trim(u8, content[eq_pos + 1 ..], " \t");
            if (var_name.len == 0 or value.len == 0) return TemplateError.InvalidSetExpression;
            try tokens.append(.{ .set_stmt = .{ .var_name = var_name, .value = value } });
            pos = findEndOfDirective(template, pos + 5);
        }
        // --- Layout Tag Parsing ---
        else if (std.mem.startsWith(u8, remaining, "#extends ")) {
            if (first_tag_found) return TemplateError.ExtendsMustBeFirst;
            first_tag_found = true;

            var path = getDirectiveContent(template, pos, 9);
            if (path.len < 2 or ((path[0] != '"' or path[path.len - 1] != '"') and (path[0] != '\'' or path[path.len - 1] != '\''))) {
                std.debug.print("Invalid #extends path format: '{s}'\n", .{path});
                return TemplateError.InvalidSyntax;
            }
            path = path[1 .. path.len - 1]; // Remove quotes
            if (path.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .extends = path });
            pos = findEndOfDirective(template, pos + 9);
        } else if (std.mem.startsWith(u8, remaining, "#block ")) {
            first_tag_found = true;
            const name = getDirectiveContent(template, pos, 7);
            if (name.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .block_start = name });
            pos = findEndOfDirective(template, pos + 7);
        } else if (std.mem.startsWith(u8, remaining, "#endblock")) {
            // Allow optional name matching: #endblock [name]
            const name_maybe = getDirectiveContent(template, pos, 9);
            _ = name_maybe; // We don't enforce name matching yet, but parse it
            first_tag_found = true;
            try tokens.append(.endblock_stmt);
            pos = findEndOfDirective(template, pos + 9);
        }
        // --- End Layout Tag Parsing ---
        else {
            const delimiters = [_][]const u8{
                "{{",   "#if",      "#else",  "#endif",
                "#for", "#endfor",  "#while", "#endwhile",
                "#set", "#extends", "#block", "#endblock",
            };
            var text_end_offset: usize = remaining.len;
            for (delimiters) |delim| {
                if (std.mem.indexOf(u8, remaining, delim)) |delim_pos| {
                    if (delim_pos == 0) { // Tag starts immediately after previous token
                        text_end_offset = 0;
                        break;
                    }
                    if (delim_pos < text_end_offset) {
                        text_end_offset = delim_pos;
                    }
                }
            }

            if (text_end_offset > 0) {
                const text_slice = remaining[0..text_end_offset];
                // Check if the slice is entirely whitespace *before* the first tag
                const leading_whitespace_count = std.mem.indexOfNone(u8, text_slice, " \t\n\r") orelse text_slice.len;
                if (!first_tag_found and leading_whitespace_count == text_slice.len) {
                    // Skip leading whitespace before any tag is encountered
                } else {
                    try tokens.append(.{ .text = text_slice });
                    first_tag_found = true; // Mark tag found once we append non-leading whitespace/text
                }
                pos += text_end_offset;
            } else if (pos < template.len) {
                // Tag starts immediately, loop will handle it in the next iteration
            } else {
                break; // End of template
            }
        }
    }

    return tokens;
}

// --- Renderer Core Logic ---
// Renders a slice of tokens into the output buffer.
fn renderTokens(
    allocator: std.mem.Allocator,
    tokens: []const Token,
    start_index: usize,
    end_index: usize, // Exclusive index
    ctx: *Context,
    output: *std.ArrayList(u8),
    block_content_map: ?*std.StringHashMap([]const u8), // Map of pre-rendered blocks (for layout)
) !void {
    var skip_until: ?usize = null; // Skip rendering tokens until this index (exclusive)
    var depth_if: u32 = 0;
    var depth_for: u32 = 0;
    var depth_while: u32 = 0;
    var depth_block: u32 = 0;
    // Tracks if the 'true' condition within an if/elseif/else chain has been rendered for the current depth
    var rendered_if_true_at_depth = std.ArrayList(bool).init(allocator);
    defer rendered_if_true_at_depth.deinit();

    var i = start_index;
    while (i < end_index) {
        const current_token = tokens[i];

        // --- Skip Logic ---
        // Handles skipping over sections like 'false' branches of 'if' or entire loops
        if (skip_until) |until| {
            if (i >= until) { // Reached the end of the skipped section
                skip_until = null;
            } else { // Still inside a skipped section, just track nesting levels
                switch (current_token) {
                    .if_start => depth_if += 1,
                    .endif_stmt => {
                        if (depth_if > 0) {
                            depth_if -= 1;
                        } else return TemplateError.InvalidSyntax; // Unmatched endif
                    },
                    .for_start => depth_for += 1,
                    .endfor_stmt => {
                        if (depth_for > 0) {
                            depth_for -= 1;
                        } else return TemplateError.InvalidSyntax; // Unmatched endfor
                    },
                    .while_start => depth_while += 1,
                    .endwhile_stmt => {
                        if (depth_while > 0) {
                            depth_while -= 1;
                        } else return TemplateError.InvalidSyntax; // Unmatched endwhile
                    },
                    .block_start => depth_block += 1,
                    .endblock_stmt => {
                        if (depth_block > 0) {
                            depth_block -= 1;
                        } else return TemplateError.InvalidSyntax; // Unmatched endblock
                    },
                    .extends => return TemplateError.InvalidSyntax, // Extends should not be nested
                    else => {},
                }
                i += 1;
                continue; // Move to the next token without rendering
            }
        }

        // --- Render Logic ---
        switch (current_token) {
            .text => |text| if (text.len > 0) try output.appendSlice(text),
            .variable => |var_name| {
                var value: []const u8 = "";
                if (std.mem.indexOf(u8, var_name, "//")) |sep_pos| {
                    const name = std.mem.trim(u8, var_name[0..sep_pos], " \t");
                    const default = std.mem.trim(u8, var_name[sep_pos + 2 ..], " \t");
                    const default_clean = if (default.len >= 2 and default[0] == '"' and default[default.len - 1] == '"')
                        default[1 .. default.len - 1]
                    else
                        default;
                    value = if (ctx.get(name)) |v| v else default_clean;
                } else {
                    value = ctx.get(var_name) orelse "";
                }
                try output.appendSlice(value);
            },

            // --- If/Elseif/Else/Endif ---
            .if_start => |condition| {
                // Ensure the tracking array is large enough for the current depth
                while (rendered_if_true_at_depth.items.len <= depth_if) {
                    try rendered_if_true_at_depth.append(false); // Default to false
                }
                rendered_if_true_at_depth.items[depth_if] = false; // Reset for this new if block
                const current_depth = depth_if;
                depth_if += 1; // Increment depth *after* recording current depth

                const should_render = try evaluateCondition(ctx, condition);
                if (should_render) {
                    // Mark that a true branch was found at this depth
                    rendered_if_true_at_depth.items[current_depth] = true;
                    // Continue rendering the block content
                } else {
                    // Skip until the next #elseif, #else, or #endif at the same nesting level
                    var j = i + 1;
                    var nested: u32 = 0; // Track nested ifs *within* this block
                    while (j < end_index) : (j += 1) {
                        switch (tokens[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) { // Found the matching endif
                                    skip_until = j + 1; // Skip the endif itself too
                                    break;
                                }
                                if (nested > 0) {
                                    nested -= 1;
                                } else return TemplateError.InvalidSyntax; // Should not happen
                            },
                            .elseif_stmt, .else_stmt => {
                                if (nested == 0) { // Found a clause at the same level
                                    skip_until = j; // Skip *up to* this clause
                                    break;
                                }
                            },
                            else => {},
                        }
                    }
                    // If loop finished without finding endif/elseif/else, it's an error
                    if (skip_until == null and j == end_index) return TemplateError.MissingEndif;
                }
            },
            .elseif_stmt => |condition| {
                if (depth_if == 0) return TemplateError.InvalidSyntax; // #elseif without #if
                const current_depth = depth_if - 1; // Clause belongs to the parent depth

                // Ensure access is valid (should always be if depth_if > 0)
                if (current_depth >= rendered_if_true_at_depth.items.len) return TemplateError.InvalidSyntax;

                if (rendered_if_true_at_depth.items[current_depth]) { // A previous branch was true, skip this one
                    var j = i + 1;
                    var nested: u32 = 0;
                    while (j < end_index) : (j += 1) {
                        switch (tokens[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) {
                                    skip_until = j + 1; // Skip to after endif
                                    break;
                                }
                                if (nested > 0) {
                                    nested -= 1;
                                } else return TemplateError.InvalidSyntax;
                            },
                            // Skip nested else/elseif too
                            else => {},
                        }
                    }
                    if (skip_until == null and j == end_index) return TemplateError.MissingEndif;
                } else { // No previous branch was true, evaluate this condition
                    const should_render = try evaluateCondition(ctx, condition);
                    if (should_render) {
                        rendered_if_true_at_depth.items[current_depth] = true; // Mark true
                        // Continue rendering this block
                    } else { // This condition is false, skip to the next clause or endif
                        var j = i + 1;
                        var nested: u32 = 0;
                        while (j < end_index) : (j += 1) {
                            switch (tokens[j]) {
                                .if_start => nested += 1,
                                .endif_stmt => {
                                    if (nested == 0) {
                                        skip_until = j + 1;
                                        break;
                                    }
                                    if (nested > 0) {
                                        nested -= 1;
                                    } else return TemplateError.InvalidSyntax;
                                },
                                .elseif_stmt, .else_stmt => {
                                    if (nested == 0) {
                                        skip_until = j;
                                        break;
                                    }
                                },
                                else => {},
                            }
                        }
                        if (skip_until == null and j == end_index) return TemplateError.MissingEndif;
                    }
                }
            },
            .else_stmt => {
                if (depth_if == 0) return TemplateError.InvalidSyntax; // #else without #if
                const current_depth = depth_if - 1;
                // Ensure access is valid
                if (current_depth >= rendered_if_true_at_depth.items.len) return TemplateError.InvalidSyntax;

                if (rendered_if_true_at_depth.items[current_depth]) { // Previous branch was true, skip else
                    var j = i + 1;
                    var nested: u32 = 0;
                    while (j < end_index) : (j += 1) {
                        switch (tokens[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) {
                                    skip_until = j + 1; // Skip to after endif
                                    break;
                                }
                                if (nested > 0) {
                                    nested -= 1;
                                } else return TemplateError.InvalidSyntax;
                            },
                            else => {},
                        }
                    }
                    if (skip_until == null and j == end_index) return TemplateError.MissingEndif;
                } else { // No previous branch was true, render this else block
                    rendered_if_true_at_depth.items[current_depth] = true; // Mark true (for safety, though not strictly needed for else)
                    // Continue rendering the else block content
                }
            },
            .endif_stmt => {
                if (depth_if == 0) return TemplateError.InvalidSyntax; // #endif without #if
                depth_if -= 1;
                // No output, just adjusts depth. Cleanup of rendered_if_true_at_depth happens naturally on next #if at this depth.
            },

            // --- For Loop ---
            .for_start => |loop| {
                depth_for += 1;
                var loop_end_idx: ?usize = null;
                var nested: u32 = 0;
                var j = i + 1;
                while (j < end_index) : (j += 1) {
                    switch (tokens[j]) {
                        .for_start => nested += 1,
                        .endfor_stmt => {
                            if (nested == 0) {
                                loop_end_idx = j;
                                break;
                            }
                            if (nested > 0) {
                                nested -= 1;
                            } else return TemplateError.InvalidSyntax;
                        },
                        else => {},
                    }
                }
                if (loop_end_idx == null) return TemplateError.MissingEndfor;
                const end_idx = loop_end_idx.?;

                const collection_val = ctx.get(loop.collection) orelse "";
                std.debug.print("For loop collection '{s}': '{s}'\n", .{ loop.collection, collection_val });

                var items_allocator = std.heap.ArenaAllocator.init(allocator);
                defer items_allocator.deinit();
                const item_alloc = items_allocator.allocator();
                var loop_items = std.ArrayList([]const u8).init(item_alloc);
                defer loop_items.deinit();

                if (collection_val.len > 1 and collection_val[0] == '[' and collection_val[collection_val.len - 1] == ']') {
                    const json_parse_result = std.json.parseFromSlice(std.json.Value, item_alloc, collection_val, .{});
                    if (json_parse_result) |parsed| {
                        if (parsed.value == .array) {
                            const json_array = parsed.value.array;
                            std.debug.print("JSON array length: {d}\n", .{json_array.items.len});
                            try loop_items.ensureTotalCapacity(json_array.items.len);
                            for (json_array.items, 0..) |item, idx| {
                                if (item == .string) {
                                    const duped = try item_alloc.dupe(u8, item.string);
                                    try loop_items.append(duped);
                                    std.debug.print("Parsed item {d}: '{s}'\n", .{ idx, duped });
                                } else {
                                    const buffer = try item_alloc.alloc(u8, 128);
                                    var buf_stream = std.io.fixedBufferStream(buffer);
                                    try std.json.stringify(item, .{}, buf_stream.writer());
                                    const written = buf_stream.getWritten();
                                    try loop_items.append(try item_alloc.dupe(u8, written));
                                    std.debug.print("Parsed item {d} (non-string): '{s}'\n", .{ idx, written });
                                }
                            }
                        } else {
                            std.debug.print("Warning: Context value '{s}' is valid JSON but not an array.\n", .{loop.collection});
                        }
                    } else |e| {
                        std.debug.print("Warning: Failed to parse '{s}' as JSON array ({any}), falling back to comma separation.\n", .{ loop.collection, e });
                        var it = std.mem.splitScalar(u8, collection_val, ',');
                        while (it.next()) |item_part| {
                            const trimmed_item = std.mem.trim(u8, item_part, " \t");
                            if (trimmed_item.len > 0) {
                                try loop_items.append(try item_alloc.dupe(u8, trimmed_item));
                                std.debug.print("Fallback item: '{s}'\n", .{trimmed_item});
                            }
                        }
                    }
                } else {
                    var it = std.mem.splitScalar(u8, collection_val, ',');
                    while (it.next()) |item_part| {
                        const trimmed_item = std.mem.trim(u8, item_part, " \t");
                        if (trimmed_item.len > 0) {
                            try loop_items.append(try item_alloc.dupe(u8, trimmed_item));
                            std.debug.print("Comma-separated item: '{s}'\n", .{trimmed_item});
                        }
                    }
                }

                std.debug.print("Total loop items: {d}\n", .{loop_items.items.len});
                for (loop_items.items, 0..) |item, idx| {
                    std.debug.print("loop_items[{d}]: '{s}'\n", .{ idx, item });
                }

                if (loop_items.items.len == 0) {
                    i = end_idx;
                } else {
                    const original_value = ctx.get(loop.var_name);
                    var original_value_copy: ?[]const u8 = null;
                    if (original_value) |ov| {
                        original_value_copy = try allocator.dupe(u8, ov);
                        defer if (original_value_copy) |ovc| allocator.free(ovc);
                    }

                    const loop_body_start = i + 1;
                    const loop_body_end = end_idx;

                    for (loop_items.items, 0..) |item_value, idx| {
                        std.debug.print("Setting item {d}: '{s}'\n", .{ idx, item_value });
                        const item_copy = try allocator.dupe(u8, item_value);
                        try ctx.setOwned(loop.var_name, item_copy);
                        std.debug.print("After setOwned[{d}]: ctx.get('{s}')='{?s}'\n", .{ idx, loop.var_name, ctx.get(loop.var_name) });
                        try renderTokens(allocator, tokens, loop_body_start, loop_body_end, ctx, output, block_content_map);
                    }

                    if (original_value_copy) |ovc| {
                        try ctx.setOwned(loop.var_name, try allocator.dupe(u8, ovc));
                    } else {
                        _ = ctx.remove(loop.var_name);
                    }
                    i = end_idx;
                }
                depth_for -= 1;
            },
            .endfor_stmt => {
                if (depth_for == 0) return TemplateError.InvalidSyntax; // Unmatched #endfor
                // Handled by the .for_start logic finding its end index
            },

            // --- While Loop ---
            .while_start => |condition_str| {
                depth_while += 1;
                // Find the matching #endwhile
                var loop_end_idx: ?usize = null;
                var nested: u32 = 0;
                var j = i + 1;
                while (j < end_index) : (j += 1) {
                    switch (tokens[j]) {
                        .while_start => nested += 1,
                        .endwhile_stmt => {
                            if (nested == 0) {
                                loop_end_idx = j;
                                break;
                            }
                            if (nested > 0) {
                                nested -= 1;
                            } else return TemplateError.InvalidSyntax;
                        },
                        else => {},
                    }
                }
                if (loop_end_idx == null) return TemplateError.MissingEndwhile;
                const end_idx = loop_end_idx.?;

                var iteration_count: usize = 0;
                const max_iterations: usize = 1000; // Prevent infinite loops
                const loop_body_start = i + 1;
                const loop_body_end = end_idx;

                while (iteration_count < max_iterations) {
                    // Evaluate the condition *before* each iteration
                    const continue_loop = try evaluateWhileCondition(ctx, condition_str);
                    if (!continue_loop) break; // Exit loop if condition is false

                    iteration_count += 1;
                    // Render the loop body
                    try renderTokens(allocator, tokens, loop_body_start, loop_body_end, ctx, output, block_content_map);

                    // Important: The loop body might modify context variables affecting the condition.
                }

                if (iteration_count >= max_iterations) return TemplateError.WhileLoopOverflow;

                i = end_idx; // Move past the #endwhile
                depth_while -= 1; // Decrement depth *after* loop processing
            },
            .endwhile_stmt => {
                if (depth_while == 0) return TemplateError.InvalidSyntax; // Unmatched #endwhile
                // Handled by the .while_start logic finding its end index
            },

            // --- Set Statement ---
            .set_stmt => |set| {
                // HandleSetStmt modifies the context directly
                try handleSetStmt(allocator, ctx, set);
            },

            // --- Block Handling ---
            .block_start => |name| {
                depth_block += 1;
                // Find the matching #endblock
                var block_end_idx: ?usize = null;
                var nested: u32 = 0; // Track nested blocks
                var j = i + 1;
                while (j < end_index) : (j += 1) {
                    switch (tokens[j]) {
                        .block_start => nested += 1,
                        .endblock_stmt => {
                            if (nested == 0) {
                                block_end_idx = j;
                                break;
                            }
                            if (nested > 0) {
                                nested -= 1;
                            } else return TemplateError.InvalidSyntax;
                        },
                        else => {},
                    }
                }
                if (block_end_idx == null) return TemplateError.MissingEndblock;
                const end_idx = block_end_idx.?;

                if (block_content_map) |bcm| {
                    // --- Rendering the LAYOUT template ---
                    // Check if this block was defined in the child (content) template
                    if (bcm.get(name)) |content_from_child| {
                        // Inject the pre-rendered content from the child
                        try output.appendSlice(content_from_child);
                        i = end_idx; // Skip the layout's default block content
                    } else {
                        // Block not defined in child, render the layout's default content
                        // Render tokens *between* #block and #endblock
                        try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, bcm); // Pass map down for nested blocks
                        i = end_idx; // Move past the #endblock
                    }
                } else {
                    // --- Rendering a CONTENT template OR a standalone template ---
                    // In this phase, we just render the block content directly.
                    // If this is part of processing a content template that extends a layout,
                    // this rendered output will be captured by the `renderTemplate` function's
                    // block capturing logic.
                    // If this is a standalone template, the output goes directly to the final result.
                    try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, null); // Pass null map down
                    i = end_idx; // Move past the #endblock
                }
                depth_block -= 1; // Decrement depth *after* processing block
            },
            .endblock_stmt => {
                if (depth_block == 0) return TemplateError.InvalidSyntax; // Unmatched #endblock
                // Handled by the .block_start logic finding its end index
            },

            .extends => return TemplateError.InvalidSyntax, // Should only be handled at the top level by renderTemplate
        }
        i += 1; // Move to the next token
    }

    // After processing all tokens in the range, check for unbalanced structures
    // These checks only apply if we started rendering from index 0 (i.e., not a recursive call for a sub-section)
    // Note: These checks might also fire if an error caused premature exit from the loop.
    if (start_index == 0 and skip_until == null) {
        if (depth_if != 0) return TemplateError.MissingEndif;
        if (depth_for != 0) return TemplateError.MissingEndfor;
        if (depth_while != 0) return TemplateError.MissingEndwhile;
        // depth_block should be 0 here unless #extends logic is involved,
        // but top-level block mismatches are caught during block capture/injection.
        // if (depth_block != 0) return TemplateError.MissingEndblock;
    }
}

// Evaluates simple conditions used in #if/#elseif
fn evaluateCondition(ctx: *Context, condition: Condition) !bool {
    return switch (condition) {
        .simple => |key| ctx.existsAndTrue(key),
        .non_empty => |var_name| {
            const val = ctx.get(var_name);
            return val != null and val.?.len > 0;
        },
        .equals => |eq| {
            const val = ctx.get(eq.var_name);
            return val != null and std.mem.eql(u8, val.?, eq.value);
        },
    };
}

// Evaluates potentially more complex conditions allowed in #while
fn evaluateWhileCondition(ctx: *Context, condition_str: []const u8) !bool {
    const trimmed_condition = std.mem.trim(u8, condition_str, " \t");

    // Check for simple equality: var == "value" or var == 'value' or var == othervar
    if (std.mem.indexOf(u8, trimmed_condition, " == ")) |eq_pos| {
        const var_n = std.mem.trim(u8, trimmed_condition[0..eq_pos], " \t");
        var val_expected = std.mem.trim(u8, trimmed_condition[eq_pos + 4 ..], " \t");
        var expected_is_literal = false;

        // Handle quoted string literal
        if (val_expected.len >= 2 and ((val_expected[0] == '"' and val_expected[val_expected.len - 1] == '"') or (val_expected[0] == '\'' and val_expected[val_expected.len - 1] == '\''))) {
            val_expected = val_expected[1 .. val_expected.len - 1];
            expected_is_literal = true;
        }

        const val_actual = ctx.get(var_n);
        if (val_actual == null) return false; // Var must exist for equality

        if (expected_is_literal) {
            return std.mem.eql(u8, val_actual.?, val_expected);
        } else { // Compare with another variable's value
            const val_expected_from_ctx = ctx.get(val_expected);
            if (val_expected_from_ctx == null) return false; // Other var must also exist
            return std.mem.eql(u8, val_actual.?, val_expected_from_ctx.?);
        }
    }
    // Check for non-equality: var != "value" or var != 'value' or var != othervar
    else if (std.mem.indexOf(u8, trimmed_condition, " != ")) |ne_pos| {
        const var_n = std.mem.trim(u8, trimmed_condition[0..ne_pos], " \t");
        var val_expected = std.mem.trim(u8, trimmed_condition[ne_pos + 4 ..], " \t");
        var expected_is_literal = false;

        // Handle quoted string literal ("" or '')
        if (val_expected.len >= 2 and ((val_expected[0] == '"' and val_expected[val_expected.len - 1] == '"') or (val_expected[0] == '\'' and val_expected[val_expected.len - 1] == '\''))) {
            val_expected = val_expected[1 .. val_expected.len - 1];
            expected_is_literal = true;
        }

        const val_actual = ctx.get(var_n);

        // Special case: var != "" (check for non-empty)
        if (expected_is_literal and val_expected.len == 0) {
            return val_actual != null and val_actual.?.len > 0;
        }

        // Standard comparison
        if (val_actual == null) {
            // If var doesn't exist, it's considered != non-empty literal or existing var
            if (expected_is_literal) return true;
            return ctx.get(val_expected) != null; // True if other var exists
        }

        // Var exists, compare values
        if (expected_is_literal) {
            return !std.mem.eql(u8, val_actual.?, val_expected);
        } else { // Compare with another variable's value
            const val_expected_from_ctx = ctx.get(val_expected);
            if (val_expected_from_ctx == null) return true; // Var exists, other doesn't -> not equal
            return !std.mem.eql(u8, val_actual.?, val_expected_from_ctx.?);
        }
    }
    // Check for less than: var < number or var < othervar
    else if (std.mem.indexOfScalar(u8, trimmed_condition, '<')) |lt_pos| {
        // Ensure it's not part of <=
        if (lt_pos + 1 < trimmed_condition.len and trimmed_condition[lt_pos + 1] == '=') {
            // TODO: Handle <= if needed
            std.debug.print("Warning: '<=' operator not implemented in #while, treating as simple truthiness.\n", .{});
            return ctx.existsAndTrue(trimmed_condition);
        }

        const var_n = std.mem.trim(u8, trimmed_condition[0..lt_pos], " \t");
        const limit_str = std.mem.trim(u8, trimmed_condition[lt_pos + 1 ..], " \t");

        const val_actual_str = ctx.get(var_n) orelse return false; // Var must exist

        // Try parsing both sides as numbers
        const val_actual_num = std.fmt.parseInt(isize, val_actual_str, 10) catch |err| {
            std.debug.print("While Warning: Failed to parse left side '{s}' ('{s}') as integer for '<': {any}\n", .{ var_n, val_actual_str, err });
            return TemplateError.ParseIntError; // Cannot compare non-numbers with '<'
        };

        // Try parsing limit as number or getting from context
        var limit_num: isize = 0;
        if (ctx.get(limit_str)) |limit_ctx_str| {
            limit_num = std.fmt.parseInt(isize, limit_ctx_str, 10) catch |err| {
                std.debug.print("While Warning: Failed to parse right side var '{s}' ('{s}') as integer for '<': {any}\n", .{ limit_str, limit_ctx_str, err });
                return TemplateError.ParseIntError;
            };
        } else { // Assume literal number
            limit_num = std.fmt.parseInt(isize, limit_str, 10) catch |err| {
                std.debug.print("While Warning: Failed to parse right side literal '{s}' as integer for '<': {any}\n", .{ limit_str, err });
                return TemplateError.ParseIntError;
            };
        }

        return val_actual_num < limit_num;
    }

    // TODO: Add support for >, >=, <= if needed

    // Default: Simple truthiness check (exists and not "false", "0", or empty)
    else {
        return ctx.existsAndTrue(trimmed_condition);
    }
}

// --- MOVED HELPER FUNCTION ---
// Helper function to parse operand (literal or context variable) for handleSetStmt
// Returns error union to signal parsing failure
fn parseSetOperand(inner_ctx: *Context, operand_str: []const u8) !isize {
    if (inner_ctx.get(operand_str)) |val_str| {
        return std.fmt.parseInt(isize, val_str, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse variable '{s}' ('{s}') as int for addition: {any}\n", .{ operand_str, val_str, err });
            return TemplateError.ParseIntError;
        };
    } else { // Assume literal
        return std.fmt.parseInt(isize, operand_str, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse literal '{s}' as int for addition: {any}\n", .{ operand_str, err });
            return TemplateError.ParseIntError;
        };
    }
}

// Handles the #set directive, modifying the context
fn handleSetStmt(allocator: std.mem.Allocator, ctx: *Context, set: SetStmtPayload) !void {
    const trimmed_value_expr = std.mem.trim(u8, set.value, " \t");

    // Check for simple addition: var = number/var + number/var
    // TODO: Make parsing more robust (handle spaces around '+')
    if (std.mem.indexOfScalar(u8, trimmed_value_expr, '+')) |plus_pos| {
        const left_str = std.mem.trim(u8, trimmed_value_expr[0..plus_pos], " \t");
        const right_str = std.mem.trim(u8, trimmed_value_expr[plus_pos + 1 ..], " \t");

        // Use the helper function defined outside this 'if' block
        const left_num = try parseSetOperand(ctx, left_str);
        const right_num = try parseSetOperand(ctx, right_str);

        const result = left_num + right_num;

        // Allocate result string using the main allocator
        const new_val_str = try std.fmt.allocPrint(allocator, "{}", .{result});
        errdefer allocator.free(new_val_str); // Ensure cleanup on context error

        // Set the result back into the context (takes ownership)
        try ctx.setOwned(set.var_name, new_val_str);
        return; // Done with addition case
    }

    // TODO: Add subtraction, maybe other basic operations?

    // --- Non-arithmetic assignment ---

    // Check for quoted string literal "value" or 'value'
    if (trimmed_value_expr.len >= 2 and ((trimmed_value_expr[0] == '"' and trimmed_value_expr[trimmed_value_expr.len - 1] == '"') or (trimmed_value_expr[0] == '\'' and trimmed_value_expr[trimmed_value_expr.len - 1] == '\''))) {
        // Assign the content inside the quotes
        const literal_content = trimmed_value_expr[1 .. trimmed_value_expr.len - 1];
        // Need to duplicate for ctx.setOwned
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, literal_content));
    }
    // Check if the value is the name of another context variable
    else if (ctx.get(trimmed_value_expr)) |val_from_var| {
        // Assign the value *of that other variable*
        // Need to duplicate for ctx.setOwned
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, val_from_var));
    }
    // Otherwise, treat the value as a literal string/number
    else {
        // Need to duplicate for ctx.setOwned
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, trimmed_value_expr));
    }
}

// --- Main Entry Point ---
// Renders template content, handling #extends internally.
pub fn renderTemplate(
    allocator: std.mem.Allocator,
    template_content: []const u8,
    ctx: *Context,
) ![]const u8 {
    // 1. Tokenize the input template content
    var content_tokens = try tokenize(allocator, template_content);
    defer content_tokens.deinit();

    var layout_rel_path: ?[]const u8 = null;
    var first_real_token_index: ?usize = null;

    // 2. Find the first non-whitespace token to check for #extends
    for (content_tokens.items, 0..) |tok, idx| {
        switch (tok) {
            .text => |t| {
                if (std.mem.indexOfNone(u8, t, " \t\n\r") != null) { // Found non-whitespace text
                    first_real_token_index = idx;
                    break;
                }
            },
            // Any directive is considered a "real" token
            else => {
                first_real_token_index = idx;
                break;
            },
        }
    }

    // 3. Check if the first real token is #extends
    if (first_real_token_index) |fri| {
        const first_token = content_tokens.items[fri];
        if (first_token == .extends) {
            layout_rel_path = first_token.extends; // Extract the path
        }
    }

    // 4. Prepare output buffer
    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit(); // Ensure output is cleaned up on error path

    // 5. Handle based on whether #extends was found
    if (layout_rel_path) |layout_path_from_tag| {
        // --- Extending a Layout ---
        std.debug.print("Template extends layout: '{s}'\n", .{layout_path_from_tag});

        // 5a. Resolve the absolute path to the layout file
        // Use a temporary allocator for path joining
        var path_join_buf: [std.fs.max_path_bytes]u8 = undefined;
        var path_fba = std.heap.FixedBufferAllocator.init(&path_join_buf);

        const resolved_layout_path = std.fs.path.join(path_fba.allocator(), &.{
            template_base_dir, // Base directory set at the top
            layout_path_from_tag, // Relative path from #extends tag
        }) catch {
            return TemplateError.PathResolutionError;
        };

        // 5b. Extract and render blocks from the *current* (content) template
        var block_content_map = std.StringHashMap([]const u8).init(allocator);
        defer { // Ensure captured block memory is freed
            var it = block_content_map.valueIterator();
            while (it.next()) |value_ptr| allocator.free(value_ptr.*);
            block_content_map.deinit();
        }

        var capture_block_name: ?[]const u8 = null;
        var capture_block_start_idx: usize = 0;
        var capture_block_depth: u32 = 0;

        // Iterate through the *content* tokens again to find and render blocks
        for (content_tokens.items, 0..) |token, idx| {
            // Skip the initial #extends tag itself during block capture
            if (first_real_token_index != null and idx == first_real_token_index.?) {
                continue;
            }

            switch (token) {
                .block_start => |name| {
                    if (capture_block_depth == 0) { // Start capturing a new top-level block
                        capture_block_name = name;
                        capture_block_start_idx = idx + 1; // Content starts *after* the #block tag token
                        std.debug.print("Capturing block: {s}\n", .{name});
                    }
                    capture_block_depth += 1;
                },
                .endblock_stmt => {
                    if (capture_block_depth == 0) return TemplateError.MissingEndblock; // Unmatched #endblock
                    capture_block_depth -= 1;
                    if (capture_block_depth == 0 and capture_block_name != null) { // End of the captured top-level block
                        std.debug.print("Finished capturing block: {s}\n", .{capture_block_name.?});
                        // Render the tokens *between* #block and #endblock into a temporary buffer
                        var block_output = std.ArrayList(u8).init(allocator);
                        errdefer block_output.deinit(); // Clean up block buffer on error

                        renderTokens(
                            allocator,
                            content_tokens.items,
                            capture_block_start_idx, // Start index of block content
                            idx, // End index (exclusive) is the #endblock token index
                            ctx, // Use current context for rendering
                            &block_output, // Render into temporary buffer
                            null, // Pass null map, we are rendering content, not injecting layout blocks
                        ) catch |err| {
                            std.debug.print("Error rendering block '{s}': {any}\n", .{ capture_block_name.?, err });
                            return err; // Propagate error
                        };

                        // Store the rendered block content in the map.
                        // `toOwnedSlice` allocates a new slice owned by the map.
                        try block_content_map.put(capture_block_name.?, try block_output.toOwnedSlice());
                        capture_block_name = null; // Reset capture state
                    }
                },
                // Disallow nested #extends within the content template
                .extends => return TemplateError.NestedExtendsNotSupported,
                // Ignore other tokens unless inside a block being captured
                else => {},
            }
        }
        // Check if a block was started but never ended in the content template
        if (capture_block_depth != 0) return TemplateError.MissingEndblock;

        // 5c. Load the LAYOUT template file content
        const layout_content = std.fs.cwd().readFileAlloc(allocator, resolved_layout_path, std.math.maxInt(usize)) catch |e| {
            std.debug.print("Error loading layout file '{s}': {any}\n", .{ resolved_layout_path, e });
            if (e == error.FileNotFound or e == error.NotDir or e == error.IsDir) return TemplateError.LayoutNotFound; // More specific error
            return TemplateError.FileNotFound; // Map other FS errors
        };
        defer allocator.free(layout_content);

        // 5d. Tokenize the LAYOUT template
        var layout_tokens = try tokenize(allocator, layout_content);
        defer layout_tokens.deinit();

        // 5e. Check if layout itself tries to extend another template (not supported)
        for (layout_tokens.items) |lt| {
            if (lt == .extends) return TemplateError.NestedExtendsNotSupported;
        }

        // 5f. Render the LAYOUT template, injecting the captured blocks
        std.debug.print("Rendering layout '{s}' with injected blocks...\n", .{resolved_layout_path});
        try renderTokens(
            allocator,
            layout_tokens.items, // Render the layout's tokens
            0, // Start from beginning of layout
            layout_tokens.items.len, // Render all layout tokens
            ctx, // Use the current context
            &output, // Render into the *final* output buffer
            &block_content_map, // Provide the map of captured blocks for injection
        );
    } else {
        // --- Render Standalone Template (No Extends) ---
        std.debug.print("Rendering standalone template...\n", .{});
        try renderTokens(
            allocator,
            content_tokens.items, // Render the template's tokens
            0, // Start from beginning
            content_tokens.items.len, // Render all tokens
            ctx, // Use the current context
            &output, // Render into the final output buffer
            null, // No block map needed for standalone templates
        );
    }

    // 6. Return the final rendered content as an owned slice
    return output.toOwnedSlice();
}
