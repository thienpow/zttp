// src/template/renderer.zig
const std = @import("std");
const types = @import("types.zig");
const cache = @import("cache.zig");
const parser = @import("parser.zig");
const Context = @import("../context.zig").Context;
const TemplateError = types.TemplateError;
const Condition = types.Condition;
const Token = types.Token;
const SetStmtPayload = types.SetStmtPayload;
const ForLoopPayload = types.ForLoopPayload;

// Helper to check truthiness according to template logic
// (exists, not null, not "false", not empty string) - Adjust rules as needed.
fn isTruthy(ctx: *Context, key: []const u8) bool {
    if (ctx.get(key)) |value| {
        if (value.len == 0) return false;
        if (std.mem.eql(u8, value, "false")) return false;
        // Add other falsy checks if needed (e.g., "0")
        // if (std.mem.eql(u8, value, "0")) return false;
        return true; // Exists and not explicitly falsy
    } else {
        return false; // Doesn't exist
    }
}

fn performComparison(ctx: *Context, var_name: []const u8, cmp_value_str: []const u8, is_literal: bool, comptime op: enum { lt, lte, gt, gte }) !bool {
    const val_actual_str = ctx.get(var_name) orelse return false;
    const val_expected_str = if (is_literal) cmp_value_str else ctx.get(cmp_value_str) orelse return false;

    // Try to parse as numbers first
    const val_actual_num = std.fmt.parseInt(isize, val_actual_str, 10) catch null;
    const val_expected_num = std.fmt.parseInt(isize, val_expected_str, 10) catch null;

    if (val_actual_num != null and val_expected_num != null) {
        const a = val_actual_num.?;
        const b = val_expected_num.?;
        return switch (op) {
            .lt => a < b,
            .lte => a <= b,
            .gt => a > b,
            .gte => a >= b,
        };
    } else {
        // Fallback to string comparison
        const order = std.mem.order(u8, val_actual_str, val_expected_str);
        return switch (op) {
            .lt => order == .lt,
            .lte => order == .lt or order == .eq,
            .gt => order == .gt,
            .gte => order == .gt or order == .eq,
        };
    }
}

fn evaluateCondition(allocator: std.mem.Allocator, ctx: *Context, condition: Condition) !bool {
    switch (condition) {
        .simple => |key| {
            // Simple truthiness check based on variable existence and value
            return isTruthy(ctx, key);
        },
        .non_empty => |var_name| {
            // Check if the variable exists and its string value is not empty
            const val = ctx.get(var_name);
            const result = val != null and val.?.len > 0;
            std.debug.print("Evaluating non_empty for '{s}': value={?s}, result={}\n", .{ var_name, val, result });
            return result;
        },
        .equals => |eq| {
            const val_actual = ctx.get(eq.var_name);
            const val_expected_lookup = if (eq.is_literal) eq.value else ctx.get(eq.value);

            // Handle null comparison: null == null -> true, null == value -> false
            if (val_actual == null and val_expected_lookup == null) return true;
            if (val_actual == null or val_expected_lookup == null) return false;

            // Both exist, compare values
            return std.mem.eql(u8, val_actual.?, val_expected_lookup.?);
        },
        .not_equals => |ne| {
            // NOTE: The special case 'var != ""' is handled by Condition.non_empty during parsing.
            // This handles general inequality comparisons.
            const val_actual = ctx.get(ne.var_name);
            const val_expected_lookup = if (ne.is_literal) ne.value else ctx.get(ne.value);

            // Handle null comparison: null != null -> false, null != value -> true
            if (val_actual == null and val_expected_lookup == null) return false;
            if (val_actual == null or val_expected_lookup == null) return true;

            // Both exist, compare values
            return !std.mem.eql(u8, val_actual.?, val_expected_lookup.?);
        },
        .less_than => |lt| {
            return performComparison(ctx, lt.var_name, lt.value, lt.is_literal, .lt);
        },
        .less_than_or_equal => |lte| {
            return performComparison(ctx, lte.var_name, lte.value, lte.is_literal, .lte);
        },
        .greater_than => |gt| {
            return performComparison(ctx, gt.var_name, gt.value, gt.is_literal, .gt);
        },
        .greater_than_or_equal => |gte| {
            return performComparison(ctx, gte.var_name, gte.value, gte.is_literal, .gte);
        },
        .logical_and => |logic| {
            // Short-circuit evaluation
            const left_result = try evaluateCondition(allocator, ctx, logic.left.*);
            if (!left_result) return false; // Don't evaluate right if left is false
            // Deallocate left condition result? Not needed if result is bool.
            // If left was true, evaluate right
            return try evaluateCondition(allocator, ctx, logic.right.*);
        },
        .logical_or => |logic| {
            // Short-circuit evaluation
            const left_result = try evaluateCondition(allocator, ctx, logic.left.*);
            if (left_result) return true; // Don't evaluate right if left is true
            // If left was false, evaluate right
            return try evaluateCondition(allocator, ctx, logic.right.*);
        },
    }
}

// Helper function to parse operands for #set arithmetic (very basic)
fn parseSetOperand(inner_ctx: *Context, operand_str: []const u8) !isize {
    const trimmed_op = std.mem.trim(u8, operand_str, " \t");
    // Check if it's a variable in the context
    if (inner_ctx.get(trimmed_op)) |val_str| {
        return std.fmt.parseInt(isize, val_str, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse variable '{s}' ('{s}') as int for arithmetic: {any}\n", .{ trimmed_op, val_str, err });
            return TemplateError.ParseIntError;
        };
    } else {
        // Try parsing as a literal number
        return std.fmt.parseInt(isize, trimmed_op, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse literal '{s}' as int for arithmetic: {any}\n", .{ trimmed_op, err });
            return TemplateError.ParseIntError;
        };
    }
}

// Handles the #set directive
fn handleSetStmt(allocator: std.mem.Allocator, ctx: *Context, set: SetStmtPayload) !void {
    const trimmed_value_expr = std.mem.trim(u8, set.value, " \t");

    // --- Basic Arithmetic Example (Addition) ---
    // Check for simple addition format "operand1 + operand2"
    // This is a very basic check, not a full expression parser.
    if (std.mem.indexOf(u8, trimmed_value_expr, " + ")) |plus_pos| {
        const left_str = trimmed_value_expr[0..plus_pos];
        const right_str = trimmed_value_expr[plus_pos + 3 ..];

        // Ensure operands are not empty after splitting
        if (left_str.len > 0 and right_str.len > 0) {
            const left_num = try parseSetOperand(ctx, left_str);
            const right_num = try parseSetOperand(ctx, right_str);
            const result = left_num + right_num;

            // Allocate string for the result and set it (owned by context)
            const new_val_str = try std.fmt.allocPrint(allocator, "{}", .{result});
            errdefer allocator.free(new_val_str); // Free if setOwned fails
            try ctx.setOwned(set.var_name, new_val_str);
            return; // Handled as arithmetic
        }
    }
    // --- End Basic Arithmetic ---

    // --- Default Handling (Literal or Variable Copy) ---
    // Check if value is a string literal ("..." or '...')
    if (trimmed_value_expr.len >= 2 and
        ((trimmed_value_expr[0] == '"' and trimmed_value_expr[trimmed_value_expr.len - 1] == '"') or
            (trimmed_value_expr[0] == '\'' and trimmed_value_expr[trimmed_value_expr.len - 1] == '\'')))
    {
        const literal_content = trimmed_value_expr[1 .. trimmed_value_expr.len - 1];
        // Duplicate the literal content for the context
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, literal_content));
    }
    // Check if value is the name of another context variable
    else if (ctx.get(trimmed_value_expr)) |val_from_var| {
        // Duplicate the other variable's value
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, val_from_var));
    }
    // Otherwise, treat the entire trimmed value expression as a literal string value
    else {
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, trimmed_value_expr));
    }
}

// Main rendering function
pub fn renderTokens(
    allocator: std.mem.Allocator,
    tokens: []const Token,
    start_index: usize,
    end_index: usize,
    ctx: *Context,
    output: *std.ArrayList(u8),
    block_content_map: ?*std.StringHashMap([]const u8), // For template inheritance
) !void {
    // State for tracking nested structures and conditional rendering
    var skip_until: ?usize = null; // Index to skip rendering until
    var depth_if: u32 = 0; // Current nesting depth of #if blocks
    var depth_for: u32 = 0; // Current nesting depth of #for blocks
    var depth_while: u32 = 0; // Current nesting depth of #while blocks
    var depth_block: u32 = 0; // Current nesting depth of #block blocks

    // Track if a true condition (#if or #elseif) was already rendered at each #if depth level
    var rendered_if_true_at_depth = std.ArrayList(bool).init(allocator);
    defer rendered_if_true_at_depth.deinit();

    var i = start_index;
    while (i < end_index) : (i += 1) { // Increment i at the end of the loop
        const current_token = tokens[i];

        // --- Skip Logic ---
        if (skip_until) |until| {
            if (i >= until) {
                // Reached the end of the skip section
                skip_until = null;
                // Fall through to process the current token 'i' normally
            } else {
                // Still skipping, just track nesting depth to know when the skipped block ends
                switch (current_token) {
                    .if_start => depth_if += 1,
                    .endif_stmt => {
                        if (depth_if > 0) depth_if -= 1 else return TemplateError.InvalidSyntax;
                    },
                    .for_start => depth_for += 1,
                    .endfor_stmt => {
                        if (depth_for > 0) depth_for -= 1 else return TemplateError.InvalidSyntax;
                    },
                    .while_start => depth_while += 1,
                    .endwhile_stmt => {
                        if (depth_while > 0) depth_while -= 1 else return TemplateError.InvalidSyntax;
                    },
                    .block_start => depth_block += 1,
                    .endblock_stmt => {
                        if (depth_block > 0) depth_block -= 1 else return TemplateError.InvalidSyntax;
                    },
                    .extends => return TemplateError.InvalidSyntax, // Should not happen mid-render
                    else => {}, // Other tokens don't affect skip nesting
                }
                continue; // Go to next token without processing
            }
        }

        // --- Token Processing ---
        switch (current_token) {
            .text => |text| {
                // Append text only if it's not empty (parser might generate empty text tokens)
                if (text.len > 0) try output.appendSlice(text);
            },

            .variable => |var_name_expr| {
                var value_to_render: []const u8 = "";
                if (std.mem.indexOf(u8, var_name_expr, "//")) |sep_pos| {
                    const name = std.mem.trim(u8, var_name_expr[0..sep_pos], " \t");
                    const default_expr = std.mem.trim(u8, var_name_expr[sep_pos + 2 ..], " \t");
                    var default_value: []const u8 = default_expr;
                    if (default_expr.len >= 2 and default_expr[0] == '"' and default_expr[default_expr.len - 1] == '"') {
                        default_value = default_expr[1 .. default_expr.len - 1];
                    } else if (default_expr.len >= 2 and default_expr[0] == '\'' and default_expr[default_expr.len - 1] == '\'') {
                        default_value = default_expr[1 .. default_expr.len - 1];
                    }
                    value_to_render = ctx.get(name) orelse default_value;
                } else {
                    value_to_render = ctx.get(var_name_expr) orelse "";
                }
                try output.appendSlice(value_to_render);
            },

            .if_start => |condition| {
                // Ensure capacity for the new depth level and initialize/reset state
                while (rendered_if_true_at_depth.items.len <= depth_if) {
                    try rendered_if_true_at_depth.append(false);
                }
                rendered_if_true_at_depth.items[depth_if] = false;

                const current_depth = depth_if; // Capture depth before incrementing
                depth_if += 1;

                const should_render = try evaluateCondition(allocator, ctx, condition);
                if (should_render) {
                    rendered_if_true_at_depth.items[current_depth] = true;
                    // Continue rendering normally inside this block
                } else {
                    // Condition is false, find the corresponding #elseif/#else/#endif and skip until then
                    var j = i + 1;
                    var nested_if: u32 = 0;
                    var found_target = false;
                    while (j < end_index) : (j += 1) {
                        switch (tokens[j]) {
                            .if_start => nested_if += 1,
                            .endif_stmt => {
                                if (nested_if == 0) {
                                    skip_until = j;
                                    found_target = true;
                                    break;
                                } // Found matching endif
                                if (nested_if > 0) nested_if -= 1 else return TemplateError.InvalidSyntax;
                            },
                            .elseif_stmt, .else_stmt => {
                                if (nested_if == 0) {
                                    skip_until = j;
                                    found_target = true;
                                    break;
                                } // Found next branch
                            },
                            else => {},
                        }
                    }
                    if (!found_target) return TemplateError.MissingEndif;
                    // Set i to the token *before* the skip target, so the next loop iteration processes the target
                    i = skip_until.? - 1;
                }
            },

            .elseif_stmt => |condition| {
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                const current_depth = depth_if - 1;
                if (current_depth >= rendered_if_true_at_depth.items.len) return TemplateError.InvalidSyntax; // Should be initialized

                // If a previous branch at this level was true, skip this one and subsequent ones
                if (rendered_if_true_at_depth.items[current_depth]) {
                    var j = i + 1;
                    var nested_if: u32 = 0;
                    var found_target = false;
                    while (j < end_index) : (j += 1) {
                        switch (tokens[j]) {
                            .if_start => nested_if += 1,
                            .endif_stmt => {
                                if (nested_if == 0) {
                                    skip_until = j;
                                    found_target = true;
                                    break;
                                }
                                if (nested_if > 0) nested_if -= 1 else return TemplateError.InvalidSyntax;
                            },
                            .elseif_stmt, .else_stmt => {
                                if (nested_if == 0) {
                                    skip_until = j;
                                    found_target = true;
                                    break;
                                }
                            },
                            else => {},
                        }
                    }
                    if (!found_target) return TemplateError.MissingEndif;
                    i = skip_until.? - 1;
                } else {
                    // Previous branches were false, evaluate this one
                    const should_render = try evaluateCondition(allocator, ctx, condition);
                    if (should_render) {
                        rendered_if_true_at_depth.items[current_depth] = true;
                        // Continue rendering normally
                    } else {
                        // This branch is also false, skip to the next branch/endif
                        var j = i + 1;
                        var nested_if: u32 = 0;
                        var found_target = false;
                        while (j < end_index) : (j += 1) {
                            switch (tokens[j]) {
                                .if_start => nested_if += 1,
                                .endif_stmt => {
                                    if (nested_if == 0) {
                                        skip_until = j;
                                        found_target = true;
                                        break;
                                    }
                                    if (nested_if > 0) nested_if -= 1 else return TemplateError.InvalidSyntax;
                                },
                                .elseif_stmt, .else_stmt => {
                                    if (nested_if == 0) {
                                        skip_until = j;
                                        found_target = true;
                                        break;
                                    }
                                },
                                else => {},
                            }
                        }
                        if (!found_target) return TemplateError.MissingEndif;
                        i = skip_until.? - 1;
                    }
                }
            },

            .else_stmt => {
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                const current_depth = depth_if - 1;
                if (current_depth >= rendered_if_true_at_depth.items.len) return TemplateError.InvalidSyntax;

                // If a previous branch was true, skip this else block
                if (rendered_if_true_at_depth.items[current_depth]) {
                    var j = i + 1;
                    var nested_if: u32 = 0;
                    var found_target = false;
                    while (j < end_index) : (j += 1) {
                        switch (tokens[j]) {
                            .if_start => nested_if += 1,
                            .endif_stmt => {
                                if (nested_if == 0) {
                                    skip_until = j;
                                    found_target = true;
                                    break;
                                }
                                if (nested_if > 0) nested_if -= 1 else return TemplateError.InvalidSyntax;
                            },
                            else => {}, // No elseif/else possible after else
                        }
                    }
                    if (!found_target) return TemplateError.MissingEndif;
                    i = skip_until.? - 1;
                } else {
                    // No previous branch was true, render this else block
                    rendered_if_true_at_depth.items[current_depth] = true; // Mark true now
                    // Continue rendering normally
                }
            },

            .endif_stmt => {
                if (depth_if == 0) return TemplateError.InvalidSyntax; // Mismatched #endif
                depth_if -= 1;
                // No output, just adjusts depth
            },

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
                            if (nested > 0) nested -= 1 else return TemplateError.InvalidSyntax;
                        },
                        else => {},
                    }
                }
                if (loop_end_idx == null) return TemplateError.MissingEndfor;
                const end_idx = loop_end_idx.?;

                const collection_val_str = ctx.get(loop.collection) orelse "";

                // Arena allocator for temporary items
                var items_allocator = std.heap.ArenaAllocator.init(allocator);
                defer items_allocator.deinit();
                const item_alloc = items_allocator.allocator();
                var loop_items = std.ArrayList([]const u8).init(item_alloc);

                // Parse JSON array
                var parsed_json = false;
                if (collection_val_str.len >= 2 and collection_val_str[0] == '[' and collection_val_str[collection_val_str.len - 1] == ']') {
                    const parse_options = std.json.ParseOptions{ .duplicate_field_behavior = .use_first };
                    const json_result = std.json.parseFromSlice(std.json.Value, item_alloc, collection_val_str, parse_options) catch return;
                    const parsed = json_result.value;
                    if (parsed == .array) {
                        const json_array = parsed.array;
                        try loop_items.ensureTotalCapacity(json_array.items.len);
                        for (json_array.items) |item| {
                            if (item == .string) {
                                try loop_items.append(try item_alloc.dupe(u8, item.string));
                            }
                        }
                        parsed_json = true;
                    }
                }

                // Fallback: Comma-separated string list
                if (!parsed_json and collection_val_str.len > 0) {
                    var it = std.mem.splitScalar(u8, collection_val_str, ',');
                    while (it.next()) |item_part| {
                        const trimmed_item = std.mem.trim(u8, item_part, " \t");
                        try loop_items.append(try item_alloc.dupe(u8, trimmed_item));
                    }
                }

                // Execute loop
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

                    for (loop_items.items) |item_value| {
                        try ctx.setOwned(loop.var_name, try allocator.dupe(u8, item_value));
                        try renderTokens(allocator, tokens, loop_body_start, loop_body_end, ctx, output, block_content_map);
                    }

                    if (original_value_copy) |ovc| {
                        const restore_copy = try allocator.dupe(u8, ovc);
                        try ctx.setOwned(loop.var_name, restore_copy);
                    } else {
                        _ = ctx.remove(loop.var_name);
                    }
                    i = end_idx;
                }
                depth_for -= 1;
            },

            .endfor_stmt => {
                if (depth_for == 0) return TemplateError.InvalidSyntax; // Mismatched #endfor
                // Primarily a marker token
            },

            .while_start => |condition| {
                depth_while += 1;
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
                            if (nested > 0) nested -= 1 else return TemplateError.InvalidSyntax;
                        },
                        else => {},
                    }
                }
                if (loop_end_idx == null) return TemplateError.MissingEndwhile;
                const end_idx = loop_end_idx.?;

                var iteration_count: usize = 0;
                const max_iterations: usize = 1000; // Safety limit
                const loop_body_start = i + 1;
                const loop_body_end = end_idx;

                while (iteration_count < max_iterations) {
                    // Evaluate condition *before* each iteration
                    const continue_loop = try evaluateCondition(allocator, ctx, condition);
                    if (!continue_loop) break;

                    iteration_count += 1; // Increment before render? Or after? Matters if body affects condition. Usually before.

                    // Render loop body
                    try renderTokens(allocator, tokens, loop_body_start, loop_body_end, ctx, output, block_content_map);

                    // Re-evaluate condition potentially modified by loop body (if needed, depends on exact requirements)
                }

                if (iteration_count >= max_iterations) {
                    std.log.err("While loop exceeded max iterations ({d}) for condition.", .{max_iterations});
                    return TemplateError.WhileLoopOverflow;
                }

                i = end_idx; // Move instruction pointer past #endwhile
                depth_while -= 1;
            },

            .endwhile_stmt => {
                if (depth_while == 0) return TemplateError.InvalidSyntax; // Mismatched #endwhile
                // Primarily a marker token
            },

            .set_stmt => |set| {
                try handleSetStmt(allocator, ctx, set);
            },

            .block_start => |name| {
                depth_block += 1;
                var block_end_idx: ?usize = null;
                var nested: u32 = 0;
                var j = i + 1;
                while (j < end_index) : (j += 1) {
                    switch (tokens[j]) {
                        .block_start => nested += 1,
                        .endblock_stmt => {
                            if (nested == 0) {
                                block_end_idx = j;
                                break;
                            }
                            if (nested > 0) nested -= 1 else return TemplateError.InvalidSyntax;
                        },
                        else => {},
                    }
                }
                if (block_end_idx == null) return TemplateError.MissingEndblock;
                const end_idx = block_end_idx.?;

                // Template Inheritance Logic:
                if (block_content_map) |bcm| {
                    // Check if the child template provided content for this block
                    if (bcm.get(name)) |content_from_child| {
                        // Render the child's content INSTEAD of the default
                        try output.appendSlice(content_from_child);
                        i = end_idx; // Skip the default content in this template
                    } else {
                        // No override from child, render the default content of this block
                        try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, bcm); // Pass map down
                        i = end_idx; // Move past the rendered default block content
                    }
                } else {
                    // Not in inheritance mode, just render the block content normally.
                    try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, null);
                    i = end_idx;
                }
                depth_block -= 1;
            },

            .endblock_stmt => {
                if (depth_block == 0) return TemplateError.InvalidSyntax; // Mismatched #endblock
                // Primarily a marker token
            },

            .extends => {
                // This token should only appear as the first token and be handled
                // by the calling function (like main.zig's renderTemplate).
                // Encountering it here during recursive rendering is an error.
                std.log.err("Encountered #extends token during recursive renderTokens call.", .{});
                return TemplateError.InvalidSyntax;
            },
        }
    }

    // Final Check at the end of the top-level render call
    if (start_index == 0 and skip_until == null) {
        if (depth_if != 0) return TemplateError.MissingEndif;
        if (depth_for != 0) return TemplateError.MissingEndfor;
        if (depth_while != 0) return TemplateError.MissingEndwhile;
        if (depth_block != 0) return TemplateError.MissingEndblock;
    }
}
