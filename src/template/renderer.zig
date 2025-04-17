const std = @import("std");
const types = @import("types.zig");
const cache = @import("cache.zig");
const parser = @import("parser.zig");
const Context = @import("../context.zig").Context;
const TemplateError = types.TemplateError;
const Condition = types.Condition;
const Token = types.Token;
const SetStmtPayload = types.SetStmtPayload;

pub fn renderTokens(
    allocator: std.mem.Allocator,
    tokens: []const Token,
    start_index: usize,
    end_index: usize,
    ctx: *Context,
    output: *std.ArrayList(u8),
    block_content_map: ?*std.StringHashMap([]const u8),
) !void {
    var skip_until: ?usize = null;
    var depth_if: u32 = 0;
    var depth_for: u32 = 0;
    var depth_while: u32 = 0;
    var depth_block: u32 = 0;
    var rendered_if_true_at_depth = std.ArrayList(bool).init(allocator);
    defer rendered_if_true_at_depth.deinit();

    var i = start_index;
    while (i < end_index) {
        const current_token = tokens[i];

        if (skip_until) |until| {
            if (i >= until) {
                skip_until = null;
            } else {
                switch (current_token) {
                    .if_start => depth_if += 1,
                    .endif_stmt => {
                        if (depth_if > 0) {
                            depth_if -= 1;
                        } else return TemplateError.InvalidSyntax;
                    },
                    .for_start => depth_for += 1,
                    .endfor_stmt => {
                        if (depth_for > 0) {
                            depth_for -= 1;
                        } else return TemplateError.InvalidSyntax;
                    },
                    .while_start => depth_while += 1,
                    .endwhile_stmt => {
                        if (depth_while > 0) {
                            depth_while -= 1;
                        } else return TemplateError.InvalidSyntax;
                    },
                    .block_start => depth_block += 1,
                    .endblock_stmt => {
                        if (depth_block > 0) {
                            depth_block -= 1;
                        } else return TemplateError.InvalidSyntax;
                    },
                    .extends => return TemplateError.InvalidSyntax,
                    else => {},
                }
                i += 1;
                continue;
            }
        }

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
            .if_start => |condition| {
                while (rendered_if_true_at_depth.items.len <= depth_if) {
                    try rendered_if_true_at_depth.append(false);
                }
                rendered_if_true_at_depth.items[depth_if] = false;
                const current_depth = depth_if;
                depth_if += 1;

                const should_render = try evaluateCondition(ctx, condition);
                if (should_render) {
                    rendered_if_true_at_depth.items[current_depth] = true;
                } else {
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
            },
            .elseif_stmt => |condition| {
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                const current_depth = depth_if - 1;
                if (current_depth >= rendered_if_true_at_depth.items.len) return TemplateError.InvalidSyntax;

                if (rendered_if_true_at_depth.items[current_depth]) {
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
                            else => {},
                        }
                    }
                    if (skip_until == null and j == end_index) return TemplateError.MissingEndif;
                } else {
                    const should_render = try evaluateCondition(ctx, condition);
                    if (should_render) {
                        rendered_if_true_at_depth.items[current_depth] = true;
                    } else {
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
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                const current_depth = depth_if - 1;
                if (current_depth >= rendered_if_true_at_depth.items.len) return TemplateError.InvalidSyntax;

                if (rendered_if_true_at_depth.items[current_depth]) {
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
                            else => {},
                        }
                    }
                    if (skip_until == null and j == end_index) return TemplateError.MissingEndif;
                } else {
                    rendered_if_true_at_depth.items[current_depth] = true;
                }
            },
            .endif_stmt => {
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                depth_if -= 1;
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
                if (depth_for == 0) return TemplateError.InvalidSyntax;
            },
            .while_start => |condition_str| {
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
                const max_iterations: usize = 1000;
                const loop_body_start = i + 1;
                const loop_body_end = end_idx;

                while (iteration_count < max_iterations) {
                    const continue_loop = try evaluateWhileCondition(ctx, condition_str);
                    if (!continue_loop) break;

                    iteration_count += 1;
                    try renderTokens(allocator, tokens, loop_body_start, loop_body_end, ctx, output, block_content_map);
                }

                if (iteration_count >= max_iterations) return TemplateError.WhileLoopOverflow;

                i = end_idx;
                depth_while -= 1;
            },
            .endwhile_stmt => {
                if (depth_while == 0) return TemplateError.InvalidSyntax;
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
                    if (bcm.get(name)) |content_from_child| {
                        try output.appendSlice(content_from_child);
                        i = end_idx;
                    } else {
                        try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, bcm);
                        i = end_idx;
                    }
                } else {
                    try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, null);
                    i = end_idx;
                }
                depth_block -= 1;
            },
            .endblock_stmt => {
                if (depth_block == 0) return TemplateError.InvalidSyntax;
            },
            .extends => return TemplateError.InvalidSyntax,
        }
        i += 1;
    }

    if (start_index == 0 and skip_until == null) {
        if (depth_if != 0) return TemplateError.MissingEndif;
        if (depth_for != 0) return TemplateError.MissingEndfor;
        if (depth_while != 0) return TemplateError.MissingEndwhile;
    }
}

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

fn evaluateWhileCondition(ctx: *Context, condition_str: []const u8) !bool {
    const trimmed_condition = std.mem.trim(u8, condition_str, " \t");

    if (std.mem.indexOf(u8, trimmed_condition, " == ")) |eq_pos| {
        const var_n = std.mem.trim(u8, trimmed_condition[0..eq_pos], " \t");
        var val_expected = std.mem.trim(u8, trimmed_condition[eq_pos + 4 ..], " \t");
        var expected_is_literal = false;

        if (val_expected.len >= 2 and ((val_expected[0] == '"' and val_expected[val_expected.len - 1] == '"') or (val_expected[0] == '\'' and val_expected[val_expected.len - 1] == '\''))) {
            val_expected = val_expected[1 .. val_expected.len - 1];
            expected_is_literal = true;
        }

        const val_actual = ctx.get(var_n);
        if (val_actual == null) return false;

        if (expected_is_literal) {
            return std.mem.eql(u8, val_actual.?, val_expected);
        } else {
            const val_expected_from_ctx = ctx.get(val_expected);
            if (val_expected_from_ctx == null) return false;
            return std.mem.eql(u8, val_actual.?, val_expected_from_ctx.?);
        }
    } else if (std.mem.indexOf(u8, trimmed_condition, " != ")) |ne_pos| {
        const var_n = std.mem.trim(u8, trimmed_condition[0..ne_pos], " \t");
        var val_expected = std.mem.trim(u8, trimmed_condition[ne_pos + 4 ..], " \t");
        var expected_is_literal = false;

        if (val_expected.len >= 2 and ((val_expected[0] == '"' and val_expected[val_expected.len - 1] == '"') or (val_expected[0] == '\'' and val_expected[val_expected.len - 1] == '\''))) {
            val_expected = val_expected[1 .. val_expected.len - 1];
            expected_is_literal = true;
        }

        const val_actual = ctx.get(var_n);

        if (expected_is_literal and val_expected.len == 0) {
            return val_actual != null and val_actual.?.len > 0;
        }

        if (val_actual == null) {
            if (expected_is_literal) return true;
            return ctx.get(val_expected) != null;
        }

        if (expected_is_literal) {
            return !std.mem.eql(u8, val_actual.?, val_expected);
        } else {
            const val_expected_from_ctx = ctx.get(val_expected);
            if (val_expected_from_ctx == null) return true;
            return !std.mem.eql(u8, val_actual.?, val_expected_from_ctx.?);
        }
    } else if (std.mem.indexOfScalar(u8, trimmed_condition, '<')) |lt_pos| {
        if (lt_pos + 1 < trimmed_condition.len and trimmed_condition[lt_pos + 1] == '=') {
            std.debug.print("Warning: '<=' operator not implemented in #while, treating as simple truthiness.\n", .{});
            return ctx.existsAndTrue(trimmed_condition);
        }

        const var_n = std.mem.trim(u8, trimmed_condition[0..lt_pos], " \t");
        const limit_str = std.mem.trim(u8, trimmed_condition[lt_pos + 1 ..], " \t");

        const val_actual_str = ctx.get(var_n) orelse return false;

        const val_actual_num = std.fmt.parseInt(isize, val_actual_str, 10) catch |err| {
            std.debug.print("While Warning: Failed to parse left side '{s}' ('{s}') as integer for '<': {any}\n", .{ var_n, val_actual_str, err });
            return TemplateError.ParseIntError;
        };

        var limit_num: isize = 0;
        if (ctx.get(limit_str)) |limit_ctx_str| {
            limit_num = std.fmt.parseInt(isize, limit_ctx_str, 10) catch |err| {
                std.debug.print("While Warning: Failed to parse right side var '{s}' ('{s}') as integer for '<': {any}\n", .{ limit_str, limit_ctx_str, err });
                return TemplateError.ParseIntError;
            };
        } else {
            limit_num = std.fmt.parseInt(isize, limit_str, 10) catch |err| {
                std.debug.print("While Warning: Failed to parse right side literal '{s}' as integer for '<': {any}\n", .{ limit_str, err });
                return TemplateError.ParseIntError;
            };
        }

        return val_actual_num < limit_num;
    } else {
        return ctx.existsAndTrue(trimmed_condition);
    }
}

fn parseSetOperand(inner_ctx: *Context, operand_str: []const u8) !isize {
    if (inner_ctx.get(operand_str)) |val_str| {
        return std.fmt.parseInt(isize, val_str, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse variable '{s}' ('{s}') as int for addition: {any}\n", .{ operand_str, val_str, err });
            return TemplateError.ParseIntError;
        };
    } else {
        return std.fmt.parseInt(isize, operand_str, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse literal '{s}' as int for addition: {any}\n", .{ operand_str, err });
            return TemplateError.ParseIntError;
        };
    }
}

fn handleSetStmt(allocator: std.mem.Allocator, ctx: *Context, set: SetStmtPayload) !void {
    const trimmed_value_expr = std.mem.trim(u8, set.value, " \t");

    if (std.mem.indexOfScalar(u8, trimmed_value_expr, '+')) |plus_pos| {
        const left_str = std.mem.trim(u8, trimmed_value_expr[0..plus_pos], " \t");
        const right_str = std.mem.trim(u8, trimmed_value_expr[plus_pos + 1 ..], " \t");

        const left_num = try parseSetOperand(ctx, left_str);
        const right_num = try parseSetOperand(ctx, right_str);

        const result = left_num + right_num;

        const new_val_str = try std.fmt.allocPrint(allocator, "{}", .{result});
        errdefer allocator.free(new_val_str);

        try ctx.setOwned(set.var_name, new_val_str);
        return;
    }

    if (trimmed_value_expr.len >= 2 and ((trimmed_value_expr[0] == '"' and trimmed_value_expr[trimmed_value_expr.len - 1] == '"') or (trimmed_value_expr[0] == '\'' and trimmed_value_expr[trimmed_value_expr.len - 1] == '\''))) {
        const literal_content = trimmed_value_expr[1 .. trimmed_value_expr.len - 1];
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, literal_content));
    } else if (ctx.get(trimmed_value_expr)) |val_from_var| {
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, val_from_var));
    } else {
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, trimmed_value_expr));
    }
}
