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
fn isTruthy(ctx: *Context, key: []const u8) bool {
    if (ctx.get(key)) |value| {
        if (value.len == 0) return false;
        if (std.mem.eql(u8, value, "false")) return false;
        return true;
    } else {
        return false;
    }
}

fn performComparison(ctx: *Context, var_name: []const u8, cmp_value_str: []const u8, is_literal: bool, comptime op: enum { lt, lte, gt, gte }) !bool {
    const val_actual_str = ctx.get(var_name) orelse return false;
    const val_expected_str = if (is_literal) cmp_value_str else ctx.get(cmp_value_str) orelse return false;

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
            return isTruthy(ctx, key);
        },
        .non_empty => |var_name| {
            const val = ctx.get(var_name);
            const result = val != null and val.?.len > 0;
            std.debug.print("Evaluating non_empty for '{s}': value={?s}, result={}\n", .{ var_name, val, result });
            return result;
        },
        .equals => |eq| {
            const val_actual = ctx.get(eq.var_name);
            const val_expected_lookup = if (eq.is_literal) eq.value else ctx.get(eq.value);
            if (val_actual == null and val_expected_lookup == null) return true;
            if (val_actual == null or val_expected_lookup == null) return false;
            return std.mem.eql(u8, val_actual.?, val_expected_lookup.?);
        },
        .not_equals => |ne| {
            const val_actual = ctx.get(ne.var_name);
            const val_expected_lookup = if (ne.is_literal) ne.value else ctx.get(ne.value);
            if (val_actual == null and val_expected_lookup == null) return false;
            if (val_actual == null or val_expected_lookup == null) return true;
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
            const left_result = try evaluateCondition(allocator, ctx, logic.left.*);
            if (!left_result) return false;
            return try evaluateCondition(allocator, ctx, logic.right.*);
        },
        .logical_or => |logic| {
            const left_result = try evaluateCondition(allocator, ctx, logic.left.*);
            if (left_result) return true;
            return try evaluateCondition(allocator, ctx, logic.right.*);
        },
    }
}

fn parseSetOperand(inner_ctx: *Context, operand_str: []const u8) !isize {
    const trimmed_op = std.mem.trim(u8, operand_str, " \t");
    if (inner_ctx.get(trimmed_op)) |val_str| {
        return std.fmt.parseInt(isize, val_str, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse variable '{s}' ('{s}') as int for arithmetic: {any}\n", .{ trimmed_op, val_str, err });
            return TemplateError.ParseIntError;
        };
    } else {
        return std.fmt.parseInt(isize, trimmed_op, 10) catch |err| {
            std.debug.print("Set Error: Failed to parse literal '{s}' as int for arithmetic: {any}\n", .{ trimmed_op, err });
            return TemplateError.ParseIntError;
        };
    }
}

fn handleSetStmt(allocator: std.mem.Allocator, ctx: *Context, set: SetStmtPayload) !void {
    const trimmed_value_expr = std.mem.trim(u8, set.value, " \t");

    if (std.mem.indexOf(u8, trimmed_value_expr, " + ")) |plus_pos| {
        const left_str = trimmed_value_expr[0..plus_pos];
        const right_str = trimmed_value_expr[plus_pos + 3 ..];
        if (left_str.len > 0 and right_str.len > 0) {
            const left_num = try parseSetOperand(ctx, left_str);
            const right_num = try parseSetOperand(ctx, right_str);
            const result = left_num + right_num;
            const new_val_str = try std.fmt.allocPrint(allocator, "{}", .{result});
            errdefer allocator.free(new_val_str);
            try ctx.setOwned(set.var_name, new_val_str);
            return;
        }
    }

    if (trimmed_value_expr.len >= 2 and
        ((trimmed_value_expr[0] == '"' and trimmed_value_expr[trimmed_value_expr.len - 1] == '"') or
            (trimmed_value_expr[0] == '\'' and trimmed_value_expr[trimmed_value_expr.len - 1] == '\'')))
    {
        const literal_content = trimmed_value_expr[1 .. trimmed_value_expr.len - 1];
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, literal_content));
    } else if (ctx.get(trimmed_value_expr)) |val_from_var| {
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, val_from_var));
    } else {
        try ctx.setOwned(set.var_name, try allocator.dupe(u8, trimmed_value_expr));
    }
}

fn collectAssetPaths(
    allocator: std.mem.Allocator,
    tokens: []const Token,
    start_index: usize,
    end_index: usize,
    css_paths: *std.StringHashMap(void),
    js_paths: *std.StringHashMap(void),
    visited_includes: *std.StringHashMap(void),
) !void {
    var i = start_index;
    while (i < end_index) : (i += 1) {
        const current_token = tokens[i];
        switch (current_token) {
            .css => |path| {
                //std.log.debug("Collecting CSS path: {s}", .{path});
                try css_paths.put(path, {});
            },
            .js => |path| {
                //std.log.debug("Collecting JS path: {s}", .{path});
                try js_paths.put(path, {});
            },
            .include => |path| {
                if (visited_includes.contains(path)) continue;
                try visited_includes.put(path, {});
                const token_list_ptr = try cache.getTokens(path) orelse {
                    std.log.err("Template not found in cache: '{s}'", .{path});
                    return TemplateError.FileNotFound;
                };
                try collectAssetPaths(
                    allocator,
                    token_list_ptr.items,
                    0,
                    token_list_ptr.items.len,
                    css_paths,
                    js_paths,
                    visited_includes,
                );
            },
            else => {},
        }
    }
}

pub fn renderTokens(
    allocator: std.mem.Allocator,
    tokens: []const Token,
    start_index: usize,
    end_index: usize,
    ctx: *Context,
    output: *std.ArrayList(u8),
    block_content_map: ?*std.StringHashMap([]const u8),
    depth: u32,
) !void {
    var skip_until: ?usize = null;
    var depth_if: u32 = 0;
    var depth_for: u32 = 0;
    var depth_while: u32 = 0;
    var depth_block: u32 = 0;

    var rendered_if_true_at_depth = std.ArrayList(bool).init(allocator);
    defer rendered_if_true_at_depth.deinit();

    var css_paths = std.StringHashMap(void).init(allocator);
    defer css_paths.deinit();
    var js_paths = std.StringHashMap(void).init(allocator);
    defer js_paths.deinit();
    var visited_includes = std.StringHashMap(void).init(allocator);
    defer visited_includes.deinit();

    //std.log.debug("Collecting assets for tokens {d} to {d}, depth {d}", .{ start_index, end_index, depth });
    try collectAssetPaths(
        allocator,
        tokens,
        start_index,
        end_index,
        &css_paths,
        &js_paths,
        &visited_includes,
    );

    if (depth == 0) {
        //std.log.debug("Rendering CSS/JS tags at depth 0", .{});
        var css_it = css_paths.keyIterator();
        while (css_it.next()) |path| {
            const css_tag = try std.fmt.allocPrint(allocator, "<link rel=\"stylesheet\" href=\"{s}\">\n", .{path.*});
            defer allocator.free(css_tag);
            //std.log.debug("Rendering CSS tag: {s}", .{css_tag});
            try output.appendSlice(css_tag);
        }

        var js_it = js_paths.keyIterator();
        while (js_it.next()) |path| {
            const js_tag = try std.fmt.allocPrint(allocator, "<script src=\"{s}\"></script>\n", .{path.*});
            defer allocator.free(js_tag);
            //std.log.debug("Rendering JS tag: {s}", .{js_tag});
            try output.appendSlice(js_tag);
        }
    }

    var i = start_index;
    while (i < end_index) : (i += 1) {
        const current_token = tokens[i];

        if (skip_until) |until| {
            if (i >= until) {
                skip_until = null;
            } else {
                switch (current_token) {
                    .if_start => depth_if += 1,
                    .endif_stmt => {
                        if (depth_if > 0) depth_if -= 1 else {
                            std.log.err("InvalidSyntax: #endif without matching #if at index {d}", .{i});
                            return TemplateError.InvalidSyntax;
                        }
                    },
                    .for_start => depth_for += 1,
                    .endfor_stmt => {
                        if (depth_for > 0) depth_for -= 1 else {
                            std.log.err("InvalidSyntax: #endfor without matching #for at index {d}", .{i});
                            return TemplateError.InvalidSyntax;
                        }
                    },
                    .while_start => depth_while += 1,
                    .endwhile_stmt => {
                        if (depth_while > 0) depth_while -= 1 else {
                            std.log.err("InvalidSyntax: #endwhile without matching #while at index {d}", .{i});
                            return TemplateError.InvalidSyntax;
                        }
                    },
                    .block_start => depth_block += 1,
                    .endblock_stmt => {
                        if (depth_block > 0) depth_block -= 1 else {
                            std.log.err("InvalidSyntax: #endblock without matching #block at index {d}", .{i});
                            return TemplateError.InvalidSyntax;
                        }
                    },
                    .extends => {
                        std.log.err("InvalidSyntax: #extends encountered mid-rendering at index {d}", .{i});
                        return TemplateError.InvalidSyntax;
                    },
                    else => {},
                }
                continue;
            }
        }

        switch (current_token) {
            .text => |text| {
                if (text.len > 0) {
                    //std.log.debug("Rendering text: {s}", .{text});
                    try output.appendSlice(text);
                }
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
                //std.log.debug("Rendering variable: {s} = {s}", .{ var_name_expr, value_to_render });
                try output.appendSlice(value_to_render);
            },
            .if_start => |condition| {
                while (rendered_if_true_at_depth.items.len <= depth_if) {
                    try rendered_if_true_at_depth.append(false);
                }
                rendered_if_true_at_depth.items[depth_if] = false;

                const current_depth = depth_if;
                depth_if += 1;

                const should_render = try evaluateCondition(allocator, ctx, condition);
                if (should_render) {
                    rendered_if_true_at_depth.items[current_depth] = true;
                } else {
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
                                if (nested_if > 0) nested_if -= 1 else {
                                    std.log.err("InvalidSyntax: #endif without matching #if at index {d}", .{j});
                                    return TemplateError.InvalidSyntax;
                                }
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
                    if (!found_target) {
                        std.log.err("MissingEndif: No matching #endif for #if at index {d}", .{i});
                        return TemplateError.MissingEndif;
                    }
                    i = skip_until.? - 1;
                }
            },
            .elseif_stmt => |condition| {
                if (depth_if == 0) {
                    std.log.err("InvalidSyntax: #elseif without matching #if at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }
                const current_depth = depth_if - 1;
                if (current_depth >= rendered_if_true_at_depth.items.len) {
                    std.log.err("InvalidSyntax: #elseif depth mismatch at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }

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
                                if (nested_if > 0) nested_if -= 1 else {
                                    std.log.err("InvalidSyntax: #endif without matching #if at index {d}", .{j});
                                    return TemplateError.InvalidSyntax;
                                }
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
                    if (!found_target) {
                        std.log.err("MissingEndif: No matching #endif for #elseif at index {d}", .{i});
                        return TemplateError.MissingEndif;
                    }
                    i = skip_until.? - 1;
                } else {
                    const should_render = try evaluateCondition(allocator, ctx, condition);
                    if (should_render) {
                        rendered_if_true_at_depth.items[current_depth] = true;
                    } else {
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
                                    if (nested_if > 0) nested_if -= 1 else {
                                        std.log.err("InvalidSyntax: #endif without matching #if at index {d}", .{j});
                                        return TemplateError.InvalidSyntax;
                                    }
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
                        if (!found_target) {
                            std.log.err("MissingEndif: No matching #endif for #elseif at index {d}", .{i});
                            return TemplateError.MissingEndif;
                        }
                        i = skip_until.? - 1;
                    }
                }
            },
            .else_stmt => {
                if (depth_if == 0) {
                    std.log.err("InvalidSyntax: #else without matching #if at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }
                const current_depth = depth_if - 1;
                if (current_depth >= rendered_if_true_at_depth.items.len) {
                    std.log.err("InvalidSyntax: #else depth mismatch at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }

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
                                if (nested_if > 0) nested_if -= 1 else {
                                    std.log.err("InvalidSyntax: #endif without matching #if at index {d}", .{j});
                                    return TemplateError.InvalidSyntax;
                                }
                            },
                            else => {},
                        }
                    }
                    if (!found_target) {
                        std.log.err("MissingEndif: No matching #endif for #else at index {d}", .{i});
                        return TemplateError.MissingEndif;
                    }
                    i = skip_until.? - 1;
                } else {
                    rendered_if_true_at_depth.items[current_depth] = true;
                }
            },
            .endif_stmt => {
                if (depth_if == 0) {
                    std.log.err("InvalidSyntax: #endif without matching #if at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }
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
                            if (nested > 0) nested -= 1 else {
                                std.log.err("InvalidSyntax: #endfor without matching #for at index {d}", .{j});
                                return TemplateError.InvalidSyntax;
                            }
                        },
                        else => {},
                    }
                }
                if (loop_end_idx == null) {
                    std.log.err("MissingEndfor: No matching #endfor for #for at index {d}", .{i});
                    return TemplateError.MissingEndfor;
                }
                const end_idx = loop_end_idx.?;

                const collection_val_str = ctx.get(loop.collection) orelse "";
                var items_allocator = std.heap.ArenaAllocator.init(allocator);
                defer items_allocator.deinit();
                const item_alloc = items_allocator.allocator();
                var loop_items = std.ArrayList([]const u8).init(item_alloc);

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

                if (!parsed_json and collection_val_str.len > 0) {
                    var it = std.mem.splitScalar(u8, collection_val_str, ',');
                    while (it.next()) |item_part| {
                        const trimmed_item = std.mem.trim(u8, item_part, " \t");
                        try loop_items.append(try item_alloc.dupe(u8, trimmed_item));
                    }
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

                    for (loop_items.items) |item_value| {
                        try ctx.setOwned(loop.var_name, try allocator.dupe(u8, item_value));
                        try renderTokens(allocator, tokens, loop_body_start, loop_body_end, ctx, output, block_content_map, depth);
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
                if (depth_for == 0) {
                    std.log.err("InvalidSyntax: #endfor without matching #for at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }
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
                            if (nested > 0) nested -= 1 else {
                                std.log.err("InvalidSyntax: #endwhile without matching #while at index {d}", .{j});
                                return TemplateError.InvalidSyntax;
                            }
                        },
                        else => {},
                    }
                }
                if (loop_end_idx == null) {
                    std.log.err("MissingEndwhile: No matching #endwhile for #while at index {d}", .{i});
                    return TemplateError.MissingEndwhile;
                }
                const end_idx = loop_end_idx.?;

                var iteration_count: usize = 0;
                const max_iterations: usize = 1000;
                const loop_body_start = i + 1;
                const loop_body_end = end_idx;

                while (iteration_count < max_iterations) {
                    const continue_loop = try evaluateCondition(allocator, ctx, condition);
                    if (!continue_loop) break;

                    iteration_count += 1;
                    try renderTokens(allocator, tokens, loop_body_start, loop_body_end, ctx, output, block_content_map, depth);
                }

                if (iteration_count >= max_iterations) {
                    std.log.err("While loop exceeded max iterations ({d}) for condition at index {d}", .{ max_iterations, i });
                    return TemplateError.WhileLoopOverflow;
                }

                i = end_idx;
                depth_while -= 1;
            },
            .endwhile_stmt => {
                if (depth_while == 0) {
                    std.log.err("InvalidSyntax: #endwhile without matching #while at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }
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
                            if (nested > 0) nested -= 1 else {
                                std.log.err("InvalidSyntax: #endblock without matching #block at index {d}", .{j});
                                return TemplateError.InvalidSyntax;
                            }
                        },
                        else => {},
                    }
                }
                if (block_end_idx == null) {
                    std.log.err("MissingEndblock: No matching #endblock for #block at index {d}", .{i});
                    return TemplateError.MissingEndblock;
                }
                const end_idx = block_end_idx.?;

                if (block_content_map) |bcm| {
                    if (bcm.get(name)) |content_from_child| {
                        try output.appendSlice(content_from_child);
                        i = end_idx;
                    } else {
                        try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, bcm, depth);
                        i = end_idx;
                    }
                } else {
                    try renderTokens(allocator, tokens, i + 1, end_idx, ctx, output, null, depth);
                    i = end_idx;
                }
                depth_block -= 1;
            },
            .endblock_stmt => {
                if (depth_block == 0) {
                    std.log.err("InvalidSyntax: #endblock without matching #block at index {d}", .{i});
                    return TemplateError.InvalidSyntax;
                }
            },
            .extends => {
                std.log.err("InvalidSyntax: #extends encountered during recursive renderTokens call at index {d}, depth {d}", .{ i, depth });
                return TemplateError.InvalidSyntax;
            },
            .include => |path| {
                //std.log.debug("Including template: {s}, depth {d}", .{ path, depth + 1 });
                const token_list_ptr = try cache.getTokens(path) orelse {
                    std.log.err("Template not found in cache: '{s}'", .{path});
                    return TemplateError.FileNotFound;
                };
                try renderTokens(
                    allocator,
                    token_list_ptr.items,
                    0,
                    token_list_ptr.items.len,
                    ctx,
                    output,
                    block_content_map,
                    depth + 1,
                );
            },
            .css => |path| {
                _ = path;
                //std.log.debug("Skipping CSS token: {s} at depth {d}", .{ path, depth });
                continue;
            },
            .js => |path| {
                _ = path;
                //std.log.debug("Skipping JS token: {s} at depth {d}", .{ path, depth });
                continue;
            },
        }
    }

    if (start_index == 0 and skip_until == null) {
        if (depth_if != 0) {
            std.log.err("MissingEndif: Unclosed #if at end of template", .{});
            return TemplateError.MissingEndif;
        }
        if (depth_for != 0) {
            std.log.err("MissingEndfor: Unclosed #for at end of template", .{});
            return TemplateError.MissingEndfor;
        }
        if (depth_while != 0) {
            std.log.err("MissingEndwhile: Unclosed #while at end of template", .{});
            return TemplateError.MissingEndwhile;
        }
        if (depth_block != 0) {
            std.log.err("MissingEndblock: Unclosed #block at end of template", .{});
            return TemplateError.MissingEndblock;
        }
    }
}
