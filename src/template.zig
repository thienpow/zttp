const std = @import("std");
pub const Context = @import("context.zig").Context;

pub const TemplateError = error{
    InvalidSyntax,
    MissingEndif,
    MissingEndfor,
    MissingEndwhile,
    FileNotFound,
    OutOfMemory,
    UnclosedTag,
    InvalidCollection,
    InvalidSetExpression,
    WhileLoopOverflow,
};

const Condition = union(enum) {
    simple: []const u8, // e.g., "logged_in" or "username"
    non_empty: []const u8, // e.g., "username" for username != ""
    equals: struct { var_name: []const u8, value: []const u8 }, // e.g., role == "user"
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
    set_stmt: struct { var_name: []const u8, value: []const u8 },
};

fn parseCondition(content: []const u8) TemplateError!Condition {
    const trimmed = std.mem.trim(u8, content, " \t");
    if (std.mem.indexOf(u8, trimmed, " != ")) |ne_pos| {
        const var_name = std.mem.trim(u8, trimmed[0..ne_pos], " \t");
        const right = std.mem.trim(u8, trimmed[ne_pos + 4 ..], " \t");
        if (std.mem.eql(u8, right, "\"\"") and var_name.len > 0) {
            return .{ .non_empty = var_name };
        }
    } else if (std.mem.indexOf(u8, trimmed, " == ")) |eq_pos| {
        const var_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
        const right = std.mem.trim(u8, trimmed[eq_pos + 4 ..], " \t");
        if (right.len >= 2 and right[0] == '"' and right[right.len - 1] == '"') {
            const value = right[1 .. right.len - 1];
            if (var_name.len > 0) {
                return .{ .equals = .{ .var_name = var_name, .value = value } };
            }
        }
    }
    if (trimmed.len == 0) return TemplateError.InvalidSyntax;
    return .{ .simple = trimmed };
}

pub fn renderTemplate(allocator: std.mem.Allocator, template: []const u8, ctx: *Context) ![]const u8 {
    // Read template file
    //std.log.debug("Template content (string):\n{s}", .{template});

    // Tokenization
    var tokens = std.ArrayList(Token).init(allocator);
    defer tokens.deinit();

    var pos: usize = 0;
    while (pos < template.len) {
        //std.log.debug("Tokenizer pos: {d}, remaining: {s}", .{ pos, template[pos..] });
        if (std.mem.startsWith(u8, template[pos..], "{{")) {
            const start = pos + 2;
            const end = std.mem.indexOf(u8, template[start..], "}}") orelse return TemplateError.InvalidSyntax;
            const var_name = template[start .. start + end];
            if (var_name.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .variable = var_name });
            //std.log.debug("Token: variable, value: {s}", .{var_name});
            pos = start + end + 2;
        } else if (std.mem.startsWith(u8, template[pos..], "#if ")) {
            const start = pos + 4;
            const end = std.mem.indexOfAny(u8, template[start..], "\n\r") orelse template.len - start;
            const condition = try parseCondition(template[start .. start + end]);
            try tokens.append(.{ .if_start = condition });
            // switch (condition) {
            //     .simple => |c| std.log.debug("Token: if_start, simple: {s}", .{c}),
            //     .non_empty => |v| std.log.debug("Token: if_start, non_empty: {s}", .{v}),
            //     .equals => |e| std.log.debug("Token: if_start, equals: {s} == {s}", .{ e.var_name, e.value }),
            // }
            pos = start + end;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#elseif ")) {
            const start = pos + 8;
            const end = std.mem.indexOfAny(u8, template[start..], "\n\r") orelse template.len - start;
            const condition = try parseCondition(template[start .. start + end]);
            try tokens.append(.{ .elseif_stmt = condition });
            // switch (condition) {
            //     .simple => |c| std.log.debug("Token: elseif_stmt, simple: {s}", .{c}),
            //     .non_empty => |v| std.log.debug("Token: elseif_stmt, non_empty: {s}", .{v}),
            //     .equals => |e| std.log.debug("Token: elseif_stmt, equals: {s} == {s}", .{ e.var_name, e.value }),
            // }
            pos = start + end;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#else")) {
            try tokens.append(.else_stmt);
            //std.log.debug("Token: else_stmt", .{});
            pos += 5;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#endif")) {
            try tokens.append(.endif_stmt);
            //std.log.debug("Token: endif_stmt", .{});
            pos += 6;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#for ")) {
            const start = pos + 5;
            const end = std.mem.indexOfAny(u8, template[start..], "\n\r") orelse template.len - start;
            const content = std.mem.trim(u8, template[start .. start + end], " \t");
            const in_pos = std.mem.indexOf(u8, content, " in ") orelse return TemplateError.InvalidSyntax;
            const var_name = content[0..in_pos];
            const collection = content[in_pos + 4 ..];
            if (var_name.len == 0 or collection.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .for_start = .{ .var_name = var_name, .collection = collection } });
            //std.log.debug("Token: for_start, var: {s}, collection: {s}", .{ var_name, collection });
            pos = start + end;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#endfor")) {
            try tokens.append(.endfor_stmt);
            //std.log.debug("Token: endfor_stmt", .{});
            pos += 7;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#while ")) {
            const start = pos + 7;
            const end = std.mem.indexOfAny(u8, template[start..], "\n\r") orelse template.len - start;
            const condition = std.mem.trim(u8, template[start .. start + end], " \t");
            if (condition.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .while_start = condition });
            //std.log.debug("Token: while_start, condition: {s}", .{condition});
            pos = start + end;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#endwhile")) {
            try tokens.append(.endwhile_stmt);
            //std.log.debug("Token: endwhile_stmt", .{});
            pos += 9;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "#set ")) {
            const start = pos + 5;
            const end = std.mem.indexOfAny(u8, template[start..], "\n\r") orelse template.len - start;
            const content = std.mem.trim(u8, template[start .. start + end], " \t");
            const eq_pos = std.mem.indexOf(u8, content, " = ") orelse return TemplateError.InvalidSyntax;
            const var_name = std.mem.trim(u8, content[0..eq_pos], " ");
            const value = std.mem.trim(u8, content[eq_pos + 3 ..], " ");
            if (var_name.len == 0 or value.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .set_stmt = .{ .var_name = var_name, .value = value } });
            //std.log.debug("Token: set_stmt, var: {s}, value: {s}", .{ var_name, value });
            pos = start + end;
            if (pos < template.len and (template[pos] == '\n' or template[pos] == '\r')) pos += 1;
        } else if (std.mem.startsWith(u8, template[pos..], "<style>")) {
            const start = pos;
            const end = std.mem.indexOf(u8, template[start + 7 ..], "</style>") orelse return TemplateError.UnclosedTag;
            pos = start + 7 + end + 8;
            //std.log.debug("Skipped style section", .{});
            continue;
        } else if (std.mem.startsWith(u8, template[pos..], "<script")) {
            const start = pos;
            const end = std.mem.indexOf(u8, template[start..], "</script>") orelse return TemplateError.UnclosedTag;
            pos = start + end + 9;
            //std.log.debug("Skipped script section", .{});
            continue;
        } else {
            const delimiters = [_][]const u8{ "#endfor", "{{", "#if ", "#elseif ", "#else", "#endif", "#for ", "#while ", "#endwhile", "#set ", "<style>", "<script" };
            var end_offset: usize = template.len - pos;
            for (delimiters) |delim| {
                if (std.mem.indexOf(u8, template[pos..], delim)) |delim_pos| {
                    if (delim_pos < end_offset) end_offset = delim_pos;
                }
            }
            if (end_offset > 0) {
                const text_slice = template[pos .. pos + end_offset];
                try tokens.append(.{ .text = text_slice });
                //std.log.debug("Token: text, value: {s}", .{text_slice});
                pos += end_offset;
            } else {
                //std.log.debug("Advancing pos, no delimiter found", .{});
                pos += 1;
            }
        }
    }

    // Rendering
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    var skip_until: ?usize = null;
    var depth_if: usize = 0;
    var depth_for: usize = 0;
    var depth_while: usize = 0;
    var rendered_at_depth = std.ArrayList(bool).init(allocator);
    defer rendered_at_depth.deinit();

    var i: usize = 0;
    while (i < tokens.items.len) {
        //std.log.debug("Rendering token {d}, depth_for: {d}, depth_if: {d}, rendered_at_depth[{d}]: {}", .{ i, depth_for, depth_if, depth_if, if (rendered_at_depth.items.len > depth_if) rendered_at_depth.items[depth_if] else false });
        if (skip_until) |until| {
            if (i >= until) skip_until = null else {
                switch (tokens.items[i]) {
                    .if_start => {
                        depth_if += 1;
                        try rendered_at_depth.append(false);
                    },
                    .endif_stmt => {
                        if (depth_if > 0) {
                            depth_if -= 1;
                            if (rendered_at_depth.items.len > 0) {
                                _ = rendered_at_depth.pop();
                            }
                        }
                    },
                    .for_start => depth_for += 1,
                    .endfor_stmt => {
                        if (depth_for > 0) {
                            depth_for -= 1;
                            //std.log.debug("Decrement depth_for to {d} in skip_until", .{depth_for});
                        }
                    },
                    .while_start => depth_while += 1,
                    .endwhile_stmt => {
                        if (depth_while > 0) {
                            depth_while -= 1;
                        }
                    },
                    else => {},
                }
                i += 1;
                continue;
            }
        }

        switch (tokens.items[i]) {
            .text => |text| if (text.len > 0) try output.appendSlice(text),
            .variable => |var_name| if (ctx.get(var_name)) |value| try output.appendSlice(value),
            .if_start => |condition| {
                try rendered_at_depth.append(false);
                depth_if += 1;
                //std.log.debug("Increment depth_if to {d}", .{depth_if});
                const should_render = switch (condition) {
                    .simple => |key| ctx.get(key) != null and (std.mem.eql(u8, key, "logged_in") and std.mem.eql(u8, ctx.get(key).?, "true") or
                        ctx.get(key).?.len > 0),
                    .non_empty => |var_name| ctx.get(var_name) != null and ctx.get(var_name).?.len > 0,
                    .equals => |eq| ctx.get(eq.var_name) != null and std.mem.eql(u8, ctx.get(eq.var_name).?, eq.value),
                };
                if (!should_render) {
                    var j = i + 1;
                    var nested: usize = 0;
                    while (j < tokens.items.len) : (j += 1) {
                        switch (tokens.items[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) {
                                    skip_until = j + 1;
                                    break;
                                }
                                nested -= 1;
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
                    if (skip_until == null) return TemplateError.MissingEndif;
                } else {
                    rendered_at_depth.items[depth_if - 1] = true;
                }
            },
            .elseif_stmt => |condition| {
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                if (rendered_at_depth.items.len > depth_if - 1 and rendered_at_depth.items[depth_if - 1]) {
                    // Skip to endif if a previous condition was rendered
                    var j = i + 1;
                    var nested: usize = 0;
                    while (j < tokens.items.len) : (j += 1) {
                        switch (tokens.items[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) {
                                    skip_until = j + 1;
                                    break;
                                }
                                nested -= 1;
                            },
                            else => {},
                        }
                    }
                    if (skip_until == null) return TemplateError.MissingEndif;
                } else {
                    var j = i + 1;
                    var nested: usize = 0;
                    while (j < tokens.items.len) : (j += 1) {
                        switch (tokens.items[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) {
                                    skip_until = j + 1;
                                    break;
                                }
                                nested -= 1;
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
                    if (skip_until == null) return TemplateError.MissingEndif;
                    const should_render = switch (condition) {
                        .simple => |key| ctx.get(key) != null and (std.mem.eql(u8, key, "logged_in") and std.mem.eql(u8, ctx.get(key).?, "true") or
                            ctx.get(key).?.len > 0),
                        .non_empty => |var_name| ctx.get(var_name) != null and ctx.get(var_name).?.len > 0,
                        .equals => |eq| ctx.get(eq.var_name) != null and std.mem.eql(u8, ctx.get(eq.var_name).?, eq.value),
                    };
                    if (should_render) {
                        skip_until = null;
                        rendered_at_depth.items[depth_if - 1] = true;
                    }
                }
            },
            .else_stmt => {
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                if (rendered_at_depth.items.len > depth_if - 1 and rendered_at_depth.items[depth_if - 1]) {
                    // Skip to endif if a previous condition was rendered
                    var j = i + 1;
                    var nested: usize = 0;
                    while (j < tokens.items.len) : (j += 1) {
                        switch (tokens.items[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) {
                                    skip_until = j + 1;
                                    break;
                                }
                                nested -= 1;
                            },
                            else => {},
                        }
                    }
                    if (skip_until == null) return TemplateError.MissingEndif;
                } else {
                    var j = i + 1;
                    var nested: usize = 0;
                    while (j < tokens.items.len) : (j += 1) {
                        switch (tokens.items[j]) {
                            .if_start => nested += 1,
                            .endif_stmt => {
                                if (nested == 0) {
                                    skip_until = j + 1;
                                    break;
                                }
                                nested -= 1;
                            },
                            else => {},
                        }
                    }
                    if (skip_until == null) return TemplateError.MissingEndif;
                    skip_until = null;
                    rendered_at_depth.items[depth_if - 1] = true;
                }
            },
            .endif_stmt => {
                if (depth_if == 0) return TemplateError.InvalidSyntax;
                depth_if -= 1;
                if (rendered_at_depth.items.len > 0) {
                    _ = rendered_at_depth.pop();
                }
                //std.log.debug("Decrement depth_if to {d}", .{depth_if});
            },
            .for_start => |loop| {
                depth_for += 1;
                //std.log.debug("Increment depth_for to {d}", .{depth_for});
                const collection = ctx.get(loop.collection) orelse return TemplateError.InvalidCollection;
                //std.log.debug("Collection: {s}", .{collection});

                var arena = std.heap.ArenaAllocator.init(allocator);
                defer arena.deinit();
                const json_allocator = arena.allocator();

                const parsed = try std.json.parseFromSlice(std.json.Value, json_allocator, collection, .{});
                const json_array: std.ArrayList(std.json.Value) = switch (parsed.value) {
                    .array => |arr| arr,
                    else => return TemplateError.InvalidCollection,
                };
                //std.log.debug("Array length: {d}", .{json_array.items.len});

                var j = i + 1;
                var nested: usize = 0;
                var loop_end: usize = tokens.items.len;
                while (j < tokens.items.len) : (j += 1) {
                    switch (tokens.items[j]) {
                        .for_start => nested += 1,
                        .endfor_stmt => {
                            if (nested == 0) {
                                loop_end = j;
                                break;
                            }
                            nested -= 1;
                        },
                        else => {},
                    }
                }
                if (loop_end >= tokens.items.len) return TemplateError.MissingEndfor;
                //std.log.debug("Loop end at token: {d}", .{loop_end});

                if (json_array.items.len == 0) {
                    i = loop_end - 1;
                    //std.log.debug("Empty array, set i to {d}", .{i});
                } else {
                    for (json_array.items) |item| {
                        const value = switch (item) {
                            .string => |str| str,
                            else => return TemplateError.InvalidCollection,
                        };
                        try ctx.set(loop.var_name, value);
                        var k = i + 1;
                        while (k < loop_end) : (k += 1) {
                            switch (tokens.items[k]) {
                                .text => |text| if (text.len > 0) try output.appendSlice(text),
                                .variable => |var_name| if (ctx.get(var_name)) |v| try output.appendSlice(v),
                                .set_stmt => |set| {
                                    if (std.mem.indexOf(u8, set.value, "+")) |plus_pos| {
                                        const left = std.mem.trim(u8, set.value[0..plus_pos], " ");
                                        const right = std.mem.trim(u8, set.value[plus_pos + 1 ..], " ");
                                        if (ctx.get(left)) |left_val| {
                                            const left_num = std.fmt.parseInt(usize, left_val, 10) catch return TemplateError.InvalidSetExpression;
                                            const right_num = std.fmt.parseInt(usize, right, 10) catch return TemplateError.InvalidSetExpression;
                                            const result = left_num + right_num;
                                            var buf: [32]u8 = undefined;
                                            const new_val = try std.fmt.bufPrint(&buf, "{}", .{result});
                                            try ctx.set(set.var_name, new_val);
                                        } else return TemplateError.InvalidSetExpression;
                                    } else {
                                        try ctx.set(set.var_name, set.value);
                                    }
                                },
                                else => {},
                            }
                        }
                    }
                    i = loop_end - 1;
                    //std.log.debug("Non-empty array, set i to {d}", .{i});
                }
            },
            .endfor_stmt => {
                if (depth_for == 0) return TemplateError.InvalidSyntax;
                depth_for -= 1;
                //std.log.debug("Decrement depth_for to {d}", .{depth_for});
            },
            .while_start => |condition| {
                depth_while += 1;
                //std.log.debug("Increment depth_while to {d}", .{depth_while});
                var j = i + 1;
                var nested: usize = 0;
                var loop_end: usize = tokens.items.len;
                while (j < tokens.items.len) : (j += 1) {
                    switch (tokens.items[j]) {
                        .while_start => nested += 1,
                        .endwhile_stmt => {
                            if (nested == 0) {
                                loop_end = j;
                                break;
                            }
                            nested -= 1;
                        },
                        else => {},
                    }
                }
                if (loop_end >= tokens.items.len) return TemplateError.MissingEndwhile;

                var iteration_count: usize = 0;
                const max_iterations: usize = 1000;
                while (true) {
                    if (iteration_count >= max_iterations) return TemplateError.WhileLoopOverflow;
                    iteration_count += 1;

                    var continue_loop = false;
                    if (std.mem.indexOf(u8, condition, " < ")) |lt_pos| {
                        const left = std.mem.trim(u8, condition[0..lt_pos], " ");
                        const right = std.mem.trim(u8, condition[lt_pos + 3 ..], " ");
                        if (ctx.get(left)) |left_val| {
                            const left_num = std.fmt.parseInt(usize, left_val, 10) catch return TemplateError.InvalidSetExpression;
                            const right_num = std.fmt.parseInt(usize, right, 10) catch return TemplateError.InvalidSetExpression;
                            continue_loop = left_num < right_num;
                        }
                    }
                    if (!continue_loop) break;

                    var k = i + 1;
                    while (k < loop_end) : (k += 1) {
                        switch (tokens.items[k]) {
                            .text => |text| if (text.len > 0) try output.appendSlice(text),
                            .variable => |var_name| if (ctx.get(var_name)) |value| try output.appendSlice(value),
                            .set_stmt => |set| {
                                if (std.mem.indexOf(u8, set.value, "+")) |plus_pos| {
                                    const left = std.mem.trim(u8, set.value[0..plus_pos], " ");
                                    const right = std.mem.trim(u8, set.value[plus_pos + 1 ..], " ");
                                    if (ctx.get(left)) |left_val| {
                                        const left_num = std.fmt.parseInt(usize, left_val, 10) catch return TemplateError.InvalidSetExpression;
                                        const right_num = std.fmt.parseInt(usize, right, 10) catch return TemplateError.InvalidSetExpression;
                                        const result = left_num + right_num;
                                        var buf: [32]u8 = undefined;
                                        const new_val = try std.fmt.bufPrint(&buf, "{}", .{result});
                                        try ctx.set(set.var_name, new_val);
                                    } else return TemplateError.InvalidSetExpression;
                                } else {
                                    try ctx.set(set.var_name, set.value);
                                }
                            },
                            else => {},
                        }
                    }
                }
                i = loop_end - 1;
                //std.log.debug("While loop, set i to {d}", .{i});
            },
            .endwhile_stmt => {
                if (depth_while == 0) return TemplateError.InvalidSyntax;
                depth_while -= 1;
                //std.log.debug("Decrement depth_while to {d}", .{depth_while});
            },
            .set_stmt => |set| {
                if (std.mem.indexOf(u8, set.value, "+")) |plus_pos| {
                    const left = std.mem.trim(u8, set.value[0..plus_pos], " ");
                    const right = std.mem.trim(u8, set.value[plus_pos + 1 ..], " ");
                    if (ctx.get(left)) |left_val| {
                        const left_num = std.fmt.parseInt(usize, left_val, 10) catch return TemplateError.InvalidSetExpression;
                        const right_num = std.fmt.parseInt(usize, right, 10) catch return TemplateError.InvalidSetExpression;
                        const result = left_num + right_num;
                        var buf: [32]u8 = undefined;
                        const new_val = try std.fmt.bufPrint(&buf, "{}", .{result});
                        try ctx.set(set.var_name, new_val);
                    } else return TemplateError.InvalidSetExpression;
                } else {
                    try ctx.set(set.var_name, set.value);
                }
            },
        }
        i += 1;
    }

    //std.log.debug("Final depth_for: {d}", .{depth_for});
    if (depth_if > 0) return TemplateError.MissingEndif;
    if (depth_for > 0) return TemplateError.MissingEndfor;
    if (depth_while > 0) return TemplateError.MissingEndwhile;

    // Extract sections
    const style_start = std.mem.indexOf(u8, template, "<style>");
    const style_end = if (style_start) |s| std.mem.indexOf(u8, template[s + 7 ..], "</style>") else null;
    const style_section = if (style_start != null and style_end != null) template[style_start.? .. style_start.? + 7 + style_end.? + 8] else "";

    const script_start = std.mem.indexOf(u8, template, "<script");
    const script_end = if (script_start) |s| std.mem.indexOf(u8, template[s..], "</script>") else null;
    const script_section = if (script_start != null and script_end != null) template[script_start.? .. script_start.? + script_end.? + 9] else "";

    // Final output
    var final_output = std.ArrayList(u8).init(allocator);
    defer final_output.deinit();

    if (style_section.len > 0) try final_output.appendSlice(style_section);
    try final_output.appendSlice(output.items);
    if (script_section.len > 0) try final_output.appendSlice(script_section);

    return final_output.toOwnedSlice();
}
