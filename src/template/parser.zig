// src/template/parser.zig
const std = @import("std");
const types = @import("types.zig");
const TemplateError = types.TemplateError;
const Condition = types.Condition;
const Token = types.Token;

pub fn findEndOfDirective(content: []const u8, start_pos: usize) usize {
    var current_pos = start_pos;
    // Find the next newline character(s)
    while (current_pos < content.len and content[current_pos] != '\n' and content[current_pos] != '\r') {
        current_pos += 1;
    }
    // Consume the newline character(s) (LF, CRLF, or CR)
    if (current_pos < content.len) {
        if (content[current_pos] == '\r') {
            current_pos += 1;
            if (current_pos < content.len and content[current_pos] == '\n') {
                current_pos += 1; // Consume LF after CR
            }
        } else if (content[current_pos] == '\n') {
            current_pos += 1; // Consume LF
        }
    }
    return current_pos;
}

pub fn getDirectiveContent(content: []const u8, tag_start_pos: usize, tag_len: usize) []const u8 {
    const content_start = tag_start_pos + tag_len;
    var content_end = content_start;
    // Find the end of the line (excluding newline chars)
    while (content_end < content.len and content[content_end] != '\n' and content[content_end] != '\r') {
        content_end += 1;
    }
    // Trim whitespace from the extracted content
    return std.mem.trim(u8, content[content_start..content_end], " \t");
}

pub fn parseCondition(allocator: std.mem.Allocator, content: []const u8) TemplateError!Condition {
    const trimmed = std.mem.trim(u8, content, " \t");
    if (trimmed.len == 0) return TemplateError.InvalidSyntax;

    // Check for logical operators 'and' or 'or', respecting parenthesis
    var paren_depth: usize = 0;
    var split_pos: ?usize = null;
    var split_op: []const u8 = "";
    // --- FIX: Add variable to store operator length ---
    var split_op_len: usize = 0;

    for (trimmed, 0..) |c, i| {
        if (c == '(') {
            paren_depth += 1;
        } else if (c == ')') {
            if (paren_depth == 0) return TemplateError.InvalidSyntax; // Mismatched parens
            paren_depth -= 1;
        } else if (paren_depth == 0) {
            // Check for " and " or " or " with spaces
            if (i + 5 <= trimmed.len and std.mem.eql(u8, trimmed[i .. i + 5], " and ")) {
                if (split_pos == null) { // Keep the first one found
                    split_pos = i;
                    split_op = "and";
                    // --- FIX: Store length ---
                    split_op_len = 5;
                }
            } else if (i + 4 <= trimmed.len and std.mem.eql(u8, trimmed[i .. i + 4], " or ")) {
                if (split_pos == null) { // Keep the first one found
                    split_pos = i;
                    split_op = "or";
                    // --- FIX: Store length ---
                    split_op_len = 4;
                }
            }
        }
    }
    if (paren_depth != 0) return TemplateError.InvalidSyntax; // Mismatched parens overall

    if (split_pos) |pos| {
        const left_str = std.mem.trim(u8, trimmed[0..pos], " \t");
        // --- FIX: Use stored length ---
        const right_start = pos + split_op_len;
        const right_str = std.mem.trim(u8, trimmed[right_start..], " \t");

        if (left_str.len == 0 or right_str.len == 0) return TemplateError.InvalidSyntax;

        // Recursively parse sub-conditions
        const left_condition = try allocator.create(Condition);
        errdefer allocator.destroy(left_condition);
        const right_condition = try allocator.create(Condition);
        errdefer allocator.destroy(right_condition);

        left_condition.* = try parseCondition(allocator, left_str);
        right_condition.* = try parseCondition(allocator, right_str);

        // Use the split_op variable which is definitely known here
        return if (std.mem.eql(u8, split_op, "and"))
            Condition{ .logical_and = .{ .left = left_condition, .right = right_condition } }
        else // Must be "or"
            Condition{ .logical_or = .{ .left = left_condition, .right = right_condition } };
    }

    // Handle Parenthesis Grouping if no logical operator was found at top level
    if (trimmed.len >= 2 and trimmed[0] == '(' and trimmed[trimmed.len - 1] == ')') {
        // Basic check for balanced parens within the outer group
        paren_depth = 0;
        var balanced = true;
        for (trimmed[1 .. trimmed.len - 1]) |c| {
            if (c == '(') {
                paren_depth += 1;
            } else if (c == ')') {
                if (paren_depth == 0) {
                    balanced = false;
                    break;
                }
                paren_depth -= 1;
            }
        }
        if (!balanced or paren_depth != 0) return TemplateError.InvalidSyntax;

        // If balanced, recursively parse the content inside the parentheses
        return parseCondition(allocator, trimmed[1 .. trimmed.len - 1]);
    }

    // Handle comparison operators
    const operators = [_]struct { op: []const u8, tag: std.meta.Tag(Condition) }{
        // Order matters: check longer operators first
        .{ .op = "==", .tag = .equals },
        .{ .op = "!=", .tag = .not_equals },
        .{ .op = "<=", .tag = .less_than_or_equal },
        .{ .op = ">=", .tag = .greater_than_or_equal },
        .{ .op = "<", .tag = .less_than },
        .{ .op = ">", .tag = .greater_than },
    };

    for (operators) |op| {
        // Find the first occurrence of the operator
        if (std.mem.indexOf(u8, trimmed, op.op)) |op_pos| {
            // Basic check to avoid matching operator within identifiers (e.g. "my==var")
            // A proper tokenizer would be more robust.
            if (op_pos > 0 and std.ascii.isAlphanumeric(trimmed[op_pos - 1])) continue;
            const end_op_pos = op_pos + op.op.len;
            if (end_op_pos < trimmed.len and std.ascii.isAlphanumeric(trimmed[end_op_pos])) continue;

            const var_name = std.mem.trim(u8, trimmed[0..op_pos], " \t");
            var raw_value = std.mem.trim(u8, trimmed[end_op_pos..], " \t");
            var is_literal = false;
            var value_content: []const u8 = raw_value; // Content if literal, or the full raw_value if identifier

            if (raw_value.len >= 2 and ((raw_value[0] == '"' and raw_value[raw_value.len - 1] == '"') or (raw_value[0] == '\'' and raw_value[raw_value.len - 1] == '\''))) {
                value_content = raw_value[1 .. raw_value.len - 1];
                is_literal = true;
            }

            // Special case handling for '!= ""' or '!= '''
            if (op.tag == .not_equals and is_literal and value_content.len == 0) {
                // Ensure the right side was *only* the empty quotes and var_name is valid
                if (raw_value.len == 2 and var_name.len > 0) {
                    // Validate var_name contains only valid identifier characters
                    for (var_name) |c| {
                        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '.') {
                            std.debug.print("Invalid variable name in non_empty condition: '{s}'\n", .{var_name});
                            return TemplateError.InvalidSyntax;
                        }
                    }
                    return Condition{ .non_empty = var_name };
                } else {
                    std.debug.print("Invalid non_empty syntax: raw_value='{s}', var_name='{s}'\n", .{ raw_value, var_name });
                    return TemplateError.InvalidSyntax;
                }
            }

            // General validation for comparison operators
            if (var_name.len == 0) return TemplateError.InvalidSyntax; // Left side must exist
            if (raw_value.len == 0) return TemplateError.InvalidSyntax; // Right side must exist (either literal quotes or identifier)

            // If the right side is NOT a literal, its identifier name cannot be empty
            if (!is_literal and value_content.len == 0) return TemplateError.InvalidSyntax;

            // Use the content inside quotes if literal, otherwise the raw identifier
            const final_value = value_content;

            return switch (op.tag) {
                .equals => Condition{ .equals = .{ .var_name = var_name, .value = final_value, .is_literal = is_literal } },
                .not_equals => Condition{ .not_equals = .{ .var_name = var_name, .value = final_value, .is_literal = is_literal } },
                .less_than => Condition{ .less_than = .{ .var_name = var_name, .value = final_value, .is_literal = is_literal } },
                .less_than_or_equal => Condition{ .less_than_or_equal = .{ .var_name = var_name, .value = final_value, .is_literal = is_literal } },
                .greater_than => Condition{ .greater_than = .{ .var_name = var_name, .value = final_value, .is_literal = is_literal } },
                .greater_than_or_equal => Condition{ .greater_than_or_equal = .{ .var_name = var_name, .value = final_value, .is_literal = is_literal } },
                else => unreachable,
            };
        }
    }

    // Simple truthiness check (if no operators or logical constructs matched)
    // Perform basic validation: must not be empty and maybe check for valid identifier chars
    if (trimmed.len == 0) return TemplateError.InvalidSyntax;
    // Could add stricter validation here (e.g., check allowed characters) if needed
    // For now, accept any non-empty string that wasn't parsed as something else.
    return .{ .simple = trimmed };
}

pub fn tokenize(allocator: std.mem.Allocator, template: []const u8) !std.ArrayList(Token) {
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
            const condition = try parseCondition(allocator, condition_str); // Uses updated parseCondition
            try tokens.append(.{ .if_start = condition });
            pos = findEndOfDirective(template, pos + 4);
        } else if (std.mem.startsWith(u8, remaining, "#elseif ")) {
            first_tag_found = true;
            const condition_str = getDirectiveContent(template, pos, 8);
            const condition = try parseCondition(allocator, condition_str); // Uses updated parseCondition
            try tokens.append(.{ .elseif_stmt = condition });
            pos = findEndOfDirective(template, pos + 8);
        } else if (std.mem.startsWith(u8, remaining, "#else")) {
            const line_content = getDirectiveContent(template, pos, 5);
            // Allow only whitespace after #else
            if (line_content.len > 0 and std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
            first_tag_found = true;
            try tokens.append(.else_stmt);
            pos = findEndOfDirective(template, pos + 5);
        } else if (std.mem.startsWith(u8, remaining, "#endif")) {
            const line_content = getDirectiveContent(template, pos, 6);
            // Allow only whitespace after #endif
            if (line_content.len > 0 and std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
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
            // Basic validation: loop variable name shouldn't contain spaces
            if (std.mem.indexOfScalar(u8, var_name, ' ') != null) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .for_start = .{ .var_name = var_name, .collection = collection } });
            pos = findEndOfDirective(template, pos + 5);
        } else if (std.mem.startsWith(u8, remaining, "#endfor")) {
            const line_content = getDirectiveContent(template, pos, 7);
            // Allow only whitespace after #endfor
            if (line_content.len > 0 and std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
            first_tag_found = true;
            try tokens.append(.endfor_stmt);
            pos = findEndOfDirective(template, pos + 7);
        } else if (std.mem.startsWith(u8, remaining, "#while ")) {
            first_tag_found = true;
            const condition_str = getDirectiveContent(template, pos, 7);
            const condition = try parseCondition(allocator, condition_str); // Uses updated parseCondition
            try tokens.append(.{ .while_start = condition });
            pos = findEndOfDirective(template, pos + 7);
        } else if (std.mem.startsWith(u8, remaining, "#endwhile")) {
            const line_content = getDirectiveContent(template, pos, 9);
            // Allow only whitespace after #endwhile
            if (line_content.len > 0 and std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
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
            // Basic validation: variable name shouldn't contain spaces
            if (std.mem.indexOfScalar(u8, var_name, ' ') != null) return TemplateError.InvalidSetExpression;
            try tokens.append(.{ .set_stmt = .{ .var_name = var_name, .value = value } });
            pos = findEndOfDirective(template, pos + 5);
        } else if (std.mem.startsWith(u8, remaining, "#extends ")) {
            // Check if this is the very first non-whitespace content
            if (first_tag_found) return TemplateError.ExtendsMustBeFirst;
            first_tag_found = true; // Mark tag found now

            var path = getDirectiveContent(template, pos, 9);
            // Validate path is quoted string literal
            if (path.len < 2 or !((path[0] == '"' and path[path.len - 1] == '"') or (path[0] == '\'' and path[path.len - 1] == '\''))) {
                std.debug.print("Invalid #extends path format: '{s}'\n", .{path});
                return TemplateError.InvalidSyntax;
            }
            path = path[1 .. path.len - 1]; // Extract path content
            if (path.len == 0) return TemplateError.InvalidSyntax; // Path cannot be empty
            try tokens.append(.{ .extends = path });
            pos = findEndOfDirective(template, pos + 9);
        } else if (std.mem.startsWith(u8, remaining, "#block ")) {
            first_tag_found = true;
            const name = getDirectiveContent(template, pos, 7);
            if (name.len == 0 or std.mem.indexOfScalar(u8, name, ' ') != null) return TemplateError.InvalidSyntax; // Block name check
            try tokens.append(.{ .block_start = name });
            pos = findEndOfDirective(template, pos + 7);
        } else if (std.mem.startsWith(u8, remaining, "#endblock")) {
            const name_maybe = getDirectiveContent(template, pos, 9);
            // Allow optional name, but only whitespace if present
            if (name_maybe.len > 0 and std.mem.indexOfNone(u8, name_maybe, " \t") != null) {
                const trimmed_name = std.mem.trim(u8, name_maybe, " \t");
                // If name is specified, it shouldn't contain spaces
                if (std.mem.indexOfScalar(u8, trimmed_name, ' ') != null) {
                    return TemplateError.InvalidSyntax;
                }
            }

            first_tag_found = true;
            try tokens.append(.endblock_stmt);
            pos = findEndOfDirective(template, pos + 9);
        } else {
            // Handle Text content
            const delimiters = [_][]const u8{
                "{{",        "#if ",    "#elseif ",  "#else",     "#endif",
                "#for ",     "#endfor", "#while ",   "#endwhile", "#set ",
                "#extends ", "#block ", "#endblock",
            };
            var text_end_offset: usize = remaining.len; // Assume text goes to the end initially
            for (delimiters) |delim| {
                if (std.mem.indexOf(u8, remaining, delim)) |delim_pos| {
                    // Found a delimiter, check if it's closer than the current end
                    if (delim_pos < text_end_offset) {
                        text_end_offset = delim_pos;
                    }
                }
            }

            if (text_end_offset > 0) {
                // Found some text before the next delimiter (or end of template)
                const text_slice = remaining[0..text_end_offset];
                // Check if this text is purely whitespace before the first *actual* tag
                const is_only_whitespace = (std.mem.indexOfNone(u8, text_slice, " \t\n\r") == null);

                if (!first_tag_found and is_only_whitespace) {
                    // Skip leading whitespace before any directive/variable tag
                } else {
                    try tokens.append(.{ .text = text_slice });
                    // Mark first tag found if we add non-whitespace text or any tag was previously found
                    if (!is_only_whitespace) {
                        first_tag_found = true;
                    }
                }
                pos += text_end_offset;
            } else {
                // text_end_offset is 0. This means a delimiter starts exactly at 'pos'.
                // The next loop iteration will handle the delimiter.
                // If pos is already at the end, the loop condition (pos < template.len) will fail.
                if (pos >= template.len) {
                    break; // End of template reached
                }
                // Safety check: if delimiter not handled, error out. Should not happen.
                var delimiter_found_at_pos = false;
                for (delimiters) |delim| {
                    if (std.mem.startsWith(u8, remaining, delim)) {
                        delimiter_found_at_pos = true;
                        break;
                    }
                }
                if (!delimiter_found_at_pos and !std.mem.startsWith(u8, remaining, "{{")) {
                    // A case where text_end_offset is 0 but no known delimiter starts here?
                    std.debug.print("Parser state error: No text and no known delimiter at pos {d}.\n", .{pos});
                    return TemplateError.InvalidSyntax;
                }
                // Otherwise, just let the next loop iteration handle the delimiter tag.
            }
        }
    }

    return tokens;
}
