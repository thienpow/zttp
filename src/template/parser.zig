const std = @import("std");
const types = @import("types.zig");
const TemplateError = types.TemplateError;
const Condition = types.Condition;
const Token = types.Token;
const ComparisonData = types.ComparisonData;

/// Finds the position immediately after the end of the current line,
/// consuming the newline character(s) (LF, CRLF, or CR).
pub fn findEndOfDirective(content: []const u8, start_pos: usize) usize {
    var current_pos = start_pos;
    // Find the start of the newline sequence
    while (current_pos < content.len and content[current_pos] != '\n' and content[current_pos] != '\r') {
        current_pos += 1;
    }

    // Consume the newline character(s) if present
    if (current_pos < content.len) {
        if (content[current_pos] == '\r') {
            current_pos += 1; // Consume CR
            // Check for LF following CR (CRLF)
            if (current_pos < content.len and content[current_pos] == '\n') {
                current_pos += 1; // Consume LF
            }
        } else if (content[current_pos] == '\n') {
            current_pos += 1; // Consume LF
        }
    }
    return current_pos;
}

/// Extracts the content of a directive tag on the same line,
/// starting immediately after the tag itself and trimmed of leading/trailing whitespace.
/// Example: For "#if my_var", given start_pos of '#' and tag_len 4 ("#if "),
/// it returns "my_var".
pub fn getDirectiveContent(content: []const u8, tag_start_pos: usize, tag_len: usize) []const u8 {
    const content_start = tag_start_pos + tag_len;
    var content_end = content_start;

    // Find the end of the line (before newline chars)
    while (content_end < content.len and content[content_end] != '\n' and content[content_end] != '\r') {
        content_end += 1;
    }

    // Ensure slice bounds are valid before trimming
    const raw_content = if (content_start < content_end) content[content_start..content_end] else "";
    return std.mem.trim(u8, raw_content, " \t");
}

/// Parses a condition string into a structured Condition representation.
/// Handles logical operators (and, or), comparisons (==, !=, <, etc.),
/// parenthesis grouping, and simple truthiness checks.
pub fn parseCondition(allocator: std.mem.Allocator, content: []const u8) TemplateError!Condition {
    const trimmed = std.mem.trim(u8, content, " \t");
    if (trimmed.len == 0) return TemplateError.InvalidSyntax;

    // --- 1. Check for logical operators 'and' or 'or' outside parentheses ---
    var paren_depth: usize = 0;
    var split_pos: ?usize = null;
    var split_op: []const u8 = "";
    var split_op_len: usize = 0; // Length of the operator (" and " or " or ")

    for (trimmed, 0..) |c, i| {
        switch (c) {
            '(' => paren_depth += 1,
            ')' => {
                if (paren_depth == 0) return TemplateError.InvalidSyntax; // Mismatched closing parenthesis
                paren_depth -= 1;
            },
            else => {
                if (paren_depth == 0) {
                    // We are at the top level (not inside parentheses)
                    // Check for " and " (5 chars)
                    if (i + 5 <= trimmed.len and std.mem.eql(u8, trimmed[i .. i + 5], " and ")) {
                        // Use the first operator found at the top level for correct precedence
                        if (split_pos == null) {
                            split_pos = i;
                            split_op = "and";
                            split_op_len = 5;
                        }
                    }
                    // Check for " or " (4 chars)
                    else if (i + 4 <= trimmed.len and std.mem.eql(u8, trimmed[i .. i + 4], " or ")) {
                        if (split_pos == null) {
                            split_pos = i;
                            split_op = "or";
                            split_op_len = 4;
                        }
                    }
                }
            },
        }
    }
    if (paren_depth != 0) return TemplateError.InvalidSyntax; // Mismatched opening parenthesis

    if (split_pos) |pos| {
        const left_str = std.mem.trim(u8, trimmed[0..pos], " \t");
        const right_start = pos + split_op_len; // Start after the operator and its spaces
        const right_str = std.mem.trim(u8, trimmed[right_start..], " \t");

        if (left_str.len == 0 or right_str.len == 0) return TemplateError.InvalidSyntax;

        // Recursively parse sub-conditions
        // Need to allocate memory for the sub-conditions on the heap
        const left_condition_ptr = try allocator.create(Condition);
        errdefer allocator.destroy(left_condition_ptr);
        const right_condition_ptr = try allocator.create(Condition);
        errdefer allocator.destroy(right_condition_ptr);

        left_condition_ptr.* = try parseCondition(allocator, left_str);
        right_condition_ptr.* = try parseCondition(allocator, right_str);

        return switch (split_op[1]) { // Quick check on the second char ('n' for and, 'r' for or)
            'n' => Condition{ .logical_and = .{ .left = left_condition_ptr, .right = right_condition_ptr } },
            'r' => Condition{ .logical_or = .{ .left = left_condition_ptr, .right = right_condition_ptr } },
            else => unreachable, // Should be "and" or "or" if split_op is set
        };
    }

    // --- 2. Handle Parenthesis Grouping if no logical operator was found at top level ---
    if (trimmed.len >= 2 and trimmed[0] == '(' and trimmed[trimmed.len - 1] == ')') {
        // Check if the parentheses are balanced *within* this group
        // Note: The outer loop already confirmed overall balance. This ensures
        // the expression isn't like `(a) + (b)` which should have been caught by operator split.
        // It primarily handles cases like `((a and b))` -> `(a and b)`.
        var inner_paren_depth: usize = 0;
        var balanced_inner = true;
        for (trimmed[1 .. trimmed.len - 1]) |c| {
            if (c == '(') {
                inner_paren_depth += 1;
            } else if (c == ')') {
                if (inner_paren_depth == 0) {
                    balanced_inner = false;
                    break;
                }
                inner_paren_depth -= 1;
            }
        }
        // If the parentheses inside are balanced and match up, parse the inner content
        if (balanced_inner and inner_paren_depth == 0) {
            return parseCondition(allocator, trimmed[1 .. trimmed.len - 1]);
        } else {
            // If inner content is not balanced (e.g., `(()`) or doesn't form a single group (e.g. `(a) or (b)`)
            // Note: the latter case *should* have been caught by the logical operator split above.
            return TemplateError.InvalidSyntax;
        }
    }

    // --- 3. Handle comparison operators ---
    // Order matters: check longer operators first (e.g., >= before >)
    const operators = [_]struct { op: []const u8, tag: std.meta.Tag(Condition) }{
        .{ .op = "==", .tag = .equals },
        .{ .op = "!=", .tag = .not_equals },
        .{ .op = "<=", .tag = .less_than_or_equal },
        .{ .op = ">=", .tag = .greater_than_or_equal },
        .{ .op = "<", .tag = .less_than },
        .{ .op = ">", .tag = .greater_than },
    };

    // Iterate through operators at runtime
    for (operators) |op_info| {
        if (std.mem.indexOf(u8, trimmed, op_info.op)) |op_pos| {
            // Basic check to avoid matching operator within identifiers (e.g., "my==var").
            // A proper tokenizer/lexer would be more robust here.
            if (op_pos > 0 and std.ascii.isAlphanumeric(trimmed[op_pos - 1])) continue; // OK in runtime for
            const op_end_pos = op_pos + op_info.op.len;
            if (op_end_pos < trimmed.len and std.ascii.isAlphanumeric(trimmed[op_end_pos])) continue; // OK in runtime for

            const var_name = std.mem.trim(u8, trimmed[0..op_pos], " \t");
            const raw_value = std.mem.trim(u8, trimmed[op_end_pos..], " \t");

            if (var_name.len == 0 or raw_value.len == 0) return TemplateError.InvalidSyntax;

            var is_literal = false;
            var value_content: []const u8 = raw_value; // Content if literal, or the full raw_value if identifier

            // Check if the right-hand side is a quoted string literal
            if (raw_value.len >= 2 and ((raw_value[0] == '"' and raw_value[raw_value.len - 1] == '"') or (raw_value[0] == '\'' and raw_value[raw_value.len - 1] == '\''))) {
                value_content = raw_value[1 .. raw_value.len - 1]; // Extract content inside quotes
                is_literal = true;
            } else {
                // If not a literal, it must be a variable identifier. Validate it? (Basic check: not empty)
                if (value_content.len == 0) return TemplateError.InvalidSyntax;
                // Could add more validation for identifier characters here if desired.
            }

            // Special case: Optimize `variable != ""` or `variable != ''` into a 'non_empty' check.
            if (op_info.tag == .not_equals and is_literal and value_content.len == 0) {
                // Ensure the right side was *only* the empty quotes (`""` or `''`)
                if (raw_value.len == 2) {
                    // Validate var_name contains only valid identifier characters (alphanumeric, _, .)
                    // This prevents parsing something like `"some string" != ""` incorrectly.
                    for (var_name) |c| {
                        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '.') {
                            //std.debug.print("Invalid variable name in non_empty condition: '{s}'\n", .{var_name});
                            return TemplateError.InvalidSyntax;
                        }
                    }
                    return Condition{ .non_empty = try allocator.dupe(u8, var_name) };
                } else {
                    // This could happen if there was whitespace like `var != "  "` which trims to `""`
                    // but isn't the intended non_empty check. Treat as regular comparison.
                    // std.debug.print("Interpreting as standard not_equals: var='{s}', raw_value='{s}'\n", .{ var_name, raw_value });
                }
            }

            // Construct the appropriate comparison condition
            const comparison_data = ComparisonData{
                .var_name = try allocator.dupe(u8, var_name),
                .value = try allocator.dupe(u8, value_content),
                .is_literal = is_literal,
            };

            return switch (op_info.tag) {
                .equals => Condition{ .equals = comparison_data },
                .not_equals => Condition{ .not_equals = comparison_data },
                .less_than => Condition{ .less_than = comparison_data },
                .less_than_or_equal => Condition{ .less_than_or_equal = comparison_data },
                .greater_than => Condition{ .greater_than = comparison_data },
                .greater_than_or_equal => Condition{ .greater_than_or_equal = comparison_data },
                else => unreachable, // Only comparison tags are in the `operators` list
            };
        }
    }

    // --- 4. Simple truthiness check (if no operators or logical constructs matched) ---
    // The remaining `trimmed` string is treated as a variable name to check for truthiness.
    // Perform basic validation: must not be empty.
    if (trimmed.len == 0) return TemplateError.InvalidSyntax; // Should have been caught earlier, but safety check.
    // Could add stricter validation here (e.g., check allowed identifier characters) if needed.
    // For now, accept any non-empty string that wasn't parsed as something else.
    return Condition{ .simple = try allocator.dupe(u8, trimmed) };
}

/// Tokenizes the template content into a sequence of Tokens.
pub fn tokenize(allocator: std.mem.Allocator, template: []const u8) !std.ArrayList(Token) {
    var tokens = std.ArrayList(Token).init(allocator);
    errdefer tokens.deinit();

    var pos: usize = 0;
    // Tracks if any non-whitespace text or tag has been encountered.
    // Used to ignore leading whitespace and enforce #extends placement.
    var first_tag_found = false;

    while (pos < template.len) {
        const remaining = template[pos..];

        // Use `if/else if` chain for mutually exclusive tags starting at `pos`
        if (std.mem.startsWith(u8, remaining, "{{")) {
            first_tag_found = true;
            const start = pos + 2; // Start after "{{"
            const end_offset = std.mem.indexOf(u8, template[start..], "}}") orelse return TemplateError.UnclosedTag;
            const end = start + end_offset;
            const var_name = std.mem.trim(u8, template[start..end], " \t");
            if (var_name.len == 0) return TemplateError.InvalidSyntax; // Variable name cannot be empty
            try tokens.append(.{ .variable = try allocator.dupe(u8, var_name) });
            pos = end + 2; // Move past "}}"
        } else if (std.mem.startsWith(u8, remaining, "#include ")) {
            first_tag_found = true;
            const tag_len = 9; // Length of "#include "
            var path = getDirectiveContent(template, pos, tag_len);
            // Validate path is a quoted string
            if (path.len < 2 or !((path[0] == '"' and path[path.len - 1] == '"') or (path[0] == '\'' and path[path.len - 1] == '\''))) {
                std.debug.print("Invalid #include path: must be quoted (e.g., \"components/button\"), got: '{s}'\n", .{path});
                return TemplateError.InvalidSyntax;
            }
            path = path[1 .. path.len - 1]; // Extract content inside quotes
            if (path.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .include = try allocator.dupe(u8, path) });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#css ")) {
            first_tag_found = true;
            const tag_len = 5; // Length of "#css "
            var path = getDirectiveContent(template, pos, tag_len);
            // Validate path is a quoted string
            if (path.len < 2 or !((path[0] == '"' and path[path.len - 1] == '"') or (path[0] == '\'' and path[path.len - 1] == '\''))) {
                std.debug.print("Invalid #css path: must be quoted (e.g., \"/static/components/button.css\"), got: '{s}'\n", .{path});
                return TemplateError.InvalidSyntax;
            }
            path = path[1 .. path.len - 1]; // Extract content inside quotes
            if (path.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .css = try allocator.dupe(u8, path) });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#js ")) {
            first_tag_found = true;
            const tag_len = 4; // Length of "#js "
            var path = getDirectiveContent(template, pos, tag_len);
            // Validate path is a quoted string
            if (path.len < 2 or !((path[0] == '"' and path[path.len - 1] == '"') or (path[0] == '\'' and path[path.len - 1] == '\''))) {
                std.debug.print("Invalid #js path: must be quoted (e.g., \"/static/components/button.js\"), got: '{s}'\n", .{path});
                return TemplateError.InvalidSyntax;
            }
            path = path[1 .. path.len - 1]; // Extract content inside quotes
            if (path.len == 0) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .js = try allocator.dupe(u8, path) });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#if ")) {
            first_tag_found = true;
            const tag_len = 4;
            const condition_str = getDirectiveContent(template, pos, tag_len);
            const condition = try parseCondition(allocator, condition_str);
            try tokens.append(.{ .if_start = condition });
            pos = findEndOfDirective(template, pos + tag_len); // Move past "#if " and the condition line
        } else if (std.mem.startsWith(u8, remaining, "#elseif ")) {
            first_tag_found = true;
            const tag_len = 8;
            const condition_str = getDirectiveContent(template, pos, tag_len);
            const condition = try parseCondition(allocator, condition_str);
            try tokens.append(.{ .elseif_stmt = condition });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#else")) {
            first_tag_found = true;
            const tag_len = 5;
            const line_content = getDirectiveContent(template, pos, tag_len);
            // Allow only whitespace after #else
            if (std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
            try tokens.append(.else_stmt);
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#endif")) {
            first_tag_found = true;
            const tag_len = 6;
            const line_content = getDirectiveContent(template, pos, tag_len);
            // Allow only whitespace after #endif
            if (std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
            try tokens.append(.endif_stmt);
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#for ")) {
            first_tag_found = true;
            const tag_len = 5;
            const content = getDirectiveContent(template, pos, tag_len);
            const in_pos = std.mem.indexOf(u8, content, " in ") orelse return TemplateError.InvalidSyntax;
            const var_name = std.mem.trim(u8, content[0..in_pos], " \t");
            const collection = std.mem.trim(u8, content[in_pos + 4 ..], " \t"); // +4 for " in "
            if (var_name.len == 0 or collection.len == 0) return TemplateError.InvalidSyntax;
            // Basic validation: loop variable name shouldn't contain spaces
            if (std.mem.indexOfScalar(u8, var_name, ' ') != null) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .for_start = .{ .var_name = try allocator.dupe(u8, var_name), .collection = try allocator.dupe(u8, collection) } });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#endfor")) {
            first_tag_found = true;
            const tag_len = 7;
            const line_content = getDirectiveContent(template, pos, tag_len);
            // Allow only whitespace after #endfor
            if (std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
            try tokens.append(.endfor_stmt);
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#while ")) {
            first_tag_found = true;
            const tag_len = 7;
            const condition_str = getDirectiveContent(template, pos, tag_len);
            const condition = try parseCondition(allocator, condition_str);
            try tokens.append(.{ .while_start = condition });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#endwhile")) {
            first_tag_found = true;
            const tag_len = 9;
            const line_content = getDirectiveContent(template, pos, tag_len);
            // Allow only whitespace after #endwhile
            if (std.mem.indexOfNone(u8, line_content, " \t") != null) {
                return TemplateError.InvalidSyntax;
            }
            try tokens.append(.endwhile_stmt);
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#set ")) {
            first_tag_found = true;
            const tag_len = 5;
            const content = getDirectiveContent(template, pos, tag_len);
            const eq_pos = std.mem.indexOf(u8, content, "=") orelse return TemplateError.InvalidSetExpression;
            const var_name = std.mem.trim(u8, content[0..eq_pos], " \t");
            const value = std.mem.trim(u8, content[eq_pos + 1 ..], " \t");
            if (var_name.len == 0 or value.len == 0) return TemplateError.InvalidSetExpression;
            // Basic validation: variable name shouldn't contain spaces
            if (std.mem.indexOfScalar(u8, var_name, ' ') != null) return TemplateError.InvalidSetExpression;
            try tokens.append(.{ .set_stmt = .{ .var_name = try allocator.dupe(u8, var_name), .value = try allocator.dupe(u8, value) } });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#extends ")) {
            // Check if this is the very first non-whitespace content encountered
            if (first_tag_found) return TemplateError.ExtendsMustBeFirst;
            first_tag_found = true; // Mark tag found now

            const tag_len = 9;
            var path = getDirectiveContent(template, pos, tag_len);
            // Validate path is a quoted string literal
            if (path.len < 2 or !((path[0] == '"' and path[path.len - 1] == '"') or (path[0] == '\'' and path[path.len - 1] == '\''))) {
                //std.debug.print("Invalid #extends path format: must be quoted string (e.g., \"layout\"), got: '{s}'\n", .{path});
                return TemplateError.InvalidSyntax;
            }
            path = path[1 .. path.len - 1]; // Extract path content inside quotes
            if (path.len == 0) return TemplateError.InvalidSyntax; // Path cannot be empty
            try tokens.append(.{ .extends = try allocator.dupe(u8, path) });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#block ")) {
            first_tag_found = true;
            const tag_len = 7;
            const name = getDirectiveContent(template, pos, tag_len);
            // Block name must exist and contain no spaces
            if (name.len == 0 or std.mem.indexOfScalar(u8, name, ' ') != null) return TemplateError.InvalidSyntax;
            try tokens.append(.{ .block_start = try allocator.dupe(u8, name) });
            pos = findEndOfDirective(template, pos + tag_len);
        } else if (std.mem.startsWith(u8, remaining, "#endblock")) {
            first_tag_found = true;
            const tag_len = 9;
            const content_after_tag = getDirectiveContent(template, pos, tag_len);
            // Allow optional block name after #endblock, but it must be valid if present
            if (content_after_tag.len > 0) {
                const trimmed_name = std.mem.trim(u8, content_after_tag, " \t");
                // If name is specified, it shouldn't contain spaces or be empty after trim
                if (trimmed_name.len == 0 or std.mem.indexOfScalar(u8, trimmed_name, ' ') != null) {
                    //std.debug.print("Invalid optional block name after #endblock: '{s}'\n", .{content_after_tag});
                    return TemplateError.InvalidSyntax;
                }
                // Note: We don't currently *use* the optional name, but we validate it.
            }
            try tokens.append(.endblock_stmt);
            pos = findEndOfDirective(template, pos + tag_len);
        } else {
            // --- Handle Text content ---
            // This block executes if `pos` does not start with any known tag.
            // We need to find where the text ends, which is either the end of the template
            // or the beginning of the *next* tag.

            // Define all possible delimiters that could end a text block
            const delimiters = [_][]const u8{
                "{{",    "#include ", "#css ",   "#js ",      "#if ",    "#elseif ",
                "#else", "#endif",    "#for ",   "#endfor",   "#while ", "#endwhile",
                "#set ", "#extends ", "#block ", "#endblock",
            };

            var next_delimiter_pos: usize = remaining.len; // Assume text goes to the end initially

            // Find the earliest occurrence of any delimiter
            // Use `inline for` for compile-time known loops
            inline for (delimiters) |delim| {
                if (std.mem.indexOf(u8, remaining, delim)) |delim_pos| {
                    // Found a delimiter, check if it's closer than the current minimum
                    if (delim_pos < next_delimiter_pos) {
                        next_delimiter_pos = delim_pos;
                    }
                }
            }

            // If next_delimiter_pos is 0, it means a tag starts *exactly* at `pos`.
            // The `if/else if` chain above should have caught it. If not, something is wrong.
            // However, if we found text (next_delimiter_pos > 0), process it.
            if (next_delimiter_pos > 0) {
                const text_slice = remaining[0..next_delimiter_pos];

                // Check if this text is purely whitespace AND occurs before any tag/content
                const is_only_whitespace = (std.mem.indexOfNone(u8, text_slice, " \t\n\r") == null);

                if (!first_tag_found and is_only_whitespace) {
                    // Skip leading whitespace before the first *actual* tag or non-whitespace text
                } else {
                    try tokens.append(.{ .text = try allocator.dupe(u8, text_slice) });
                    // Mark first tag found if we add non-whitespace text,
                    // or if any tag was previously found (even if this text is whitespace).
                    if (!is_only_whitespace or first_tag_found) {
                        first_tag_found = true;
                    }
                }
                pos += next_delimiter_pos; // Advance position past the text
            } else {
                // If next_delimiter_pos is 0, it implies a delimiter starts exactly at 'pos'.
                // The outer loop's `if/else if` chain *should* handle this in the next iteration.
                // If `pos` is already at the end, the loop condition `pos < template.len` will terminate it.

                // Safety check: If we are here, `pos` should point to a known delimiter.
                // If not, it indicates a parser logic error.
                if (pos < template.len) { // Avoid checking beyond bounds
                    var delimiter_found_at_pos = false;
                    inline for (delimiters) |delim| {
                        if (std.mem.startsWith(u8, remaining, delim)) {
                            delimiter_found_at_pos = true;
                            break;
                        }
                    }
                    // Also check for "{{" which isn't in the `delimiters` array used for text splitting
                    if (!delimiter_found_at_pos and !std.mem.startsWith(u8, remaining, "{{")) {
                        //std.debug.print("Parser state error: Position {d} has zero text length but doesn't start with a known delimiter.\n", .{pos});
                        return TemplateError.InvalidSyntax; // Or a more specific internal error
                    }
                }
                // If a delimiter was found (or we're at the end), the loop continues/terminates correctly.
                // No increment to `pos` here; the tag handlers above will advance it.
                if (pos >= template.len) break; // Explicitly break if at end
            }
        }
    }

    return tokens;
}
