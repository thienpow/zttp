const std = @import("std");
const types = @import("types.zig");
const TemplateError = types.TemplateError;
const Condition = types.Condition;
const Token = types.Token;

pub fn findEndOfDirective(content: []const u8, start_pos: usize) usize {
    var current_pos = start_pos;
    while (current_pos < content.len and content[current_pos] != '\n' and content[current_pos] != '\r') {
        current_pos += 1;
    }
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

pub fn getDirectiveContent(content: []const u8, tag_start_pos: usize, tag_len: usize) []const u8 {
    const content_start = tag_start_pos + tag_len;
    var content_end = content_start;
    while (content_end < content.len and content[content_end] != '\n' and content[content_end] != '\r') {
        content_end += 1;
    }
    return std.mem.trim(u8, content[content_start..content_end], " \t");
}

pub fn parseCondition(content: []const u8) TemplateError!Condition {
    const trimmed = std.mem.trim(u8, content, " \t");
    if (std.mem.indexOf(u8, trimmed, " != ")) |ne_pos| {
        const var_name = std.mem.trim(u8, trimmed[0..ne_pos], " \t");
        const right = std.mem.trim(u8, trimmed[ne_pos + 4 ..], " \t");
        if ((std.mem.eql(u8, right, "\"\"") or std.mem.eql(u8, right, "''")) and var_name.len > 0) {
            return .{ .non_empty = var_name };
        }
    } else if (std.mem.indexOf(u8, trimmed, " == ")) |eq_pos| {
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
    return .{ .simple = trimmed };
}

// Rest of the tokenize function remains unchanged
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
        } else if (std.mem.startsWith(u8, remaining, "#endfor LTS")) {
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
        } else if (std.mem.startsWith(u8, remaining, "#extends ")) {
            if (first_tag_found) return TemplateError.ExtendsMustBeFirst;
            first_tag_found = true;

            var path = getDirectiveContent(template, pos, 9);
            if (path.len < 2 or ((path[0] != '"' or path[path.len - 1] != '"') and (path[0] != '\'' or path[path.len - 1] != '\''))) {
                std.debug.print("Invalid #extends path format: '{s}'\n", .{path});
                return TemplateError.InvalidSyntax;
            }
            path = path[1 .. path.len - 1];
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
            const name_maybe = getDirectiveContent(template, pos, 9);
            _ = name_maybe;
            first_tag_found = true;
            try tokens.append(.endblock_stmt);
            pos = findEndOfDirective(template, pos + 9);
        } else {
            const delimiters = [_][]const u8{
                "{{",   "#if",      "#else",  "#endif",
                "#for", "#endfor",  "#while", "#endwhile",
                "#set", "#extends", "#block", "#endblock",
            };
            var text_end_offset: usize = remaining.len;
            for (delimiters) |delim| {
                if (std.mem.indexOf(u8, remaining, delim)) |delim_pos| {
                    if (delim_pos == 0) {
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
                const leading_whitespace_count = std.mem.indexOfNone(u8, text_slice, " \t\n\r") orelse text_slice.len;
                if (!first_tag_found and leading_whitespace_count == text_slice.len) {} else {
                    try tokens.append(.{ .text = text_slice });
                    first_tag_found = true;
                }
                pos += text_end_offset;
            } else if (pos < template.len) {} else {
                break;
            }
        }
    }

    return tokens;
}
