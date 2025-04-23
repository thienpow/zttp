const std = @import("std");
const TemplateError = @import("types.zig").TemplateError;

// Supported languages
const Language = enum {
    zig,
    html,
    css,
    javascript,
    zmx,
    text,
};

// Token types mapped to Pygments classes
const TokenType = enum {
    keyword, // .k, .kd, .kn, .kp, .kr, .kt
    identifier, // .n, .ni, .nl, .nn, .nx, .nv
    operator, // .o, .ow
    punctuation, // .p
    comment, // .c, .c1, .cs, .cm
    string, // .s, .s1, .s2, .sb, .sc, .sd, .se, .sh, .si, .ss, .sx
    number, // .m, .mf, .mh, .mi, .mo, .il
    builtin, // .nb, .bp, .nf, .fm
    class_name, // .nc, .no, .nd, .ne
    constant, // .kc
    invalid, // .err
    tag, // .nt (HTML)
    attribute, // .na (HTML)
    property, // .py (CSS)
    pseudo, // .nb (CSS pseudo-classes/elements)
    delimiter, // .cp, .cs (template delimiters)
    text, // Plain text (whitespace, newlines, HTML content)
};

// Token structure
const Token = struct {
    content: []const u8,
    type: TokenType,
};

// Language-specific keyword sets
const zig_keywords = [_][]const u8{
    "const", "var", "fn", "if", "else", "return", "try", "defer", "while", "for", "switch", "break", "continue", "pub", "struct", "enum", "union", "error",
};
const js_keywords = [_][]const u8{
    "const", "let", "var", "function", "if", "else", "return", "while", "for", "switch", "break", "continue", "class", "this", "new", "try", "catch",
};
const css_keywords = [_][]const u8{
    "media", "keyframes", "important", "initial", "inherit",
};
const zmx_directives = [_][]const u8{
    "extends", "block", "endblock", "include", "if", "endif", "elseif", "else", "for", "endfor", "while", "endwhile", "set",
};

// HTML-escape a string - CORRECTED to properly handle quotes and preserve whitespace
fn htmlEscape(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var escaped = std.ArrayList(u8).init(allocator);
    defer escaped.deinit();

    for (input) |c| {
        switch (c) {
            '<' => try escaped.appendSlice("&lt;"),
            '>' => try escaped.appendSlice("&gt;"),
            '&' => try escaped.appendSlice("&amp;"),
            '"' => try escaped.appendSlice("&quot;"),
            '\'' => try escaped.appendSlice("&#39;"),
            else => try escaped.append(c),
        }
    }

    return try escaped.toOwnedSlice();
}

// Check if a string is a keyword or directive for a given language
fn isKeyword(lang: Language, str: []const u8) bool {
    switch (lang) {
        .zig => {
            for (zig_keywords) |kw| {
                if (std.mem.eql(u8, str, kw)) return true;
            }
        },
        .javascript => {
            for (js_keywords) |kw| {
                if (std.mem.eql(u8, str, kw)) return true;
            }
        },
        .css => {
            for (css_keywords) |kw| {
                if (std.mem.startsWith(u8, str, "@") or std.mem.eql(u8, str, kw)) return true;
            }
        },
        .zmx => {
            for (zmx_directives) |dir| {
                if (std.mem.eql(u8, str, dir)) return true;
            }
        },
        else => {},
    }
    return false;
}

// Simple tokenizer - IMPROVED to better handle whitespace and newlines
fn tokenize(allocator: std.mem.Allocator, code: []const u8, lang: Language) !std.ArrayList(Token) {
    var tokens = std.ArrayList(Token).init(allocator);
    var i: usize = 0;
    var current_token = std.ArrayList(u8).init(allocator);
    defer current_token.deinit();
    var state: enum { normal, string, comment, identifier, number, html_tag, html_attr, html_text, zmx_delimiter, zmx_var } = .normal;

    // Helper function to add whitespace token
    const addWhitespaceToken = struct {
        fn add(tks: *std.ArrayList(Token), alloc: std.mem.Allocator, ws: []const u8) !void {
            if (ws.len > 0) {
                try tks.append(.{ .content = try alloc.dupe(u8, ws), .type = .text });
            }
        }
    }.add;

    while (i < code.len) {
        const c = code[i];
        switch (state) {
            .normal => {
                if (std.ascii.isWhitespace(c)) {
                    // Collect all whitespace characters as a single token
                    try current_token.append(c);
                    while (i + 1 < code.len and std.ascii.isWhitespace(code[i + 1])) {
                        i += 1;
                        try current_token.append(code[i]);
                    }
                    try addWhitespaceToken(&tokens, allocator, current_token.items);
                    current_token.clearAndFree();
                    i += 1;
                    continue;
                }
                if (c == '/' and i + 1 < code.len and code[i + 1] == '/') {
                    // Single-line comment
                    if (lang == .zmx) {
                        // In ZMX context, treat // as an operator
                        try tokens.append(.{ .content = try allocator.dupe(u8, "//"), .type = .operator });
                        i += 2;
                    } else {
                        // Otherwise treat as comment
                        state = .comment;
                        try current_token.appendSlice("//");
                        i += 2;
                    }
                    continue;
                }
                if (c == '/' and i + 1 < code.len and code[i + 1] == '*') {
                    // Multi-line comment
                    state = .comment;
                    try current_token.appendSlice("/*");
                    i += 2;
                    continue;
                }
                if ((lang == .html or lang == .zmx) and c == '<' and i + 3 < code.len and code[i + 1] == '!' and code[i + 2] == '-' and code[i + 3] == '-') {
                    // HTML comment
                    state = .comment;
                    try current_token.appendSlice("<!--");
                    i += 4;
                    continue;
                }
                if (c == '"' or c == '\'') {
                    // String literal
                    state = .string;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                if (std.ascii.isDigit(c) or (c == '-' and i + 1 < code.len and std.ascii.isDigit(code[i + 1]))) {
                    // Number
                    state = .number;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                if (std.ascii.isAlphabetic(c) or c == '_' or c == '@') {
                    // Identifier or keyword
                    state = .identifier;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                if (lang == .zmx and c == '#') {
                    // ZMX directive
                    state = .zmx_delimiter;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                if (lang == .zmx and c == '{' and i + 1 < code.len and code[i + 1] == '{') {
                    // ZMX variable delimiter start
                    try tokens.append(.{ .content = try allocator.dupe(u8, "{{"), .type = .delimiter });
                    state = .zmx_var;
                    i += 2;
                    continue;
                }
                if (lang == .zmx and c == '}' and i + 1 < code.len and code[i + 1] == '}') {
                    // ZMX variable delimiter end
                    try tokens.append(.{ .content = try allocator.dupe(u8, "}}"), .type = .delimiter });
                    state = .normal;
                    i += 2;
                    continue;
                }
                if ((lang == .html or lang == .zmx) and c == '<') {
                    // HTML tag
                    state = .html_tag;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                // Operators and punctuation
                if (std.mem.indexOfScalar(u8, "+-*/=<>!&|;:,(){}[].,", c) != null) {
                    try tokens.append(.{ .content = try allocator.dupe(u8, &[_]u8{c}), .type = if (c == '(' or c == ')' or c == '{' or c == '}' or c == '[' or c == ']' or c == ',' or c == ';' or c == '.') .punctuation else .operator });
                    i += 1;
                    continue;
                }
                if (lang == .css and c == '#') {
                    // CSS ID or hex color
                    try current_token.append(c);
                    state = .number; // Treat as number (hex)
                    i += 1;
                    continue;
                }
                // Unknown character
                try tokens.append(.{ .content = try allocator.dupe(u8, &[_]u8{c}), .type = .invalid });
                i += 1;
            },
            .string => {
                try current_token.append(c);
                if ((c == '"' or c == '\'') and (current_token.items.len <= 1 or current_token.items[current_token.items.len - 2] != '\\')) {
                    try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .string });
                    current_token.clearAndFree();
                    state = if (lang == .zmx) (if (state == .zmx_var) .zmx_var else if (state == .html_attr) .html_attr else .normal) else .normal;
                }
                i += 1;
            },
            .comment => {
                try current_token.append(c);
                if (std.mem.endsWith(u8, current_token.items, "*/")) {
                    try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .comment });
                    current_token.clearAndFree();
                    state = .normal;
                } else if (std.mem.endsWith(u8, current_token.items, "-->")) {
                    try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .comment });
                    current_token.clearAndFree();
                    state = .normal;
                } else if (c == '\n' and std.mem.startsWith(u8, current_token.items, "//")) {
                    try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .comment });
                    current_token.clearAndFree();
                    state = .normal;
                }
                i += 1;
            },
            .identifier => {
                if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-') {
                    try current_token.append(c);
                    i += 1;
                } else {
                    const content = try allocator.dupe(u8, current_token.items);
                    const token_type: TokenType = if (isKeyword(lang, content))
                        if (lang == .zmx) .delimiter else .keyword
                    else if (lang == .javascript and (std.mem.eql(u8, content, "true") or std.mem.eql(u8, content, "false") or std.mem.eql(u8, content, "null")))
                        .constant
                    else if (lang == .javascript and (std.mem.eql(u8, content, "console") or std.mem.eql(u8, content, "Math") or std.mem.eql(u8, content, "document")))
                        .builtin
                    else if ((lang == .html or lang == .zmx) and std.mem.startsWith(u8, content, "@"))
                        .keyword // HTML entities or CSS at-rules
                    else if ((lang == .html or (lang == .zmx and state == .html_attr)))
                        .attribute
                    else if (lang == .css and std.mem.startsWith(u8, content, "."))
                        .class_name
                    else if (lang == .css and std.mem.startsWith(u8, content, ":"))
                        .pseudo
                    else
                        .identifier;
                    try tokens.append(.{ .content = content, .type = token_type });
                    current_token.clearAndFree();
                    state = if (lang == .zmx) (if (state == .html_attr) .html_attr else if (state == .zmx_var) .zmx_var else .normal) else .normal;
                    continue; // Don't increment i, reprocess current char
                }
            },
            .number => {
                if (std.ascii.isAlphanumeric(c) or c == '.' or c == '#') {
                    try current_token.append(c);
                    i += 1;
                } else {
                    try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .number });
                    current_token.clearAndFree();
                    state = .normal;
                    continue; // Don't increment i, reprocess current char
                }
            },
            .html_tag => {
                try current_token.append(c);
                if (c == '>') {
                    try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .tag });
                    current_token.clearAndFree();
                    state = .html_text;
                } else if (std.ascii.isWhitespace(c)) {
                    try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items[0 .. current_token.items.len - 1]), .type = .tag });
                    try addWhitespaceToken(&tokens, allocator, &[_]u8{c});
                    current_token.clearAndFree();
                    state = .html_attr;
                }
                i += 1;
            },
            .html_attr => {
                if (std.ascii.isWhitespace(c)) {
                    try current_token.append(c);
                    while (i + 1 < code.len and std.ascii.isWhitespace(code[i + 1])) {
                        i += 1;
                        try current_token.append(code[i]);
                    }
                    try addWhitespaceToken(&tokens, allocator, current_token.items);
                    current_token.clearAndFree();
                    i += 1;
                    continue;
                }
                if (c == '>') {
                    try tokens.append(.{ .content = try allocator.dupe(u8, ">"), .type = .tag });
                    current_token.clearAndFree();
                    state = .html_text;
                    i += 1;
                    continue;
                }
                if (c == '=') {
                    try tokens.append(.{ .content = try allocator.dupe(u8, "="), .type = .punctuation });
                    i += 1;
                    // Check if the next character is a quote
                    if (i < code.len and (code[i] == '"' or code[i] == '\'')) {
                        state = .string;
                        try current_token.append(code[i]);
                        i += 1;
                    }
                    continue;
                }
                if (std.ascii.isAlphabetic(c) or c == '-' or c == ':') {
                    try current_token.append(c);
                    state = .identifier;
                    i += 1;
                    continue;
                }
                try tokens.append(.{ .content = try allocator.dupe(u8, &[_]u8{c}), .type = .invalid });
                i += 1;
            },
            .html_text => {
                if (c == '<') {
                    if (current_token.items.len > 0) {
                        try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .text });
                        current_token.clearAndFree();
                    }
                    state = .html_tag;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                if (lang == .zmx and c == '#') {
                    if (current_token.items.len > 0) {
                        try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .text });
                        current_token.clearAndFree();
                    }
                    state = .zmx_delimiter;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                if (lang == .zmx and c == '{' and i + 1 < code.len and code[i + 1] == '{') {
                    if (current_token.items.len > 0) {
                        try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .text });
                        current_token.clearAndFree();
                    }
                    try tokens.append(.{ .content = try allocator.dupe(u8, "{{"), .type = .delimiter });
                    state = .zmx_var;
                    i += 2;
                    continue;
                }
                try current_token.append(c);
                i += 1;
            },
            .zmx_delimiter => {
                if (std.ascii.isAlphanumeric(c) or c == '_') {
                    try current_token.append(c);
                    i += 1;
                } else {
                    const content = try allocator.dupe(u8, current_token.items);
                    try tokens.append(.{ .content = content, .type = .delimiter });
                    current_token.clearAndFree();
                    state = .normal;
                    continue; // Don't increment i, reprocess current char
                }
            },
            .zmx_var => {
                if (std.ascii.isWhitespace(c)) {
                    try current_token.append(c);
                    while (i + 1 < code.len and std.ascii.isWhitespace(code[i + 1])) {
                        i += 1;
                        try current_token.append(code[i]);
                    }
                    try addWhitespaceToken(&tokens, allocator, current_token.items);
                    current_token.clearAndFree();
                    i += 1;
                    continue;
                }
                if (c == '"' or c == '\'') {
                    state = .string;
                    try current_token.append(c);
                    i += 1;
                    continue;
                }
                if (std.ascii.isAlphabetic(c) or c == '_') {
                    try current_token.append(c);
                    state = .identifier;
                    i += 1;
                    continue;
                }
                // FIXED: Treat // as operator instead of comment in zmx_var context
                if (c == '/' and i + 1 < code.len and code[i + 1] == '/') {
                    try tokens.append(.{ .content = try allocator.dupe(u8, "//"), .type = .operator });
                    i += 2;
                    state = .zmx_var;
                    continue;
                }
                if (c == '}' and i + 1 < code.len and code[i + 1] == '}') {
                    if (current_token.items.len > 0) {
                        try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = .identifier });
                        current_token.clearAndFree();
                    }
                    try tokens.append(.{ .content = try allocator.dupe(u8, "}}"), .type = .delimiter });
                    state = .html_text;
                    i += 2;
                    continue;
                }
                try tokens.append(.{ .content = try allocator.dupe(u8, &[_]u8{c}), .type = if (c == '/' or c == '+' or c == '-' or c == '*') .operator else .invalid });
                i += 1;
            },
        }
    }

    // Handle unclosed tokens
    if (current_token.items.len > 0) {
        const token_type: TokenType = switch (state) {
            .normal => .invalid,
            .string => .string,
            .comment => .comment,
            .identifier => if (isKeyword(lang, current_token.items)) (if (lang == .zmx) .delimiter else .keyword) else .identifier,
            .number => .number,
            .html_tag => .tag,
            .html_attr => .attribute,
            .html_text => .text,
            .zmx_delimiter => .delimiter,
            .zmx_var => .identifier,
        };
        try tokens.append(.{ .content = try allocator.dupe(u8, current_token.items), .type = token_type });
    }

    return tokens;
}

// Map token type to Pygments class
fn tokenTypeToClass(token_type: TokenType) []const u8 {
    return switch (token_type) {
        .keyword => "k",
        .identifier => "n",
        .operator => "o",
        .punctuation => "p",
        .comment => "c",
        .string => "s",
        .number => "m",
        .builtin => "nb",
        .class_name => "nc",
        .constant => "kc",
        .invalid => "err",
        .tag => "nt",
        .attribute => "na",
        .property => "py",
        .pseudo => "nb",
        .delimiter => "cp",
        .text => "", // No class for plain text (whitespace, newlines, HTML content)
    };
}

// Highlight code and return HTML with Pygments classes
pub fn highlight(allocator: std.mem.Allocator, code: []const u8, language: []const u8) ![]const u8 {
    const lang: Language = if (std.mem.eql(u8, language, "zig"))
        .zig
    else if (std.mem.eql(u8, language, "html"))
        .html
    else if (std.mem.eql(u8, language, "css"))
        .css
    else if (std.mem.eql(u8, language, "javascript"))
        .javascript
    else if (std.mem.eql(u8, language, "zmx"))
        .zmx
    else
        .text;

    if (lang == .text) {
        const escaped = try htmlEscape(allocator, code);
        return escaped;
    }

    var tokens = try tokenize(allocator, code, lang);
    defer {
        for (tokens.items) |token| {
            allocator.free(token.content);
        }
        tokens.deinit();
    }

    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    for (tokens.items) |token| {
        const escaped_content = try htmlEscape(allocator, token.content);
        defer allocator.free(escaped_content);
        const class = tokenTypeToClass(token.type);
        if (token.type == .text) {
            try output.appendSlice(escaped_content);
        } else {
            const html = try std.fmt.allocPrint(allocator, "<span class=\"{s}\">{s}</span>", .{ class, escaped_content });
            defer allocator.free(html);
            try output.appendSlice(html);
        }
    }

    return try output.toOwnedSlice();
}
