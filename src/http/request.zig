// src/http/request.zig
const std = @import("std");
const HeaderMap = @import("header_map.zig").HeaderMap;
const cookie = @import("cookie.zig");

const log = std.log.scoped(.request);

pub const HttpMethod = enum {
    get,
    post,
    put,
    delete,
    patch,
    head,
    options,
    trace,
};

/// Custom error set for request parsing.
const RequestError = error{
    RequestTooLarge,
    InvalidRequestLine,
    InvalidMethod,
    InvalidPath,
    InvalidHeader,
    InvalidHeaderName,
    InvalidVersion,
    TooManyHeaders,
    TooManyQueryParams,
    IncompleteBody,
    InvalidMultipart,
    BodyTooLarge,
    FoldedHeadersNotSupported,
} || cookie.CookieError;

/// Represents an HTTP request with parsed method, path, headers, query, cookies, and body.
pub const Request = struct {
    allocator: std.mem.Allocator,
    method: HttpMethod,
    path: []const u8,
    version: []const u8,
    headers: HeaderMap,
    query: std.StringHashMap([]const u8),
    cookies: std.StringHashMap([]const u8),
    body: ?[]const u8,
    json: ?std.json.Value,
    json_arena: ?*std.heap.ArenaAllocator,
    form: ?std.StringHashMap([]const u8),
    multipart: ?std.ArrayList(MultipartPart),
    streaming: bool,
    body_buffer: std.ArrayList(u8),
    body_stream_handler: ?*const fn (req: *Request, chunk: []const u8) void,

    pub const MultipartPart = struct {
        name: []const u8,
        filename: ?[]const u8,
        content_type: []const u8,
        data: []const u8,
    };

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Request {
        if (data.len > 65536) return RequestError.RequestTooLarge;

        var req = Request{
            .allocator = allocator,
            .method = undefined,
            .path = "",
            .version = "",
            .headers = HeaderMap.init(allocator),
            .query = std.StringHashMap([]const u8).init(allocator),
            .cookies = std.StringHashMap([]const u8).init(allocator),
            .body = null,
            .json = null,
            .json_arena = null,
            .form = null,
            .multipart = null,
            .streaming = false,
            .body_buffer = std.ArrayList(u8).init(allocator),
            .body_stream_handler = null,
        };
        errdefer req.deinit();

        var lines = std.mem.splitSequence(u8, data, "\r\n");
        const request_line = lines.next() orelse return RequestError.InvalidRequestLine;
        try parseRequestLine(allocator, request_line, &req);

        try parseHeaders(allocator, &lines, &req);
        try parseBody(allocator, data, &req);

        return req;
    }

    pub fn setStreamHandler(self: *Request, handler: *const fn (req: *Request, chunk: []const u8) void) void {
        self.body_stream_handler = handler;
    }

    pub fn deinit(self: *Request) void {
        self.headers.deinit();

        var query_it = self.query.iterator();
        while (query_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.query.deinit();

        var cookie_it = self.cookies.iterator();
        while (cookie_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.cookies.deinit();

        if (self.path.len > 0) self.allocator.free(self.path);
        if (self.version.len > 0) self.allocator.free(self.version);

        if (self.body) |body| {
            self.allocator.free(body);
        }

        if (self.json) |json| {
            if (self.json_arena) |arena| {
                var parsed = std.json.Parsed(std.json.Value){
                    .arena = arena,
                    .value = json,
                };
                parsed.deinit();
            }
        }

        if (self.form) |*form| {
            var form_it = form.iterator();
            while (form_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            form.deinit();
        }

        if (self.multipart) |*multipart| {
            for (multipart.items) |part| {
                self.allocator.free(part.name);
                if (part.filename) |filename| {
                    self.allocator.free(filename);
                }
                self.allocator.free(part.content_type);
                self.allocator.free(part.data);
            }
            multipart.deinit();
        }

        self.body_buffer.deinit();
    }

    pub fn isKeepAlive(self: *const Request) bool {
        if (std.mem.eql(u8, self.version, "HTTP/1.1")) {
            if (self.headers.get("Connection")) |conn| {
                return !std.ascii.eqlIgnoreCase(conn, "close");
            }
            return true;
        }
        if (self.headers.get("Connection")) |conn| {
            return std.ascii.eqlIgnoreCase(conn, "keep-alive");
        }
        return false;
    }

    pub fn isWebSocketUpgrade(self: *const Request) bool {
        if (self.method != .get) return false;
        if (!std.mem.eql(u8, self.version, "HTTP/1.1")) return false;
        if (!std.ascii.eqlIgnoreCase(self.headers.get("Upgrade") orelse "", "websocket")) return false;
        if (!std.ascii.eqlIgnoreCase(self.headers.get("Connection") orelse "", "Upgrade")) return false;
        if (!std.mem.eql(u8, self.headers.get("Sec-WebSocket-Version") orelse "", "13")) return false;
        if (self.headers.get("Sec-WebSocket-Key") == null) return false;
        return true;
    }
};

const ContentType = enum {
    json,
    form_urlencoded,
    multipart_form_data,
    other,

    pub fn fromString(str: []const u8) ContentType {
        if (std.mem.startsWith(u8, str, "application/json")) return .json;
        if (std.mem.startsWith(u8, str, "application/x-www-form-urlencoded")) return .form_urlencoded;
        if (std.mem.startsWith(u8, str, "multipart/form-data")) return .multipart_form_data;
        return .other;
    }
};

fn parseRequestLine(allocator: std.mem.Allocator, line: []const u8, req: *Request) !void {
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method_str = parts.next() orelse return RequestError.InvalidRequestLine;
    req.method = try parseMethod(method_str);

    const raw_path = parts.next() orelse return RequestError.InvalidPath;
    const path_parts = try parsePath(allocator, raw_path);
    req.path = path_parts.path;
    req.query = path_parts.query;

    const version = parts.next() orelse return RequestError.InvalidVersion;
    req.version = try allocator.dupe(u8, version);
    if (!std.mem.startsWith(u8, req.version, "HTTP/")) return RequestError.InvalidVersion;
}

fn parseHeaders(allocator: std.mem.Allocator, lines: *std.mem.SplitIterator(u8, .sequence), req: *Request) !void {
    var header_count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (header_count >= 100) return RequestError.TooManyHeaders;

        if (line[0] == ' ' or line[0] == '\t') {
            return RequestError.FoldedHeadersNotSupported;
        }

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return RequestError.InvalidHeader;
        if (colon + 1 >= line.len) return RequestError.InvalidHeader;

        const name = std.mem.trim(u8, line[0..colon], " ");
        const value = std.mem.trim(u8, line[colon + 1 ..], " ");
        if (name.len == 0) return RequestError.InvalidHeader;

        for (name) |c| {
            if (c < 33 or c > 126) return RequestError.InvalidHeaderName;
        }

        try req.headers.put(name, value);

        if (std.ascii.eqlIgnoreCase(name, "Cookie")) {
            var cookie_map = try cookie.parseCookies(allocator, value);
            var cookie_it = cookie_map.iterator();
            while (cookie_it.next()) |entry| {
                try req.cookies.put(entry.key_ptr.*, entry.value_ptr.*);
            }
            cookie_map.deinit();
        }

        header_count += 1;
    }
}

fn parseBody(allocator: std.mem.Allocator, data: []const u8, req: *Request) !void {
    const max_body_size = 1024 * 1024;
    const stream_threshold = 1024 * 256; // 256 KB threshold for streaming

    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |body_start| {
        if (body_start + 4 >= data.len) return;
        const body_data = data[body_start + 4 ..];
        if (body_data.len > max_body_size) return RequestError.BodyTooLarge;

        var body_len: ?usize = null;
        var is_chunked = false;
        // Check for Content-Length or Transfer-Encoding
        if (req.headers.get("Transfer-Encoding")) |te| {
            if (std.ascii.eqlIgnoreCase(te, "chunked")) {
                is_chunked = true;
                req.streaming = true;
            }
        } else if (req.headers.get("Content-Length")) |len_str| {
            body_len = try std.fmt.parseInt(usize, len_str, 10);

            if (body_len.? > stream_threshold) {
                req.streaming = true;
            }
            if (body_data.len < body_len.?) return RequestError.IncompleteBody;
        }

        if (req.streaming) {
            // For streaming, append to body_buffer instead of setting body
            try req.body_buffer.appendSlice(body_data);
            log.debug("Streaming enabled, appended {d} bytes to body_buffer", .{body_data.len});
        } else {
            // Non-streaming case: buffer entire body
            if (body_data.len > max_body_size) return RequestError.BodyTooLarge;
            req.body = try allocator.dupe(u8, body_data[0..(body_len orelse body_data.len)]);

            if (req.body.?.len == 0) return;
            if (req.headers.get("Content-Type")) |ct| {
                switch (ContentType.fromString(ct)) {
                    .json => {
                        var arena = try allocator.create(std.heap.ArenaAllocator);
                        arena.* = std.heap.ArenaAllocator.init(allocator);
                        errdefer {
                            arena.deinit();
                            allocator.destroy(arena);
                        }

                        const arena_allocator = arena.allocator();
                        const parsed = try std.json.parseFromSlice(
                            std.json.Value,
                            arena_allocator,
                            req.body.?,
                            .{ .allocate = .alloc_always },
                        );
                        req.json = parsed.value;
                        req.json_arena = arena;
                    },
                    .form_urlencoded => {
                        var form = std.StringHashMap([]const u8).init(allocator);
                        var pairs = std.mem.splitScalar(u8, req.body.?, '&');
                        while (pairs.next()) |pair| {
                            if (pair.len == 0) continue;
                            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
                            const key = try decodeUri(allocator, pair[0..eq]);
                            const value = try decodeUri(allocator, pair[eq + 1 ..]);
                            try form.put(key, value);
                        }
                        req.form = form;
                    },
                    .multipart_form_data => {
                        if (std.mem.indexOf(u8, ct, "boundary=")) |b| {
                            const boundary = ct[b + 9 ..];
                            req.multipart = try parseMultipart(allocator, req.body.?, boundary);
                        }
                    },
                    .other => {},
                }
            }
        }
    }
}

fn parsePath(allocator: std.mem.Allocator, raw_path: []const u8) !struct { path: []const u8, query: std.StringHashMap([]const u8) } {
    var query = std.StringHashMap([]const u8).init(allocator);
    if (raw_path.len == 0 or raw_path[0] != '/') return RequestError.InvalidPath;

    if (std.mem.indexOfScalar(u8, raw_path, '?')) |q| {
        const path = try allocator.dupe(u8, raw_path[0..q]);
        if (q + 1 == raw_path.len) {
            return .{ .path = path, .query = query };
        }

        const query_str = raw_path[q + 1 ..];
        var pairs = std.mem.splitScalar(u8, query_str, '&');
        var param_count: usize = 0;
        while (pairs.next()) |pair| {
            if (pair.len == 0) continue;
            param_count += 1;
            if (param_count > 50) return RequestError.TooManyQueryParams;

            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
            const key = try decodeUri(allocator, pair[0..eq]);
            const value = try decodeUri(allocator, pair[eq + 1 ..]);
            try query.put(key, value);
        }
        return .{ .path = path, .query = query };
    }
    return .{ .path = try allocator.dupe(u8, raw_path), .query = query };
}

fn parseMultipart(allocator: std.mem.Allocator, body: []const u8, boundary: []const u8) !std.ArrayList(Request.MultipartPart) {
    var parts = std.ArrayList(Request.MultipartPart).init(allocator);
    const boundary_marker = try std.fmt.allocPrint(allocator, "--{s}", .{boundary});
    defer allocator.free(boundary_marker);

    var sections = std.mem.splitSequence(u8, body, boundary_marker);
    _ = sections.next();
    while (sections.next()) |section| {
        if (section.len == 0 or std.mem.startsWith(u8, section, "--")) continue;

        var part = Request.MultipartPart{
            .name = "",
            .filename = null,
            .content_type = "application/octet-stream",
            .data = "",
        };

        var lines = std.mem.splitSequence(u8, section, "\r\n");
        var headers_done = false;
        var data = std.ArrayList(u8).init(allocator);
        defer data.deinit();

        while (lines.next()) |line| {
            if (line.len == 0) {
                headers_done = true;
                continue;
            }
            if (!headers_done) {
                if (std.mem.startsWith(u8, line, "Content-Disposition:")) {
                    if (std.mem.indexOf(u8, line, "name=\"")) |n| {
                        const start = n + 6;
                        const end = std.mem.indexOfScalar(u8, line[start..], '"') orelse return RequestError.InvalidMultipart;
                        part.name = try allocator.dupe(u8, line[start .. start + end]);
                    }
                    if (std.mem.indexOf(u8, line, "filename=\"")) |f| {
                        const start = f + 10;
                        const end = std.mem.indexOfScalar(u8, line[start..], '"') orelse return RequestError.InvalidMultipart;
                        part.filename = try allocator.dupe(u8, line[start .. start + end]);
                    }
                } else if (std.mem.startsWith(u8, line, "Content-Type:")) {
                    part.content_type = try allocator.dupe(u8, std.mem.trim(u8, line[13..], " "));
                }
            } else {
                try data.appendSlice(line);
                try data.appendSlice("\r\n");
            }
        }
        if (data.items.len > 0) {
            part.data = try allocator.dupe(u8, data.items[0 .. data.items.len - 2]);
        }
        try parts.append(part);
    }
    return parts;
}

fn parseMethod(method_str: []const u8) !HttpMethod {
    if (std.mem.eql(u8, method_str, "GET")) return .get;
    if (std.mem.eql(u8, method_str, "POST")) return .post;
    if (std.mem.eql(u8, method_str, "PUT")) return .put;
    if (std.mem.eql(u8, method_str, "DELETE")) return .delete;
    if (std.mem.eql(u8, method_str, "PATCH")) return .patch;
    if (std.mem.eql(u8, method_str, "HEAD")) return .head;
    if (std.mem.eql(u8, method_str, "OPTIONS")) return .options;
    if (std.mem.eql(u8, method_str, "TRACE")) return .trace;
    return RequestError.InvalidMethod;
}

fn decodeUri(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    var decoded = std.ArrayList(u8).init(allocator);
    defer decoded.deinit();

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex = input[i + 1 .. i + 3];
            const value = try std.fmt.parseInt(u8, hex, 16);
            try decoded.append(value);
            i += 3;
        } else {
            try decoded.append(input[i]);
            i += 1;
        }
    }
    return try allocator.dupe(u8, decoded.items);
}
