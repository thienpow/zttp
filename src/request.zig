// src/request.zig
const std = @import("std");

const cookie = @import("cookie.zig");

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
} || cookie.CookieError;

/// Represents an HTTP request with parsed method, path, headers, query, cookies, and body.
pub const Request = struct {
    /// Allocator used for all dynamic memory in the request.
    allocator: std.mem.Allocator,
    /// HTTP method (GET, POST, etc.).
    method: HttpMethod,
    /// Request path (e.g., "/users").
    path: []const u8,
    /// HTTP version (e.g., "HTTP/1.1").
    version: []const u8,
    /// HTTP headers as key-value pairs.
    headers: std.StringHashMap([]const u8),
    /// Query parameters as key-value pairs.
    query: std.StringHashMap([]const u8),
    /// Cookies as key-value pairs.
    cookies: std.StringHashMap([]const u8),
    /// Raw body data, if present.
    body: ?[]const u8,
    /// Parsed JSON body, if applicable.
    json: ?std.json.Value,
    /// Arena allocator for JSON, if applicable.
    json_arena: ?*std.heap.ArenaAllocator,
    /// Parsed form data, if applicable.
    form: ?std.StringHashMap([]const u8),
    /// Parsed multipart form data, if applicable.
    multipart: ?std.ArrayList(MultipartPart),

    /// Represents a single part in a multipart/form-data request.
    pub const MultipartPart = struct {
        name: []const u8,
        filename: ?[]const u8,
        content_type: []const u8,
        data: []const u8,
    };

    /// Parses an HTTP request from raw data.
    /// Caller is responsible for calling `deinit` on the returned request.
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Request {
        if (data.len > 65536) return RequestError.RequestTooLarge;

        var req = Request{
            .allocator = allocator,
            .method = undefined,
            .path = "",
            .version = "",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .query = std.StringHashMap([]const u8).init(allocator),
            .cookies = std.StringHashMap([]const u8).init(allocator),
            .body = null,
            .json = null,
            .json_arena = null,
            .form = null,
            .multipart = null,
        };
        errdefer req.deinit();

        var lines = std.mem.splitSequence(u8, data, "\r\n");
        const request_line = lines.next() orelse return RequestError.InvalidRequestLine;
        try parseRequestLine(allocator, request_line, &req);

        try parseHeaders(allocator, &lines, &req);
        try parseBody(allocator, data, &req);

        return req;
    }

    /// Frees all memory associated with the request.
    pub fn deinit(self: *Request) void {
        // Free headers
        var header_it = self.headers.iterator();
        while (header_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();

        // Free query parameters
        var query_it = self.query.iterator();
        while (query_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.query.deinit();

        // Free cookies
        var cookie_it = self.cookies.iterator();
        while (cookie_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.cookies.deinit();

        // Free path and version
        if (self.path.len > 0) self.allocator.free(self.path);
        if (self.version.len > 0) self.allocator.free(self.version);

        // Free body
        if (self.body) |body| {
            self.allocator.free(body);
        }

        // Free JSON if present
        if (self.json) |json| {
            if (self.json_arena) |arena| {
                var parsed = std.json.Parsed(std.json.Value){
                    .arena = arena,
                    .value = json,
                };
                parsed.deinit();
            }
        }

        // Free form data
        if (self.form) |*form| {
            var form_it = form.iterator();
            while (form_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            form.deinit();
        }

        // Free multipart data
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
    }

    /// Checks if the request should keep the connection alive.
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

    /// Checks if the request is a WebSocket upgrade request.
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

/// Enum for supported content types.
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

/// Parses the request line (e.g., "GET /path HTTP/1.1").
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

/// Parses HTTP headers and cookies from the request.
fn parseHeaders(allocator: std.mem.Allocator, lines: *std.mem.SplitIterator(u8, .sequence), req: *Request) !void {
    var header_count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (header_count >= 100) return RequestError.TooManyHeaders;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return RequestError.InvalidHeader;
        if (colon + 1 >= line.len) return RequestError.InvalidHeader;

        const name = std.mem.trim(u8, line[0..colon], " ");
        const value = std.mem.trim(u8, line[colon + 1 ..], " ");
        if (name.len == 0) return RequestError.InvalidHeader;

        // Validate header name (printable ASCII only)
        for (name) |c| {
            if (c < 33 or c > 126) return RequestError.InvalidHeaderName;
        }

        try req.headers.put(
            try allocator.dupe(u8, name),
            try allocator.dupe(u8, value),
        );

        // Parse cookies if the header is "Cookie"
        if (std.ascii.eqlIgnoreCase(name, "Cookie")) {
            var cookie_map = try cookie.parseCookies(allocator, value);
            var cookie_it = cookie_map.iterator();
            while (cookie_it.next()) |entry| {
                try req.cookies.put(entry.key_ptr.*, entry.value_ptr.*);
            }
            // Do not deinit cookie_map entries, as they are now owned by req.cookies
            cookie_map.deinit();
        }

        header_count += 1;
    }
}

/// Parses the request body, if present.
fn parseBody(allocator: std.mem.Allocator, data: []const u8, req: *Request) !void {
    const max_body_size = 1024 * 1024; // 1 MB
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |body_start| {
        if (body_start + 4 >= data.len) return;
        const body_data = data[body_start + 4 ..];
        if (body_data.len > max_body_size) return RequestError.BodyTooLarge;

        var body_len: ?usize = null;
        if (req.headers.get("Content-Length")) |len_str| {
            body_len = try std.fmt.parseInt(usize, len_str, 10);
            if (body_data.len < body_len.?) return RequestError.IncompleteBody;
        }

        req.body = try allocator.dupe(u8, body_data[0..(body_len orelse body_data.len)]);

        if (req.body.?.len == 0) return;
        if (req.headers.get("Content-Type")) |ct| {
            switch (ContentType.fromString(ct)) {
                .json => {
                    // Create an arena for JSON parsing
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
                    // Do not call parsed.deinit() here, as we store the arena
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

/// Parses the path and query parameters.
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

/// Parses multipart/form-data body.
fn parseMultipart(allocator: std.mem.Allocator, body: []const u8, boundary: []const u8) !std.ArrayList(Request.MultipartPart) {
    var parts = std.ArrayList(Request.MultipartPart).init(allocator);
    const boundary_marker = try std.fmt.allocPrint(allocator, "--{s}", .{boundary});
    defer allocator.free(boundary_marker);

    var sections = std.mem.splitSequence(u8, body, boundary_marker);
    _ = sections.next(); // Skip first boundary
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
            part.data = try allocator.dupe(u8, data.items[0 .. data.items.len - 2]); // Remove trailing \r\n
        }
        try parts.append(part);
    }
    return parts;
}

/// Parses the HTTP method string.
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

/// Decodes URI-encoded strings (e.g., %20 to space).
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
