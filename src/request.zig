const std = @import("std");
const HttpMethod = @import("zttp.zig").HttpMethod;

pub const Request = struct {
    allocator: std.mem.Allocator,
    method: HttpMethod,
    path: []const u8,
    version: []const u8,
    headers: std.StringHashMap([]const u8),
    query: std.StringHashMap([]const u8),
    body: ?[]const u8,
    json: ?std.json.Value,
    form: ?std.StringHashMap([]const u8),
    multipart: ?std.ArrayList(MultipartPart),

    pub const MultipartPart = struct {
        name: []const u8,
        filename: ?[]const u8,
        content_type: []const u8,
        data: []const u8,
    };

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Request {
        if (data.len > 65536) return error.RequestTooLarge;
        var req = Request{
            .allocator = allocator,
            .method = undefined, // Will be set by parseMethod
            .path = "",
            .version = "",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .query = std.StringHashMap([]const u8).init(allocator),
            .body = null,
            .json = null,
            .form = null,
            .multipart = null,
        };

        var lines = std.mem.splitSequence(u8, data, "\r\n");
        const request_line = lines.next() orelse return error.InvalidRequest;
        var parts = std.mem.splitScalar(u8, request_line, ' ');

        const method_str = parts.next() orelse return error.InvalidRequest;
        req.method = try parseMethod(method_str);

        const raw_path = parts.next() orelse return error.InvalidRequest;
        const path_parts = try parsePath(allocator, raw_path);
        req.path = path_parts.path;
        req.query = path_parts.query;

        req.version = try allocator.dupe(u8, parts.rest());
        if (!std.mem.startsWith(u8, req.version, "HTTP/")) return error.InvalidVersion;

        var header_count: usize = 0;
        while (lines.next()) |line| {
            if (line.len == 0) break;
            if (header_count >= 100) return error.TooManyHeaders;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
            const name = std.mem.trim(u8, line[0..colon], " ");
            const value = std.mem.trim(u8, line[colon + 1 ..], " ");
            if (name.len == 0) return error.InvalidHeader;
            try req.headers.put(
                try allocator.dupe(u8, name),
                try allocator.dupe(u8, value),
            );
            header_count += 1;
        }

        if (std.mem.indexOf(u8, data, "\r\n\r\n")) |body_start| {
            if (body_start + 4 < data.len) {
                const body_data = data[body_start + 4 ..];
                if (req.headers.get("Content-Length")) |len_str| {
                    const len = try std.fmt.parseInt(usize, len_str, 10);
                    if (body_data.len >= len) {
                        req.body = try allocator.dupe(u8, body_data[0..len]);
                        try parseBody(&req, allocator);
                    } else {
                        return error.IncompleteBody;
                    }
                } else {
                    req.body = try allocator.dupe(u8, body_data);
                    try parseBody(&req, allocator);
                }
            }
        }

        return req;
    }

    pub fn deinit(self: *Request) void {
        self.allocator.free(self.path);
        self.allocator.free(self.version);
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        var qit = self.query.iterator();
        while (qit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.query.deinit();
        if (self.body) |b| self.allocator.free(b);
        if (self.form) |*form| {
            var fit = form.iterator();
            while (fit.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            form.deinit();
        }
        if (self.multipart) |*mp| {
            for (mp.items) |part| {
                self.allocator.free(part.name);
                if (part.filename) |f| self.allocator.free(f);
                self.allocator.free(part.content_type);
                self.allocator.free(part.data);
            }
            mp.deinit();
        }
        if (self.json) |json| {
            json.deinit();
        }
    }

    pub fn isKeepAlive(self: *Request) bool {
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
};

fn parsePath(allocator: std.mem.Allocator, raw_path: []const u8) !struct { path: []const u8, query: std.StringHashMap([]const u8) } {
    var query = std.StringHashMap([]const u8).init(allocator);
    if (raw_path.len == 0 or raw_path[0] != '/') return error.InvalidPath;

    if (std.mem.indexOfScalar(u8, raw_path, '?')) |q| {
        const path = try allocator.dupe(u8, raw_path[0..q]);
        const query_str = raw_path[q + 1 ..];
        var pairs = std.mem.splitScalar(u8, query_str, '&');
        while (pairs.next()) |pair| {
            if (pair.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
            const key = try allocator.dupe(u8, pair[0..eq]);
            const value = try allocator.dupe(u8, pair[eq + 1 ..]);
            try query.put(key, value);
        }
        return .{ .path = path, .query = query };
    }
    return .{ .path = try allocator.dupe(u8, raw_path), .query = query };
}

fn parseBody(self: *Request, allocator: std.mem.Allocator) !void {
    if (self.body == null or self.body.?.len == 0) return;
    if (self.headers.get("Content-Type")) |ct| {
        if (std.mem.startsWith(u8, ct, "application/json")) {
            const parsed = std.json.parseFromSlice(
                std.json.Value,
                self.allocator,
                self.body.?,
                .{ .allocate = .alloc_always },
            ) catch return;
            self.json = parsed.value;
        } else if (std.mem.startsWith(u8, ct, "application/x-www-form-urlencoded")) {
            self.form = std.StringHashMap([]const u8).init(self.allocator);
            var pairs = std.mem.splitScalar(u8, self.body.?, '&');
            while (pairs.next()) |pair| {
                if (pair.len == 0) continue;
                const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
                const key = try allocator.dupe(u8, pair[0..eq]);
                const value = try allocator.dupe(u8, pair[eq + 1 ..]);
                try self.form.?.put(key, value);
            }
        } else if (std.mem.startsWith(u8, ct, "multipart/form-data")) {
            if (std.mem.indexOf(u8, ct, "boundary=")) |b| {
                const boundary = ct[b + 9 ..];
                self.multipart = try parseMultipart(self.allocator, self.body.?, boundary);
            }
        }
    }
}

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
        while (lines.next()) |line| {
            if (line.len == 0) {
                headers_done = true;
                continue;
            }
            if (!headers_done) {
                if (std.mem.startsWith(u8, line, "Content-Disposition:")) {
                    if (std.mem.indexOf(u8, line, "name=\"")) |n| {
                        const start = n + 6;
                        const end = std.mem.indexOfScalar(u8, line[start..], '"') orelse return error.InvalidMultipart;
                        part.name = try allocator.dupe(u8, line[start .. start + end]);
                    }
                    if (std.mem.indexOf(u8, line, "filename=\"")) |f| {
                        const start = f + 10;
                        const end = std.mem.indexOfScalar(u8, line[start..], '"') orelse return error.InvalidMultipart;
                        part.filename = try allocator.dupe(u8, line[start .. start + end]);
                    }
                } else if (std.mem.startsWith(u8, line, "Content-Type:")) {
                    part.content_type = try allocator.dupe(u8, std.mem.trim(u8, line[13..], " "));
                }
            } else {
                part.data = try allocator.dupe(u8, line);
                break; // Only take first line of data for simplicity
            }
        }
        try parts.append(part);
    }
    return parts;
}

fn parseMethod(method_str: []const u8) !HttpMethod {
    if (std.mem.eql(u8, method_str, "GET")) return .get;
    if (std.mem.eql(u8, method_str, "POST")) return .post;
    return error.InvalidMethod;
}
