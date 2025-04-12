const std = @import("std");

pub const HandlerFn = *const fn (*Request, *Response) void;

pub const Router = struct {
    routes: std.ArrayList(Route),
    allocator: std.mem.Allocator,

    const Route = struct {
        path: []const u8,
        handler: HandlerFn,
    };

    pub fn init(allocator: std.mem.Allocator) Router {
        return .{
            .routes = std.ArrayList(Route).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Router) void {
        for (self.routes.items) |route| {
            self.allocator.free(route.path);
        }
        self.routes.deinit();
    }

    pub fn add(self: *Router, path: []const u8, handler: HandlerFn) !void {
        if (path.len == 0 or path[0] != '/') return error.InvalidPath;
        const path_owned = try self.allocator.dupe(u8, path);
        try self.routes.append(.{
            .path = path_owned,
            .handler = handler,
        });
    }

    pub fn find(self: *Router, path: []const u8) ?HandlerFn {
        for (self.routes.items) |route| {
            if (std.mem.eql(u8, route.path, path)) {
                return route.handler;
            }
        }
        return null;
    }
};

pub const Request = struct {
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    version: []const u8,
    headers: std.StringHashMap([]const u8),
    query: std.StringHashMap([]const u8),
    body: ?[]const u8,

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Request {
        if (data.len > 16384) return error.RequestTooLarge;
        var req = Request{
            .allocator = allocator,
            .method = "",
            .path = "",
            .version = "",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .query = std.StringHashMap([]const u8).init(allocator),
            .body = null,
        };

        var lines = std.mem.splitSequence(u8, data, "\r\n");
        const request_line = lines.next() orelse return error.InvalidRequest;
        var parts = std.mem.splitScalar(u8, request_line, ' ');

        req.method = try allocator.dupe(u8, parts.next() orelse return error.InvalidRequest);
        if (!isValidMethod(req.method)) return error.InvalidMethod;

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
                    } else {
                        return error.IncompleteBody;
                    }
                } else {
                    req.body = try allocator.dupe(u8, body_data);
                }
            }
        }

        return req;
    }

    pub fn deinit(self: *Request) void {
        self.allocator.free(self.method);
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

    fn isValidMethod(method: []const u8) bool {
        const valid = [_][]const u8{ "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH" };
        for (valid) |m| {
            if (std.mem.eql(u8, method, m)) return true;
        }
        return false;
    }
};

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: StatusCode,
    headers: std.StringHashMap([]const u8),
    body: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator) Response {
        return .{
            .allocator = allocator,
            .status = .ok,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
        };
    }

    pub fn deinit(self: *Response) void {
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        if (self.body) |b| self.allocator.free(b);
    }

    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
        if (self.headers.get(name)) |old| self.allocator.free(old);
        try self.headers.put(
            try self.allocator.dupe(u8, name),
            try self.allocator.dupe(u8, value),
        );
    }

    pub fn setBody(self: *Response, body: []const u8) !void {
        if (self.body) |b| self.allocator.free(b);
        self.body = try self.allocator.dupe(u8, body);
    }

    pub fn send(self: *Response, stream: std.net.Stream) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try buffer.writer().print("HTTP/1.1 {d} {s}\r\n", .{
            @intFromEnum(self.status),
            self.status.reason(),
        });

        if (self.body) |body| {
            try buffer.writer().print("Content-Length: {d}\r\n", .{body.len});
            if (!self.headers.contains("Content-Type")) {
                try buffer.writer().writeAll("Content-Type: text/plain; charset=utf-8\r\n");
            }
        } else {
            try buffer.writer().writeAll("Content-Length: 0\r\n");
        }

        const date = try getHttpDate(self.allocator);
        defer self.allocator.free(date);
        try buffer.writer().print("Date: {s}\r\n", .{date});

        var it = self.headers.iterator();
        while (it.next()) |entry| {
            try buffer.writer().print("{s}: {s}\r\n", .{
                entry.key_ptr.*,
                entry.value_ptr.*,
            });
        }

        try buffer.writer().writeAll("\r\n");
        if (self.body) |body| {
            try buffer.writer().writeAll(body);
        }

        try stream.writeAll(buffer.items);
    }
};

pub const StatusCode = enum(u16) {
    ok = 200,
    created = 201,
    no_content = 204,
    bad_request = 400,
    not_found = 404,
    internal_server_error = 500,

    pub fn reason(self: StatusCode) []const u8 {
        return switch (self) {
            .ok => "OK",
            .created => "Created",
            .no_content => "No Content",
            .bad_request => "Bad Request",
            .not_found => "Not Found",
            .internal_server_error => "Internal Server Error",
        };
    }
};

fn getHttpDate(allocator: std.mem.Allocator) ![]const u8 {
    const timestamp = std.time.timestamp();
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const day = epoch_secs.getEpochDay();
    const year_day = day.calculateYearDay();
    const seconds = epoch_secs.getDaySeconds();
    const hours = seconds.getHoursIntoDay();
    const minutes = seconds.getMinutesIntoHour();
    const secs = seconds.getSecondsIntoMinute();

    // Calculate day of week (0=Sunday, 6=Saturday)
    const days_since_epoch = day.day;
    const day_of_week = @mod(days_since_epoch + 4, 7); // Adjust for Jan 1, 1970 (Thursday)

    // Calculate month and day of month
    const year = year_day.year;
    var day_of_year = year_day.day;
    const is_leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
    const month_lengths = [_]u8{ 31, if (is_leap) @as(u8, 29) else @as(u8, 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var month: u8 = 0;
    var day_of_month: u8 = @as(u8, @intCast(day_of_year));
    for (month_lengths, 0..) |len, m| {
        if (day_of_year < len) {
            month = @intCast(m);
            day_of_month = @as(u8, @intCast(day_of_year)) + 1; // 1-based
            break;
        }
        day_of_year -= len;
    }

    const days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    return try std.fmt.allocPrint(allocator, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        days[@intCast(day_of_week)],
        day_of_month,
        months[month],
        year,
        hours,
        minutes,
        secs,
    });
}
