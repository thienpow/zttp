const std = @import("std");
const Request = @import("request.zig").Request;
const HeaderMap = @import("header_map.zig").HeaderMap;
const cookie = @import("cookie.zig");

const log = std.log.scoped(.response);

/// Errors related to response construction and sending.
const ResponseError = error{
    InvalidHeaderName,
    StreamWriteError,
    AllocationFailed,
    InvalidStatusCode,
} || std.fmt.AllocPrintError || std.json.ParseFromValueError || cookie.CookieError;

/// Represents an HTTP response with status, headers, and body.
pub const Response = struct {
    allocator: std.mem.Allocator,
    status: StatusCode,
    headers: HeaderMap,
    body: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator) Response {
        return .{
            .allocator = allocator,
            .status = .ok,
            .headers = HeaderMap.init(allocator),
            .body = null,
        };
    }

    pub fn deinit(self: *Response) void {
        if (self.body) |b| {
            self.allocator.free(b);
            self.body = null;
        }
        self.headers.deinit();
    }

    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
        try validateHeaderName(name);
        try self.headers.put(name, value);
    }

    pub fn setBody(self: *Response, body_data: []const u8) !void {
        if (self.body) |b| {
            self.allocator.free(b);
        }
        self.body = try self.allocator.dupe(u8, body_data);
    }

    pub fn setJson(self: *Response, value: anytype) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        try std.json.stringify(value, .{}, buffer.writer());
        try self.setBody(try buffer.toOwnedSlice());
        try self.setHeader("Content-Type", "application/json");
    }

    pub fn setCookie(self: *Response, name: []const u8, value: []const u8, options: CookieOptions) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();

        try buffer.writer().print("{s}={s}", .{ name, value });
        if (options.expires) |exp| {
            try buffer.writer().print("; Expires={s}", .{exp});
        }
        if (options.path) |path| {
            try buffer.writer().print("; Path={s}", .{path});
        }
        if (options.secure) {
            try buffer.writer().print("; Secure");
        }
        if (options.same_site) |ss| {
            try buffer.writer().print("; SameSite={s}", .{ss});
        }
        const cookie_str = try self.allocator.dupe(u8, buffer.items);
        errdefer self.allocator.free(cookie_str);
        try self.headers.put("Set-Cookie", cookie_str);
    }

    pub fn redirect(self: *Response, status: StatusCode, location: []const u8) !void {
        if (@intFromEnum(status) < 300 or @intFromEnum(status) >= 400) {
            return ResponseError.InvalidStatusCode;
        }
        self.status = status;
        try self.setHeader("Location", location);
        try self.setBody("");
    }

    pub fn setWebSocketHandshake(self: *Response, ws_key: []const u8) !void {
        self.status = .switching_protocols;

        try self.setHeader("Upgrade", "websocket");

        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var concat_buf: [128]u8 = undefined;
        const concat = try std.fmt.bufPrint(&concat_buf, "{s}{s}", .{ ws_key, magic });

        var sha1_hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(concat, &sha1_hash, .{});

        const accept_key_buf = try self.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(sha1_hash.len));
        defer self.allocator.free(accept_key_buf); // Free after use
        const accept_key_final = std.base64.standard.Encoder.encode(accept_key_buf, &sha1_hash);

        try self.setHeader("Sec-WebSocket-Accept", accept_key_final);
        try self.setHeader("Connection", "Upgrade");
        try self.setBody("");
    }

    pub fn send(self: *Response, stream: std.net.Stream, request: ?Request) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try writeStatusLine(self, buffer.writer());
        try writeHeaders(self, buffer.writer(), request, self.allocator);
        try buffer.writer().writeAll("\r\n");
        if (self.body) |body| {
            try buffer.writer().writeAll(body);
        }

        try stream.writeAll(buffer.items);
    }

    pub fn toBuffer(self: *Response, allocator: std.mem.Allocator, request: ?Request) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();

        try writeStatusLine(self, buffer.writer());
        try writeHeaders(self, buffer.writer(), request, allocator);
        try buffer.writer().writeAll("\r\n");
        if (self.body) |body| {
            try buffer.writer().writeAll(body);
        }

        return try buffer.toOwnedSlice();
    }
};

pub const CookieOptions = struct {
    expires: ?[]const u8 = null,
    path: ?[]const u8 = null,
    secure: bool = false,
    same_site: ?[]const u8 = null,
};

pub const StatusCode = enum(u16) {
    unknown = 0,
    switching_protocols = 101,
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    payload_too_large = 413,
    internal_server_error = 500,
    _,

    pub fn reason(self: StatusCode) []const u8 {
        return switch (self) {
            .unknown => "Unknown",
            .switching_protocols => "Switching Protocols",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .no_content => "No Content",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .payload_too_large => "Payload Too Large",
            .internal_server_error => "Internal Server Error",
            _ => "Unknown",
        };
    }
};

fn validateHeaderName(name: []const u8) !void {
    for (name) |c| {
        if (c < 33 or c > 126) return ResponseError.InvalidHeaderName;
    }
}

fn writeStatusLine(resp: *Response, writer: anytype) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{
        @intFromEnum(resp.status),
        resp.status.reason(),
    });
}

fn writeHeaders(resp: *Response, writer: anytype, request: ?Request, allocator: std.mem.Allocator) !void {
    if (resp.body) |body| {
        try writer.print("Content-Length: {d}\r\n", .{body.len});
        if (!resp.headers.contains("Content-Type")) {
            try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        }
    } else {
        try writer.writeAll("Content-Length: 0\r\n");
    }

    const date = try getHttpDate(allocator);
    defer allocator.free(date);
    try writer.print("Date: {s}\r\n", .{date});

    if (request) |req| {
        const keep_alive = req.isKeepAlive();
        try writer.print("Connection: {s}\r\n", .{if (keep_alive) "keep-alive" else "close"});
    } else {
        try writer.writeAll("Connection: close\r\n");
    }

    try writer.writeAll("Server: zttp/1.0\r\n");

    var it = resp.headers.map.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |value| {
            try writer.print("{s}: {s}\r\n", .{ entry.key_ptr.*, value });
        }
    }
}

fn getHttpDate(allocator: std.mem.Allocator) ![]const u8 {
    const timestamp = std.time.timestamp();
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const day = epoch_secs.getEpochDay();
    const year_day = day.calculateYearDay();
    const seconds = epoch_secs.getDaySeconds();
    const hours = seconds.getHoursIntoDay();
    const minutes = seconds.getMinutesIntoHour();
    const secs = seconds.getSecondsIntoMinute();

    const days_since_epoch = day.day;
    const day_of_week = @mod(days_since_epoch + 4, 7);

    const year = year_day.year;
    var day_of_year = year_day.day;
    const is_leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
    const month_lengths = [_]u8{ 31, if (is_leap) @as(u8, 29) else @as(u8, 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var month: u8 = 0;
    var day_of_month: u8 = @as(u8, @intCast(day_of_year));
    for (month_lengths, 0..) |len, m| {
        if (day_of_year < len) {
            month = @intCast(m);
            day_of_month = @as(u8, @intCast(day_of_year)) + 1;
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
