// src/response.zig
const std = @import("std");
const Request = @import("request.zig").Request;
const cookie = @import("cookie.zig");

/// Errors related to response construction and sending.
const ResponseError = error{
    InvalidHeaderName,
    StreamWriteError,
    AllocationFailed,
    InvalidStatusCode,
} || std.fmt.AllocPrintError || std.json.ParseFromValueError || cookie.CookieError;

/// Represents an HTTP response with status, headers, and body.
pub const Response = struct {
    /// Allocator used for dynamic memory within the response (headers, body).
    allocator: std.mem.Allocator,
    /// HTTP status code (e.g., 200 OK).
    status: StatusCode,
    /// HTTP headers as key-value pairs.
    headers: std.StringHashMap([]const u8),
    /// Response body, if present. Owned by Response, freed in deinit.
    body: ?[]const u8,

    /// Initializes a new response with default values using the provided allocator.
    pub fn init(allocator: std.mem.Allocator) Response {
        std.log.debug("Response.init with allocator: {any}", .{allocator});
        return .{
            .allocator = allocator,
            .status = .ok,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
        };
    }

    /// Frees all memory associated with the response.
    pub fn deinit(self: *Response) void {
        if (self.body) |b| {
            self.allocator.free(b);
            self.body = null;
        }
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        std.log.debug("Response.deinit: freed body and headers", .{});
    }

    /// Sets a header with the given name and value. Overwrites existing header.
    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
        try validateHeaderName(name);
        std.log.debug("setHeader: before, name={s}, value={s}, body_len={d}, body_ptr={x}", .{
            name,
            value,
            if (self.body) |b| b.len else 0,
            if (self.body) |b| @intFromPtr(b.ptr) else 0,
        });

        // Check if header exists and free old key/value
        if (self.headers.getEntry(name)) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
            _ = self.headers.remove(name);
        }

        const key_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);
        try self.headers.put(key_copy, value_copy);

        std.log.debug("setHeader: after, name={s}, value={s}, body_len={d}, body_ptr={x}", .{
            name,
            value,
            if (self.body) |b| b.len else 0,
            if (self.body) |b| @intFromPtr(b.ptr) else 0,
        });
    }

    /// Sets the response body. Copies body_data; caller can free it.
    pub fn setBody(self: *Response, body_data: []const u8) !void {
        if (self.body) |b| {
            self.allocator.free(b);
        }
        self.body = try self.allocator.dupe(u8, body_data);
        std.log.debug("setBody: body_len={d}, body_ptr={x}", .{ self.body.?.len, @intFromPtr(self.body.?.ptr) });
    }

    /// Sets the response body to a JSON-serialized value. Sets Content-Type to application/json.
    pub fn setJson(self: *Response, value: anytype) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();
        try std.json.stringify(value, .{}, buffer.writer());
        try self.setBody(try buffer.toOwnedSlice());
        try self.setHeader("Content-Type", "application/json");
    }

    /// Sets a cookie in the response using a Set-Cookie header.
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
        try self.setHeader("Set-Cookie", cookie_str);
    }

    /// Sets a redirect response with the given status and location.
    pub fn redirect(self: *Response, status: StatusCode, location: []const u8) !void {
        if (@intFromEnum(status) < 300 or @intFromEnum(status) >= 400) {
            return ResponseError.InvalidStatusCode;
        }
        self.status = status;
        try self.setHeader("Location", location);
        try self.setBody("");
    }

    /// Sets the response for a WebSocket handshake (101 Switching Protocols).
    pub fn setWebSocketHandshake(self: *Response, ws_key: []const u8) !void {
        self.status = .switching_protocols;
        std.log.debug("setWebSocketHandshake: ws_key={s}", .{ws_key});
        try self.setHeader("Upgrade", "websocket");

        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var concat_buf: [128]u8 = undefined;
        const concat = try std.fmt.bufPrint(&concat_buf, "{s}{s}", .{ ws_key, magic });

        var sha1_hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(concat, &sha1_hash, .{});

        const accept_key_buf = try self.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(sha1_hash.len));
        const accept_key_final = std.base64.standard.Encoder.encode(accept_key_buf, &sha1_hash);

        try self.setHeader("Sec-WebSocket-Accept", accept_key_final);
        try self.setHeader("Connection", "Upgrade");
        try self.setBody("");
    }

    /// Sends the response over the given stream. Optionally takes a Request for Connection header.
    pub fn send(self: *Response, stream: std.net.Stream, request: ?Request) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try writeStatusLine(self, buffer.writer());
        try writeHeaders(self, buffer.writer(), request, self.allocator);
        try buffer.writer().writeAll("\r\n");
        if (self.body) |body| {
            std.log.debug("send: appending body_len={d}, body_ptr={x}", .{ body.len, @intFromPtr(body.ptr) });
            try buffer.writer().writeAll(body);
        }

        try stream.writeAll(buffer.items);
    }

    /// Converts the response to a buffer for async writing.
    pub fn toBuffer(self: *Response, allocator: std.mem.Allocator, request: ?Request) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();

        try writeStatusLine(self, buffer.writer());
        try writeHeaders(self, buffer.writer(), request, allocator);
        try buffer.writer().writeAll("\r\n");
        if (self.body) |body| {
            std.log.debug("toBuffer: appending body_len={d}, body_ptr={x}, buffer_len_before={d}", .{
                body.len,
                @intFromPtr(body.ptr),
                buffer.items.len,
            });
            try buffer.writer().writeAll(body);
        }

        const final_buffer = try buffer.toOwnedSlice();
        std.log.debug("toBuffer: final_buffer_len={d}", .{final_buffer.len});
        return final_buffer; // Caller must free
    }
};

/// Options for setting cookies.
pub const CookieOptions = struct {
    expires: ?[]const u8 = null,
    path: ?[]const u8 = null,
    secure: bool = false,
    same_site: ?[]const u8 = null,
};

/// HTTP status codes.
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
    internal_server_error = 500,
    _,

    /// Returns the reason phrase for the status code.
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
            .internal_server_error => "Internal Server Error",
            _ => "Unknown",
        };
    }
};

/// Validates that a header name contains only printable ASCII characters.
fn validateHeaderName(name: []const u8) !void {
    for (name) |c| {
        if (c < 33 or c > 126) return ResponseError.InvalidHeaderName;
    }
}

/// Writes the status line to the buffer (e.g., "HTTP/1.1 200 OK").
fn writeStatusLine(resp: *Response, writer: anytype) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{
        @intFromEnum(resp.status),
        resp.status.reason(),
    });
}

/// Writes headers to the buffer, including default headers and Connection based on request.
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

    var it = resp.headers.iterator();
    while (it.next()) |entry| {
        try writer.print("{s}: {s}\r\n", .{
            entry.key_ptr.*,
            entry.value_ptr.*,
        });
    }
}

/// Formats the current time as an HTTP date (e.g., "Wed, 21 Oct 2025 07:28:00 GMT").
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
