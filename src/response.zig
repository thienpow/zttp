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
    // Removed: arena: std.heap.ArenaAllocator,
    /// Allocator used for dynamic memory within the response (headers, body).
    allocator: std.mem.Allocator, // Added
    /// HTTP status code (e.g., 200 OK).
    status: StatusCode,
    /// HTTP headers as key-value pairs.
    headers: std.StringHashMap([]const u8),
    /// Response body, if present.
    body: ?[]const u8,

    /// Initializes a new response with default values using the provided allocator.
    pub fn init(allocator: std.mem.Allocator) Response { // Changed parameter name for clarity
        // std.log.debug("Response.init with allocator: {any}", .{allocator});
        return .{
            .allocator = allocator, // Store the provided allocator
            .status = .ok,
            .headers = std.StringHashMap([]const u8).init(allocator), // Init headers with the same allocator
            .body = null,
        };
    }

    /// Frees all memory associated with the response. (Now does nothing as it doesn't own an arena)
    pub fn deinit(self: *Response) void {
        _ = self;
        // std.log.debug("Response.deinit called for response using allocator: {any}", .{self.allocator});
        // The allocator provided at init is responsible for freeing memory (e.g., the handleConnection arena)
        // We only need to potentially free the body if it was allocated separately,
        // but using the passed-in arena allocator handles this automatically on arena.deinit().
        // If self.body held memory from a *different* allocator, it would need freeing here.
        // Since setBody uses self.allocator, we're good.
        // No need to deinit self.headers as its memory comes from self.allocator.
    }

    /// Sets a header with the given name and value.
    /// Overwrites existing header if it exists.
    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
        try validateHeaderName(name);
        // Use self.allocator directly
        // std.log.debug("setHeader: name={s}, value={s}, allocator={any}", .{ name, value, self.allocator });
        // The headers map already uses self.allocator from init
        try self.headers.put(name, value);
    }

    /// Sets the response body.
    /// Overwrites existing body if it exists.
    pub fn setBody(self: *Response, body_data: []const u8) !void { // Renamed parameter
        // std.log.debug("setBody: body_len={d}, allocator={any}", .{ body_data.len, self.allocator });
        // If body exists and was allocated by self.allocator (which it should have been),
        // it will be freed when the arena backing self.allocator is deinit'd.
        // Overwriting self.body pointer is sufficient.

        // Duplicate the body using self.allocator
        self.body = try self.allocator.dupe(u8, body_data);
    }

    /// Sets the response body to a JSON-serialized value.
    /// Automatically sets Content-Type to application/json.
    pub fn setJson(self: *Response, value: anytype) !void {
        // Use self.allocator for the temporary buffer and final body
        var buffer = std.ArrayList(u8).init(self.allocator);
        // Use errdefer for robust cleanup if stringify or dupe fails
        errdefer buffer.deinit();
        try std.json.stringify(value, .{}, buffer.writer());
        self.body = try self.allocator.dupe(u8, buffer.items); // Allocate final body slice
        // No need to buffer.deinit() here, errdefer handles failure, success means body owns it
        try self.setHeader("Content-Type", "application/json");
    }

    /// Sets a cookie in the response using a Set-Cookie header.
    pub fn setCookie(self: *Response, name: []const u8, value: []const u8, options: CookieOptions) !void {
        // Use self.allocator for the temporary buffer and final cookie string
        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit(); // Ensure buffer cleanup on error

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
        // Duplicate the final cookie string using self.allocator
        const cookie_str = try self.allocator.dupe(u8, buffer.items);
        // If setHeader fails, cookie_str needs cleanup if not using arena
        // Since we use the handleConnection arena, it's auto-cleaned.
        try self.setHeader("Set-Cookie", cookie_str);
    }

    /// Sets a redirect response with the given status and location.
    pub fn redirect(self: *Response, status: StatusCode, location: []const u8) !void {
        if (@intFromEnum(status) < 300 or @intFromEnum(status) >= 400) {
            return ResponseError.InvalidStatusCode;
        }
        self.status = status;
        // location will be duplicated by setHeader using self.allocator
        try self.setHeader("Location", location);
        try self.setBody(""); // setBody uses self.allocator
    }

    /// Sets the response for a WebSocket handshake (101 Switching Protocols).
    /// Requires Sec-WebSocket-Key from the request.
    pub fn setWebSocketHandshake(self: *Response, ws_key: []const u8) !void {
        self.status = .switching_protocols;
        // std.log.debug("setWebSocketHandshake: ws_key={s}", .{ws_key});
        // setHeader and setBody use self.allocator
        try self.setHeader("Upgrade", "websocket");
        // Note: Calculating Sec-WebSocket-Accept might need allocations.
        // If calculated outside, pass result to setHeader. If calculated inside, use self.allocator.
        // For now, assuming key calculation is handled elsewhere or doesn't need alloc here.
        // Let's add the key calculation and header setting here:

        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        // Use a stack buffer if possible, or self.allocator if needed for concat
        var concat_buf: [128]u8 = undefined; // Adjust size if keys/magic are huge
        const concat = try std.fmt.bufPrint(&concat_buf, "{s}{s}", .{ ws_key, magic });

        var sha1_hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(concat, &sha1_hash, .{});

        // Use self.allocator for the base64 encoded key
        const accept_key_buf = try self.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(sha1_hash.len));
        // Ensure cleanup if setHeader fails - handled by arena
        const accept_key_final = std.base64.standard.Encoder.encode(accept_key_buf, &sha1_hash);

        try self.setHeader("Sec-WebSocket-Accept", accept_key_final);
        try self.setHeader("Connection", "Upgrade"); // Also set connection header
        try self.setBody("");
    }

    /// Sends the response over the given stream.
    /// Optionally takes a Request to set Connection header based on keep-alive.
    pub fn send(self: *Response, stream: std.net.Stream, request: ?*const Request) !void {
        // Use self.allocator for the send buffer
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit(); // Ensure buffer cleanup

        try writeStatusLine(self, buffer.writer());
        // writeHeaders needs allocator for Date, pass self.allocator
        try writeHeaders(self, buffer.writer(), request, self.allocator);
        try buffer.writer().writeAll("\r\n");
        if (self.body) |body| {
            try buffer.writer().writeAll(body);
        }

        try stream.writeAll(buffer.items);
    }
};

// --- CookieOptions and StatusCode remain the same ---

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
// Added allocator parameter for getHttpDate
fn writeHeaders(resp: *Response, writer: anytype, request: ?*const Request, allocator: std.mem.Allocator) !void {
    // Set Content-Length and default Content-Type
    if (resp.body) |body| {
        try writer.print("Content-Length: {d}\r\n", .{body.len});
        if (!resp.headers.contains("Content-Type")) {
            try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        }
    } else {
        try writer.writeAll("Content-Length: 0\r\n");
    }

    // Set Date header using the provided allocator
    const date = try getHttpDate(allocator);
    // Since allocator is likely an arena, freeing might not be strictly needed if arena is deinit'd soon,
    // but it's good practice if the allocation isn't trivial. Arena handles cleanup anyway.
    defer if (allocator.vtable != std.heap.page_allocator.vtable) allocator.free(date); // FIX: Correct vtable comparison
    try writer.print("Date: {s}\r\n", .{date});

    // Set Connection header based on request keep-alive
    if (request) |req| {
        const keep_alive = req.isKeepAlive();
        try writer.print("Connection: {s}\r\n", .{if (keep_alive) "keep-alive" else "close"});
    } else {
        // Default to close if request info isn't available (e.g., error response)
        try writer.writeAll("Connection: close\r\n");
    }

    // Set default Server header
    try writer.writeAll("Server: zttp/1.0\r\n");

    // Write user-defined headers (these were already allocated using resp.allocator)
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
