const std = @import("std");
const protocol = @import("protocol.zig");

/// Common HTTP status codes
pub const StatusCode = enum(u16) {
    // 1xx - Informational
    CONTINUE = 100,
    SWITCHING_PROTOCOLS = 101,
    PROCESSING = 102,
    EARLY_HINTS = 103,

    // 2xx - Success
    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NON_AUTHORITATIVE_INFORMATION = 203,
    NO_CONTENT = 204,
    RESET_CONTENT = 205,
    PARTIAL_CONTENT = 206,

    // 3xx - Redirection
    MULTIPLE_CHOICES = 300,
    MOVED_PERMANENTLY = 301,
    FOUND = 302,
    SEE_OTHER = 303,
    NOT_MODIFIED = 304,
    TEMPORARY_REDIRECT = 307,
    PERMANENT_REDIRECT = 308,

    // 4xx - Client Errors
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    PAYMENT_REQUIRED = 402,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    NOT_ACCEPTABLE = 406,
    PROXY_AUTHENTICATION_REQUIRED = 407,
    REQUEST_TIMEOUT = 408,
    CONFLICT = 409,
    GONE = 410,
    LENGTH_REQUIRED = 411,
    PRECONDITION_FAILED = 412,
    PAYLOAD_TOO_LARGE = 413,
    URI_TOO_LONG = 414,
    UNSUPPORTED_MEDIA_TYPE = 415,
    RANGE_NOT_SATISFIABLE = 416,
    EXPECTATION_FAILED = 417,
    IM_A_TEAPOT = 418,
    UNPROCESSABLE_ENTITY = 422,
    TOO_EARLY = 425,
    UPGRADE_REQUIRED = 426,
    PRECONDITION_REQUIRED = 428,
    TOO_MANY_REQUESTS = 429,
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    UNAVAILABLE_FOR_LEGAL_REASONS = 451,

    // 5xx - Server Errors
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    BAD_GATEWAY = 502,
    SERVICE_UNAVAILABLE = 503,
    GATEWAY_TIMEOUT = 504,
    HTTP_VERSION_NOT_SUPPORTED = 505,
    VARIANT_ALSO_NEGOTIATES = 506,
    INSUFFICIENT_STORAGE = 507,
    LOOP_DETECTED = 508,
    NOT_EXTENDED = 510,
    NETWORK_AUTHENTICATION_REQUIRED = 511,

    // Custom status code
    CUSTOM = 0,

    /// Get the standard reason phrase for a status code
    pub fn getReasonPhrase(self: StatusCode) []const u8 {
        return switch (self) {
            // 1xx
            .CONTINUE => "Continue",
            .SWITCHING_PROTOCOLS => "Switching Protocols",
            .PROCESSING => "Processing",
            .EARLY_HINTS => "Early Hints",

            // 2xx
            .OK => "OK",
            .CREATED => "Created",
            .ACCEPTED => "Accepted",
            .NON_AUTHORITATIVE_INFORMATION => "Non-Authoritative Information",
            .NO_CONTENT => "No Content",
            .RESET_CONTENT => "Reset Content",
            .PARTIAL_CONTENT => "Partial Content",

            // 3xx
            .MULTIPLE_CHOICES => "Multiple Choices",
            .MOVED_PERMANENTLY => "Moved Permanently",
            .FOUND => "Found",
            .SEE_OTHER => "See Other",
            .NOT_MODIFIED => "Not Modified",
            .TEMPORARY_REDIRECT => "Temporary Redirect",
            .PERMANENT_REDIRECT => "Permanent Redirect",

            // 4xx
            .BAD_REQUEST => "Bad Request",
            .UNAUTHORIZED => "Unauthorized",
            .PAYMENT_REQUIRED => "Payment Required",
            .FORBIDDEN => "Forbidden",
            .NOT_FOUND => "Not Found",
            .METHOD_NOT_ALLOWED => "Method Not Allowed",
            .NOT_ACCEPTABLE => "Not Acceptable",
            .PROXY_AUTHENTICATION_REQUIRED => "Proxy Authentication Required",
            .REQUEST_TIMEOUT => "Request Timeout",
            .CONFLICT => "Conflict",
            .GONE => "Gone",
            .LENGTH_REQUIRED => "Length Required",
            .PRECONDITION_FAILED => "Precondition Failed",
            .PAYLOAD_TOO_LARGE => "Payload Too Large",
            .URI_TOO_LONG => "URI Too Long",
            .UNSUPPORTED_MEDIA_TYPE => "Unsupported Media Type",
            .RANGE_NOT_SATISFIABLE => "Range Not Satisfiable",
            .EXPECTATION_FAILED => "Expectation Failed",
            .IM_A_TEAPOT => "I'm a teapot",
            .UNPROCESSABLE_ENTITY => "Unprocessable Entity",
            .TOO_EARLY => "Too Early",
            .UPGRADE_REQUIRED => "Upgrade Required",
            .PRECONDITION_REQUIRED => "Precondition Required",
            .TOO_MANY_REQUESTS => "Too Many Requests",
            .REQUEST_HEADER_FIELDS_TOO_LARGE => "Request Header Fields Too Large",
            .UNAVAILABLE_FOR_LEGAL_REASONS => "Unavailable For Legal Reasons",

            // 5xx
            .INTERNAL_SERVER_ERROR => "Internal Server Error",
            .NOT_IMPLEMENTED => "Not Implemented",
            .BAD_GATEWAY => "Bad Gateway",
            .SERVICE_UNAVAILABLE => "Service Unavailable",
            .GATEWAY_TIMEOUT => "Gateway Timeout",
            .HTTP_VERSION_NOT_SUPPORTED => "HTTP Version Not Supported",
            .VARIANT_ALSO_NEGOTIATES => "Variant Also Negotiates",
            .INSUFFICIENT_STORAGE => "Insufficient Storage",
            .LOOP_DETECTED => "Loop Detected",
            .NOT_EXTENDED => "Not Extended",
            .NETWORK_AUTHENTICATION_REQUIRED => "Network Authentication Required",

            // Custom
            .CUSTOM => "Custom Status",
        };
    }
};

/// Common MIME types
pub const ContentType = struct {
    pub const TEXT_PLAIN = "text/plain; charset=utf-8";
    pub const TEXT_HTML = "text/html; charset=utf-8";
    pub const TEXT_CSS = "text/css; charset=utf-8";
    pub const TEXT_JAVASCRIPT = "text/javascript; charset=utf-8";
    pub const APPLICATION_JSON = "application/json; charset=utf-8";
    pub const APPLICATION_XML = "application/xml; charset=utf-8";
    pub const APPLICATION_FORM = "application/x-www-form-urlencoded";
    pub const APPLICATION_OCTET_STREAM = "application/octet-stream";
    pub const MULTIPART_FORM_DATA = "multipart/form-data";
    pub const IMAGE_JPEG = "image/jpeg";
    pub const IMAGE_PNG = "image/png";
    pub const IMAGE_GIF = "image/gif";
    pub const IMAGE_SVG = "image/svg+xml";
};

/// HTTP response structure
pub const Response = struct {
    allocator: std.mem.Allocator,
    status: u16,
    status_enum: StatusCode,
    reason_phrase: []const u8,
    headers: std.StringHashMap([]const u8),
    body: ?[]const u8,
    cookies: std.ArrayList(Cookie),
    sent: bool,

    /// Initialize a new response with default values
    pub fn init(allocator: std.mem.Allocator) Response {
        return .{
            .allocator = allocator,
            .status = 200,
            .status_enum = .OK,
            .reason_phrase = "OK",
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
            .cookies = std.ArrayList(Cookie).init(allocator),
            .sent = false,
        };
    }

    /// Set the status code and reason phrase
    pub fn setStatus(self: *Response, status: StatusCode) !void {
        self.status = @intFromEnum(status);
        self.status_enum = status;

        // Free any previous custom reason phrase
        if (self.reason_phrase.len > 0 and self.status_enum == .CUSTOM) {
            self.allocator.free(self.reason_phrase);
        }

        self.reason_phrase = status.getReasonPhrase();
    }

    /// Set a custom status code and reason phrase
    pub fn setCustomStatus(self: *Response, code: u16, reason: []const u8) !void {
        self.status = code;
        self.status_enum = .CUSTOM;

        // Free any previous custom reason phrase
        if (self.reason_phrase.len > 0 and self.status_enum == .CUSTOM) {
            self.allocator.free(self.reason_phrase);
        }

        self.reason_phrase = try self.allocator.dupe(u8, reason);
    }

    /// Set a response header
    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);

        const value_dup = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_dup);

        // If header already exists, free the old value
        if (self.headers.get(name_dup)) |old_value| {
            self.allocator.free(old_value);
        }

        try self.headers.put(name_dup, value_dup);
    }

    /// Set the response body
    pub fn setBody(self: *Response, body: []const u8) !void {
        // Free any existing body
        if (self.body) |b| {
            self.allocator.free(b);
        }

        self.body = try self.allocator.dupe(u8, body);
    }

    /// Set the response body with specific content type
    pub fn setBodyWithType(self: *Response, body: []const u8, content_type: []const u8) !void {
        try self.setBody(body);
        try self.setHeader("Content-Type", content_type);
    }

    /// Set JSON response body from a string
    pub fn json(self: *Response, json_string: []const u8) !void {
        try self.setBodyWithType(json_string, ContentType.APPLICATION_JSON);
    }

    /// Set HTML response body
    pub fn html(self: *Response, html_string: []const u8) !void {
        try self.setBodyWithType(html_string, ContentType.TEXT_HTML);
    }

    /// Set plain text response body
    pub fn text(self: *Response, text_string: []const u8) !void {
        try self.setBodyWithType(text_string, ContentType.TEXT_PLAIN);
    }

    /// Add a cookie to the response
    pub fn setCookie(self: *Response, cookie: Cookie) !void {
        try self.cookies.append(cookie);
    }

    /// Create and add a simple cookie with just name and value
    pub fn addSimpleCookie(self: *Response, name: []const u8, value: []const u8) !void {
        const cookie = Cookie{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
            .max_age = null,
            .expires = null,
            .path = null,
            .domain = null,
            .secure = false,
            .http_only = false,
            .same_site = .LAX,
        };
        try self.cookies.append(cookie);
    }

    /// Send redirect response
    pub fn redirect(self: *Response, location: []const u8, temporary: bool) !void {
        try self.setHeader("Location", location);

        if (temporary) {
            try self.setStatus(.FOUND); // 302 Found
        } else {
            try self.setStatus(.MOVED_PERMANENTLY); // 301 Moved Permanently
        }
    }

    /// Generate the full response as a byte array
    pub fn generate(self: *Response) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();

        // Status line
        try buffer.writer().print("HTTP/1.1 {} {s}\r\n", .{ self.status, self.reason_phrase });

        // Add content length header if body exists
        if (self.body) |body| {
            if (protocol.getHeaderValue("Content-Length") == null) {
                try buffer.writer().print("Content-Length: {}\r\n", .{body.len});
            }

            // Add default content type if not set
            if (protocol.getHeaderValue("Content-Type") == null) {
                try buffer.writer().writeAll("Content-Type: text/plain; charset=utf-8\r\n");
            }
        } else if (self.status != 204 and self.status != 304) {
            // Add zero content length for non-body responses except 204 and 304
            try buffer.writer().writeAll("Content-Length: 0\r\n");
        }

        // Add Date header if not set
        if (protocol.getHeaderValue("Date") == null) {
            const date = try protocol.getHttpDate();
            try buffer.writer().print("Date: {s}\r\n", .{date});
        }

        // Add Connection header if not set
        if (protocol.getHeaderValue("Connection") == null) {
            try buffer.writer().writeAll("Connection: keep-alive\r\n");
        }

        // Add Server header if not set
        if (protocol.getHeaderValue("Server") == null) {
            try buffer.writer().writeAll("Server: Zig HTTP Server\r\n");
        }

        // Add headers
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            try buffer.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // Add cookies
        for (self.cookies.items) |cookie| {
            const cookie_str = try cookie.toString(self.allocator);
            defer self.allocator.free(cookie_str);
            try buffer.writer().print("Set-Cookie: {s}\r\n", .{cookie_str});
        }

        // End of headers
        try buffer.writer().writeAll("\r\n");

        // Add body if exists
        if (self.body) |body| {
            try buffer.writer().writeAll(body);
        }

        return buffer.toOwnedSlice();
    }

    /// Send the response to a network stream
    pub fn send(self: *Response, stream: std.net.Stream) !void {
        if (self.sent) {
            return error.ResponseAlreadySent;
        }

        const response_data = try self.generate();
        defer self.allocator.free(response_data);

        try stream.writeAll(response_data);
        self.sent = true;
    }

    /// Create a JSON error response
    pub fn errorResponse(self: *Response, status: StatusCode, message: []const u8) !void {
        try self.setStatus(status);

        const error_json = try std.fmt.allocPrint(self.allocator,
            \\{{
            \\  "error": true,
            \\  "status": {},
            \\  "message": "{s}"
            \\}}
        , .{ self.status, message });
        defer self.allocator.free(error_json);

        try self.json(error_json);
    }

    /// Create a simple text response with a status code
    pub fn simpleResponse(self: *Response, status: StatusCode, message: []const u8) !void {
        try self.setStatus(status);
        try self.text(message);
    }

    /// Create a basic 404 Not Found response
    pub fn notFound(self: *Response) !void {
        try self.setStatus(.NOT_FOUND);
        try self.html("<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource could not be found on this server.</p></body></html>");
    }

    /// Create a basic 500 Internal Server Error response
    pub fn internalError(self: *Response) !void {
        try self.setStatus(.INTERNAL_SERVER_ERROR);
        try self.html("<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1><p>The server encountered an internal error and was unable to complete your request.</p></body></html>");
    }

    /// Free all resources allocated by the response
    pub fn deinit(self: *Response) void {
        // Free all header keys and values
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();

        // Free custom reason phrase if any
        if (self.status_enum == .CUSTOM) {
            self.allocator.free(self.reason_phrase);
        }

        // Free body if it exists
        if (self.body) |b| {
            self.allocator.free(b);
        }

        // Free cookies
        for (self.cookies.items) |*cookie| {
            cookie.deinit(self.allocator);
        }
        self.cookies.deinit();
    }
};

/// HTTP Cookie structure
pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    max_age: ?i64,
    expires: ?[]const u8,
    path: ?[]const u8,
    domain: ?[]const u8,
    secure: bool,
    http_only: bool,
    same_site: SameSite,

    pub const SameSite = enum {
        STRICT,
        LAX,
        NONE,

        pub fn toString(self: SameSite) []const u8 {
            return switch (self) {
                .STRICT => "Strict",
                .LAX => "Lax",
                .NONE => "None",
            };
        }
    };

    /// Convert a cookie to its string representation
    pub fn toString(self: *const Cookie, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();

        try buffer.writer().print("{s}={s}", .{ self.name, self.value });

        if (self.max_age) |age| {
            try buffer.writer().print("; Max-Age={}", .{age});
        }

        if (self.expires) |exp| {
            try buffer.writer().print("; Expires={s}", .{exp});
        }

        if (self.path) |p| {
            try buffer.writer().print("; Path={s}", .{p});
        }

        if (self.domain) |d| {
            try buffer.writer().print("; Domain={s}", .{d});
        }

        if (self.secure) {
            try buffer.writer().writeAll("; Secure");
        }

        if (self.http_only) {
            try buffer.writer().writeAll("; HttpOnly");
        }

        try buffer.writer().print("; SameSite={s}", .{self.same_site.toString()});

        return buffer.toOwnedSlice();
    }

    /// Free all resources allocated by the cookie
    pub fn deinit(self: *Cookie, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);

        if (self.expires) |exp| {
            allocator.free(exp);
        }

        if (self.path) |p| {
            allocator.free(p);
        }

        if (self.domain) |d| {
            allocator.free(d);
        }
    }
};

/// Utility functions to create common responses
pub fn createTextResponse(allocator: std.mem.Allocator, text: []const u8) !Response {
    var response = Response.init(allocator);
    try response.text(text);
    return response;
}

pub fn createJsonResponse(allocator: std.mem.Allocator, json: []const u8) !Response {
    var response = Response.init(allocator);
    try response.json(json);
    return response;
}

pub fn createHtmlResponse(allocator: std.mem.Allocator, html: []const u8) !Response {
    var response = Response.init(allocator);
    try response.html(html);
    return response;
}

pub fn createRedirectResponse(allocator: std.mem.Allocator, location: []const u8, temporary: bool) !Response {
    var response = Response.init(allocator);
    try response.redirect(location, temporary);
    return response;
}

pub fn createErrorResponse(allocator: std.mem.Allocator, status: StatusCode, message: []const u8) !Response {
    var response = Response.init(allocator);
    try response.errorResponse(status, message);
    return response;
}

pub fn createNotFoundResponse(allocator: std.mem.Allocator) !Response {
    var response = Response.init(allocator);
    try response.notFound();
    return response;
}
