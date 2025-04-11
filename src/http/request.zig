const std = @import("std");
const protocol = @import("protocol.zig");

/// HTTP request methods
pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    CONNECT,
    TRACE,
    UNKNOWN,

    /// Convert string to Method enum
    pub fn fromString(str: []const u8) Method {
        const methods = std.ComptimeStringMap(Method, .{
            .{ "GET", .GET },
            .{ "POST", .POST },
            .{ "PUT", .PUT },
            .{ "DELETE", .DELETE },
            .{ "HEAD", .HEAD },
            .{ "OPTIONS", .OPTIONS },
            .{ "PATCH", .PATCH },
            .{ "CONNECT", .CONNECT },
            .{ "TRACE", .TRACE },
        });

        return methods.get(str) orelse .UNKNOWN;
    }

    /// Convert Method enum to string
    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .PATCH => "PATCH",
            .CONNECT => "CONNECT",
            .TRACE => "TRACE",
            .UNKNOWN => "UNKNOWN",
        };
    }
};

/// HTTP version enum
pub const HttpVersion = enum {
    HTTP_1_0,
    HTTP_1_1,
    HTTP_2_0,
    UNKNOWN,

    /// Convert string to HttpVersion enum
    pub fn fromString(str: []const u8) HttpVersion {
        if (std.mem.eql(u8, str, "HTTP/1.0")) return .HTTP_1_0;
        if (std.mem.eql(u8, str, "HTTP/1.1")) return .HTTP_1_1;
        if (std.mem.eql(u8, str, "HTTP/2.0")) return .HTTP_2_0;
        return .UNKNOWN;
    }

    /// Convert HttpVersion enum to string
    pub fn toString(self: HttpVersion) []const u8 {
        return switch (self) {
            .HTTP_1_0 => "HTTP/1.0",
            .HTTP_1_1 => "HTTP/1.1",
            .HTTP_2_0 => "HTTP/2.0",
            .UNKNOWN => "UNKNOWN",
        };
    }
};

/// HTTP request structure
pub const Request = struct {
    allocator: std.mem.Allocator,
    method: []const u8,
    method_enum: Method,
    path: []const u8,
    version: []const u8,
    version_enum: HttpVersion,
    headers: std.StringHashMap([]const u8),
    params: std.StringHashMap([]const u8),
    body: ?[]const u8,
    content_type: ?[]const u8,
    content_length: ?usize,
    host: ?[]const u8,
    is_keep_alive: bool,

    /// Create a new empty request with the given allocator
    pub fn init(allocator: std.mem.Allocator) !Request {
        return Request{
            .allocator = allocator,
            .method = try allocator.dupe(u8, ""),
            .method_enum = .UNKNOWN,
            .path = try allocator.dupe(u8, ""),
            .version = try allocator.dupe(u8, ""),
            .version_enum = .UNKNOWN,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .params = std.StringHashMap([]const u8).init(allocator),
            .body = null,
            .content_type = null,
            .content_length = null,
            .host = null,
            .is_keep_alive = false,
        };
    }

    /// Free all resources allocated by the request
    pub fn deinit(self: *Request) void {
        // Free all header keys and values
        var header_iter = self.headers.iterator();
        while (header_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();

        // Free all param keys and values
        var param_iter = self.params.iterator();
        while (param_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.params.deinit();

        // Free other string fields
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        self.allocator.free(self.version);

        // Free body if it exists
        if (self.body) |b| self.allocator.free(b);

        // Note: content_type, host are just references to headers and shouldn't be freed separately
    }

    /// Get a query parameter by name
    pub fn getParam(self: *const Request, name: []const u8) ?[]const u8 {
        return self.params.get(name);
    }

    /// Check if request has a specific header
    pub fn hasHeader(_: *const Request, name: []const u8) bool {
        return protocol.getHeaderValue(name) != null;
    }

    /// Check if request is a specific method
    pub fn isMethod(self: *const Request, method_check: Method) bool {
        return self.method_enum == method_check;
    }

    /// Parse content type from headers
    pub fn parseContentType(self: *Request) void {
        self.content_type = protocol.getHeaderValue("Content-Type");
    }

    /// Parse content length from headers
    pub fn parseContentLength(self: *Request) void {
        if (protocol.getHeaderValue("Content-Length")) |len_str| {
            self.content_length = std.fmt.parseInt(usize, len_str, 10) catch null;
        }
    }

    /// Parse host from headers
    pub fn parseHost(self: *Request) void {
        self.host = protocol.getHeaderValue("Host");
    }

    /// Check if request uses keep-alive connection
    pub fn parseKeepAlive(self: *Request) void {
        if (self.version_enum == .HTTP_1_1) {
            // HTTP/1.1 defaults to keep-alive unless explicitly set to close
            if (protocol.getHeaderValue("Connection")) |conn| {
                self.is_keep_alive = !std.ascii.eqlIgnoreCase(conn, "close");
            } else {
                self.is_keep_alive = true;
            }
        } else {
            // HTTP/1.0 defaults to close unless explicitly set to keep-alive
            if (protocol.getHeaderValue("Connection")) |conn| {
                self.is_keep_alive = std.ascii.eqlIgnoreCase(conn, "keep-alive");
            } else {
                self.is_keep_alive = false;
            }
        }
    }

    /// Parse common fields from headers for convenience access
    pub fn parseCommonFields(self: *Request) void {
        self.method_enum = Method.fromString(self.method);
        self.version_enum = HttpVersion.fromString(self.version);
        self.parseContentType();
        self.parseContentLength();
        self.parseHost();
        self.parseKeepAlive();
    }

    /// Get the path without any query parameters
    pub fn getPathOnly(self: *const Request) []const u8 {
        if (std.mem.indexOfScalar(u8, self.path, '?')) |idx| {
            return self.path[0..idx];
        }
        return self.path;
    }

    /// Check if the path matches a pattern (exact match)
    pub fn pathMatches(self: *const Request, pattern: []const u8) bool {
        return std.mem.eql(u8, self.getPathOnly(), pattern);
    }

    /// Check if the path starts with a prefix
    pub fn pathStartsWith(self: *const Request, prefix: []const u8) bool {
        return std.mem.startsWith(u8, self.getPathOnly(), prefix);
    }

    /// Check if this is a JSON request based on Content-Type header
    pub fn isJsonRequest(self: *const Request) bool {
        if (self.content_type) |ct| {
            return std.mem.startsWith(u8, ct, "application/json");
        }
        return false;
    }

    /// Check if this is a form submission based on Content-Type header
    pub fn isFormSubmission(self: *const Request) bool {
        if (self.content_type) |ct| {
            return std.mem.startsWith(u8, ct, "application/x-www-form-urlencoded") or
                std.mem.startsWith(u8, ct, "multipart/form-data");
        }
        return false;
    }

    /// Clone this request (creates a deep copy)
    pub fn clone(self: *const Request) !Request {
        var new_request = try Request.init(self.allocator);
        errdefer new_request.deinit();

        // Copy basic fields
        new_request.allocator.free(new_request.method);
        new_request.method = try self.allocator.dupe(u8, self.method);
        new_request.method_enum = self.method_enum;

        new_request.allocator.free(new_request.path);
        new_request.path = try self.allocator.dupe(u8, self.path);

        new_request.allocator.free(new_request.version);
        new_request.version = try self.allocator.dupe(u8, self.version);
        new_request.version_enum = self.version_enum;

        // Copy headers
        var header_iter = self.headers.iterator();
        while (header_iter.next()) |entry| {
            const key_dup = try self.allocator.dupe(u8, entry.key_ptr.*);
            errdefer self.allocator.free(key_dup);
            const val_dup = try self.allocator.dupe(u8, entry.value_ptr.*);
            errdefer self.allocator.free(val_dup);
            try new_request.headers.put(key_dup, val_dup);
        }

        // Copy params
        var param_iter = self.params.iterator();
        while (param_iter.next()) |entry| {
            const key_dup = try self.allocator.dupe(u8, entry.key_ptr.*);
            errdefer self.allocator.free(key_dup);
            const val_dup = try self.allocator.dupe(u8, entry.value_ptr.*);
            errdefer self.allocator.free(val_dup);
            try new_request.params.put(key_dup, val_dup);
        }

        // Copy body if it exists
        if (self.body) |b| {
            new_request.body = try self.allocator.dupe(u8, b);
        }

        // Copy derived fields
        new_request.content_type = self.content_type;
        new_request.content_length = self.content_length;
        new_request.host = self.host;
        new_request.is_keep_alive = self.is_keep_alive;

        return new_request;
    }

    /// Create a debug representation of the request
    pub fn debugString(self: *const Request, allocator: std.mem.Allocator) ![]u8 {
        var result = std.ArrayList(u8).init(allocator);
        errdefer result.deinit();

        try result.writer().print("{s} {s} {s}\n", .{ self.method, self.path, self.version });

        // Print headers
        var header_iter = self.headers.iterator();
        while (header_iter.next()) |entry| {
            try result.writer().print("{s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // Print params
        try result.writer().print("\nQuery Parameters:\n", .{});
        var param_iter = self.params.iterator();
        while (param_iter.next()) |entry| {
            try result.writer().print("  {s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // Print body if it exists
        if (self.body) |b| {
            try result.writer().print("\nBody ({} bytes):\n{s}\n", .{ b.len, b });
        } else {
            try result.writer().print("\nNo body\n", .{});
        }

        return result.toOwnedSlice();
    }
};

/// Utility function to create a simple GET request
pub fn createGetRequest(allocator: std.mem.Allocator, path: []const u8) !Request {
    var request = try Request.init(allocator);
    errdefer request.deinit();

    // Free default empty strings
    allocator.free(request.method);
    allocator.free(request.path);
    allocator.free(request.version);

    // Set new values
    request.method = try allocator.dupe(u8, "GET");
    request.path = try allocator.dupe(u8, path);
    request.version = try allocator.dupe(u8, "HTTP/1.1");
    request.method_enum = .GET;
    request.version_enum = .HTTP_1_1;

    // Set default keep-alive for HTTP/1.1
    request.is_keep_alive = true;

    return request;
}
