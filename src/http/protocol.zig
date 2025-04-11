const std = @import("std");

/// Standard HTTP versions
pub const HttpVersion = struct {
    pub const HTTP_0_9 = "HTTP/0.9";
    pub const HTTP_1_0 = "HTTP/1.0";
    pub const HTTP_1_1 = "HTTP/1.1";
    pub const HTTP_2_0 = "HTTP/2.0";
    pub const HTTP_3_0 = "HTTP/3.0";
};

/// Standard HTTP methods
pub const HttpMethod = struct {
    pub const GET = "GET";
    pub const POST = "POST";
    pub const PUT = "PUT";
    pub const DELETE = "DELETE";
    pub const HEAD = "HEAD";
    pub const OPTIONS = "OPTIONS";
    pub const PATCH = "PATCH";
    pub const CONNECT = "CONNECT";
    pub const TRACE = "TRACE";
};

/// Common HTTP header names
pub const HttpHeader = struct {
    pub const ACCEPT = "Accept";
    pub const ACCEPT_CHARSET = "Accept-Charset";
    pub const ACCEPT_ENCODING = "Accept-Encoding";
    pub const ACCEPT_LANGUAGE = "Accept-Language";
    pub const AUTHORIZATION = "Authorization";
    pub const CACHE_CONTROL = "Cache-Control";
    pub const CONNECTION = "Connection";
    pub const CONTENT_ENCODING = "Content-Encoding";
    pub const CONTENT_LENGTH = "Content-Length";
    pub const CONTENT_TYPE = "Content-Type";
    pub const COOKIE = "Cookie";
    pub const DATE = "Date";
    pub const EXPECT = "Expect";
    pub const HOST = "Host";
    pub const IF_MATCH = "If-Match";
    pub const IF_MODIFIED_SINCE = "If-Modified-Since";
    pub const IF_NONE_MATCH = "If-None-Match";
    pub const IF_RANGE = "If-Range";
    pub const IF_UNMODIFIED_SINCE = "If-Unmodified-Since";
    pub const KEEP_ALIVE = "Keep-Alive";
    pub const ORIGIN = "Origin";
    pub const PRAGMA = "Pragma";
    pub const RANGE = "Range";
    pub const REFERER = "Referer";
    pub const SERVER = "Server";
    pub const SET_COOKIE = "Set-Cookie";
    pub const TE = "TE";
    pub const TRANSFER_ENCODING = "Transfer-Encoding";
    pub const UPGRADE = "Upgrade";
    pub const USER_AGENT = "User-Agent";
    pub const X_FORWARDED_FOR = "X-Forwarded-For";
    pub const X_FORWARDED_HOST = "X-Forwarded-Host";
    pub const X_FORWARDED_PROTO = "X-Forwarded-Proto";
};

/// Common HTTP header values
pub const HttpHeaderValue = struct {
    pub const CONNECTION_CLOSE = "close";
    pub const CONNECTION_KEEP_ALIVE = "keep-alive";
    pub const TRANSFER_ENCODING_CHUNKED = "chunked";
    pub const CONTENT_TYPE_FORM = "application/x-www-form-urlencoded";
    pub const CONTENT_TYPE_JSON = "application/json";
    pub const CONTENT_TYPE_HTML = "text/html";
    pub const CONTENT_TYPE_TEXT = "text/plain";
    pub const CONTENT_TYPE_XML = "application/xml";
    pub const CONTENT_TYPE_MULTIPART = "multipart/form-data";
};

/// Error types for HTTP protocol handling
pub const HttpError = error{
    InvalidRequest,
    InvalidHeader,
    InvalidMethod,
    InvalidVersion,
    InvalidStatus,
    InvalidUri,
    InvalidContentLength,
    InvalidTransferEncoding,
    InvalidChunk,
    IncompleteRequest,
    RequestTooLarge,
    ConnectionClosed,
    Timeout,
    ProtocolError,
};

/// Maximum size limits for various HTTP components
pub const HttpLimits = struct {
    pub const MAX_HEADER_SIZE = 8192; // 8KB
    pub const MAX_REQUEST_LINE_SIZE = 8192; // 8KB
    pub const MAX_HEADERS = 100;
    pub const MAX_REQUEST_SIZE = 1024 * 1024; // 1MB
    pub const MAX_URI_LENGTH = 8192; // 8KB
    pub const DEFAULT_TIMEOUT_MS = 30000; // 30 seconds
};

/// Chunk parser for chunked transfer encoding
pub const ChunkParser = struct {
    allocator: std.mem.Allocator,
    state: State,
    chunk_size: usize,
    chunk_read: usize,
    result: std.ArrayList(u8),
    buffer: []u8,

    pub const State = enum {
        CHUNK_SIZE,
        CHUNK_EXTENSION,
        CHUNK_DATA,
        CHUNK_END,
        TRAILER,
        FINISHED,
        ERROR,
    };

    /// Initialize a new chunk parser
    pub fn init(allocator: std.mem.Allocator, buffer_size: usize) !ChunkParser {
        return ChunkParser{
            .allocator = allocator,
            .state = .CHUNK_SIZE,
            .chunk_size = 0,
            .chunk_read = 0,
            .result = std.ArrayList(u8).init(allocator),
            .buffer = try allocator.alloc(u8, buffer_size),
        };
    }

    /// Free resources used by the chunk parser
    pub fn deinit(self: *ChunkParser) void {
        self.result.deinit();
        self.allocator.free(self.buffer);
    }

    /// Reset the chunk parser state for reuse
    pub fn reset(self: *ChunkParser) void {
        self.state = .CHUNK_SIZE;
        self.chunk_size = 0;
        self.chunk_read = 0;
        self.result.clearRetainingCapacity();
    }

    /// Parse a chunk of data
    pub fn parse(self: *ChunkParser, data: []const u8) !usize {
        var pos: usize = 0;

        while (pos < data.len) {
            switch (self.state) {
                .CHUNK_SIZE => {
                    // Read chunk size (hex number)
                    const line_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse {
                        // Not enough data to read chunk size
                        return pos;
                    };

                    // Find end of size (before any chunk extension)
                    const size_end = std.mem.indexOfPos(u8, data, pos, ";") orelse line_end;

                    // Parse hex chunk size
                    const size_str = std.mem.trim(u8, data[pos..size_end], " \t");
                    self.chunk_size = try std.fmt.parseInt(usize, size_str, 16);

                    if (size_end < line_end) {
                        // There's a chunk extension, skip to end of line
                        pos = line_end + 2;
                        self.state = .CHUNK_DATA;
                    } else {
                        // No chunk extension
                        pos = line_end + 2;
                        self.state = .CHUNK_DATA;
                    }

                    // If chunk size is 0, this is the last chunk
                    if (self.chunk_size == 0) {
                        self.state = .TRAILER;
                    }

                    self.chunk_read = 0;
                },

                .CHUNK_EXTENSION => {
                    // Skip any chunk extensions (rarely used)
                    const line_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse {
                        // Not enough data
                        return pos;
                    };

                    pos = line_end + 2;
                    self.state = .CHUNK_DATA;
                },

                .CHUNK_DATA => {
                    // Read chunk data
                    const remaining = self.chunk_size - self.chunk_read;
                    const available = data.len - pos;
                    const to_read = @min(remaining, available);

                    // Append chunk data to result
                    try self.result.appendSlice(data[pos .. pos + to_read]);

                    pos += to_read;
                    self.chunk_read += to_read;

                    // If we've read the entire chunk, move to the next state
                    if (self.chunk_read >= self.chunk_size) {
                        self.state = .CHUNK_END;
                    } else {
                        // Need more data for this chunk
                        return pos;
                    }
                },

                .CHUNK_END => {
                    // Each chunk ends with CRLF
                    if (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n') {
                        pos += 2;
                        self.state = .CHUNK_SIZE;
                    } else if (pos + 1 >= data.len) {
                        // Not enough data
                        return pos;
                    } else {
                        // Invalid chunk format
                        self.state = .ERROR;
                        return HttpError.InvalidChunk;
                    }
                },

                .TRAILER => {
                    // Handle trailing headers (if any)
                    const line_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse {
                        // Not enough data
                        return pos;
                    };

                    // Empty line indicates end of trailers
                    if (line_end == pos) {
                        pos += 2;
                        self.state = .FINISHED;
                        return pos;
                    }

                    // Skip this trailer header
                    pos = line_end + 2;
                },

                .FINISHED => {
                    // Parsing complete
                    return pos;
                },

                .ERROR => {
                    return HttpError.InvalidChunk;
                },
            }
        }

        return pos;
    }

    /// Get the parsed data
    pub fn getResult(self: *ChunkParser) ![]u8 {
        if (self.state != .FINISHED) {
            return HttpError.IncompleteRequest;
        }

        return self.result.toOwnedSlice();
    }
};

/// URL encode a string
pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~') {
            try result.append(c);
        } else if (c == ' ') {
            try result.append('+');
        } else {
            try result.writer().print("%{X:0>2}", .{c});
        }
    }

    return result.toOwnedSlice();
}

/// URL decode a string
pub fn urlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex = input[i + 1 .. i + 3];
            const value = try std.fmt.parseInt(u8, hex, 16);
            try result.append(value);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(' ');
            i += 1;
        } else {
            try result.append(input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

/// Parse a query string into a hash map
pub fn parseQueryString(allocator: std.mem.Allocator, query: []const u8) !std.StringHashMap([]const u8) {
    var params = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        var iter = params.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        params.deinit();
    }

    if (query.len == 0) {
        return params;
    }

    var pairs = std.mem.split(u8, query, "&");
    while (pairs.next()) |pair| {
        if (pair.len == 0) continue;

        var kv = std.mem.split(u8, pair, "=");
        const key_raw = kv.next() orelse continue;
        const val_raw = kv.next() orelse "";

        // URL decode the key and value
        const key = try urlDecode(allocator, key_raw);
        errdefer allocator.free(key);

        const value = try urlDecode(allocator, val_raw);
        errdefer allocator.free(value);

        // Check for duplicates and free them
        if (params.get(key)) |old_value| {
            allocator.free(old_value);
        }

        try params.put(key, value);
    }

    return params;
}

/// Get the current date in HTTP format (RFC 7231)
pub fn getHttpDate() []const u8 {
    var buffer: [32]u8 = undefined;
    const timestamp = std.time.timestamp();
    const date_time = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const utc = date_time.getEpochDay().calculateCivilFromDays();
    const seconds = date_time.getDaySeconds();
    const hours = @divTrunc(seconds, 3600);
    const minutes = @divTrunc(seconds % 3600, 60);
    const secs = seconds % 60;

    const days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    // HTTP date format: Wed, 21 Oct 2015 07:28:00 GMT
    const len = std.fmt.bufPrint(&buffer, "{s}, {d} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        days[@as(usize, @intCast(utc.day_of_week))],
        utc.day,
        months[@as(usize, @intCast(utc.month - 1))],
        utc.year,
        hours,
        minutes,
        secs,
    }) catch return "Thu, 01 Jan 1970 00:00:00 GMT";

    return buffer[0..len];
}

/// Parse a URI into its components
pub fn parseUri(allocator: std.mem.Allocator, uri: []const u8) !Uri {
    var result = Uri{
        .scheme = null,
        .username = null,
        .password = null,
        .host = null,
        .port = null,
        .path = "",
        .query = null,
        .fragment = null,
    };

    // Start by handling the scheme
    var rest = uri;
    if (std.mem.indexOf(u8, uri, "://")) |scheme_end| {
        result.scheme = try allocator.dupe(u8, uri[0..scheme_end]);
        rest = uri[scheme_end + 3 ..];
    }

    // Extract authority (user:pass@host:port)
    var path_start: usize = 0;
    if (result.scheme != null) {
        // Look for the first slash after the scheme
        path_start = std.mem.indexOf(u8, rest, "/") orelse rest.len;

        const authority = rest[0..path_start];

        // Extract username and password if present
        if (std.mem.indexOf(u8, authority, "@")) |auth_sep| {
            const user_pass = authority[0..auth_sep];

            if (std.mem.indexOf(u8, user_pass, ":")) |pass_sep| {
                result.username = try allocator.dupe(u8, user_pass[0..pass_sep]);
                result.password = try allocator.dupe(u8, user_pass[pass_sep + 1 ..]);
            } else {
                result.username = try allocator.dupe(u8, user_pass);
            }

            // Extract host and port
            const host_port = authority[auth_sep + 1 ..];

            if (std.mem.lastIndexOf(u8, host_port, ":")) |port_sep| {
                result.host = try allocator.dupe(u8, host_port[0..port_sep]);
                result.port = try allocator.dupe(u8, host_port[port_sep + 1 ..]);
            } else {
                result.host = try allocator.dupe(u8, host_port);
            }
        } else {
            // No username/password, just host and port
            if (std.mem.lastIndexOf(u8, authority, ":")) |port_sep| {
                result.host = try allocator.dupe(u8, authority[0..port_sep]);
                result.port = try allocator.dupe(u8, authority[port_sep + 1 ..]);
            } else {
                result.host = try allocator.dupe(u8, authority);
            }
        }

        // Move rest to point to the path part
        if (path_start < rest.len) {
            rest = rest[path_start..];
        } else {
            rest = "";
        }
    }

    // Parse path, query, and fragment
    const query_start = std.mem.indexOf(u8, rest, "?");
    const fragment_start = std.mem.indexOf(u8, rest, "#");

    // Determine boundaries
    const path_end = if (query_start) |qs|
        qs
    else if (fragment_start) |fs|
        fs
    else
        rest.len;

    // Extract path
    result.path = try allocator.dupe(u8, rest[0..path_end]);

    // Extract query if present
    if (query_start) |qs| {
        const query_end = if (fragment_start) |fs| if (fs > qs) fs else rest.len else rest.len;
        result.query = try allocator.dupe(u8, rest[qs + 1 .. query_end]);
    }

    // Extract fragment if present
    if (fragment_start) |fs| {
        result.fragment = try allocator.dupe(u8, rest[fs + 1 ..]);
    }

    return result;
}

/// URI structure with all components
pub const Uri = struct {
    scheme: ?[]const u8,
    username: ?[]const u8,
    password: ?[]const u8,
    host: ?[]const u8,
    port: ?[]const u8,
    path: []const u8,
    query: ?[]const u8,
    fragment: ?[]const u8,

    /// Free all allocated components of the URI
    pub fn deinit(self: *Uri, allocator: std.mem.Allocator) void {
        if (self.scheme) |s| allocator.free(s);
        if (self.username) |u| allocator.free(u);
        if (self.password) |p| allocator.free(p);
        if (self.host) |h| allocator.free(h);
        if (self.port) |p| allocator.free(p);
        allocator.free(self.path);
        if (self.query) |q| allocator.free(q);
        if (self.fragment) |f| allocator.free(f);
    }

    /// Convert URI to string
    pub fn toString(self: *const Uri, allocator: std.mem.Allocator) ![]u8 {
        var result = std.ArrayList(u8).init(allocator);
        errdefer result.deinit();

        // Add scheme if present
        if (self.scheme) |scheme| {
            try result.writer().print("{s}://", .{scheme});
        }

        // Add username and password if present
        if (self.username != null or self.password != null) {
            if (self.username) |username| {
                try result.writer().print("{s}", .{username});
            }

            if (self.password) |password| {
                try result.writer().print(":{s}", .{password});
            }

            try result.writer().writeAll("@");
        }

        // Add host and port if present
        if (self.host) |host| {
            try result.writer().print("{s}", .{host});

            if (self.port) |port| {
                try result.writer().print(":{s}", .{port});
            }
        }

        // Add path (always present, even if empty)
        try result.writer().print("{s}", .{self.path});

        // Add query if present
        if (self.query) |query| {
            if (query.len > 0) {
                try result.writer().print("?{s}", .{query});
            }
        }

        // Add fragment if present
        if (self.fragment) |fragment| {
            try result.writer().print("#{s}", .{fragment});
        }

        return result.toOwnedSlice();
    }
};

/// Parse form-urlencoded body data
pub fn parseFormUrlEncoded(allocator: std.mem.Allocator, body: []const u8) !std.StringHashMap([]const u8) {
    return parseQueryString(allocator, body);
}

/// Detect content type from file extension
pub fn getContentTypeFromExtension(extension: []const u8) []const u8 {
    const ext = std.ascii.lowerString(extension, extension);

    const mime_types = std.ComptimeStringMap([]const u8, .{
        .{ "html", "text/html; charset=utf-8" },
        .{ "htm", "text/html; charset=utf-8" },
        .{ "css", "text/css; charset=utf-8" },
        .{ "js", "text/javascript; charset=utf-8" },
        .{ "json", "application/json; charset=utf-8" },
        .{ "xml", "application/xml; charset=utf-8" },
        .{ "txt", "text/plain; charset=utf-8" },
        .{ "md", "text/markdown; charset=utf-8" },
        .{ "jpg", "image/jpeg" },
        .{ "jpeg", "image/jpeg" },
        .{ "png", "image/png" },
        .{ "gif", "image/gif" },
        .{ "webp", "image/webp" },
        .{ "svg", "image/svg+xml" },
        .{ "ico", "image/x-icon" },
        .{ "pdf", "application/pdf" },
        .{ "zip", "application/zip" },
        .{ "tar", "application/x-tar" },
        .{ "gz", "application/gzip" },
        .{ "mp3", "audio/mpeg" },
        .{ "mp4", "video/mp4" },
        .{ "webm", "video/webm" },
        .{ "ttf", "font/ttf" },
        .{ "woff", "font/woff" },
        .{ "woff2", "font/woff2" },
    });

    return mime_types.get(ext) orelse "application/octet-stream";
}

/// Generate a boundary string for multipart form data
pub fn generateBoundary(allocator: std.mem.Allocator) ![]u8 {
    var rnd = std.crypto.random;
    var bytes: [16]u8 = undefined;
    rnd.bytes(&bytes);

    var buffer: [48]u8 = undefined;
    const hex_str = try std.fmt.bufPrint(&buffer, "------------------------{}", .{std.fmt.fmtSliceHexLower(bytes)});

    return allocator.dupe(u8, hex_str);
}

/// Safely get a header value with case-insensitive lookup
pub fn getHeaderValue(headers: std.StringHashMap([]const u8), name: []const u8) ?[]const u8 {
    // Try direct lookup first (faster)
    if (headers.get(name)) |value| {
        return value;
    }

    // Try case-insensitive lookup
    var iter = headers.iterator();
    while (iter.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) {
            return entry.value_ptr.*;
        }
    }

    return null;
}
