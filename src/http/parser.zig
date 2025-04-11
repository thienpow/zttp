const std = @import("std");
const Request = @import("request.zig").Request;
const protocol = @import("protocol.zig");

/// Error types specific to HTTP parsing
pub const ParseError = error{
    InvalidRequest,
    InvalidMethod,
    InvalidPath,
    InvalidVersion,
    InvalidHeader,
    InvalidContentLength,
    IncompleteBody,
    InvalidChunkedEncoding,
    RequestTooLarge,
    UrlDecodingError,
};

/// Parse an HTTP request from raw data
pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Request {
    // Ensure request isn't empty
    if (data.len == 0) return ParseError.InvalidRequest;

    var lines = std.mem.split(u8, data, "\r\n");
    const request_line = lines.next() orelse return ParseError.InvalidRequest;

    // Parse request line: "METHOD /path?query HTTP/VERSION"
    var parts = std.mem.split(u8, request_line, " ");
    const method = parts.next() orelse return ParseError.InvalidMethod;
    const full_path = parts.next() orelse return ParseError.InvalidPath;
    const version = parts.next() orelse return ParseError.InvalidVersion;

    // Validate HTTP method
    if (method.len == 0) return ParseError.InvalidMethod;

    // Validate path (must start with /)
    if (full_path.len == 0 or full_path[0] != '/') return ParseError.InvalidPath;

    // Validate HTTP version (must be HTTP/1.0 or HTTP/1.1)
    if (!std.mem.startsWith(u8, version, "HTTP/")) return ParseError.InvalidVersion;

    // Parse path and query parameters
    var path: []const u8 = undefined;
    var params = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        // Free all keys and values
        var param_iter = params.iterator();
        while (param_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        params.deinit();
    }

    if (std.mem.indexOfScalar(u8, full_path, '?')) |query_idx| {
        path = full_path[0..query_idx];
        const query = full_path[query_idx + 1 ..];
        var query_pairs = std.mem.split(u8, query, "&");

        while (query_pairs.next()) |pair| {
            if (pair.len == 0) continue;

            const kv = std.mem.split(u8, pair, "=");
            const key_raw = kv.next() orelse continue;
            const val_raw = kv.next() orelse "";

            // URL decode the key and value
            const key = try protocol.urlDecode(allocator, key_raw);
            errdefer allocator.free(key);

            const value = try protocol.urlDecode(allocator, val_raw);
            errdefer allocator.free(value);

            // Check for duplicates and free them
            if (params.get(key)) |old_value| {
                allocator.free(old_value);
            }

            try params.put(key, value);
        }
    } else {
        path = full_path;
    }

    // Parse headers
    var headers = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        // Free all keys and values
        var header_iter = headers.iterator();
        while (header_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        headers.deinit();
    }

    var body_start: ?usize = null;
    var line_idx: usize = request_line.len + 2; // After first "\r\n"

    while (lines.next()) |line| {
        if (line.len == 0) {
            body_start = line_idx + 2; // After "\r\n\r\n"
            break;
        }

        const header_parts = std.mem.indexOf(u8, line, ": ") orelse {
            line_idx += line.len + 2; // Move past this line + "\r\n"
            continue; // Skip malformed headers
        };

        const key = std.mem.trim(u8, line[0..header_parts], " ");
        const value = std.mem.trim(u8, line[header_parts + 2 ..], " ");

        if (key.len == 0) {
            line_idx += line.len + 2;
            continue; // Skip empty header names
        }

        const key_dup = try allocator.dupe(u8, key);
        errdefer allocator.free(key_dup);

        const val_dup = try allocator.dupe(u8, value);
        errdefer allocator.free(val_dup);

        // Check for and free any duplicate headers
        if (headers.get(key_dup)) |old_value| {
            allocator.free(old_value);
        }

        try headers.put(key_dup, val_dup);
        line_idx += line.len + 2; // Update position
    }

    // Parse body based on transfer encoding or content length
    var body: ?[]u8 = null;
    errdefer if (body) |b| allocator.free(b);

    if (body_start) |start| {
        const transfer_encoding = headers.get("Transfer-Encoding");

        if (transfer_encoding != null and std.mem.eql(u8, transfer_encoding.?, "chunked")) {
            // Handle chunked encoding
            body = try parseChunkedBody(allocator, data[start..]);
        } else if (headers.get("Content-Length")) |len_str| {
            const content_length = std.fmt.parseInt(usize, len_str, 10) catch
                return ParseError.InvalidContentLength;

            if (start + content_length <= data.len) {
                body = try allocator.dupe(u8, data[start .. start + content_length]);
            } else {
                return ParseError.IncompleteBody;
            }
        } else if (start < data.len) {
            // No content length or chunked encoding, but there is data
            body = try allocator.dupe(u8, data[start..]);
        }
    }

    const path_decoded = try protocol.urlDecode(allocator, path);
    const method_dup = try allocator.dupe(u8, method);
    const version_dup = try allocator.dupe(u8, version);

    return Request{
        .allocator = allocator,
        .method = method_dup,
        .path = path_decoded,
        .version = version_dup,
        .headers = headers,
        .params = params,
        .body = body,
    };
}

/// Parse chunked transfer encoding
fn parseChunkedBody(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var pos: usize = 0;

    while (pos < data.len) {
        // Find the end of the chunk size line
        const chunk_size_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse
            return ParseError.InvalidChunkedEncoding;

        // Parse the chunk size (in hex)
        const chunk_size_hex = std.mem.trim(u8, data[pos..chunk_size_end], " ");
        const chunk_size = try std.fmt.parseInt(usize, chunk_size_hex, 16);

        // Move past the chunk size line
        pos = chunk_size_end + 2;

        // Check if this is the final chunk
        if (chunk_size == 0) break;

        // Ensure we have enough data for the chunk
        if (pos + chunk_size > data.len) return ParseError.IncompleteBody;

        // Append the chunk data
        try result.appendSlice(data[pos .. pos + chunk_size]);

        // Move past the chunk data and its trailing CRLF
        pos = pos + chunk_size + 2;
    }

    return result.toOwnedSlice();
}
