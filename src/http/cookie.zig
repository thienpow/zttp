const std = @import("std");

/// Errors related to cookie parsing.
pub const CookieError = error{
    TooManyCookies,
    InvalidCookie,
};

/// Parses the Cookie header value into a map of cookie names and values.
/// The caller owns the returned map and must free it using the provided allocator.
pub fn parseCookies(allocator: std.mem.Allocator, cookie_str: []const u8) !std.StringHashMap([]const u8) {
    var cookies = std.StringHashMap([]const u8).init(allocator);
    var cookie_count: usize = 0;

    var pairs = std.mem.splitScalar(u8, cookie_str, ';');
    while (pairs.next()) |pair| {
        if (pair.len == 0) continue;
        cookie_count += 1;
        if (cookie_count > 50) return CookieError.TooManyCookies;

        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return CookieError.InvalidCookie;
        const name = std.mem.trim(u8, pair[0..eq], " ");
        const value = std.mem.trim(u8, pair[eq + 1 ..], " ");
        if (name.len == 0) return CookieError.InvalidCookie;

        try cookies.put(
            try allocator.dupe(u8, name),
            try allocator.dupe(u8, value),
        );
    }

    return cookies;
}
