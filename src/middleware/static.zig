// src/middleware/static.zig
const std = @import("std");
pub const Request = @import("../request.zig").Request;
pub const Response = @import("../response.zig").Response;
pub const Context = @import("../context.zig").Context;

const Allocator = std.mem.Allocator;

// Hardcoded static folder path
const STATIC_DIR = "static";

// Helper function to determine content type based on file extension
fn getContentType(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    if (std.mem.eql(u8, ext, ".html")) return "text/html";
    if (std.mem.eql(u8, ext, ".css")) return "text/css";
    if (std.mem.eql(u8, ext, ".js")) return "application/javascript";
    if (std.mem.eql(u8, ext, ".png")) return "image/png";
    if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg")) return "image/jpeg";
    if (std.mem.eql(u8, ext, ".gif")) return "image/gif";
    return "application/octet-stream";
}

// Middleware handler for static files
pub fn static(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    // Check if the request path starts with /static/
    if (!std.mem.startsWith(u8, req.path, "/static/")) {
        next(req, res, ctx);
        return;
    }

    // Get the relative path by removing /static/ prefix
    const relative_path = req.path[8..]; // Skip "/static/"

    // Prevent directory traversal
    if (std.mem.indexOf(u8, relative_path, "..") != null) {
        res.status = @enumFromInt(403); // Forbidden
        res.body = "Forbidden";
        return;
    }

    // Create an allocator for this request
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Construct the full file path
    const file_path = std.fs.path.join(allocator, &[_][]const u8{ STATIC_DIR, relative_path }) catch |err| {
        std.log.warn("Failed to join path: {}", .{err});
        res.status = @enumFromInt(500); // Internal Server Error
        res.body = "Internal Server Error";
        return;
    };
    defer allocator.free(file_path);

    // Open and read the file
    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            res.status = @enumFromInt(404); // Not Found
            res.body = "Not Found";
        } else {
            std.log.warn("Failed to open file: {}", .{err});
            res.status = @enumFromInt(500); // Internal Server Error
            res.body = "Internal Server Error";
        }
        return;
    };
    defer file.close();

    // Read file contents
    const file_size = file.getEndPos() catch |err| {
        std.log.warn("Failed to get file size: {}", .{err});
        res.status = @enumFromInt(500); // Internal Server Error
        res.body = "Internal Server Error";
        return;
    };

    // Allocate memory for file content using the response's allocator (or context allocator)
    const file_content = res.allocator.alloc(u8, file_size) catch |err| {
        std.log.warn("Failed to allocate memory: {}", .{err});
        res.status = @enumFromInt(500); // Internal Server Error
        res.body = "Internal Server Error";
        return;
    };

    _ = file.readAll(file_content) catch |err| {
        std.log.warn("Failed to read file: {}", .{err});
        res.allocator.free(file_content); // Clean up on error
        res.status = @enumFromInt(500); // Internal Server Error
        res.body = "Internal Server Error";
        return;
    };

    // Set response headers and body
    res.headers.put("Content-Type", getContentType(file_path)) catch |err| {
        std.log.warn("Failed to set Content-Type: {}", .{err});
        res.allocator.free(file_content); // Clean up on error
        res.status = @enumFromInt(500); // Internal Server Error
        res.body = "Internal Server Error";
        return;
    };

    res.status = @enumFromInt(200); // OK
    res.body = file_content; // Transfer ownership to res.body
}
