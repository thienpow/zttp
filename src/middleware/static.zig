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
    if (std.mem.eql(u8, ext, ".svg")) return "image/svg+xml";
    if (std.mem.eql(u8, ext, ".ico")) return "image/x-icon";
    if (std.mem.eql(u8, ext, ".json")) return "application/json";
    if (std.mem.eql(u8, ext, ".pdf")) return "application/pdf";
    if (std.mem.eql(u8, ext, ".txt")) return "text/plain";
    if (std.mem.eql(u8, ext, ".xml")) return "application/xml";
    if (std.mem.eql(u8, ext, ".woff")) return "font/woff";
    if (std.mem.eql(u8, ext, ".woff2")) return "font/woff2";
    if (std.mem.eql(u8, ext, ".ttf")) return "font/ttf";
    if (std.mem.eql(u8, ext, ".mp4")) return "video/mp4";
    if (std.mem.eql(u8, ext, ".webm")) return "video/webm";
    if (std.mem.eql(u8, ext, ".mp3")) return "audio/mpeg";
    if (std.mem.eql(u8, ext, ".wav")) return "audio/wav";
    if (std.mem.eql(u8, ext, ".ogg")) return "audio/ogg";
    if (std.mem.eql(u8, ext, ".m4a")) return "audio/mp4";
    if (std.mem.eql(u8, ext, ".mov")) return "video/quicktime";
    if (std.mem.eql(u8, ext, ".avi")) return "video/x-msvideo";
    if (std.mem.eql(u8, ext, ".zip")) return "application/zip";
    if (std.mem.eql(u8, ext, ".csv")) return "text/csv";
    if (std.mem.eql(u8, ext, ".md")) return "text/markdown";
    if (std.mem.eql(u8, ext, ".webp")) return "image/webp";
    if (std.mem.eql(u8, ext, ".eot")) return "application/vnd.ms-fontobject";
    if (std.mem.eql(u8, ext, ".otf")) return "font/otf";
    if (std.mem.eql(u8, ext, ".doc")) return "application/msword";
    if (std.mem.eql(u8, ext, ".docx")) return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    if (std.mem.eql(u8, ext, ".xls")) return "application/vnd.ms-excel";
    if (std.mem.eql(u8, ext, ".xlsx")) return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    if (std.mem.eql(u8, ext, ".ppt")) return "application/vnd.ms-powerpoint";
    if (std.mem.eql(u8, ext, ".pptx")) return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    if (std.mem.eql(u8, ext, ".midi")) return "audio/midi";
    if (std.mem.eql(u8, ext, ".mpeg")) return "video/mpeg";
    if (std.mem.eql(u8, ext, ".rtf")) return "application/rtf";
    if (std.mem.eql(u8, ext, ".wasm")) return "application/wasm";
    if (std.mem.eql(u8, ext, ".ts")) return "video/mp2t";
    if (std.mem.eql(u8, ext, ".flv")) return "video/x-flv";
    if (std.mem.eql(u8, ext, ".mkv")) return "video/x-matroska";
    if (std.mem.eql(u8, ext, ".aac")) return "audio/aac";
    if (std.mem.eql(u8, ext, ".flac")) return "audio/flac";
    if (std.mem.eql(u8, ext, ".tar")) return "application/x-tar";
    if (std.mem.eql(u8, ext, ".gz")) return "application/gzip";
    if (std.mem.eql(u8, ext, ".7z")) return "application/x-7z-compressed";
    if (std.mem.eql(u8, ext, ".rar")) return "application/x-rar-compressed";
    if (std.mem.eql(u8, ext, ".yaml") or std.mem.eql(u8, ext, ".yml")) return "application/x-yaml";
    if (std.mem.eql(u8, ext, ".webmanifest")) return "application/manifest+json";
    return "application/octet-stream";
}

// Middleware handler for static files
pub fn static(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    // Remove leading slash from path
    const relative_path = if (std.mem.startsWith(u8, req.path, "/")) req.path[1..] else req.path;

    // Skip if path is empty or likely a dynamic route (no extension)
    if (relative_path.len == 0 or !std.mem.containsAtLeast(u8, relative_path, 1, ".")) {
        next(req, res, ctx);
        return;
    }

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
            next(req, res, ctx); // Pass to next handler
            return;
        } else {
            std.log.warn("Failed to open file: {}", .{err});
            res.status = @enumFromInt(500); // Internal Server Error
            res.body = "Internal Server Error";
            return;
        }
    };
    defer file.close();

    // Read file contents
    const file_size = file.getEndPos() catch |err| {
        std.log.warn("Failed to get file size: {}", .{err});
        res.status = @enumFromInt(500); // Internal Server Error
        res.body = "Internal Server Error";
        return;
    };

    // Allocate memory for file content using the response's allocator
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
