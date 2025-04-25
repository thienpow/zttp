const std = @import("std");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const StatusCode = @import("response.zig").StatusCode;

pub fn notFound(_: *Request, res: *Response, _: *Context) void {
    res.status = .not_found;
    res.body = "Not Found";
    _ = res.headers.put("Content-Type", "text/plain; charset=utf-8") catch {};
}

pub fn sendError(stream: std.net.Stream, allocator: std.mem.Allocator, status: StatusCode, message: []const u8) void {
    var error_res = Response.init(allocator);
    defer error_res.deinit();

    error_res.status = status;
    error_res.setBody(message) catch {
        std.log.err("Failed to set error response body for status {d}", .{@intFromEnum(status)});
        return;
    };
    error_res.setHeader("Connection", "close") catch {};
    error_res.setHeader("Content-Type", "text/plain; charset=utf-8") catch {};

    error_res.send(stream, null) catch |err| {
        std.log.err("Failed to send error response (status {d}): {any}", .{ @intFromEnum(status), err });
    };
}
