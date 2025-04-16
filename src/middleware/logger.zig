// src/middleware/logger.zig
const std = @import("std");
pub const Request = @import("../request.zig").Request;
pub const Response = @import("../response.zig").Response;
pub const Context = @import("../context.zig").Context;

pub fn log(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    // Generate a unique request ID
    const request_id = std.fmt.allocPrint(ctx.allocator, "{d}", .{std.time.nanoTimestamp()}) catch "unknown";
    defer ctx.allocator.free(request_id); // Free request_id after use
    ctx.set("request_id", request_id) catch return;

    // Get client IP (try headers, then socket/remote_addr)
    const client_ip = blk: {
        if (req.headers.get("X-Forwarded-For")) |ip| break :blk ip;
        if (req.headers.get("Remote-Addr")) |ip| break :blk ip;
        if (@hasField(@TypeOf(req.*), "remote_addr")) break :blk req.remote_addr orelse "unknown";
        break :blk "unknown";
    };
    if (std.mem.eql(u8, client_ip, "unknown")) {
        std.log.debug("No client IP found for request_id={s}", .{request_id});
    }

    // Get User-Agent
    const user_agent = req.headers.get("User-Agent") orelse "unknown";

    // Format query parameters from req.query (HashMap)
    const query = blk: {
        if (!@hasField(@TypeOf(req.*), "query")) break :blk "";
        var query_buf = std.ArrayList(u8).init(ctx.allocator);
        defer query_buf.deinit();
        var it = req.query.iterator();
        var first = true;
        while (it.next()) |entry| {
            if (!first) {
                query_buf.append('&') catch {
                    std.log.warn("Failed to append query separator for request_id={s}", .{request_id});
                    break :blk "";
                };
            }
            query_buf.appendSlice(entry.key_ptr.*) catch {
                std.log.warn("Failed to append query key for request_id={s}", .{request_id});
                break :blk "";
            };
            query_buf.append('=') catch {
                std.log.warn("Failed to append query equals for request_id={s}", .{request_id});
                break :blk "";
            };
            query_buf.appendSlice(entry.value_ptr.*) catch {
                std.log.warn("Failed to append query value for request_id={s}", .{request_id});
                break :blk "";
            };
            first = false;
        }
        break :blk query_buf.toOwnedSlice() catch "";
    };
    defer if (query.len > 0) ctx.allocator.free(query); // Free query if non-empty

    // Record start time for measuring duration
    const start_time = std.time.nanoTimestamp();

    // Log incoming request
    std.log.info(
        "request.incoming method={s} path={s} query={s} request_id={s} client_ip={s} user_agent=\"{s}\"",
        .{ @tagName(req.method), req.path, query, request_id, client_ip, user_agent },
    );

    // Call the next handler
    next(req, res, ctx);

    // Calculate duration in microseconds
    const duration_ns = std.time.nanoTimestamp() - start_time;
    const duration_us = @divFloor(duration_ns, 1_000); // Convert to microseconds

    // Log response details
    std.log.info(
        "request.complete method={s} path={s} query={s} request_id={s} status={d} duration_us={d}",
        .{ @tagName(req.method), req.path, query, request_id, @intFromEnum(res.status), duration_us },
    );
}
