const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

const app = @import("app");

pub fn get(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const user_id = ctx.get("id") orelse "unknown";

    const app_ctx = ctx.getApp(app.AppContext) orelse {
        std.log.err("Failed to retrieve AppContext from request context!", .{});
        // Set an error status and return
        res.status = .internal_server_error;
        return; // Propagate the error implicitly or explicitly handle it
    };

    const client_result = app_ctx.redis_pool.acquire();
    if (client_result) |client| {
        // Success case: 'client' is now declared and assigned the *app.redis.RedisClient pointer
        // This block runs only if acquire succeeded

        // Place the defer *inside* this success block, applying to this block's execution
        defer app_ctx.redis_pool.release(client);

        // Now perform subsequent operations using 'client' and handle their errors
        const set_result = client.set("test_key", "bobo");
        if (set_result) {
            // SET succeeded
        } else |set_err| {
            std.log.debug("Redis SET error: {}", .{set_err});
            res.status = .internal_server_error;
            return; // Exit the void function
        }

        // Handle the error union/optional from client.get() explicitly
        // Assuming client.get returns !?[]const u8 (optional slice on success or error)
        const get_result = client.get("test_key");
        var value_from_redis: []const u8 = undefined;
        if (get_result) |maybe_value| {
            // GET succeeded, handle the optional value
            value_from_redis = maybe_value orelse "not found";
        } else |get_err| {
            // GET failed with an error
            std.log.debug("Redis GET error: {}", .{get_err});
            res.status = .internal_server_error;
            return; // Exit the void function
        }

        // Handle the error union from std.fmt.allocPrint explicitly
        const message_result = std.fmt.allocPrint(res.allocator, "User ID: {s}, value from redis: {s}", .{ user_id, value_from_redis });
        var message: []const u8 = undefined;
        if (message_result) |msg| {
            // allocPrint succeeded
            message = msg;
            // Defer freeing the allocated message string *after* successful allocation
            defer res.allocator.free(message);

            // Handle the error union from res.setBody explicitly
            const set_body_result = res.setBody(message); // Assuming setBody returns !void or similar
            if (set_body_result) {
                // setBody succeeded
            } else |body_err| {
                std.log.debug("SetBody error: {}", .{body_err});
                // Status might already be 500, or could set here. Just return.
                return; // Exit the void function
            }

            // Handle the error union from res.setHeader explicitly
            const set_header_result = res.setHeader("Content-Type", "text/plain"); // Assuming setHeader returns !void or similar
            if (set_header_result) {
                // setHeader succeeded
            } else |header_err| {
                std.log.debug("SetHeader error: {}", .{header_err});
                return; // Exit the void function
            }
        } else |msg_err| {
            // allocPrint failed
            std.log.debug("AllocPrint error: {}", .{msg_err});
            res.status = .internal_server_error;
            return; // Exit the void function
        }

        // If we reach here, all operations after acquire succeeded.
        // The defer will release the client upon exiting this block.

    } else |err| {
        // Error case for acquire(): log the error, set status, and exit
        std.log.debug("Redis acquire error: {}", .{err});
        res.status = .internal_server_error;
        return; // Exit the void function
    }
}

pub fn post(_: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;
    const user_id = ctx.get("id") orelse "unknown";
    const message = std.fmt.allocPrint(res.allocator, "Posted for User ID: {s}", .{user_id}) catch "Error";
    res.setBody(message) catch return;
    res.setHeader("Content-Type", "text/plain") catch return;
}
