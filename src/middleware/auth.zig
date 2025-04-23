const std = @import("std");
const http = std.http;
pub const Request = @import("../request.zig").Request;
pub const Response = @import("../response.zig").Response;
pub const Context = @import("../context.zig").Context;

// Define a scoped logger for auth middleware
const log = std.log.scoped(.auth);

// --- Configuration ---
const SESSION_COOKIE_NAME = "session_id";
const AUTH_SCHEME = "Bearer ";
const AUTH_REALM = "api";

// Simple structure to hold authenticated user info
const UserInfo = struct {
    id: []const u8, // Must be allocated by validation functions
};

// --- Placeholder Validation Functions ---
// Replace with actual implementations for session store, JWT library, and API key database.

fn validateSession(allocator: std.mem.Allocator, sessionId: []const u8) !?UserInfo {
    // TODO: Implement session validation (e.g., check Redis/DB)
    if (std.mem.eql(u8, sessionId, "valid-session-cookie-value")) {
        const user_id = try allocator.dupe(u8, "user_session_123");
        return UserInfo{ .id = user_id };
    }
    return null;
}

fn isLikelyJwt(token: []const u8) bool {
    var dot_count: u32 = 0;
    for (token) |char| {
        if (char == '.') dot_count += 1;
    }
    return dot_count >= 2;
}

fn validateJwt(allocator: std.mem.Allocator, token: []const u8) !?UserInfo {
    // TODO: Implement JWT validation (e.g., using zig-jwt)
    if (std.mem.eql(u8, token, "valid.jwt.token")) {
        const user_id = try allocator.dupe(u8, "user_jwt_456");
        return UserInfo{ .id = user_id };
    }
    return null;
}

fn validateApiKey(allocator: std.mem.Allocator, apiKey: []const u8) !?UserInfo {
    // TODO: Implement API key validation (e.g., check DB/config)
    if (std.mem.eql(u8, apiKey, "valid-api-key-secret")) {
        const user_id = try allocator.dupe(u8, "service_api_789");
        return UserInfo{ .id = user_id };
    }
    return null;
}

// --- Middleware ---

pub fn auth(req: *Request, res: *Response, ctx: *Context, next: *const fn (*Request, *Response, *Context) void) void {
    var user_info: ?UserInfo = null;
    var auth_method: ?[]const u8 = null;

    // --- 1. Try Session Cookie Authentication ---
    if (req.getCookieValue(SESSION_COOKIE_NAME)) |sessionId| {
        log.debug("Attempting session auth with cookie: {s}", .{SESSION_COOKIE_NAME});
        user_info = validateSession(ctx.allocator, sessionId) catch |err| blk: {
            log.err("Session validation failed: {s}", .{@errorName(err)});
            break :blk null;
        };
        if (user_info) |ui| {
            auth_method = "session";
            log.debug("Session auth successful for user: {s}", .{ui.id});
        } else {
            log.debug("Session cookie found but invalid or expired.", .{});
        }
    }

    // --- 2. Try Bearer Token Authentication ---
    if (user_info == null) {
        if (req.headers.get("authorization")) |auth_header| {
            if (std.mem.startsWith(u8, auth_header, AUTH_SCHEME)) {
                const token = auth_header[AUTH_SCHEME.len..];
                if (token.len > 0) {
                    log.debug("Attempting Bearer token auth.", .{});
                    if (isLikelyJwt(token)) {
                        log.debug("Token appears to be JWT.", .{});
                        user_info = validateJwt(ctx.allocator, token) catch |err| blk: {
                            log.err("JWT validation failed: {s}", .{@errorName(err)});
                            break :blk null;
                        };
                        if (user_info) |ui| {
                            auth_method = "jwt";
                            log.debug("JWT auth successful for user: {s}", .{ui.id});
                        } else {
                            log.debug("Invalid JWT token provided.", .{});
                        }
                    } else {
                        log.debug("Token appears to be API Key.", .{});
                        user_info = validateApiKey(ctx.allocator, token) catch |err| blk: {
                            log.err("API Key validation failed: {s}", .{@errorName(err)});
                            break :blk null;
                        };
                        if (user_info) |ui| {
                            auth_method = "apikey";
                            log.debug("API Key auth successful for user: {s}", .{ui.id});
                        } else {
                            log.debug("Invalid API Key provided.", .{});
                        }
                    }
                } else {
                    log.warn("Empty Bearer token provided.", .{});
                }
            } else {
                log.warn("Authorization header found with invalid scheme (expected '{s}').", .{AUTH_SCHEME});
            }
        }
    }

    // --- 3. Handle Authentication Result ---
    if (user_info) |ui| {
        // Authentication successful
        ctx.set("user_id", ui.id) catch |err| {
            log.err("Failed to set user_id in context: {s}", .{@errorName(err)});
            ctx.allocator.free(ui.id); // Clean up
            internalServerError(res, "Failed to set auth context");
            return;
        };
        ctx.set("auth_method", auth_method.?) catch |err| {
            log.warn("Failed to set auth_method in context: {s}", .{@errorName(err)});
        };

        // Call next handler
        next(req, res, ctx);

        // Clean up user_id if stored in context
        if (ctx.delete("user_id")) |uid| {
            ctx.allocator.free(uid); // Free the stored string
        }
        ctx.allocator.free(ui.id); // Free the original allocated ID
    } else {
        // Authentication failed
        log.info("Authentication failed for request: {s} {s}", .{ @tagName(req.method), req.path });
        unauthorized(res, "Authentication required");
    }
}

// --- Helpers ---

fn unauthorized(res: *Response, message: []const u8) void {
    res.status = @enumFromInt(401);
    const challenge = std.fmt.allocPrint(res.allocator, "Bearer realm=\"{s}\"", .{AUTH_REALM}) catch "Bearer";
    defer if (!std.mem.eql(u8, challenge, "Bearer")) res.allocator.free(challenge);
    _ = res.headers.put("www-authenticate", challenge) catch {};
    _ = res.headers.put("content-type", "text/plain") catch {};
    res.body = message;
}

fn internalServerError(res: *Response, message: []const u8) void {
    res.status = @enumFromInt(500);
    _ = res.headers.put("content-type", "text/plain") catch {};
    res.body = message;
}
