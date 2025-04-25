const std = @import("std");
const Context = @import("context.zig").Context;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const StatusCode = @import("response.zig").StatusCode;
const ThreadPool = @import("pool.zig").ThreadPool;
const HandlerFn = @import("router.zig").HandlerFn;
const Router = @import("router.zig").Router;
const Template = @import("template/main.zig");
const WebSocket = @import("websocket.zig").WebSocket;
const WebSocketTask = @import("websocket.zig").WebSocketTask;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const Server = @import("server.zig").Server;
const utils = @import("utils.zig");
const MiddlewareContext = @import("middleware.zig").MiddlewareContext;
const callNextMiddleware = @import("middleware.zig").callNextMiddleware;

pub const ConnectionTask = struct {
    server: *Server,
    conn: std.net.Server.Connection,
};

pub fn handleConnection(task: ConnectionTask, result: *ThreadPool.TaskResult) void {
    const alloc = task.server.allocator;

    // Ensure connection stream is closed
    var close_connection_on_exit = true;

    defer {
        if (close_connection_on_exit) {
            std.log.debug("Closing connection stream (FD: {d}) via handleConnection defer.", .{task.conn.stream.handle});
            task.conn.stream.close();
        } else {
            std.log.debug("Skipping connection stream close (FD: {d}) in handleConnection defer (WebSocket took ownership).", .{task.conn.stream.handle});
        }
    }

    var buffer: [65536]u8 = undefined;
    const bytes_read = task.conn.stream.read(&buffer) catch |err| {
        std.log.err("Failed to read request: {}", .{err});
        result.success = false;
        return;
    };
    if (bytes_read == 0) {
        std.log.debug("Connection closed by peer before request.", .{});
        result.success = true;
        return;
    }

    var req = Request.parse(alloc, buffer[0..bytes_read]) catch |err| {
        std.log.err("Failed to parse request: {}", .{err});
        utils.sendError(task.conn.stream, alloc, .bad_request, "Invalid Request");
        result.success = false;
        return;
    };
    defer req.deinit();

    var ctx = Context.init(alloc);
    defer ctx.deinit();

    // Check for WebSocket upgrade
    if (req.isWebSocketUpgrade()) {
        std.log.debug("WebSocket upgrade request detected for path: {s}", .{req.path});

        var ws_res = Response.init(alloc);
        errdefer ws_res.deinit();

        const ws_key = req.headers.get("Sec-WebSocket-Key") orelse {
            std.log.err("Missing Sec-WebSocket-Key for WebSocket upgrade.", .{});
            utils.sendError(task.conn.stream, alloc, .bad_request, "Missing Sec-WebSocket-Key");
            ws_res.deinit();
            result.success = false;
            return;
        };

        ws_res.setWebSocketHandshake(ws_key) catch |err| {
            std.log.err("Failed to set WebSocket handshake response: {any}", .{err});
            utils.sendError(task.conn.stream, alloc, .internal_server_error, "Handshake Error");
            ws_res.deinit();
            result.success = false;
            return;
        };

        // Heap-allocate the WebSocket context so it persists after this function returns
        var ws_ctx_ptr = alloc.create(Context) catch |err| {
            std.log.err("Failed to allocate WebSocket context: {any}", .{err});
            ws_res.deinit();
            result.success = false;
            return;
        };
        errdefer {
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
        }

        ws_ctx_ptr.* = Context.init(alloc);

        // Copy values from original context to WebSocket context
        var original_ctx_it = ctx.data.iterator();
        while (original_ctx_it.next()) |entry| {
            const key_copy = alloc.dupe(u8, entry.key_ptr.*) catch |err| {
                std.log.err("Failed to copy context key for WebSocket: {any}", .{err});
                ws_res.deinit();
                ws_ctx_ptr.deinit();
                alloc.destroy(ws_ctx_ptr);
                result.success = false;
                return;
            };
            errdefer alloc.free(key_copy);

            const value_copy = alloc.dupe(u8, entry.value_ptr.*) catch |err| {
                std.log.err("Failed to copy context value for WebSocket: {any}", .{err});
                alloc.free(key_copy);
                ws_res.deinit();
                ws_ctx_ptr.deinit();
                alloc.destroy(ws_ctx_ptr);
                result.success = false;
                return;
            };
            errdefer alloc.free(value_copy);

            ws_ctx_ptr.setOwned(key_copy, value_copy) catch |err| {
                std.log.err("Failed to set copied context for WebSocket: {any}", .{err});
                alloc.free(key_copy);
                alloc.free(value_copy);
                ws_res.deinit();
                ws_ctx_ptr.deinit();
                alloc.destroy(ws_ctx_ptr);
                result.success = false;
                return;
            };
        }

        const ws_handler = task.server.router.getWebSocketHandler(req.method, req.path, ws_ctx_ptr) orelse {
            std.log.warn("No WebSocket handler found for path: {s}", .{req.path});
            utils.sendError(task.conn.stream, alloc, .not_found, "No WebSocket handler found");
            ws_res.deinit();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };

        const http_handler = task.server.router.getHandler(req.method, req.path, &ctx);
        if (http_handler) |handler| {
            std.log.debug("Running associated HTTP handler before WebSocket handshake for {s}", .{req.path});
            handler(&req, &ws_res, &ctx);
            if (ws_res.status != .switching_protocols) {
                std.log.warn("HTTP handler for WebSocket path {s} changed status to {d}, aborting handshake.", .{ req.path, @intFromEnum(ws_res.status) });
                ws_res.send(task.conn.stream, &req) catch |send_err| {
                    std.log.err("Failed to send handler response for aborted WebSocket handshake: {any}", .{send_err});
                };
                ws_res.deinit();
                ws_ctx_ptr.deinit();
                alloc.destroy(ws_ctx_ptr);
                result.success = false;
                return;
            }
        }

        ws_res.setHeader("Upgrade", "websocket") catch {};
        ws_res.setHeader("Connection", "Upgrade") catch {};

        std.log.debug("Sending WebSocket handshake response for {s}", .{req.path});
        ws_res.send(task.conn.stream, &req) catch |err| {
            std.log.err("Failed to send WebSocket handshake response: {any}", .{err});
            ws_res.deinit();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };

        ws_res.deinit();
        const socket_fd = task.conn.stream.handle;
        var ws = WebSocket.init(socket_fd, alloc);
        var ws_added_to_server = false;
        defer if (!ws_added_to_server and close_connection_on_exit) ws.close();

        task.server.websockets.append(ws) catch |err| {
            std.log.err("Failed to append WebSocket to list: {any}", .{err});
            ws.close();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };
        ws_added_to_server = true;

        const ws_ptr = &task.server.websockets.items[task.server.websockets.items.len - 1];

        std.log.info("WebSocket connection established for {s}", .{req.path});

        const ws_task = WebSocketTask{
            .server = task.server,
            .ws = ws_ptr,
            .ctx = ws_ctx_ptr, // Now using heap-allocated context
            .handler = ws_handler,
        };
        const ws_task_ptr = alloc.create(WebSocketTask) catch |err| {
            std.log.err("Failed to allocate WebSocketTask: {any}", .{err});
            _ = task.server.websockets.swapRemove(task.server.websockets.items.len - 1);
            ws.close();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };
        errdefer alloc.destroy(ws_task_ptr);
        ws_task_ptr.* = ws_task;

        const ws_task_id = task.server.pool.schedule(
            @import("websocket.zig").handleWebSocket,
            ws_task_ptr,
            null,
            5,
            null,
            0,
            0,
            null,
            null,
        ) catch |err| {
            std.log.err("Failed to schedule WebSocket task: {any}", .{err});
            _ = task.server.websockets.swapRemove(task.server.websockets.items.len - 1);
            ws.close();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            alloc.destroy(ws_task_ptr);
            result.success = false;
            return;
        };
        _ = ws_task_id;

        close_connection_on_exit = false;
        std.log.debug("WebSocket ownership transferred for FD {d}. handleConnection will not close it.", .{socket_fd});

        result.success = true;
        return;
    }

    // Standard HTTP Request Handling
    var res = Response.init(alloc);
    defer res.deinit();

    res.setHeader("Server", "zttp/1.0") catch {
        utils.sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
        result.success = false;
        return;
    };

    // Middleware Chain
    const middlewares = task.server.router.getMiddlewares();
    var final_handler: HandlerFn = utils.notFound;

    if (middlewares.len > 0) {
        const middleware_context = MiddlewareContext{
            .middlewares = middlewares,
            .index = 0,
            .server = task.server,
            .final_handler = &final_handler,
        };
        const context_ptr = alloc.create(MiddlewareContext) catch |err| {
            std.log.err("Failed to allocate MiddlewareContext: {any}", .{err});
            utils.sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
            result.success = false;
            return;
        };
        defer alloc.destroy(context_ptr);
        context_ptr.* = middleware_context;

        const context_addr_str = std.fmt.allocPrint(alloc, "{x}", .{@intFromPtr(context_ptr)}) catch |err| {
            std.log.err("Failed to format MiddlewareContext address: {any}", .{err});
            utils.sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
            result.success = false;
            return;
        };
        defer alloc.free(context_addr_str);
        ctx.set("middleware_context", context_addr_str) catch |err| {
            std.log.err("Failed to set middleware_context in ctx: {any}", .{err});
            utils.sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
            result.success = false;
            return;
        };

        callNextMiddleware(&req, &res, &ctx);

        if (res.body != null) {
            std.log.debug("Response body set by middleware or handler, skipping template rendering.", .{});
            res.send(task.conn.stream, &req) catch |send_err| {
                std.log.err("Failed to send response after middleware: {any}", .{send_err});
                result.success = false;
                return;
            };
            result.success = true;
            return;
        }

        std.log.debug("Middleware chain complete, executing final handler.", .{});
        final_handler(&req, &res, &ctx);
    } else {
        std.log.debug("No middleware configured, executing route handler directly.", .{});
        final_handler = task.server.router.getHandler(req.method, req.path, &ctx) orelse utils.notFound;
        final_handler(&req, &res, &ctx);
    }

    // Template Rendering
    if (res.body == null) {
        std.log.debug("Response body not set by handler, attempting template rendering for {s}", .{req.path});
        const rendered = Template.renderTemplate(alloc, req.path, &ctx) catch |err| {
            std.log.err("Template rendering error for {s}: {any}", .{ req.path, err });
            utils.sendError(task.conn.stream, alloc, .internal_server_error, "Template Rendering Error");
            result.success = false;
            return;
        };

        if (rendered) |r| {
            std.log.debug("Template rendered successfully for {s}, setting body.", .{req.path});
            res.setBody(r) catch {
                utils.sendError(task.conn.stream, alloc, .internal_server_error, "Failed to set template body");
                alloc.free(r);
                result.success = false;
                return;
            };
            alloc.free(r);
            res.setHeader("Content-Type", "text/html; charset=utf-8") catch {};
        } else {
            std.log.warn("Template rendering returned null for {s}, sending 404.", .{req.path});
            if (res.status == .ok) {
                res.status = .not_found;
            }
            utils.sendError(task.conn.stream, alloc, res.status, "Not Found (or No Template Content)");
            result.success = true;
            return;
        }
    } else {
        std.log.debug("Response body was already set, skipping template rendering for {s}.", .{req.path});
    }

    std.log.debug("Sending final HTTP response for {s}", .{req.path});
    res.send(task.conn.stream, &req) catch |err| {
        std.log.err("Failed to send final response: {any}", .{err});
        result.success = false;
        return;
    };

    result.success = true;
}
