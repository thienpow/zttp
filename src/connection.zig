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
const WebSocketConnection = @import("websocket.zig").WebSocketConnection;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const Server = @import("server.zig").Server;
const utils = @import("utils.zig");
const MiddlewareContext = @import("middleware.zig").MiddlewareContext;
const callNextMiddleware = @import("middleware.zig").callNextMiddleware;
const HttpMethod = @import("zttp.zig").HttpMethod;

pub const ConnectionTask = struct {
    server: *Server,
    conn: std.net.Server.Connection,
};

pub fn handleConnection(task: ConnectionTask, result: *ThreadPool.TaskResult) void {
    const alloc = task.server.allocator;
    var close_connection_on_exit = true;

    defer {
        if (close_connection_on_exit) {
            std.log.debug("Closing connection (FD: {d})", .{task.conn.stream.handle});
            task.conn.stream.close();
        }
    }

    var buffer: [65536]u8 = undefined;
    const bytes_read = task.conn.stream.read(&buffer) catch |err| {
        std.log.err("Failed to read request (FD: {d}): {any}", .{ task.conn.stream.handle, err });
        result.success = false;
        return;
    };
    if (bytes_read == 0) {
        std.log.debug("No data read from connection (FD: {d})", .{task.conn.stream.handle});
        result.success = true;
        return;
    }

    std.log.debug("Read {d} bytes from FD: {d}", .{ bytes_read, task.conn.stream.handle });
    var req = Request.parse(alloc, buffer[0..bytes_read]) catch |err| {
        std.log.err("Failed to parse request (FD: {d}): {any}", .{ task.conn.stream.handle, err });
        utils.sendError(task.conn.stream, alloc, .bad_request, "Invalid Request");
        result.success = false;
        return;
    };
    defer req.deinit();

    var ctx = Context.init(alloc);
    defer ctx.deinit();

    if (req.isWebSocketUpgrade()) {
        std.log.debug("Processing WebSocket upgrade for FD: {d}", .{task.conn.stream.handle});

        // Format headers as a string
        var header_buf = std.ArrayList(u8).init(alloc);
        defer header_buf.deinit();
        var header_it = req.headers.iterator();
        while (header_it.next()) |entry| {
            header_buf.writer().print("{s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* }) catch |err| {
                std.log.err("Failed to format header {s}: {any}", .{ entry.key_ptr.*, err });
                continue;
            };
        }
        std.log.debug("Request headers:\n{s}", .{header_buf.items});

        if (req.headers.get("Sec-WebSocket-Extensions")) |extensions| {
            std.log.info("Client requested WebSocket extensions: {s} (FD: {d})", .{ extensions, task.conn.stream.handle });
        } else {
            std.log.debug("Client did not request WebSocket extensions. (FD: {d})", .{task.conn.stream.handle});
        }

        var ws_res = Response.init(alloc);
        errdefer ws_res.deinit();

        const ws_key = req.headers.get("Sec-WebSocket-Key") orelse {
            std.log.err("Missing Sec-WebSocket-Key for WebSocket upgrade (FD: {d})", .{task.conn.stream.handle});
            utils.sendError(task.conn.stream, alloc, .bad_request, "Missing Sec-WebSocket-Key");
            ws_res.deinit();
            result.success = false;
            return;
        };

        ws_res.setWebSocketHandshake(ws_key) catch |err| {
            std.log.err("Failed to set WebSocket handshake response (FD: {d}): {any}", .{ task.conn.stream.handle, err });
            utils.sendError(task.conn.stream, alloc, .internal_server_error, "Handshake Error");
            ws_res.deinit();
            result.success = false;
            return;
        };

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
            std.log.warn("No WebSocket handler found for path: {s} (FD: {d})", .{ req.path, task.conn.stream.handle });
            utils.sendError(task.conn.stream, alloc, .not_found, "No WebSocket handler found");
            ws_res.deinit();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };

        const http_handler = task.server.router.getHandler(req.method, req.path, &ctx);
        if (http_handler) |handler| {
            handler(&req, &ws_res, &ctx);
            if (ws_res.status != .switching_protocols) {
                std.log.warn("HTTP handler for WebSocket path {s} changed status to {d}, aborting handshake (FD: {d})", .{ req.path, @intFromEnum(ws_res.status), task.conn.stream.handle });
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

        std.log.debug("Sending WebSocket handshake response for FD: {d}", .{task.conn.stream.handle});

        var response_header_buf = std.ArrayList(u8).init(alloc);
        defer response_header_buf.deinit();
        var response_header_it = ws_res.headers.iterator();
        while (response_header_it.next()) |entry| {
            response_header_buf.writer().print("{s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* }) catch |err| {
                std.log.err("Failed to format response header {s}: {any}", .{ entry.key_ptr.*, err });
                continue;
            };
        }
        std.log.debug("Response headers being sent:\n{s}", .{response_header_buf.items});

        ws_res.send(task.conn.stream, &req) catch |err| {
            std.log.err("Failed to send WebSocket handshake response (FD: {d}): {any}", .{ task.conn.stream.handle, err });
            ws_res.deinit();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };
        std.log.info("WebSocket handshake completed for FD: {d}", .{task.conn.stream.handle});

        ws_res.deinit();

        const socket_fd = task.conn.stream.handle;

        var ws = WebSocket.init(socket_fd, alloc, task.server.options.websocket_options, task.server.async_io.?);
        var ws_added_to_server = false;
        defer if (!ws_added_to_server and close_connection_on_exit) ws.close();

        task.server.websockets.append(ws) catch |err| {
            std.log.err("Failed to append WebSocket to list after handshake: {any}", .{err});
            ws.close();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };
        ws_added_to_server = true;

        task.server.websocket_fds.put(socket_fd, {}) catch |err| {
            std.log.err("Failed to add FD: {d} to websocket_fds after upgrade: {any}", .{ socket_fd, err });
            _ = task.server.websockets.swapRemove(task.server.websockets.items.len - 1);
            ws.close();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };
        std.log.debug("Added FD: {d} to websocket_fds after upgrade", .{socket_fd});

        const ws_ptr = &task.server.websockets.items[task.server.websockets.items.len - 1];

        _ = WebSocketConnection.init(task.server, ws_ptr, ws_ctx_ptr, ws_handler, alloc) catch |err| {
            std.log.err("Failed to initialize WebSocketConnection after handshake: {any}", .{err});
            _ = task.server.websockets.swapRemove(task.server.websockets.items.len - 1);
            _ = task.server.websocket_fds.remove(socket_fd);
            ws.close();
            ws_ctx_ptr.deinit();
            alloc.destroy(ws_ctx_ptr);
            result.success = false;
            return;
        };

        close_connection_on_exit = false;
        result.success = true;
        return;
    }

    var res = Response.init(alloc);
    defer res.deinit();

    res.setHeader("Server", "zttp/1.0") catch {
        utils.sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
        result.success = false;
        return;
    };

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
            res.send(task.conn.stream, &req) catch |send_err| {
                std.log.err("Failed to send response after middleware: {any}", .{send_err});
                result.success = false;
                return;
            };
            result.success = true;
            return;
        }

        final_handler(&req, &res, &ctx);
    } else {
        final_handler = task.server.router.getHandler(req.method, req.path, &ctx) orelse utils.notFound;
        final_handler(&req, &res, &ctx);
    }

    if (res.body == null) {
        const rendered = Template.renderTemplate(alloc, req.path, &ctx) catch |err| {
            std.log.err("Template rendering error for {s}: {any}", .{ req.path, err });
            utils.sendError(task.conn.stream, alloc, .internal_server_error, "Template Rendering Error");
            result.success = false;
            return;
        };

        if (rendered) |r| {
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
    }

    res.send(task.conn.stream, &req) catch |err| {
        std.log.err("Failed to send final response: {any}", .{err});
        result.success = false;
        return;
    };

    result.success = true;
}
