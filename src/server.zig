const std = @import("std");
const Context = @import("context.zig").Context;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const StatusCode = @import("response.zig").StatusCode;
const ThreadPool = @import("pool.zig").ThreadPool;
const HandlerFn = @import("router.zig").HandlerFn;
const MiddlewareFn = @import("router.zig").MiddlewareFn;
const NextFn = @import("router.zig").NextFn;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;
const Router = @import("router.zig").Router;
const HttpMethod = @import("zttp.zig").HttpMethod;
const Template = @import("template/main.zig");
const WebSocket = @import("websocket.zig").WebSocket;

pub const Server = struct {
    allocator: std.mem.Allocator,
    listener: ?std.net.Server,
    port: u16,
    running: bool,
    router: Router,
    pool: *ThreadPool,
    websockets: std.ArrayList(WebSocket),

    pub fn init(allocator: std.mem.Allocator, port: u16, pool: *ThreadPool) Server {
        return .{
            .allocator = allocator,
            .listener = null,
            .port = port,
            .running = false,
            .router = Router.init(allocator),
            .pool = pool,
            .websockets = std.ArrayList(WebSocket).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        for (self.websockets.items) |*ws| {
            ws.close();
        }
        self.websockets.deinit();
        if (self.listener) |*listener| {
            listener.deinit();
        }
        self.router.deinit();
    }

    pub fn route(self: *Server, module_name: []const u8, method: HttpMethod, path: []const u8, handler: ?HandlerFn, ws_handler: ?WebSocketHandlerFn) !void {
        try self.router.add(module_name, method, path, handler, ws_handler);
    }

    pub fn use(self: *Server, middleware: MiddlewareFn) !void {
        try self.router.use(middleware);
    }

    pub fn start(self: *Server) !void {
        if (self.running) return error.AlreadyRunning;

        const address = try std.net.Address.parseIp("0.0.0.0", self.port);
        self.listener = try address.listen(.{ .reuse_address = true });
        self.running = true;

        std.log.info("Server listening on 0.0.0.0:{d}", .{self.port});

        while (self.running) {
            const conn = self.listener.?.accept() catch |err| {
                std.log.err("Failed to accept connection: {}", .{err});
                continue;
            };
            const task_id = try self.pool.schedule(
                handleConnection,
                ConnectionTask{ .server = self, .conn = conn },
                null,
                5, // priority
                null, // timeout
                0, // max_retries
                0, // retry_delay
                null, // dependencies
                null, // dep_timeout
            );
            _ = task_id;
        }
    }

    const ConnectionTask = struct {
        server: *Server,
        conn: std.net.Server.Connection,
    };

    fn handleConnection(task: ConnectionTask, result: *ThreadPool.TaskResult) void {
        const alloc = task.server.allocator;

        // Ensure connection stream is closed
        defer task.conn.stream.close();

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
            sendError(task.conn.stream, alloc, .bad_request, "Invalid Request");
            result.success = false;
            return;
        };
        defer req.deinit(); // Required since Request manages its own memory

        var ctx = Context.init(alloc);
        defer ctx.deinit(); // Context needs explicit cleanup

        // Check for WebSocket upgrade BEFORE initializing the standard Response
        if (req.isWebSocketUpgrade()) {
            std.log.debug("WebSocket upgrade request detected for path: {s}", .{req.path});

            var ws_res = Response.init(alloc);
            defer ws_res.deinit(); // Explicit cleanup for WebSocket response

            const ws_key = req.headers.get("Sec-WebSocket-Key") orelse {
                std.log.err("Missing Sec-WebSocket-Key for WebSocket upgrade.", .{});
                sendError(task.conn.stream, alloc, .bad_request, "Missing Sec-WebSocket-Key");
                result.success = false;
                return;
            };

            // Set WebSocket handshake headers
            ws_res.setWebSocketHandshake(ws_key) catch |err| {
                std.log.err("Failed to set WebSocket handshake response: {any}", .{err});
                sendError(task.conn.stream, alloc, .internal_server_error, "Handshake Error");
                result.success = false;
                return;
            };

            // Create a copy of the context for WebSocket - with proper error handling
            var ws_ctx = Context.init(alloc);
            errdefer ws_ctx.deinit(); // Clean up on error path

            var ctx_transfer_successful = false;
            defer if (!ctx_transfer_successful) ws_ctx.deinit(); // Only deinit if not transferred

            // Copy context data with proper cleanup on error
            var original_ctx_it = ctx.data.iterator();
            while (original_ctx_it.next()) |entry| {
                const key_copy = alloc.dupe(u8, entry.key_ptr.*) catch |err| {
                    std.log.err("Failed to copy context key for WebSocket: {any}", .{err});
                    result.success = false;
                    return;
                };
                errdefer alloc.free(key_copy);

                const value_copy = alloc.dupe(u8, entry.value_ptr.*) catch |err| {
                    std.log.err("Failed to copy context value for WebSocket: {any}", .{err});
                    alloc.free(key_copy);
                    result.success = false;
                    return;
                };
                errdefer alloc.free(value_copy);

                ws_ctx.setOwned(key_copy, value_copy) catch |err| {
                    std.log.err("Failed to set copied context for WebSocket: {any}", .{err});
                    alloc.free(key_copy);
                    alloc.free(value_copy);
                    result.success = false;
                    return;
                };
            }

            // Find WebSocket handler
            const ws_handler = task.server.router.getWebSocketHandler(req.method, req.path, &ws_ctx) orelse {
                std.log.warn("No WebSocket handler found for path: {s}", .{req.path});
                sendError(task.conn.stream, alloc, .not_found, "No WebSocket handler found");
                result.success = false;
                return;
            };

            // Run associated HTTP handler/middleware if present
            const http_handler = task.server.router.getHandler(req.method, req.path, &ctx);
            if (http_handler) |handler| {
                std.log.debug("Running associated HTTP handler before WebSocket handshake for {s}", .{req.path});
                handler(&req, &ws_res, &ctx);
                if (ws_res.status != .switching_protocols) {
                    std.log.warn("HTTP handler for WebSocket path {s} changed status to {d}, aborting handshake.", .{ req.path, @intFromEnum(ws_res.status) });
                    ws_res.send(task.conn.stream, &req) catch |send_err| {
                        std.log.err("Failed to send handler response for aborted WebSocket handshake: {any}", .{send_err});
                    };
                    result.success = false;
                    return;
                }
            }

            // Ensure handshake headers
            ws_res.setHeader("Upgrade", "websocket") catch {};
            ws_res.setHeader("Connection", "Upgrade") catch {};

            // Send handshake response
            std.log.debug("Sending WebSocket handshake response for {s}", .{req.path});
            ws_res.send(task.conn.stream, &req) catch |err| {
                std.log.err("Failed to send WebSocket handshake response: {any}", .{err});
                result.success = false;
                return;
            };

            // Initialize WebSocket with the FD
            const socket_fd = task.conn.stream.handle;
            var ws = WebSocket.init(socket_fd, alloc);
            var ws_added_to_server = false;
            defer if (!ws_added_to_server) ws.close(); // Close if not added to server

            // Add to server's WebSocket list (needs thread safety)
            task.server.websockets.append(ws) catch |err| {
                std.log.err("Failed to append WebSocket to list: {any}", .{err});
                result.success = false;
                return;
            };
            ws_added_to_server = true;
            const ws_ptr = &task.server.websockets.items[task.server.websockets.items.len - 1];

            std.log.info("WebSocket connection established for {s}", .{req.path});

            // Schedule WebSocket task - with proper error handling
            const ws_task = WebSocketTask{
                .server = task.server,
                .ws = ws_ptr,
                .ctx = ws_ctx,
                .handler = ws_handler,
            };
            const ws_task_ptr = alloc.create(WebSocketTask) catch |err| {
                std.log.err("Failed to allocate WebSocketTask: {any}", .{err});
                // Remove socket from server's list
                for (task.server.websockets.items, 0..) |*server_ws, i| {
                    if (server_ws.socket == ws_ptr.socket) {
                        _ = task.server.websockets.swapRemove(i);
                        break;
                    }
                }
                result.success = false;
                return;
            };
            errdefer alloc.destroy(ws_task_ptr);
            ws_task_ptr.* = ws_task;

            const ws_task_id = task.server.pool.schedule(
                handleWebSocket,
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
                // Remove socket from server's list
                for (task.server.websockets.items, 0..) |*server_ws, i| {
                    if (server_ws.socket == ws_ptr.socket) {
                        _ = task.server.websockets.swapRemove(i);
                        break;
                    }
                }
                result.success = false;
                return;
            };
            _ = ws_task_id;

            // Transfer ownership of ws_ctx to the task
            ctx_transfer_successful = true;

            result.success = true;
            return;
        }

        // Standard HTTP Request Handling
        var res = Response.init(alloc);
        defer res.deinit(); // Explicit cleanup

        // Set default headers
        res.setHeader("Server", "zttp/1.0") catch {
            sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
            result.success = false;
            return;
        };

        // Middleware Chain
        const middlewares = task.server.router.getMiddlewares();
        var final_handler: HandlerFn = notFound;

        if (middlewares.len > 0) {
            const middleware_context = MiddlewareContext{
                .middlewares = middlewares,
                .index = 0,
                .server = task.server,
                .final_handler = &final_handler,
            };
            const context_ptr = alloc.create(MiddlewareContext) catch |err| {
                std.log.err("Failed to allocate MiddlewareContext: {any}", .{err});
                sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
                result.success = false;
                return;
            };
            defer alloc.destroy(context_ptr);
            context_ptr.* = middleware_context;

            const context_addr_str = std.fmt.allocPrint(alloc, "{x}", .{@intFromPtr(context_ptr)}) catch |err| {
                std.log.err("Failed to format MiddlewareContext address: {any}", .{err});
                sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
                result.success = false;
                return;
            };
            defer alloc.free(context_addr_str);
            ctx.set("middleware_context", context_addr_str) catch |err| {
                std.log.err("Failed to set middleware_context in ctx: {any}", .{err});
                sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
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
            final_handler = task.server.router.getHandler(req.method, req.path, &ctx) orelse notFound;
            final_handler(&req, &res, &ctx);
        }

        // Template Rendering
        if (res.body == null) {
            std.log.debug("Response body not set by handler, attempting template rendering for {s}", .{req.path});
            const rendered = Template.renderTemplate(alloc, req.path, &ctx) catch |err| {
                std.log.err("Template rendering error for {s}: {any}", .{ req.path, err });
                sendError(task.conn.stream, alloc, .internal_server_error, "Template Rendering Error");
                result.success = false;
                return;
            };

            if (rendered) |r| {
                std.log.debug("Template rendered successfully for {s}, setting body.", .{req.path});
                res.setBody(r) catch {
                    sendError(task.conn.stream, alloc, .internal_server_error, "Failed to set template body");
                    alloc.free(r); // Free rendered template
                    result.success = false;
                    return;
                };
                alloc.free(r); // Free rendered template after duplication in setBody
                res.setHeader("Content-Type", "text/html; charset=utf-8") catch {};
            } else {
                std.log.warn("Template rendering returned null for {s}, sending 404.", .{req.path});
                if (res.status == .ok) {
                    res.status = .not_found;
                }
                sendError(task.conn.stream, alloc, res.status, "Not Found (or No Template Content)");
                result.success = true;
                return;
            }
        } else {
            std.log.debug("Response body was already set, skipping template rendering for {s}.", .{req.path});
        }

        // Send Final Response
        std.log.debug("Sending final HTTP response for {s}", .{req.path});
        res.send(task.conn.stream, &req) catch |err| {
            std.log.err("Failed to send final response: {any}", .{err});
            result.success = false;
            return;
        };

        result.success = true;
    }

    const WebSocketTask = struct {
        server: *Server,
        ws: *WebSocket,
        ctx: Context,
        handler: WebSocketHandlerFn,
    };

    fn handleWebSocket(task_ptr: *WebSocketTask, result: *ThreadPool.TaskResult) void {
        const task = task_ptr.*;
        const alloc = task.server.allocator;

        // Make sure everything gets cleaned up properly
        var ctx_deinit_done = false;
        defer if (!ctx_deinit_done) @constCast(&task.ctx).deinit();

        var ws_close_done = false;
        defer if (!ws_close_done) task.ws.close();

        defer alloc.destroy(task_ptr); // Free the task struct last

        // Remove WebSocket from server list when we're done
        defer {
            var found = false;
            for (task.server.websockets.items, 0..) |*server_ws, i| {
                if (server_ws.socket == task.ws.socket) {
                    _ = task.server.websockets.swapRemove(i);
                    found = true;
                    std.log.info("Removed WebSocket (FD: {d}) from server list.", .{task.ws.socket});
                    break;
                }
            }
            if (!found) {
                std.log.warn("WebSocket (FD: {d}) already removed from server list?", .{task.ws.socket});
            }

            // Mark these as done to prevent double cleanup
            ctx_deinit_done = true;
            ws_close_done = true;
        }

        std.log.info("WebSocket handler started for socket FD: {d}", .{task.ws.socket});

        var read_buffer: [4096]u8 = undefined;

        while (task.ws.is_open) {
            // Read Frame Header
            const header_bytes_read = task.ws.readBlocking(read_buffer[0..2]) catch |err| {
                std.log.info("WebSocket read error (header): {any}. Closing connection FD: {d}", .{ err, task.ws.socket });
                break;
            };

            if (header_bytes_read == 0) {
                std.log.info("WebSocket connection closed by peer (FD: {d}).", .{task.ws.socket});
                break;
            }
            if (header_bytes_read < 2) {
                std.log.warn("Incomplete WebSocket frame header received ({d} bytes). Closing FD: {d}", .{ header_bytes_read, task.ws.socket });
                break;
            }

            const fin_bit = (read_buffer[0] >> 7) & 1;
            const rsv_bits = (read_buffer[0] >> 4) & 7;
            const opcode = read_buffer[0] & 0x0F;
            const mask_bit = (read_buffer[1] >> 7) & 1;
            const payload_len_short = read_buffer[1] & 0x7F;

            // Validate reserved bits and mask bit
            if (rsv_bits != 0) {
                std.log.warn("WebSocket frame received with non-zero RSV bits ({b}). Closing FD: {d}", .{ rsv_bits, task.ws.socket });
                break;
            }
            if (mask_bit == 0) {
                std.log.warn("WebSocket frame received from client without mask bit set. Closing FD: {d}", .{task.ws.socket});
                break;
            }

            // Read Extended Payload Length
            var payload_len: u64 = 0;
            var mask_key: [4]u8 = undefined;
            var current_read_offset: usize = 2;

            if (payload_len_short <= 125) {
                payload_len = payload_len_short;
            } else if (payload_len_short == 126) {
                var len_buffer: [2]u8 = undefined;
                if (task.ws.readBlocking(&len_buffer) catch |err| {
                    std.log.warn("WebSocket read error (16-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                    break;
                } != 2) {
                    std.log.warn("Incomplete WebSocket frame (16-bit length). Closing FD: {d}", .{task.ws.socket});
                    break;
                }
                payload_len = std.mem.readInt(u16, &len_buffer, .big);
                current_read_offset += 2;
            } else {
                var len_buffer: [8]u8 = undefined;
                if (task.ws.readBlocking(&len_buffer) catch |err| {
                    std.log.warn("WebSocket read error (64-bit length): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                    break;
                } != 8) {
                    std.log.warn("Incomplete WebSocket frame (64-bit length). Closing FD: {d}", .{task.ws.socket});
                    break;
                }
                payload_len = std.mem.readInt(u64, &len_buffer, .big);
                current_read_offset += 8;
            }

            // Read Masking Key
            if (task.ws.readBlocking(read_buffer[current_read_offset .. current_read_offset + 4]) catch |err| {
                std.log.warn("WebSocket read error (mask key): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                break;
            } != 4) {
                std.log.warn("Incomplete WebSocket frame (mask key). Closing FD: {d}", .{task.ws.socket});
                break;
            }
            @memcpy(&mask_key, read_buffer[current_read_offset .. current_read_offset + 4]);
            current_read_offset += 4;

            // Handle Control Frames
            if (opcode >= 0x8) {
                if (payload_len > 125) {
                    std.log.warn("Control frame received with payload > 125 bytes. Closing FD: {d}", .{task.ws.socket});
                    break;
                }
                if (fin_bit == 0) {
                    std.log.warn("Control frame received fragmented (FIN=0). Closing FD: {d}", .{task.ws.socket});
                    break;
                }

                const control_payload = alloc.alloc(u8, @intCast(payload_len)) catch {
                    std.log.err("Failed to allocate buffer for control frame payload. Closing FD: {d}", .{task.ws.socket});
                    break;
                };
                defer alloc.free(control_payload);

                if (task.ws.readBlocking(control_payload) catch |err| {
                    std.log.warn("WebSocket read error (control payload): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                    break;
                } != control_payload.len) {
                    std.log.warn("Incomplete WebSocket control frame payload. Closing FD: {d}", .{task.ws.socket});
                    break;
                }
                for (control_payload, 0..) |*byte, j| {
                    byte.* ^= mask_key[j % 4];
                }

                switch (opcode) {
                    0x8 => {
                        std.log.info("WebSocket Close frame received. Closing connection FD: {d}", .{task.ws.socket});
                        task.ws.close();
                        break;
                    },
                    0x9 => {
                        std.log.debug("WebSocket Ping frame received. Sending Pong. FD: {d}", .{task.ws.socket});
                        task.ws.sendFrame(0xA, control_payload) catch |err| {
                            std.log.err("Failed to send WebSocket Pong frame: {any}. Closing FD: {d}", .{ err, task.ws.socket });
                            break;
                        };
                    },
                    0xA => {
                        std.log.debug("WebSocket Pong frame received. FD: {d}", .{task.ws.socket});
                    },
                    else => {
                        std.log.warn("Unknown control frame opcode received: {x}. Closing FD: {d}", .{ opcode, task.ws.socket });
                        break;
                    },
                }
                if (!task.ws.is_open) break;
                continue;
            }

            // Handle Data Frames
            if (opcode != 0x1 and opcode != 0x2) {
                std.log.warn("Unsupported data frame opcode received: {x}. Closing FD: {d}", .{ opcode, task.ws.socket });
                break;
            }

            const max_payload: u64 = 1024 * 1024;
            if (payload_len > max_payload) {
                std.log.warn("WebSocket payload too large ({d} bytes). Closing FD: {d}", .{ payload_len, task.ws.socket });
                break;
            }
            if (payload_len == 0) {
                if (opcode == 0x1) {
                    task.handler(task.ws, "", &task.ctx);
                } else {
                    std.log.debug("Received empty binary frame. Ignoring. FD: {d}", .{task.ws.socket});
                }
                continue;
            }

            const payload_buffer = alloc.alloc(u8, @intCast(payload_len)) catch |err| {
                std.log.err("Failed to allocate buffer for WebSocket payload ({d} bytes): {any}. Closing FD: {d}", .{ payload_len, err, task.ws.socket });
                break;
            };
            defer alloc.free(payload_buffer);

            if (task.ws.readBlocking(payload_buffer) catch |err| {
                std.log.warn("WebSocket read error (payload): {any}. Closing FD: {d}", .{ err, task.ws.socket });
                break;
            } != payload_buffer.len) {
                std.log.warn("Incomplete WebSocket payload received. Closing FD: {d}", .{task.ws.socket});
                break;
            }

            for (payload_buffer, 0..) |*byte, j| {
                byte.* ^= mask_key[j % 4];
            }

            if (opcode == 0x1) {
                task.handler(task.ws, payload_buffer, &task.ctx);
            } else {
                std.log.debug("Received binary frame ({d} bytes). Ignoring. FD: {d}", .{ payload_buffer.len, task.ws.socket });
            }
        }

        std.log.info("WebSocket handler finished for FD: {d}", .{task.ws.socket});
        result.success = true;
    }

    const MiddlewareContext = struct {
        middlewares: []const MiddlewareFn,
        index: usize,
        server: *Server,
        final_handler: *HandlerFn,
    };

    fn callNextMiddleware(req: *Request, res: *Response, ctx: *Context) void {
        const context_addr_str = ctx.get("middleware_context") orelse {
            std.log.err("Middleware context address not found in Ctx.", .{});
            sendError(undefined, ctx.allocator, .internal_server_error, "Middleware Context Missing");
            return;
        };

        const context_ptr_addr = std.fmt.parseInt(usize, context_addr_str, 16) catch |err| {
            std.log.err("Failed to parse middleware context address '{s}': {any}", .{ context_addr_str, err });
            sendError(undefined, ctx.allocator, .internal_server_error, "Invalid Middleware Context Address");
            return;
        };
        const context_ptr = @as(*MiddlewareContext, @ptrFromInt(context_ptr_addr));

        if (context_ptr.index < context_ptr.middlewares.len) {
            const mw = context_ptr.middlewares[context_ptr.index];
            context_ptr.index += 1;
            std.log.debug("Calling middleware index {d}", .{context_ptr.index - 1});
            mw(req, res, ctx, callNextMiddleware);
        } else {
            std.log.debug("Middleware chain exhausted, finding final route handler.", .{});
            context_ptr.final_handler.* = context_ptr.server.router.getHandler(req.method, req.path, ctx) orelse notFound;
        }
    }

    fn notFound(_: *Request, res: *Response, _: *Context) void {
        res.status = .not_found;
        res.body = "Not Found";
        _ = res.headers.put("Content-Type", "text/plain; charset=utf-8") catch {};
    }

    fn sendError(stream: std.net.Stream, allocator: std.mem.Allocator, status: StatusCode, message: []const u8) void {
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
};
