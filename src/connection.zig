const std = @import("std");
const Allocator = std.mem.Allocator;
const AsyncIo = @import("async/async.zig").AsyncIo;
const Task = @import("async/task.zig").Task;
const Server = @import("server.zig").Server;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const StatusCode = @import("response.zig").StatusCode;
const Context = @import("context.zig").Context;
const WebSocket = @import("websocket.zig").WebSocket;
const WebSocketConnection = @import("websocket.zig").WebSocketConnection;
const middleware = @import("middleware.zig");
const MiddlewareContext = middleware.MiddlewareContext;
const Template = @import("template/main.zig");
const utils = @import("utils.zig");
const HandlerFn = @import("router.zig").HandlerFn;
const WebSocketHandlerFn = @import("router.zig").WebSocketHandlerFn;

// Wrapper for WebSocket close callback
const ConnectionWrapper = struct {
    ws_conn: *WebSocketConnection,
};

pub const Connection = struct {
    server: *Server,
    fd: std.posix.fd_t,
    allocator: Allocator,
    state: State,
    task_data: *ConnectionTaskData,

    pub const State = enum {
        reading_request,
        processing_request,
        sending_response,
        upgrading_websocket,
        closing,
        closed,
    };

    pub fn init(server: *Server, conn: std.net.Server.Connection, allocator: Allocator) !*Connection {
        const connection = try allocator.create(Connection);
        errdefer allocator.destroy(connection);

        const task_data = try ConnectionTaskData.init(allocator, connection);
        errdefer {
            task_data.deinit();
            allocator.destroy(task_data);
        }

        connection.* = .{
            .server = server,
            .fd = conn.stream.handle,
            .allocator = allocator,
            .state = .reading_request,
            .task_data = task_data,
        };

        std.log.debug("Connection initialized for FD: {d}", .{connection.fd});
        try connection.startReading();
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        self.task_data.deinit();
        self.allocator.destroy(self.task_data);
        self.allocator.destroy(self);
        std.log.debug("Connection deinit for FD: {d}", .{self.fd});
    }

    pub fn startReading(self: *Connection) !void {
        std.log.debug("Starting read for FD: {d}", .{self.fd});
        try self.readNext();
    }

    fn readNext(self: *Connection) !void {
        if (self.state != .reading_request) {
            std.log.debug("Skipping readNext on FD: {d}, state: {s}", .{ self.fd, @tagName(self.state) });
            return;
        }

        const task_data = self.task_data;
        const buffer_size = 65536;
        try task_data.request_buffer.ensureTotalCapacity(buffer_size);
        const buf = task_data.request_buffer.addManyAsSlice(buffer_size) catch unreachable;
        @memset(buf, 0);

        const task = try self.server.async_io.?.getTask();
        task.* = .{
            .userdata = task_data,
            .callback = handleReadCompletion,
            .req = .{ .recv = .{ .fd = self.fd, .buffer = buf } },
        };
        self.server.async_io.?.submission_q.push(task);
        std.log.debug("Scheduled async recv for FD: {d}, buffer size: {d}, task ptr: {*}", .{ self.fd, buffer_size, task });
    }

    pub fn asyncClose(self: *Connection) !void {
        if (self.state == .closed or self.state == .closing) {
            std.log.debug("Skipping asyncClose on FD: {d}, state: {s}", .{ self.fd, @tagName(self.state) });
            return;
        }

        const task = try self.server.async_io.?.getTask();
        if (self.state == .upgrading_websocket) {
            const wrapper = try self.allocator.create(ConnectionWrapper);
            wrapper.* = .{ .ws_conn = @ptrCast(self) };
            task.* = .{
                .userdata = wrapper,
                .callback = handleWebSocketClose,
                .req = .{ .close = self.fd },
            };
        } else {
            task.* = .{
                .userdata = self,
                .callback = handleHttpClose,
                .req = .{ .close = self.fd },
            };
        }

        self.server.async_io.?.submission_q.push(task);
        self.state = .closing;
        std.log.debug("Scheduled async close for FD: {d}, task ptr: {*}, callback: {s}", .{
            self.fd,
            task,
            if (self.state == .upgrading_websocket) "handleWebSocketClose" else "handleHttpClose",
        });
    }
};

const ConnectionTaskData = struct {
    conn: *Connection,
    ctx: *Context,
    request_buffer: std.ArrayList(u8),
    req: ?Request = null,
    res: ?*Response = null,
    ws_ctx: ?*Context = null,
    ws_handler: ?WebSocketHandlerFn = null,
    middleware_ctx: ?*MiddlewareContext = null,

    pub fn init(allocator: Allocator, conn: *Connection) !*ConnectionTaskData {
        const ctx = try allocator.create(Context);
        errdefer allocator.destroy(ctx);
        ctx.* = Context.init(allocator);

        const data = try allocator.create(ConnectionTaskData);
        data.* = .{
            .conn = conn,
            .ctx = ctx,
            .request_buffer = std.ArrayList(u8).init(allocator),
        };
        return data;
    }

    pub fn deinit(self: *ConnectionTaskData) void {
        std.log.debug("ConnectionTaskData.deinit: FD: {d}, ctx_ptr={x}, res_ptr={x}", .{
            self.conn.fd,
            @intFromPtr(self.ctx),
            if (self.res) |res| @intFromPtr(res) else 0,
        });

        if (self.req) |*req| {
            req.deinit();
            self.req = null;
        }

        if (self.res) |res| {
            res.deinit();
            self.res = null;
        }

        if (self.ws_ctx) |ws_ctx| {
            ws_ctx.deinit();
            if (self.conn.state != .upgrading_websocket) {
                self.conn.allocator.destroy(ws_ctx);
            }
            self.ws_ctx = null;
        }

        if (self.middleware_ctx) |mctx| {
            self.conn.allocator.destroy(mctx);
            self.middleware_ctx = null;
        }

        self.request_buffer.deinit();
        self.ctx.deinit();
        self.conn.allocator.destroy(self.ctx);
    }
};

fn sendErrorAsync(task_data: *ConnectionTaskData, status: StatusCode, message: []const u8) !void {
    const conn = task_data.conn;
    if (conn.state == .closed or conn.state == .closing) {
        std.log.debug("Skipping sendErrorAsync on FD: {d}, state: {s}", .{ conn.fd, @tagName(conn.state) });
        return;
    }

    const res = try conn.allocator.create(Response);
    errdefer conn.allocator.destroy(res);
    res.* = Response.init(conn.allocator);
    task_data.res = res;
    errdefer {
        res.deinit();
        task_data.res = null;
    }

    res.status = status;
    try res.setBody(try conn.allocator.dupe(u8, message));

    conn.state = .sending_response;
    try sendResponseAsync(task_data);
}

fn handleReadCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;
    const result = task.result orelse return error.NoResult;

    const bytes_read = result.recv catch |err| {
        std.log.err("Read error on FD: {d}: {any}", .{ conn.fd, err });
        conn.state = .closing;
        try conn.asyncClose();
        task.userdata = null;
        return;
    };

    if (bytes_read == 0) {
        std.log.info("Connection closed by peer (FD: {d})", .{conn.fd});
        conn.state = .closing;
        try conn.asyncClose();
        task.userdata = null;
        return;
    }

    try task_data.request_buffer.resize(bytes_read);
    std.log.debug("Read {d} bytes on FD: {d}", .{ bytes_read, conn.fd });

    conn.state = .processing_request;
    try processRequest(task_data);
    task.userdata = null;
}

fn processRequest(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    if (conn.state != .processing_request) return;

    const req_data = task_data.request_buffer.items;
    std.log.debug("Request data (FD: {d}): len={d}, data={s}", .{
        conn.fd,
        req_data.len,
        req_data[0..@min(req_data.len, 100)],
    });

    var req = Request.parse(conn.allocator, req_data) catch |err| {
        std.log.err("Failed to parse request (FD: {d}): {any}", .{ conn.fd, err });
        try sendErrorAsync(task_data, .bad_request, "Invalid Request");
        return;
    };
    task_data.req = req;
    errdefer task_data.req = null;

    if (req.isWebSocketUpgrade()) {
        try handleWebSocketUpgrade(task_data);
    } else {
        try handleHttpRequest(task_data);
    }
}

fn handleHttpRequest(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    const req = &(task_data.req orelse return error.NoRequest);
    const res = try conn.allocator.create(Response);
    errdefer conn.allocator.destroy(res);
    res.* = Response.init(conn.allocator);
    task_data.res = res;
    errdefer {
        res.deinit();
        task_data.res = null;
    }

    try res.setHeader("Server", "zttp/1.0");

    const middlewares = conn.server.router.getMiddlewares();
    var final_handler: HandlerFn = utils.notFound;
    std.log.debug("FD: {d}, path: {s}, middlewares: {d}", .{ conn.fd, req.path, middlewares.len });

    if (middlewares.len > 0) {
        const middleware_context = MiddlewareContext{
            .middlewares = middlewares,
            .index = 0,
            .server = conn.server,
            .final_handler = &final_handler,
        };
        const context_ptr = try conn.allocator.create(MiddlewareContext);
        task_data.middleware_ctx = context_ptr;
        context_ptr.* = middleware_context;

        const context_addr_str = try std.fmt.allocPrint(conn.allocator, "{x}", .{@intFromPtr(context_ptr)});
        defer conn.allocator.free(context_addr_str);
        try task_data.ctx.set("middleware_context", context_addr_str);

        middleware.callNextMiddleware(req, res, task_data.ctx);
        if (res.body != null) {
            conn.state = .sending_response;
            try sendResponseAsync(task_data);
            return;
        }

        final_handler(req, res, task_data.ctx);
    } else {
        final_handler = conn.server.router.getHandler(req.method, req.path, task_data.ctx) orelse utils.notFound;
        std.log.debug("FD: {d}, handler for {s} {s}: {s}", .{
            conn.fd,
            @tagName(req.method),
            req.path,
            if (final_handler == utils.notFound) "not_found" else "found",
        });
        final_handler(req, res, task_data.ctx);
    }

    if (res.body == null) {
        const rendered = try Template.renderTemplate(conn.allocator, req.path, task_data.ctx);
        if (rendered) |r| {
            try res.setBody(r);
            try res.setHeader("Content-Type", "text/html; charset=utf-8");
        } else if (std.mem.eql(u8, req.path, "/")) {
            res.status = .ok;
            try res.setBody(try conn.allocator.dupe(u8, "Hello, World!"));
            try res.setHeader("Content-Type", "text/plain; charset=utf-8");
        } else {
            std.log.warn("Template rendering returned null for {s}, sending 404", .{req.path});
            if (res.status == .ok) res.status = .not_found;
            try sendErrorAsync(task_data, res.status, "Not Found (or No Template Content)");
            return;
        }
    }

    std.log.debug("FD: {d}, sending response, status: {d}, body_len: {d}", .{
        conn.fd,
        @intFromEnum(res.status),
        if (res.body) |b| b.len else 0,
    });

    conn.state = .sending_response;
    try sendResponseAsync(task_data);
}

fn sendResponseAsync(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    const req = task_data.req;
    const res = task_data.res orelse return error.NoResponse;

    if (conn.state != .sending_response) {
        std.log.debug("Skipping sendResponseAsync on FD: {d}, state: {s}", .{ conn.fd, @tagName(conn.state) });
        return;
    }

    const buffer = try res.toBuffer(conn.allocator, req);
    std.log.debug("Sending response for FD: {d}, status: {d}, buffer_len: {d}", .{
        conn.fd,
        @intFromEnum(res.status),
        buffer.len,
    });

    const task = try conn.server.async_io.?.getTask();
    task.* = .{
        .userdata = task_data,
        .callback = handleWriteCompletion,
        .req = .{ .write = .{ .fd = conn.fd, .buffer = buffer } },
    };
    conn.server.async_io.?.submission_q.push(task);
    std.log.debug("Scheduled async response for FD: {d}, task ptr: {*}", .{ conn.fd, task });
}

fn handleWriteCompletion(_: *AsyncIo, task: *Task) anyerror!void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;
    const result = task.result orelse return error.NoResult;

    const bytes_written = result.write catch |err| {
        std.log.err("Write error on FD: {d}: {any}", .{ conn.fd, err });
        conn.state = .closing;
        try conn.asyncClose();
        task.userdata = null;
        return;
    };

    if (task.req == .write) {
        conn.allocator.free(task.req.write.buffer);
    }

    std.log.debug("Write completed on FD: {d}, bytes: {d}", .{ conn.fd, bytes_written });

    if (conn.state == .sending_response and task_data.req != null and task_data.req.?.isWebSocketUpgrade()) {
        std.log.debug("Detected WebSocket upgrade, completing for FD: {d}", .{conn.fd});
        try completeWebSocketUpgrade(task_data);
    } else {
        // Check if keep-alive is requested
        const req = task_data.req orelse {
            std.log.debug("No request, closing connection for FD: {d}", .{conn.fd});
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
            task.userdata = null;
            return;
        };

        const connection_header = req.headers.get("Connection") orelse "keep-alive";
        if (std.mem.eql(u8, connection_header, "keep-alive")) {
            std.log.debug("Keep-alive requested, resetting to reading_request for FD: {d}", .{conn.fd});
            conn.state = .reading_request;
            task_data.req = null;
            task_data.res = null;
            task_data.request_buffer.clearAndFree();
            try conn.readNext();
        } else {
            std.log.debug("No keep-alive, closing connection for FD: {d}", .{conn.fd});
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
        }
        task.userdata = null;
    }
}

fn handleWebSocketUpgrade(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    const req = &(task_data.req orelse return error.NoRequest);
    std.log.debug("Processing WebSocket upgrade for FD: {d}", .{conn.fd});

    const ws_res = try conn.allocator.create(Response);
    errdefer conn.allocator.destroy(ws_res);
    ws_res.* = Response.init(conn.allocator);
    task_data.res = ws_res;
    errdefer {
        ws_res.deinit();
        task_data.res = null;
    }

    const ws_key = req.headers.get("Sec-WebSocket-Key") orelse {
        std.log.err("Missing Sec-WebSocket-Key for WebSocket upgrade (FD: {d})", .{conn.fd});
        try sendErrorAsync(task_data, .bad_request, "Missing Sec-WebSocket-Key");
        return;
    };

    try ws_res.setWebSocketHandshake(ws_key);

    var ws_ctx_ptr = try conn.allocator.create(Context);
    errdefer conn.allocator.destroy(ws_ctx_ptr);
    ws_ctx_ptr.* = Context.init(conn.allocator);
    task_data.ws_ctx = ws_ctx_ptr;

    var original_ctx_it = task_data.ctx.data.iterator();
    while (original_ctx_it.next()) |entry| {
        const key_copy = try conn.allocator.dupe(u8, entry.key_ptr.*);
        const value_copy = try conn.allocator.dupe(u8, entry.value_ptr.*);
        errdefer {
            conn.allocator.free(key_copy);
            conn.allocator.free(value_copy);
        }
        try ws_ctx_ptr.setOwned(key_copy, value_copy);
    }

    const ws_handler = conn.server.router.getWebSocketHandler(req.method, req.path, ws_ctx_ptr) orelse {
        std.log.warn("No WebSocket handler found for path: {s} (FD: {d})", .{ req.path, conn.fd });
        try sendErrorAsync(task_data, .not_found, "No WebSocket handler found");
        return;
    };
    task_data.ws_handler = ws_handler;

    const http_handler = conn.server.router.getHandler(req.method, req.path, task_data.ctx);
    if (http_handler) |handler| {
        std.log.debug("Running HTTP handler for WebSocket path: {s}, FD: {d}", .{ req.path, conn.fd });
        handler(req, ws_res, task_data.ctx);
        if (ws_res.status != .switching_protocols) {
            std.log.warn("HTTP handler changed status to {d}, aborting handshake (FD: {d})", .{ @intFromEnum(ws_res.status), conn.fd });
            conn.state = .sending_response;
            try sendResponseAsync(task_data);
            return;
        }
    }

    conn.state = .sending_response;
    try sendResponseAsync(task_data);
}

fn completeWebSocketUpgrade(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    const ws_ctx = task_data.ws_ctx orelse return error.NoWebSocketContext;
    const ws_handler = task_data.ws_handler orelse return error.NoWebSocketHandler;

    std.log.debug("Completing WebSocket upgrade for FD: {d}", .{conn.fd});

    const ws = WebSocket.init(conn.fd, conn.allocator, conn.server.options.websocket_options, conn.server.async_io.?);
    const ws_conn = try WebSocketConnection.init(conn.server, ws, ws_ctx, ws_handler, conn.allocator);

    try conn.server.websocket_fds.put(conn.fd, {});
    std.log.debug("Added FD: {d} to websocket_fds after upgrade", .{conn.fd});

    std.log.debug("WebSocketConnection initialized for FD: {d}, ws_conn_ptr={x}", .{ conn.fd, @intFromPtr(ws_conn) });

    conn.state = .upgrading_websocket;
    std.log.debug("Task data retained for WebSocket upgrade, FD: {d}", .{conn.fd});
}

fn handleWebSocketClose(_: *AsyncIo, task: *Task) anyerror!void {
    const wrapper: *ConnectionWrapper = @ptrCast(@alignCast(task.userdata));
    const ws_conn = wrapper.ws_conn;
    const result = task.result orelse {
        ws_conn.allocator.destroy(wrapper);
        return error.NoResult;
    };

    _ = result.close catch |err| {
        std.log.err("Close error (FD: {d}): {any}", .{ ws_conn.ws.socket, err });
    };

    std.log.debug("Async close completed for WebSocket FD: {d}", .{ws_conn.ws.socket});
    ws_conn.state = .closed;

    _ = ws_conn.server.websocket_fds.remove(ws_conn.ws.socket);

    ws_conn.deinit();
    ws_conn.allocator.destroy(wrapper);
    task.userdata = null;
}

fn handleHttpClose(_: *AsyncIo, task: *Task) anyerror!void {
    const conn: *Connection = @ptrCast(@alignCast(task.userdata));
    const result = task.result orelse return error.NoResult;

    _ = result.close catch |err| {
        std.log.err("Close error (FD: {d}): {any}", .{ conn.fd, err });
    };

    std.log.debug("Async close completed for HTTP FD: {d}", .{conn.fd});
    conn.state = .closed;

    _ = conn.server.connections.remove(conn.fd);
    conn.deinit();
    task.userdata = null;
}
