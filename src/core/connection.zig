const std = @import("std");
const Allocator = std.mem.Allocator;

const Server = @import("server.zig").Server;
const Context = @import("context.zig").Context;

const router = @import("router.zig");
const HandlerFn = router.HandlerFn;
const WebSocketHandlerFn = router.WebSocketHandlerFn;

const AsyncIo = @import("../async/async.zig").AsyncIo;
const Task = @import("../async/task.zig").Task;
const Timespec = @import("../async/async.zig").Timespec;

const http = @import("../http/mod.zig");
const Request = http.Request;
const Response = http.Response;
const StatusCode = http.StatusCode;

const websocket = @import("../websocket/mod.zig");
const WebSocket = websocket.WebSocket;
const WebSocketTransport = websocket.WebSocketTransport;
const WebSocketConnection = websocket.WebSocketConnection;
const computeAcceptKey = websocket.computeAcceptKey;

const middleware = @import("../middleware/mod.zig");
const MiddlewareContext = middleware.MiddlewareContext;
const Template = @import("../template/main.zig");
const utils = @import("../utils.zig");

const log = std.log.scoped(.connection);

const ConnectionError = error{
    NoResult,
    NoRequest,
    NoResponse,
    NoWebSocketContext,
    NoWebSocketHandler,
    InvalidWebSocketKey,
    UnexpectedResult,
    NoAsyncIo,
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
        websocket_active,
        closing,
        closed,
    };

    pub fn init(server: *Server, conn: std.net.Server.Connection, allocator: Allocator) !*Connection {
        const connection = try allocator.create(Connection);
        errdefer allocator.destroy(connection);

        const task_data = try ConnectionTaskData.init(allocator, connection);
        errdefer task_data.deinit(allocator);

        connection.* = .{
            .server = server,
            .fd = conn.stream.handle,
            .allocator = allocator,
            .state = .reading_request,
            .task_data = task_data,
        };

        try connection.startReading();
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        self.task_data.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn startReading(self: *Connection) !void {
        try self.readNext();
    }

    fn readNext(self: *Connection) !void {
        if (self.state != .reading_request) {
            log.warn("readNext called in state: {}", .{self.state});
            return;
        }

        // Clear buffer before reading new request
        self.task_data.request_buffer.clearAndFree();
        log.debug("Cleared request buffer for FD {d}, size: {d}", .{ self.fd, self.task_data.request_buffer.items.len });

        // Cancel any existing header timer
        if (self.task_data.header_timer_task) |timer_task| {
            self.server.async_io.?.cancel(timer_task, .{ .ptr = self.task_data, .cb = handleTimerCancelCompletion }) catch |err| {
                log.err("Failed to cancel header timer for FD {d}: {}", .{ self.fd, err });
            };
            self.task_data.header_timer_task = null;
        }

        const task_data = self.task_data;
        const buffer_size = 65536;
        try task_data.request_buffer.ensureTotalCapacity(buffer_size);
        task_data.request_buffer.items.len = 0; // Reset length
        const buf = task_data.request_buffer.allocatedSlice()[0..buffer_size];

        // Schedule the read task
        const read_task = try self.server.async_io.?.getTask();
        read_task.* = .{
            .userdata = task_data,
            .callback = handleReadCompletion,
            .req = .{ .recv = .{ .fd = self.fd, .buffer = buf } },
        };
        self.server.async_io.?.submission_q.push(read_task);

        // Schedule header timeout
        const timeout_ms = self.server.options.header_read_timeout_ms;
        const timeout_ms_i64 = @min(timeout_ms, std.math.maxInt(i64));
        const timeout_ts = Timespec{
            .sec = @divTrunc(timeout_ms_i64, 1000),
            .nsec = @intCast((timeout_ms_i64 % 1000) * 1_000_000),
        };
        const timer_task = try self.server.async_io.?.timer(timeout_ts, .{
            .ptr = task_data,
            .cb = handleHeaderTimeoutCompletion,
        });
        task_data.header_timer_task = timer_task;
        log.debug("Scheduled header timeout for FD {d} ({d}ms)", .{ self.fd, timeout_ms });
    }

    pub fn asyncClose(self: *Connection) !void {
        if (self.state == .closed or self.state == .closing) return;
        self.state = .closing;

        // Cancel header timer
        if (self.task_data.header_timer_task) |timer_task| {
            self.server.async_io.?.cancel(timer_task, .{ .ptr = self.task_data, .cb = handleTimerCancelCompletion }) catch |err| {
                log.err("Failed to cancel header timer for FD {d}: {}", .{ self.fd, err });
            };
            self.task_data.header_timer_task = null;
        }

        const task = try self.server.async_io.?.getTask();
        task.* = .{
            .userdata = self,
            .callback = handleClose,
            .req = .{ .close = self.fd },
        };
        self.server.async_io.?.submission_q.push(task);
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
    header_timer_task: ?*Task = null,

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
        data.request_buffer.clearAndFree(); // Ensure empty
        log.debug("Initialized request buffer for FD {d}, size: {d}", .{ conn.fd, data.request_buffer.items.len });
        return data;
    }

    pub fn deinit(self: *ConnectionTaskData, allocator: Allocator) void {
        std.debug.assert(self.header_timer_task == null);

        if (self.req) |*req| {
            req.deinit();
            self.req = null;
        }
        if (self.res) |res| {
            res.deinit();
            allocator.destroy(res);
            self.res = null;
        }
        if (self.ws_ctx) |ws_ctx| {
            log.warn("Deinit called with non-null ws_ctx for FD {d}. Potential double-free risk.", .{self.conn.fd});
            ws_ctx.deinit();
            allocator.destroy(ws_ctx);
            self.ws_ctx = null;
        }
        if (self.middleware_ctx) |mctx| {
            allocator.destroy(mctx.final_handler);
            allocator.destroy(mctx);
            self.middleware_ctx = null;
        }

        self.request_buffer.clearAndFree(); // Ensure buffer is cleared
        self.request_buffer.deinit();
        self.ctx.deinit();
        allocator.destroy(self.ctx);
        allocator.destroy(self);
    }
};

fn sendErrorAsync(task_data: *ConnectionTaskData, status: StatusCode, message: []const u8) !void {
    const conn = task_data.conn;
    if (conn.state == .closed or conn.state == .closing) return;

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

fn handleReadCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    const bytes_read = switch (task.result orelse return error.NoResult) {
        .recv => |res| res catch |err| {
            log.err("Read error on FD {d}: {}", .{ conn.fd, err });
            conn.state = .closing;
            try conn.asyncClose();
            return;
        },
        else => {
            log.err("Unexpected result type in handleReadCompletion for FD {d}", .{conn.fd});
            conn.state = .closing;
            try conn.asyncClose();
            return error.UnexpectedResult;
        },
    };

    if (bytes_read == 0) {
        log.debug("Connection closed by peer on FD {d}", .{conn.fd});
        conn.state = .closing;
        try conn.asyncClose();
        return;
    }

    // Adjust buffer length to reflect actual bytes read
    task_data.request_buffer.items.len = bytes_read;
    log.debug("Read {d} bytes on FD {d}. Total buffer: {d}", .{ bytes_read, conn.fd, task_data.request_buffer.items.len });
    log.debug("Request data: {s}", .{task_data.request_buffer.items[0..@min(task_data.request_buffer.items.len, 1024)]});

    _ = processRequest(task_data) catch |err| switch (err) {
        error.RequestTooLarge => {
            log.debug("Parse error on FD {d}: {}. Buffer content: {s}", .{ conn.fd, err, task_data.request_buffer.items[0..@min(task_data.request_buffer.items.len, 1024)] });
            try sendErrorAsync(task_data, .payload_too_large, "Request entity too large");
            task_data.request_buffer.clearAndFree(); // Clear buffer
            conn.state = .closing;
            try conn.asyncClose();
            return;
        },
        error.InvalidRequestLine,
        error.InvalidMethod,
        error.InvalidPath,
        error.InvalidHeader,
        error.InvalidHeaderName,
        error.InvalidVersion,
        error.TooManyHeaders,
        error.TooManyQueryParams,
        error.IncompleteBody,
        error.InvalidMultipart,
        error.BodyTooLarge,
        => {
            log.debug("Parse error on FD {d}: {}", .{ conn.fd, err });
            try sendErrorAsync(task_data, .bad_request, "Invalid request");
            task_data.request_buffer.clearAndFree(); // Clear buffer
            return;
        },
        else => {
            log.err("Unexpected error on FD {d}: {}", .{ conn.fd, err });
            task_data.request_buffer.clearAndFree(); // Clear buffer
            conn.state = .closing;
            try conn.asyncClose();
            return;
        },
    };

    if (conn.state == .reading_request) {
        try conn.readNext();
    }
}

fn handleHeaderTimeoutCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    const result = task.result orelse return error.NoResult;
    switch (result) {
        .timer => |_| {
            if (conn.state == .reading_request) {
                log.warn("Header timeout on FD {d}", .{conn.fd});
                conn.state = .closing;
                try conn.asyncClose();
            }
        },
        else => {
            log.err("Unexpected result type in handleHeaderTimeoutCompletion for FD {d}", .{conn.fd});
            conn.state = .closing;
            try conn.asyncClose();
        },
    }
}

fn handleTimerCancelCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    const result = task.result orelse return error.NoResult;
    switch (result) {
        .cancel => |_| log.debug("Header timer cancelled for FD {d}", .{conn.fd}),
        else => {
            log.err("Unexpected result type in handleTimerCancelCompletion for FD {d}", .{conn.fd});
            conn.state = .closing;
            try conn.asyncClose();
        },
    }
}

fn processRequest(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    conn.state = .processing_request;

    const req_data = task_data.request_buffer.items;
    var req = try Request.parse(conn.allocator, req_data);
    if (task_data.header_timer_task) |timer_task| {
        conn.server.async_io.?.cancel(timer_task, .{ .ptr = task_data, .cb = handleTimerCancelCompletion }) catch |err| {
            log.err("Failed to cancel header timer on FD {d}: {}", .{ conn.fd, err });
        };
        task_data.header_timer_task = null;
    }

    task_data.req = req;
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
    const route_handler = conn.server.router.getHandler(req.method, req.path, task_data.ctx) orelse utils.notFound;

    if (middlewares.len > 0) {
        const middleware_ctx = try conn.allocator.create(MiddlewareContext);
        errdefer conn.allocator.destroy(middleware_ctx);
        const final_handler_ptr = try conn.allocator.create(HandlerFn);
        errdefer conn.allocator.destroy(final_handler_ptr);
        final_handler_ptr.* = route_handler;
        middleware_ctx.* = .{
            .middlewares = middlewares,
            .index = 0,
            .server = conn.server,
            .final_handler = final_handler_ptr,
        };
        task_data.middleware_ctx = middleware_ctx;
        try middleware.executeChain(req, res, task_data.ctx, middleware_ctx, route_handler);
    } else {
        route_handler(req, res, task_data.ctx);
    }

    if (res.body == null) {
        if (try Template.renderTemplate(conn.allocator, req.path, task_data.ctx)) |rendered| {
            try res.setBody(rendered);
            try res.setHeader("Content-Type", "text/html; charset=utf-8");
        } else if (std.mem.eql(u8, req.path, "/") and res.status == .ok) {
            try res.setBody(try conn.allocator.dupe(u8, "Hello, World!"));
            try res.setHeader("Content-Type", "text/plain; charset=utf-8");
        } else {
            if (res.status == .ok) res.status = .not_found;
            try sendErrorAsync(task_data, res.status, "Not Found");
            return;
        }
    }

    conn.state = .sending_response;
    try sendResponseAsync(task_data);
}

fn sendResponseAsync(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    const req = task_data.req orelse return error.NoRequest;
    const res = task_data.res orelse return error.NoResponse;

    if (conn.state != .sending_response) {
        log.debug("Invalid state for sending response on FD {d}: {}", .{ conn.fd, conn.state });
        return;
    }

    const buffer = try res.toBuffer(conn.allocator, req);
    const task = try conn.server.async_io.?.getTask();
    task.* = .{
        .userdata = task_data,
        .callback = handleWriteCompletion,
        .req = .{ .write = .{ .fd = conn.fd, .buffer = buffer } },
    };
    conn.server.async_io.?.submission_q.push(task);
}

fn handleWriteCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    if (task.req == .write) {
        conn.allocator.free(task.req.write.buffer);
    }

    const bytes_written = switch (task.result orelse return error.NoResult) {
        .write => |write_res| write_res catch |err| {
            log.err("Write error on FD {d}: {}", .{ conn.fd, err });
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
            if (task_data.res) |res| {
                res.deinit();
                conn.allocator.destroy(res);
                task_data.res = null;
            }
            return;
        },
        else => {
            log.err("Unexpected result type in handleWriteCompletion for FD {d}", .{conn.fd});
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
            return error.UnexpectedResult;
        },
    };
    _ = bytes_written;

    if (task_data.res) |res| {
        res.deinit();
        conn.allocator.destroy(res);
        task_data.res = null;
    }

    if (conn.state == .sending_response and task_data.req != null and task_data.req.?.isWebSocketUpgrade()) {
        conn.state = .upgrading_websocket;
        try completeWebSocketUpgrade(task_data);
    } else if (task_data.req) |*req| {
        const is_keep_alive = req.isKeepAlive();
        req.deinit();
        task_data.req = null;

        if (is_keep_alive) {
            log.debug("Keep-alive on FD {d}", .{conn.fd});
            conn.state = .reading_request;
            try conn.readNext();
        } else {
            log.debug("Closing connection on FD {d}", .{conn.fd});
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
        }
    } else {
        log.err("No request after write on FD {d}", .{conn.fd});
        conn.state = .closing;
        _ = conn.server.connections.remove(conn.fd);
        try conn.asyncClose();
    }
}

fn handleWebSocketUpgrade(task_data: *ConnectionTaskData) !void {
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

    res.status = .switching_protocols;
    try res.setHeader("Upgrade", "websocket");
    try res.setHeader("Connection", "Upgrade");

    const ws_key = req.headers.get("Sec-WebSocket-Key") orelse return error.InvalidWebSocketKey;
    const ws_accept = try computeAcceptKey(conn.allocator, ws_key);
    defer conn.allocator.free(ws_accept);
    try res.setHeader("Sec-WebSocket-Accept", ws_accept);

    const ws_ctx = try conn.allocator.create(Context);
    errdefer conn.allocator.destroy(ws_ctx);
    ws_ctx.* = Context.init(conn.allocator);
    task_data.ws_ctx = ws_ctx;

    task_data.ws_handler = conn.server.router.getWebSocketHandler(req.method, req.path, task_data.ctx) orelse return error.NoWebSocketHandler;
    conn.state = .sending_response;
    try sendResponseAsync(task_data);
}

fn completeWebSocketUpgrade(task_data: *ConnectionTaskData) !void {
    const conn = task_data.conn;
    const ws_ctx = task_data.ws_ctx orelse return error.NoWebSocketContext;
    const ws_handler = task_data.ws_handler orelse return error.NoWebSocketHandler;

    const transport = try WebSocketTransport.init(conn.fd, conn.allocator, conn.server.async_io.?);
    errdefer transport.deinit();
    const ws = try WebSocket.init(transport, conn.allocator, conn.server.options.websocket_options);
    errdefer ws.deinit();
    _ = try WebSocketConnection.init(conn.server, ws, transport, ws_ctx, ws_handler, conn.allocator);

    try conn.server.websocket_fds.put(conn.fd, {});
    conn.state = .websocket_active;

    task_data.ws_ctx = null;
    task_data.ws_handler = null;
    task_data.request_buffer.deinit();
}

fn handleClose(_: *AsyncIo, task: *Task) !void {
    const conn: *Connection = @ptrCast(@alignCast(task.userdata));

    _ = switch (task.result orelse return error.NoResult) {
        .close => |res| res catch |err| {
            log.err("Close error on FD {d}: {}", .{ conn.fd, err });
            return;
        },
        else => {
            log.err("Unexpected result type in handleClose for FD {d}", .{conn.fd});
            return;
        },
    };

    log.info("Connection closed on FD {d}", .{conn.fd});
    conn.state = .closed;
    _ = conn.server.connections.remove(conn.fd);
    conn.deinit();
}
