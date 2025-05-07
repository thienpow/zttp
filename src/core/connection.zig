// src/core/connection.zig
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
const HeaderMap = http.HeaderMap;

const websocket = @import("../websocket/mod.zig");
const WebSocket = websocket.WebSocket;
const WebSocketTransport = websocket.WebSocketTransport;
const WebSocketConnection = websocket.WebSocketConnection;
const computeAcceptKey = websocket.computeAcceptKey;

const middleware = @import("../middleware/mod.zig");
const MiddlewareContext = middleware.MiddlewareContext;
const Template = @import("../template/main.zig");
const utils = @import("../utils.zig");

const http2 = @import("../http2/mod.zig");
const Stream = http2.Stream;
const HPACK = http2.HPACK;

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
    protocol: Protocol = .http1, // Track protocol (HTTP/1.1 or HTTP/2)
    hpack: ?HPACK = null, // HPACK context for HTTP/2
    streams: std.AutoHashMap(u31, *Stream) = undefined, // HTTP/2 streams

    pub const Protocol = enum {
        http1,
        http2,
    };

    pub const State = enum {
        reading_request,
        processing_request,
        sending_response,
        upgrading_websocket,
        websocket_active,
        closing,
        closed,
        reading_http2_preface,
        processing_http2,
    };

    pub fn init(server: *Server, conn: std.net.Server.Connection, allocator: Allocator) !*Connection {
        const connection = try allocator.create(Connection);
        errdefer allocator.destroy(connection);

        // must pass app_context_ptr like this, because connection object is refilled later, and ConnectionTaskData needed app_context_ptr earlier...
        // so don't refactor this on first impression.
        const task_data = try ConnectionTaskData.init(allocator, connection, server.options.app_context_ptr);
        errdefer task_data.deinit(allocator);

        connection.* = .{
            .server = server,
            .fd = conn.stream.handle,
            .allocator = allocator,
            .state = .reading_request,
            .task_data = task_data,
            .protocol = .http1, // Default to HTTP/1.1
            .hpack = null,
            .streams = std.AutoHashMap(u31, *Stream).init(allocator),
        };

        try connection.startReading();
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        // Clean up HTTP/2 streams
        var stream_it = self.streams.iterator();
        while (stream_it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.streams.deinit();

        // Clean up HPACK
        if (self.hpack) |*hpack| {
            hpack.deinit();
            self.hpack = null;
        }

        self.task_data.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn startReading(self: *Connection) !void {
        if (self.state == .reading_http2_preface) {
            try self.readPreface();
        } else {
            try self.readNext();
        }
    }

    fn readPreface(self: *Connection) !void {
        const task_data = self.task_data;
        const buffer_size = 24; // Size of HTTP/2 client preface
        try task_data.request_buffer.ensureTotalCapacity(buffer_size);
        task_data.request_buffer.items.len = 0;
        const buf = task_data.request_buffer.allocatedSlice()[0..buffer_size];

        const read_task = try self.server.async_io.?.getTask();
        read_task.* = .{
            .userdata = task_data,
            .callback = handlePrefaceCompletion,
            .req = .{ .recv = .{ .fd = self.fd, .buffer = buf } },
        };
        self.server.async_io.?.submission_q.push(read_task);
    }

    fn readNext(self: *Connection) !void {
        if (self.state == .processing_http2) {
            try self.readHttp2Frame();
        } else if (self.state == .reading_request) {
            // Existing HTTP/1.1 logic
            if (self.state != .reading_request) {
                log.warn("readNext called in state: {}", .{self.state});
                return;
            }
            self.task_data.request_buffer.clearAndFree();
            log.debug("Cleared request buffer for FD {d}, size: {d}", .{ self.fd, self.task_data.request_buffer.items.len });

            if (self.task_data.header_timer_task) |timer_task| {
                self.server.async_io.?.cancel(timer_task, .{ .ptr = self.task_data, .cb = handleTimerCancelCompletion }) catch |err| {
                    log.err("Failed to cancel header timer for FD {d}: {}", .{ self.fd, err });
                };
                self.task_data.header_timer_task = null;
            }

            const task_data = self.task_data;
            const buffer_size = 65536;
            try task_data.request_buffer.ensureTotalCapacity(buffer_size);
            task_data.request_buffer.items.len = 0;
            const buf = task_data.request_buffer.allocatedSlice()[0..buffer_size];

            const read_task = try self.server.async_io.?.getTask();
            read_task.* = .{
                .userdata = task_data,
                .callback = handleReadCompletion,
                .req = .{ .recv = .{ .fd = self.fd, .buffer = buf } },
            };
            self.server.async_io.?.submission_q.push(read_task);

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
    }

    fn readHttp2Frame(self: *Connection) !void {
        const task_data = self.task_data;
        const buffer_size = 16384; // Max frame size (default)
        try task_data.request_buffer.ensureTotalCapacity(buffer_size);
        task_data.request_buffer.items.len = 0;
        const buf = task_data.request_buffer.allocatedSlice()[0..buffer_size];

        const read_task = try self.server.async_io.?.getTask();
        read_task.* = .{
            .userdata = task_data,
            .callback = handleHttp2FrameCompletion,
            .req = .{ .recv = .{ .fd = self.fd, .buffer = buf } },
        };
        self.server.async_io.?.submission_q.push(read_task);
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
    write_task_id: ?usize = null, // Track write task to prevent double processing

    pub fn init(allocator: Allocator, conn: *Connection, app_context_ptr: *anyopaque) !*ConnectionTaskData {
        const ctx = try allocator.create(Context);
        errdefer allocator.destroy(ctx);
        ctx.* = Context.init(allocator);
        ctx.app_context_ptr = app_context_ptr;

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
            log.debug("Deinit task_data.res for FD {d} in ConnectionTaskData.deinit", .{self.conn.fd});
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

    // Clean up existing response if it exists
    if (task_data.res) |res| {
        log.debug("Cleaning up existing response for FD {d} before sending error", .{conn.fd});
        res.deinit();
        conn.allocator.destroy(res);
        task_data.res = null;
    }

    const res = try conn.allocator.create(Response);
    errdefer conn.allocator.destroy(res);
    res.* = Response.init(conn.allocator);
    log.debug("Created new response for FD {d}: status={s}", .{ conn.fd, status.reason() });
    task_data.res = res;
    errdefer {
        res.deinit();
        task_data.res = null;
    }

    res.status = status;
    try res.setBody(message); // Avoid redundant allocation

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
    log.debug("Created response for FD {d} in handleHttpRequest", .{conn.fd});
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
            // Clean up original response before sendErrorAsync
            res.deinit();
            conn.allocator.destroy(res);
            task_data.res = null;
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
        log.debug("Invalid state for sending response on FD {d}: {any}", .{ conn.fd, conn.state });
        return;
    }

    const buffer = try res.toBuffer(conn.allocator, req);
    const task = try conn.server.async_io.?.getTask();
    task.* = .{
        .userdata = task_data,
        .callback = handleWriteCompletion,
        .req = .{ .write = .{ .fd = conn.fd, .buffer = buffer } },
    };
    task_data.write_task_id = @intFromPtr(task);
    log.debug("Submitting write task {any} for FD {d}", .{ task_data.write_task_id, conn.fd });
    conn.server.async_io.?.submission_q.push(task);
}

fn handleWriteCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    // Check if task was already processed
    const task_id = @intFromPtr(task);
    if (task_data.write_task_id != task_id) {
        log.warn("Unexpected write task ID {d} for FD {d}; expected {any}. Ignoring.", .{
            task_id, conn.fd, task_data.write_task_id,
        });
        return;
    }
    task_data.write_task_id = null; // Clear task ID

    if (task.req == .write) {
        conn.allocator.free(task.req.write.buffer);
    }

    const bytes_written = switch (task.result orelse return error.NoResult) {
        .write => |write_res| write_res catch |err| {
            log.err("Write error on FD {d}: {any}", .{ conn.fd, err });
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
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

    // Deinit response only if it exists and hasn't been deinitialized
    if (task_data.res) |res| {
        log.debug("Deinit response for FD {d}: status={s}, body_len={any}", .{
            conn.fd,
            res.status.reason(),
            if (res.body) |b| b.len else null,
        });
        //res.deinit();
        conn.allocator.destroy(res);
        task_data.res = null;
    } else {
        log.warn("No response to deinit for FD {d} in handleWriteCompletion", .{conn.fd});
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
    log.debug("Created response for FD {d} in handleWebSocketUpgrade", .{conn.fd});
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
    const ws = try WebSocket.init(transport, conn.allocator, conn.server.options.websocket);
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
            log.err("Close error on FD {d}: {any}", .{ conn.fd, err });
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

// http2

fn handlePrefaceCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    const bytes_read = switch (task.result orelse return error.NoResult) {
        .recv => |res| res catch |err| {
            log.err("Preface read error on FD {d}: {}", .{ conn.fd, err });
            conn.state = .closing;
            try conn.asyncClose();
            return;
        },
        else => return error.UnexpectedResult,
    };

    if (bytes_read < 24) {
        log.debug("Incomplete preface on FD {d}, switching to HTTP/1.1", .{conn.fd});
        conn.state = .reading_request;
        conn.protocol = .http1;
        try conn.readNext();
        return;
    }

    const preface = task_data.request_buffer.items[0..24];
    const expected_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (!std.mem.eql(u8, preface, expected_preface)) {
        log.debug("Invalid preface on FD {d}, switching to HTTP/1.1", .{conn.fd});
        conn.state = .reading_request;
        conn.protocol = .http1;
        try conn.readNext();
        return;
    }

    log.info("HTTP/2 preface received on FD {d}", .{conn.fd});
    conn.protocol = .http2;
    conn.state = .processing_http2;
    conn.hpack = HPACK.init(conn.allocator, 4096);
    task_data.request_buffer.clearAndFree();

    // Send SETTINGS frame
    const settings = http2.Settings{};
    const payload = try settings.writePayload(conn.allocator);
    defer conn.allocator.free(payload);
    const frame_header = http2.FrameHeader{
        .length = @intCast(payload.len),
        .type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    var buf = std.ArrayList(u8).init(conn.allocator);
    defer buf.deinit();
    try frame_header.write(buf.writer());
    try buf.appendSlice(payload);
    const write_task = try conn.server.async_io.?.getTask();
    write_task.* = .{
        .userdata = task_data,
        .callback = handleWriteCompletion,
        .req = .{ .write = .{ .fd = conn.fd, .buffer = try buf.toOwnedSlice() } },
    };
    task_data.write_task_id = @intFromPtr(write_task);
    conn.server.async_io.?.submission_q.push(write_task);

    try conn.readHttp2Frame();
}

fn handleHttp2FrameCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    const bytes_read = switch (task.result orelse return error.NoResult) {
        .recv => |res| res catch |err| {
            log.err("Frame read error on FD {d}: {}", .{ conn.fd, err });
            conn.state = .closing;
            try conn.asyncClose();
            return;
        },
        else => return error.UnexpectedResult,
    };

    if (bytes_read == 0) {
        log.debug("Connection closed by peer on FD {d}", .{conn.fd});
        conn.state = .closing;
        try conn.asyncClose();
        return;
    }

    task_data.request_buffer.items.len = bytes_read;
    var buffer_stream = std.io.fixedBufferStream(task_data.request_buffer.items);
    const reader = buffer_stream.reader();

    const header = try http2.FrameHeader.read(reader);
    if (header.length > bytes_read - 9) {
        log.err("Incomplete frame on FD {d}", .{conn.fd});
        conn.state = .closing;
        try conn.asyncClose();
        return;
    }

    switch (header.type) {
        .settings => {
            const payload = task_data.request_buffer.items[9 .. 9 + header.length];
            const settings = try http2.Settings.readPayload(conn.allocator, payload);
            log.debug("Received SETTINGS on FD {d}: max_concurrent_streams={d}", .{ conn.fd, settings.max_concurrent_streams });
            // Send SETTINGS ACK
            const ack_header = http2.FrameHeader{
                .length = 0,
                .type = .settings,
                .flags = 0x1, // ACK flag
                .stream_id = 0,
            };
            var buf = std.ArrayList(u8).init(conn.allocator);
            defer buf.deinit();
            try ack_header.write(buf.writer());
            const write_task = try conn.server.async_io.?.getTask();
            write_task.* = .{
                .userdata = task_data,
                .callback = handleWriteCompletion,
                .req = .{ .write = .{ .fd = conn.fd, .buffer = try buf.toOwnedSlice() } },
            };
            task_data.write_task_id = @intFromPtr(write_task);
            conn.server.async_io.?.submission_q.push(write_task);
        },
        .headers => {
            if (!conn.streams.contains(header.stream_id)) {
                const stream = try http2.Stream.init(conn.allocator, header.stream_id);
                stream.state = .open;
                try conn.streams.put(header.stream_id, stream);
            }
            const stream = conn.streams.get(header.stream_id).?;
            const payload = task_data.request_buffer.items[9 .. 9 + header.length];
            var payload_stream = std.io.fixedBufferStream(payload);
            const headers = try conn.hpack.?.decode(payload_stream.reader(), conn.allocator);
            defer {
                for (headers.items) |h| {
                    conn.allocator.free(h.name);
                    conn.allocator.free(h.value);
                }
                headers.deinit();
            }

            var req = try conn.allocator.create(Request);
            req.* = Request{
                .allocator = conn.allocator,
                .method = .get, // Default, will parse from headers
                .path = "",
                .version = "HTTP/2.0",
                .headers = HeaderMap.init(conn.allocator),
                .query = std.StringHashMap([]const u8).init(conn.allocator),
                .cookies = std.StringHashMap([]const u8).init(conn.allocator),
                .body = null,
                .json = null,
                .json_arena = null,
                .form = null,
                .multipart = null,
            };
            for (headers.items) |h| {
                if (std.mem.eql(u8, h.name, ":method")) {
                    req.method = try http.parseMethod(h.value);
                } else if (std.mem.eql(u8, h.name, ":path")) {
                    const path_parts = try http.parsePath(conn.allocator, h.value);
                    req.path = path_parts.path;
                    req.query = path_parts.query;
                } else {
                    try req.headers.put(h.name, h.value);
                }
            }
            stream.request = req;

            // Process request
            const res = try conn.allocator.create(Response);
            res.* = Response.init(conn.allocator);
            stream.response = res;

            const route_handler = conn.server.router.getHandler(req.method, req.path, task_data.ctx) orelse utils.notFound;
            route_handler(req, res, task_data.ctx);

            // Send response
            var headers_out = std.ArrayList(http2.hpack.Header).init(conn.allocator);
            defer headers_out.deinit();
            const status_str = try std.fmt.allocPrint(conn.allocator, "{}", .{@intFromEnum(res.status)});
            defer conn.allocator.free(status_str);
            try headers_out.append(.{ .name = ":status", .value = status_str });
            var header_it = res.headers.iterator();
            while (header_it.next()) |entry| {
                for (entry.value_ptr.items) |value| {
                    try headers_out.append(.{ .name = entry.key_ptr.*, .value = value });
                }
            }
            var buf = std.ArrayList(u8).init(conn.allocator);
            defer buf.deinit();
            try conn.hpack.?.encode(headers_out, buf.writer());
            const frame_header = http2.FrameHeader{
                .length = @intCast(buf.items.len),
                .type = .headers,
                .flags = 0x4, // END_HEADERS
                .stream_id = header.stream_id,
            };
            var out_buf = std.ArrayList(u8).init(conn.allocator);
            defer out_buf.deinit();
            try frame_header.write(out_buf.writer());
            try out_buf.appendSlice(buf.items);
            if (res.body) |body| {
                const data_frame = http2.FrameHeader{
                    .length = @intCast(body.len),
                    .type = .data,
                    .flags = 0x1, // END_STREAM
                    .stream_id = header.stream_id,
                };
                try data_frame.write(out_buf.writer());
                try out_buf.appendSlice(body);
            }
            const write_task = try conn.server.async_io.?.getTask();
            write_task.* = .{
                .userdata = task_data,
                .callback = handleWriteCompletion,
                .req = .{ .write = .{ .fd = conn.fd, .buffer = try out_buf.toOwnedSlice() } },
            };
            task_data.write_task_id = @intFromPtr(write_task);
            conn.server.async_io.?.submission_q.push(write_task);

            // Clean up response and stream
            stream.state = .half_closed_remote;
            if (stream.response) |response| {
                response.deinit();
                conn.allocator.destroy(response);
                stream.response = null;
            }
            if (stream.state == .half_closed_remote and (header.flags & 0x1) != 0) {
                // Remove stream if fully closed
                if (conn.streams.get(header.stream_id)) |stream_to_remove| {
                    if (conn.streams.remove(header.stream_id)) {
                        stream_to_remove.deinit(conn.allocator);
                    }
                }
            }
        },
        .data => {
            if (conn.streams.get(header.stream_id)) |stream| {
                if (stream.request) |req| {
                    const payload = task_data.request_buffer.items[9 .. 9 + header.length];
                    req.body = try conn.allocator.dupe(u8, payload);
                    // Re-process request if needed
                }
                if (header.flags & 0x1 != 0) { // END_STREAM
                    stream.state = .half_closed_remote;
                }
            }
        },
        else => {
            log.warn("Unsupported frame type {any} on FD {d}", .{ header.type, conn.fd });
        },
    }

    task_data.request_buffer.clearAndFree();
    try conn.readHttp2Frame();
}
