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
const Http2Connection = http2.Http2Connection;
const Http2Stream = http2.Stream;

const http3 = @import("../http3/mod.zig");
const Http3Connection = http3.Http3Connection;
const Http3Stream = http3.Http3Stream;

const tls = @import("tls.zig");

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
    QuicProcessingFailed,
};

pub const Connection = struct {
    server: *Server,
    fd: std.posix.fd_t,
    allocator: Allocator,
    state: State,
    task_data: *ConnectionTaskData,
    protocol: Protocol,
    http2_conn: ?*Http2Connection = null,
    quic_conn: ?*Http3Connection = null,
    tls_conn: ?*tls.TlsConnection,
    quic_conn_id: ?[]const u8 = null,
    remote_address: ?std.net.Address = null, // Added for HTTP/3

    pub const Protocol = enum {
        http1,
        http2,
        http3,
    };

    pub const State = enum {
        reading_request,
        processing_request,
        sending_response,
        upgrading_websocket,
        websocket_active,
        closing,
        closed,
        processing_http2,
        processing_http3,
    };

    pub fn init(server: *Server, fd: std.posix.fd_t, allocator: Allocator, tls_conn: ?*tls.TlsConnection, protocol: Protocol, quic_conn_id: ?[]const u8, remote_address: ?std.net.Address) !*Connection {
        const connection = try allocator.create(Connection);
        errdefer allocator.destroy(connection);

        const task_data = try ConnectionTaskData.init(allocator, connection, server.options.app_context_ptr);
        errdefer task_data.deinit(allocator);

        connection.* = .{
            .server = server,
            .fd = fd,
            .allocator = allocator,
            .state = switch (protocol) {
                .http1 => .reading_request,
                .http2 => .processing_http2,
                .http3 => .processing_http3,
            },
            .task_data = task_data,
            .protocol = protocol,
            .http2_conn = null,
            .quic_conn = null,
            .tls_conn = tls_conn,
            .quic_conn_id = quic_conn_id,
            .remote_address = remote_address,
        };

        try connection.startReading();
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        if (self.http2_conn) |http2_conn| {
            http2_conn.deinit();
            self.allocator.destroy(http2_conn);
        }
        if (self.quic_conn) |quic_conn| {
            quic_conn.deinit();
            self.allocator.destroy(quic_conn);
        }
        if (self.tls_conn) |tls_conn| {
            tls_conn.deinit();
        }
        if (self.quic_conn_id) |conn_id| {
            self.allocator.free(conn_id);
        }
        self.task_data.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn startReading(self: *Connection) !void {
        switch (self.protocol) {
            .http1 => try self.readNext(),
            .http2 => try self.readHttp2Frame(),
            .http3 => try self.readHttp3Packet(),
        }
    }

    fn readNext(self: *Connection) !void {
        if (self.state != .reading_request) {
            log.warn("readNext called in state: {}", .{self.state});
            return;
        }
        self.task_data.request_buffer.clearAndFree();

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
        const timer_task = try self.server.async_io.?.setTimer(timeout_ts, .{
            .ptr = task_data,
            .cb = handleHeaderTimeoutCompletion,
        });
        task_data.header_timer_task = timer_task;
    }

    fn readHttp2Frame(self: *Connection) !void {
        const task_data = self.task_data;
        const buffer_size = 16384;
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

    fn readHttp3Packet(self: *Connection) !void {
        const task_data = self.task_data;
        const buffer_size = 1500;
        try task_data.request_buffer.ensureTotalCapacity(buffer_size);
        task_data.request_buffer.items.len = 0;
        const buf = task_data.request_buffer.allocatedSlice()[0..buffer_size];

        const read_task = try self.server.async_io.?.getTask();
        read_task.* = .{
            .userdata = task_data,
            .callback = handleHttp3PacketCompletion,
            .req = .{ .recv = .{ .fd = self.fd, .buffer = buf } },
        };
        self.server.async_io.?.submission_q.push(read_task);
    }

    pub fn asyncClose(self: *Connection) !void {
        if (self.state == .closed or self.state == .closing) return;
        self.state = .closing;

        if (self.protocol == .http2) {
            if (self.http2_conn) |http2_conn| {
                try http2_conn.close();
            }
        } else if (self.protocol == .http3) {
            if (self.quic_conn) |quic_conn| {
                try quic_conn.asyncClose(.no_error);
            }
        }

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
    write_task_id: ?usize = null,
    http2_stream_responses: std.AutoHashMap(u31, *Response),
    quic_stream_responses: std.AutoHashMap(u64, *Response), // Added for HTTP/3

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
            .http2_stream_responses = std.AutoHashMap(u31, *Response).init(allocator),
            .quic_stream_responses = std.AutoHashMap(u64, *Response).init(allocator),
        };
        return data;
    }

    pub fn deinit(self: *ConnectionTaskData, allocator: Allocator) void {
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
            ws_ctx.deinit();
            allocator.destroy(ws_ctx);
            self.ws_ctx = null;
        }
        if (self.middleware_ctx) |mctx| {
            allocator.destroy(mctx.final_handler);
            allocator.destroy(mctx);
            self.middleware_ctx = null;
        }

        var res_it = self.http2_stream_responses.iterator();
        while (res_it.next()) |entry| {
            entry.value_ptr.*.deinit();
            allocator.destroy(entry.value_ptr.*);
        }
        self.http2_stream_responses.deinit();

        var quic_res_it = self.quic_stream_responses.iterator();
        while (quic_res_it.next()) |entry| {
            entry.value_ptr.*.deinit();
            allocator.destroy(entry.value_ptr.*);
        }
        self.quic_stream_responses.deinit();

        self.request_buffer.deinit();
        self.ctx.deinit();
        allocator.destroy(self.ctx);
        allocator.destroy(self);
    }
};

fn sendErrorAsync(task_data: *ConnectionTaskData, status: StatusCode, message: []const u8) !void {
    const conn = task_data.conn;
    if (conn.state == .closed or conn.state == .closing) return;

    if (task_data.res) |res| {
        res.deinit();
        conn.allocator.destroy(res);
        task_data.res = null;
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
    try res.setBody(message);

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
        else => return error.UnexpectedResult,
    };

    if (bytes_read == 0) {
        log.debug("Connection closed by peer on FD {d}", .{conn.fd});
        conn.state = .closing;
        try conn.asyncClose();
        return;
    }

    task_data.request_buffer.items.len = bytes_read;

    _ = processRequest(task_data) catch |err| switch (err) {
        error.RequestTooLarge => {
            try sendErrorAsync(task_data, .payload_too_large, "Request entity too large");
            task_data.request_buffer.clearAndFree();
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
            try sendErrorAsync(task_data, .bad_request, "Invalid request");
            task_data.request_buffer.clearAndFree();
            return;
        },
        else => {
            log.err("Unexpected error on FD {d}: {}", .{ conn.fd, err });
            task_data.request_buffer.clearAndFree();
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

    switch (task.result orelse return error.NoResult) {
        .timer => |_| {
            if (conn.state == .reading_request) {
                log.warn("Header timeout on FD {d}", .{conn.fd});
                conn.state = .closing;
                try conn.asyncClose();
            }
        },
        else => {
            log.err("Unexpected result type for FD {d}", .{conn.fd});
            conn.state = .closing;
            try conn.asyncClose();
        },
    }
}

fn handleTimerCancelCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    switch (task.result orelse return error.NoResult) {
        .cancel => |_| log.debug("Header timer cancelled for FD {d}", .{conn.fd}),
        else => {
            log.err("Unexpected result type for FD {d}", .{conn.fd});
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
        if (conn.protocol != .http1) {
            try sendErrorAsync(task_data, .bad_request, "WebSocket upgrade not supported over HTTP/2 or HTTP/3");
            return;
        }
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
            res.status = .not_found;
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
    task_data.write_task_id = @intFromPtr(task);
    conn.server.async_io.?.submission_q.push(task);
}

fn handleWriteCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    const task_id = @intFromPtr(task);
    if (task_data.write_task_id != task_id) {
        log.warn("Unexpected write task ID {d} for FD {d}", .{ task_id, conn.fd });
        return;
    }
    task_data.write_task_id = null;

    if (task.req == .write) {
        conn.allocator.free(task.req.write.buffer);
    }

    const bytes_written = switch (task.result orelse return error.NoResult) {
        .write => |write_res| write_res catch |err| {
            log.err("Write error on FD {d}: {}", .{ conn.fd, err });
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
            return;
        },
        else => return error.UnexpectedResult,
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
            conn.state = .reading_request;
            try conn.readNext();
        } else {
            conn.state = .closing;
            _ = conn.server.connections.remove(conn.fd);
            try conn.asyncClose();
        }
    } else {
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

    switch (task.result orelse return error.NoResult) {
        .close => |res| res catch |err| {
            log.err("Close error on FD {d}: {}", .{ conn.fd, err });
            return;
        },
        else => {
            log.err("Unexpected result type for FD {d}", .{conn.fd});
            return;
        },
    }

    conn.state = .closed;
    _ = conn.server.connections.remove(conn.fd);
    conn.deinit();
}

// Reader/Writer adapter functions
fn fixedBufferStreamReadFn(context: *const anyopaque, buffer: []u8) !usize {
    const stream: *std.io.FixedBufferStream([]const u8) = @ptrCast(@constCast(@alignCast(context)));
    return stream.read(buffer);
}

fn bufferedReaderReadFn(context: *const anyopaque, buffer: []u8) !usize {
    const reader: *std.io.BufferedReader(4096, std.fs.File.Reader) = @ptrCast(@constCast(@alignCast(context)));
    return reader.read(buffer);
}

fn fileWriterWriteFn(context: *const anyopaque, buffer: []const u8) !usize {
    const writer: std.fs.File.Writer = @ptrCast(@constCast(@alignCast(context)));
    return writer.write(buffer);
}

fn bufferedWriterWriteFn(context: *const anyopaque, buffer: []const u8) !usize {
    const writer: *std.io.BufferedWriter(4096, std.fs.File.Writer) = @ptrCast(@constCast(@alignCast(context)));
    return writer.write(buffer);
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

    if (conn.http2_conn == null) {
        const http2_conn = try conn.allocator.create(Http2Connection);
        errdefer conn.allocator.destroy(http2_conn);

        const file = std.fs.File{ .handle = conn.fd };
        var buffered_reader = std.io.bufferedReader(file.reader());
        const reader: std.io.AnyReader = if (conn.tls_conn) |tls_conn|
            tls_conn.*.reader()
        else
            std.io.AnyReader{
                .context = @ptrCast(&buffered_reader),
                .readFn = bufferedReaderReadFn,
            };

        var buffered_writer = std.io.bufferedWriter(file.writer());
        const writer: std.io.AnyWriter = if (conn.tls_conn) |tls_conn|
            tls_conn.*.writer()
        else
            std.io.AnyWriter{
                .context = @ptrCast(&buffered_writer),
                .writeFn = bufferedWriterWriteFn,
            };

        http2_conn.* = try Http2Connection.init(
            conn.allocator,
            reader,
            writer,
        );
        conn.http2_conn = http2_conn;
    }

    if (conn.http2_conn) |http2_conn| {
        const buffer = task_data.request_buffer.items[0..bytes_read];
        var buffer_stream = std.io.fixedBufferStream(buffer);
        http2_conn.reader = std.io.AnyReader{
            .context = @ptrCast(&buffer_stream),
            .readFn = fixedBufferStreamReadFn,
        };

        try http2_conn.processFrames();

        var stream_it = http2_conn.streams.streams.iterator();
        while (stream_it.next()) |stream_entry| {
            const stream = stream_entry.value_ptr.*;
            if (stream.request) |req| {
                if (stream.state == .half_closed_remote or stream.state == .closed) {
                    if (task_data.http2_stream_responses.get(stream.id)) |existing_res| {
                        _ = existing_res;
                        continue;
                    }

                    const res = try conn.allocator.create(Response);
                    errdefer conn.allocator.destroy(res);
                    res.* = Response.init(conn.allocator);
                    try task_data.http2_stream_responses.put(stream.id, res);

                    const route_handler = conn.server.router.getHandler(req.method, req.path, task_data.ctx) orelse utils.notFound;
                    route_handler(req, res, task_data.ctx);

                    try http2_conn.sendResponse(stream, res);
                }
            }
        }
    }

    task_data.request_buffer.clearAndFree();
    try conn.readHttp2Frame();
}

fn handleHttp3PacketCompletion(_: *AsyncIo, task: *Task) !void {
    const task_data: *ConnectionTaskData = @ptrCast(@alignCast(task.userdata));
    const conn = task_data.conn;

    defer task_data.request_buffer.clearAndFree();

    if (conn.protocol != .http3) {
        log.err("Invalid protocol {s} for HTTP/3 packet handling on FD {d}", .{ @tagName(conn.protocol), conn.fd });
        conn.state = .closing;
        try conn.asyncClose();
        return;
    }

    const bytes_read = switch (task.result orelse return error.NoResult) {
        .recv => |res| res catch |err| {
            log.err("QUIC packet read error on FD {d}: {}", .{ conn.fd, err });
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

    if (conn.quic_conn == null) {
        var quic_conn = try conn.allocator.create(Http3Connection);
        errdefer conn.allocator.destroy(quic_conn);

        quic_conn = try Http3Connection.init(
            conn.allocator,
            conn.server,
            conn.server.async_io.?,
            conn.fd,
            conn.remote_address orelse return error.QuicProcessingFailed,
        );
        try quic_conn.start();
        conn.quic_conn = quic_conn;
    }

    if (conn.quic_conn) |quic_conn| {
        const buffer = task_data.request_buffer.items[0..bytes_read];
        try quic_conn.handleUdpData(buffer);

        var stream_it = quic_conn.streams.valueIterator();
        while (stream_it.next()) |stream_ptr| {
            const stream = stream_ptr.*;
            if (stream.request) |req| {
                if (stream.state == .half_closed_remote or stream.state == .closed) {
                    if (task_data.quic_stream_responses.get(stream.stream_id)) |existing_res| {
                        _ = existing_res;
                        continue;
                    }

                    const res = try conn.allocator.create(Response);
                    errdefer conn.allocator.destroy(res);
                    res.* = Response.init(conn.allocator);
                    try task_data.quic_stream_responses.put(stream.stream_id, res);

                    const route_handler = conn.server.router.getHandler(req.method, req.path, task_data.ctx) orelse utils.notFound;
                    route_handler(req, res, task_data.ctx);

                    try stream.sendResponse(res);
                }
            }
        }
    }

    try conn.readHttp3Packet();
}
