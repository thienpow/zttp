// src/http3/handler.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

const AsyncIo = @import("../async/async.zig").AsyncIo;
const Task = @import("../async/task.zig").Task;
const AsyncContext = @import("../async/async.zig").AsyncContext;

const Server = @import("../core/server.zig").Server;
const Context = @import("../core/context.zig").Context;
const Request = @import("../http/request.zig").Request;
const Response = @import("../http/response.zig").Response;
const core_router = @import("../core/router.zig");

const types = @import("types.zig");
const http3_error = @import("error.zig");
const Http3Error = http3_error.Http3Error;
const ErrorCode = http3_error.ErrorCode;
const Frame = @import("frame.zig").Frame;
const Http3Stream = @import("stream.zig").Http3Stream;
const QpackEncoder = @import("qpack/encoder.zig").QpackEncoder;
const QpackDecoder = @import("qpack/decoder.zig").QpackDecoder;

const log = std.log.scoped(.http3_handler);

/// Handles HTTP/3 protocol logic for a QUIC connection, processing streams.
pub const Http3Handler = struct {
    server: *Server,
    allocator: Allocator,
    router: *core_router.Router,
    qpack_encoder: ?*QpackEncoder,
    qpack_decoder: ?*QpackDecoder,

    pub fn init(server: *Server, allocator: Allocator, router: *core_router.Router) !*Http3Handler {
        const self = try allocator.create(Http3Handler);
        self.* = .{
            .server = server,
            .allocator = allocator,
            .router = router,
            .qpack_encoder = null,
            .qpack_decoder = null,
        };
        log.debug("Initialized Http3Handler", .{});
        return self;
    }

    pub fn deinit(self: *Http3Handler) void {
        log.debug("Deinitializing Http3Handler", .{});
        self.allocator.destroy(self);
    }

    pub fn handleNewStream(self: *Http3Handler, stream: *Http3Stream) !void {
        log.info("Handling stream {d} (type: {?})", .{ stream.stream_id, stream.stream_type });
        if (stream.stream_type == null) {
            const HandlerContext = struct {
                handler: *Http3Handler,
                stream: *Http3Stream,
            };
            const ctx_struct = try self.allocator.create(HandlerContext);
            ctx_struct.* = .{ .handler = self, .stream = stream };
            const ctx = AsyncContext{
                .ptr = @as(*anyopaque, ctx_struct),
                .cb = handleRequestStreamCallback,
            };
            _ = try self.server.async_io.?.noop(ctx);
            try self.server.async_io.?.submit();
        }
    }

    fn handleRequestStreamCallback(async_io: *AsyncIo, task: *Task) anyerror!void {
        const HandlerContext = struct {
            handler: *Http3Handler,
            stream: *Http3Stream,
        };
        const ctx = @as(*HandlerContext, @alignCast(@ptrCast(task.userdata.?)));
        defer async_io.gpa.destroy(ctx);
        try handleRequestStream(ctx.handler, ctx.stream);
    }

    fn handleRequestStream(self: *Http3Handler, stream: *Http3Stream) anyerror!void {
        log.debug("Handler task started for stream {d}", .{stream.stream_id});

        var req: ?Request = null;
        var res: ?Response = null;
        var ctx: ?Context = null;
        defer {
            if (ctx) |*c| c.deinit();
            if (res) |*r| r.deinit();
            if (req) |*r| r.deinit();
        }

        while (stream.parser_state != .request_complete) {
            try self.server.async_io.?.submitAndWait();
            if (stream.state == .errored or stream.state == .closed) {
                log.err("Stream {d} closed unexpectedly", .{stream.stream_id});
                return Http3Error.InvalidFrame;
            }
        }

        req = stream.request orelse {
            log.err("Stream {d}: Request missing after completion", .{stream.stream_id});
            try stream.handleResetStream(@intFromEnum(ErrorCode.internal_error));
            return Http3Error.InvalidFrame;
        };
        res = Response.init(self.allocator);
        ctx = Context.init(self.allocator, self.server.options.app_context_ptr, req.?, res.?);

        log.debug("Stream {d}: Routing request", .{stream.stream_id});
        if (self.router.getHandler(req.?.method, req.?.path, &ctx.?)) |handler| {
            handler(&req.?, &res.?, &ctx.?);
        } else {
            log.err("Stream {d}: Route not found", .{stream.stream_id});
            res.?.status = .not_found;
        }

        log.debug("Stream {d}: Sending response (status {d})", .{ stream.stream_id, res.?.status });
        try stream.sendResponse(&res.?);
        try stream.closeWrite();

        log.debug("Stream {d}: Handler task finished", .{stream.stream_id});
    }

    pub fn setQpackInstances(self: *Http3Handler, encoder: *QpackEncoder, decoder: *QpackDecoder) void {
        self.qpack_encoder = encoder;
        self.qpack_decoder = decoder;
        log.debug("QPACK instances set", .{});
    }
};
