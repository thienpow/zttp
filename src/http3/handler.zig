// src/http3/handler.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

// Import necessary components from core, http, and http3
const Server = @import("../core/server.zig").Server;
const Context = @import("../core/context.zig").Context;
const Request = @import("../http/request.zig").Request;
const Response = @import("../http/response.zig").Response;
const core_router = @import("../core/router.zig");
const middleware = @import("../middleware/mod.zig");
const WebSocket = @import("../websocket/mod.zig").WebSocket; // Might be needed for WebTransport context

// Import types, error, settings, frame, stream, and qpack from http3 module
const types = @import("types.zig");
const http3_error = @import("error.zig");
const Http3Error = http3_error.Http3Error;
const Frame = @import("frame.zig").Frame;
const quic_stream = @import("stream.zig");
const QuicStream = quic_stream.QuicStream;
const qpack = @import("qpack/mod.zig");
const QpackEncoder = qpack.QpackEncoder;
const QpackDecoder = qpack.QpackDecoder;

const log = std.log.scoped(.http3_handler);

/// Handles the HTTP/3 protocol logic for a single QUIC connection,
/// orchestrating the processing of streams.
/// A single instance of Http3Handler might manage multiple streams
/// on a single connection, or potentially be a per-connection object.
/// Let's assume it's per-connection for now, holding QPACK state etc.
pub const Http3Handler = struct {
    server: *Server,
    allocator: Allocator,
    router: *core_router.Router, // Need a reference to the core router
    // TODO: Add QPACK encoder and decoder instances
    // qpack_encoder: QpackEncoder,
    // qpack_decoder: QpackDecoder,
    // TODO: Add references to control streams, push streams, etc.

    pub fn init(server: *Server, allocator: Allocator, router: *core_router.Router) !*Http3Handler {
        const self = try allocator.create(Http3Handler);
        self.* = .{
            .server = server,
            .allocator = allocator,
            .router = router,
            // TODO: Initialize QPACK encoder/decoder based on negotiated settings
            // .qpack_encoder = try QpackEncoder.init(...),
            // .qpack_decoder = try QpackDecoder.init(...),
        };
        // @compileError("Unimplemented: Http3Handler init"); // Remove compile error

        // TODO: Initialize control streams and send initial SETTINGS frame
        // try self.initControlStreams(); // Unimplemented

        return self; // Placeholder return
    }

    pub fn deinit(self: *Http3Handler) void {
        log.debug("Deinitializing Http3Handler", .{});
        // TODO: Deinitialize QPACK encoder/decoder
        // self.qpack_encoder.deinit();
        // self.qpack_decoder.deinit();
        // TODO: Clean up control streams etc.
        self.allocator.destroy(self);
    }

    /// This function is the entry point for handling a newly opened QUIC stream
    /// that is intended to carry HTTP/3 traffic. It should determine the stream type
    /// and delegate to the appropriate handler logic (e.g., request/response, control, QPACK).
    /// This function might spawn a new fiber for request/response streams.
    pub fn handleNewStream(self: *Http3Handler, stream: *QuicStream) anyerror!void {
        log.info("Handling new HTTP/3 stream {d} (type: {})", .{ stream.stream_id, stream.stream_type });

        switch (stream.stream_type) {
            .control => {
                // TODO: Handle control stream logic. This stream receives SETTINGS, GOAWAY, etc.
                // It's usually managed by the connection handler or the Http3Handler itself.
                // It will have its own read loop processing control frames.
                log.warn("Control stream handling unimplemented", .{});
                return Http3Error.Unimplemented;
            },
            .push => {
                // TODO: Handle server push streams (if enabled and implemented).
                log.warn("Push stream handling unimplemented", .{});
                return Http3Error.Unimplemented;
            },
            .encoder => {
                // TODO: Handle QPACK encoder stream. Data received here updates the decoder\'s view.
                log.warn("QPACK encoder stream handling unimplemented", .{});
                // Delegate incoming data to the connection\'s QPACK decoder
                // try self.qpack_decoder.handleEncoderStreamData(stream); // Needs access to stream data
                return Http3Error.Unimplemented;
            },
            .decoder => {
                // TODO: Handle QPACK decoder stream. Data received here updates the encoder\'s view.
                log.warn("QPACK decoder stream handling unimplemented", .{});
                // Delegate incoming data to the connection\'s QPACK encoder
                // try self.qpack_encoder.handleDecoderStream(stream); // Needs access to stream data
                return Http3Error.Unimplemented;
            },
            // Standard bidirectional streams (request/response) have stream_type == null
            null => {
                // This is likely a standard request/response stream.
                // Spawn a fiber to handle the request/response lifecycle on this stream.
                // The fiber will read frames, build the request, process it, and send the response.
                log.debug("Spawning handler for request stream {d}", .{stream.stream_id});
                _ = self.server.async_io.?.spawnTask(self.handleRequestStream, .{ self, stream }) catch |err| {
                    log.err("Failed to spawn task for request stream {d}: {}", .{ stream.stream_id, err });
                    stream.closeWrite() catch {}; // Attempt to close the stream on error
                    return err;
                };
                return; // Task spawned successfully
            },
        }
    }

    /// Handles the lifecycle of a single HTTP/3 request/response on a bidirectional stream.
    /// This function runs as a separate task/fiber per request stream.
    fn handleRequestStream(self: *Http3Handler, stream: *QuicStream) anyerror!void {
        _ = self;
        log.debug("Handler task started for stream {d}", .{stream.stream_id});

        var req: ?Request = null;
        var res: ?Response = null;
        var ctx: ?Context = null;

        defer {
            if (ctx) |*c| c.deinit();
            if (res) |*r| r.deinit();
            if (req) |*rq| rq.deinit();
        }

        // TODO: Implement the core request/response processing loop:
        // 1. Read frames from the stream using stream.handleReadData or a similar mechanism
        //    until a complete HEADERS frame is received, followed by any DATA frames.
        //    The stream object should manage buffering and frame parsing internally.
        // 2. Once a complete HTTP Request has been assembled from the stream data:
        //    var request = try stream.parseRequest(); // Needs implementation in stream.zig
        //    req = request;

        // 3. Create Response and Context objects:
        //    res = try Response.init(self.allocator);
        //    ctx = try Context.init(self.allocator, self.server.options.app_context_ptr, &req.?, &res.?);

        // 4. Apply middleware and route the request:
        //    // Use the core router, which handles middleware and handler dispatch
        //    try self.router.handleRequest(&ctx.?, &req.?, &res.?);

        // 5. Send the response back on the stream:
        //    // The stream should handle serializing the Response into HTTP/3 frames
        //    try stream.sendResponse(&res.?); // Needs implementation in stream.zig

        // 6. Close the stream (write side) after sending the response:
        //    try stream.closeWrite();

        // 7. Handle errors during processing (parsing, routing, handling, sending).
        //    On error, send an appropriate HTTP/3 error response or reset the stream.
        //    log.err("Error handling stream {d}: {}", .{stream.stream_id, err});
        //    stream.handleResetStream(...) or connection.asyncClose(...)

        log.warn("Request stream handling logic unimplemented for stream {d}", .{stream.stream_id});
        return Http3Error.Unimplemented; // Placeholder
    }

    // TODO: Add methods for handling specific control frames if needed, e.g.:
    // pub fn handleSettings(self: *Http3Handler, settings: types.Settings) anyerror!void { ... }
    // pub fn handleGoaway(self: *Http3Handler, stream_id: u62) anyerror!void { ... }
};
