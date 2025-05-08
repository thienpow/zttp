// src/http3/stream.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

// Import types from within the http3 module
const types = @import("types.zig");
const Frame = types.Frame;
const FrameType = types.FrameType;
const StreamType = types.StreamType;

const http3_error = @import("error.zig"); // Corrected import name
const Http3Error = http3_error.Http3Error;
const ErrorCode = http3_error.ErrorCode;

const settings = @import("settings.zig");
const Settings = settings.Settings;

// Import frame parsing/serialization functions
const frame_utils = @import("frame.zig");
const readFrame = frame_utils.readFrame; // Used internally
const writeFrame = frame_utils.writeFrame; // Used internally

// Import QPACK types
const qpack = @import("qpack/mod.zig");
const QpackEncoder = qpack.QpackEncoder;
const QpackDecoder = qpack.QpackDecoder;

// Forward declaration for connection struct to avoid circular dependency
const QuicConnection = @import("connection.zig").QuicConnection;

// Other necessary imports from core and http
const Request = @import("../http/request.zig").Request;
const Response = @import("../http/response.zig").Response;
const Context = @import("../core/context.zig").Context;
const HandlerFn = @import("../core/router.zig").HandlerFn;
const NextFn = @import("../core/router.zig").NextFn;

// Placeholder for the Http3Handler, needed to pass requests for processing
const Http3Handler = @import("handler.zig").Http3Handler;

const log = std.log.scoped(.http3_stream);

/// Represents a single HTTP/3 stream within a QUIC connection.
/// HTTP/3 streams are built on top of QUIC streams, providing
/// ordered, reliable byte streams. HTTP/3 frames are sent over these.
pub const QuicStream = struct {
    allocator: Allocator,
    /// A reference to the parent QUIC connection.
    connection: *QuicConnection,
    /// The underlying QUIC stream ID.
    stream_id: u64,
    /// The type of HTTP/3 stream (control, push, encoder, decoder) or if it's a request/response stream.
    /// Note: Request/response streams don't have an explicit type ID like control streams,
    /// but it's useful to know if it's a bidirectional stream used for requests/responses.
    /// Maybe this field indicates if it's a special stream type or a standard bidirectional stream.
    stream_type: ?StreamType, // Null for standard request/response streams? Or maybe a different enum?

    /// Current state of the HTTP/3 stream processing (e.g., waiting for HEADERS, receiving DATA).
    state: State,

    /// Buffer for incoming data that hasn't been fully processed into HTTP/3 frames yet.
    read_buffer: std.ArrayList(u8),

    /// State for parsing incoming HTTP/3 frames and messages.
    /// This would track the state of reading frame headers, payloads,
    /// and assembling a complete HTTP request.
    parser_state: ParserState,

    /// Placeholder for the incoming HTTP request being parsed.
    /// This is populated once HEADERS and potentially initial DATA frames are received.
    request: ?Request,

    /// Placeholder for the outgoing HTTP response to be serialized and sent.
    /// This is set by the Http3Handler after the application handler completes.
    response: ?Response,

    pub const State = enum {
        /// Stream is newly created, no data exchanged yet.
        idle,
        /// Stream is open and actively processing data.
        open, // Can be in read or write states
        /// Stream is receiving data and parsing frames (HEADERS, DATA, etc.).
        receiving,
        /// A complete request has been received and is being processed by the handler.
        processing,
        /// Sending response data.
        sending,
        /// Local side has sent FIN or equivalent, waiting for peer FIN.
        half_closed_local,
        /// Remote side has sent FIN or equivalent, waiting for local FIN.
        half_closed_remote,
        /// Both sides have closed the stream.
        closed,
        /// Error occurred on this stream.
        errored,
    };

    // State machine for parsing incoming data into frames and then into a request
    pub const ParserState = enum {
        /// Waiting for the start of a new frame (reading type and length).
        waiting_for_frame_header,
        /// Reading the payload of the current frame.
        reading_frame_payload,
        /// Waiting for the full HEADERS frame to parse the request line and headers.
        waiting_for_headers,
        /// Reading DATA frames for the request body.
        reading_body,
        /// Parsing complete, ready to dispatch the request.
        request_complete,
    };

    pub fn init(allocator: Allocator, connection: *QuicConnection, stream_id: u64, stream_type: ?StreamType) !*QuicStream {
        const self = try allocator.create(QuicStream);
        self.* = .{
            .allocator = allocator,
            .connection = connection,
            .stream_id = stream_id,
            .stream_type = stream_type,
            .state = .idle,
            .read_buffer = std.ArrayList(u8).init(allocator),
            .parser_state = .waiting_for_frame_header,
            .request = null,
            .response = null,
        };

        log.debug("Initialized HTTP/3 stream {d} (Type: {}, QUIC ID: {})", .{ stream_id, stream_type, stream_id });

        // For standard bidirectional streams, the first frame is expected to be HEADERS.
        // For control streams, the first frame is typically SETTINGS.
        // This initial state management needs to be refined based on stream_type.
        if (stream_type == null) {
            self.parser_state = .waiting_for_headers; // Expect HEADERS first on a request stream
        } else if (stream_type == .control) {
            // Control stream might expect SETTINGS first
            self.parser_state = .waiting_for_frame_header; // Or a more specific control frame state
        }

        return self;
    }

    pub fn deinit(self: *QuicStream) void {
        log.debug("Deinitializing HTTP/3 stream {d}", .{self.stream_id});
        self.read_buffer.deinit();
        if (self.request) |*req| req.deinit();
        if (self.response) |*res| res.deinit();
        // TODO: Clean up any other allocated resources specific to this stream.
        self.allocator.destroy(self); // Free the struct itself
    }

    /// Handles incoming raw data from the underlying QUIC stream.
    /// This data needs to be buffered and then parsed into HTTP/3 frames.
    /// This function is called by the QuicConnection when data arrives for this stream.
    pub fn handleReadData(self: *QuicStream, data: []const u8, is_fin: bool) anyerror!void {
        log.debug("Stream {d}: handleReadData({d} bytes, fin: {}) in state {}, parser state {}", .{ self.stream_id, data.len, is_fin, @tagName(self.state), @tagName(self.parser_state) });

        // Append incoming data to the buffer
        try self.read_buffer.appendSlice(data);

        // Attempt to parse frames from the buffer
        var reader = std.io.Buffer.init(self.read_buffer.items).reader();

        while (true) {
            // Need to make sure we have enough data for a frame header (type + length)
            // Variable length integers can be up to 8 bytes each.
            // Minimum frame header size is 2 bytes (1-byte type, 1-byte length=0).
            // So we need at least 2 bytes to even attempt reading a frame header.
            if (reader.bytesLeft() < 2) break; // Need more data for the next potential header

            // Try to read the next frame
            const frame_result = readFrame(self.allocator, &reader);
            switch (frame_result) {
                .{} => |parsed_frame| {
                    // Successfully parsed a frame
                    try self.handleFrame(parsed_frame); // Process the frame
                    parsed_frame.deinit(self.allocator); // Deinit frame if it allocated payload
                    // Keep parsing if more data is in the buffer
                    self.parser_state = .waiting_for_frame_header; // Reset state for next frame read attempt
                },
                http3_error.NeedMoreData => { // Corrected error reference
                    // Not enough data for a full frame yet.
                    // Keep the remaining data in the buffer and wait for more.
                    self.parser_state = .reading_frame_payload; // Indicate we are reading a frame payload
                    break; // Exit parsing loop
                },
                else => |err| {
                    // Error parsing frame
                    log.err("Stream {d}: Failed to parse frame: {}", .{ self.stream_id, err });
                    // According to spec, frame parsing errors are connection errors
                    try self.connection.asyncClose(.frame_error);
                    return err; // Propagate error
                },
            }
            // After parsing a frame, we should check if we reached a state to dispatch the request
            if (self.parser_state == .request_complete) {
                try self.dispatchRequestToHandler();
                // After dispatching, we might transition to a new state (e.g., sending response)
                // and stop parsing incoming frames for the request body.
                // Additional incoming frames might be trailers or unexpected, handle based on state.
                break; // Exit parsing loop after dispatch
            }
        }

        // Update the read buffer to remove consumed bytes
        const bytes_consumed = reader.pos; // How many bytes the reader advanced
        if (bytes_consumed > 0) {
            // Create a new ArrayList with remaining data and replace the old one
            var remaining_data = try std.ArrayList(u8).initCapacity(self.allocator, self.read_buffer.items.len - bytes_consumed);
            try remaining_data.appendSlice(self.read_buffer.items[bytes_consumed..]);
            self.read_buffer.deinit(); // Deinit the old buffer
            self.read_buffer = remaining_data; // Replace with the new buffer
        }

        // Handle FIN bit from QUIC layer
        if (is_fin) {
            log.debug("Stream {d}: Received FIN", .{self.stream_id});
            self.state = .half_closed_remote;
            // TODO: Check if receiving side is now fully closed and notify handler/connection.
            // If this was the end of the request body, and we were waiting for it,
            // the request is now complete.
            if (self.parser_state == .reading_body) {
                self.parser_state = .request_complete;
                try self.dispatchRequestToHandler(); // Dispatch if not already
            } else if (self.parser_state != .request_complete) {
                // FIN received unexpectedly before request was fully parsed.
                log.err("Stream {d}: Received FIN unexpectedly in parser state {}", .{ self.stream_id, @tagName(self.parser_state) });
                try self.connection.asyncClose(.stream_creation_error); // Or other relevant error
                return Http3Error.ProtocolError;
            }
        }
    }

    /// Processes a fully parsed HTTP/3 frame received on this stream.
    /// This is where the HTTP/3 protocol logic per stream would go.
    fn handleFrame(self: *QuicStream, frame: Frame) anyerror!void {
        // TODO: @unionToTag is invalid builtin function, please look for a valid alternative
        // log.debug("Stream {d}: handleFrame({}) in parser state {}, stream type {}", .{ self.stream_id, @tagName(@unionToTag(frame)), @tagName(self.parser_state), self.stream_type });

        // Logic depends on stream type and current parser state
        switch (self.stream_type) {
            .control => {
                // Handle frames specific to the control stream
                switch (@unionToTag(frame)) {
                    .settings => {
                        log.debug("Stream {d} (Control): Processing SETTINGS frame", .{self.stream_id});
                        // TODO: Parse and apply settings to the connection or server.
                        // Use settings.parse(self.allocator, frame.settings.payload)
                        // try self.connection.applySettings(&frame.settings);
                        return http3_error.Unimplemented; // Placeholder
                    },
                    .goaway => {
                        log.info("Stream {d} (Control): Received GOAWAY frame, stream ID {}", .{ self.stream_id, frame.goaway.stream_id });
                        // TODO: Handle GOAWAY frame - initiate connection shutdown.
                        // The connection should be notified to stop accepting new streams and close gracefully.
                        // try self.connection.asyncClose(.goaway); // Example, need to use the stream_id in the GOAWAY frame
                        return http3_error.Unimplemented; // Placeholder
                    },
                    .max_push_id => {
                        log.debug("Stream {d} (Control): Received MAX_PUSH_ID frame with push ID {}", .{ self.stream_id, frame.max_push_id.push_id });
                        // Update the maximum Push ID the client is willing to accept.
                        // This is relevant for server push implementation.
                        return http3_error.Unimplemented; // Placeholder
                    },
                    // TODO: Handle other control frames (e.g., H3_DATAGRAM)

                    // Reserved or unexpected frames on control stream are protocol errors
                    inline else => {
                        log.err("Stream {d}: Received unexpected frame type {} on control stream", .{ self.stream_id, @tagName(@unionToTag(frame)) });
                        try self.connection.asyncClose(.frame_unexpected);
                        return Http3Error.FrameUnexpected;
                    },
                }
            },
            .push => {
                // Handle frames on a server push stream (unidirectional from server to client)
                // The server initiates this stream. It carries a PUSH_PROMISE frame first (client receives),
                // followed by HEADERS and DATA frames for the pushed resource (client receives).
                log.warn("Push stream handling unimplemented for stream {}", .{self.stream_id});
                // TODO: Implement server push logic if needed.
                try self.connection.asyncClose(.unimplemented); // Close stream if push is not supported
                return http3_error.Unimplemented; // Placeholder
            },
            .encoder => {
                // Handle frames on the QPACK encoder stream (unidirectional)
                // This stream carries QPACK encoder instructions (client to server).
                log.debug("Stream {d}: Handling QPACK encoder stream data", .{self.stream_id});
                // Pass the raw payload data to the connection's QPACK decoder.
                if (self.connection.qpack_decoder) |decoder| {
                    try decoder.handleDecoderStreamData(frame.data.payload); // Assuming DATA frame on encoder stream
                } else {
                    log.err("Stream {d}: Received encoder stream data but no QPACK decoder!", .{self.stream_id});
                    try self.connection.asyncClose(.protocol_error);
                    return Http3Error.ProtocolError;
                }
                return; // Handled by QPACK decoder
            },
            .decoder => {
                // Handle frames on the QPACK decoder stream (unidirectional)
                // This stream carries QPACK decoder instructions (server to client).
                log.debug("Stream {d}: Handling QPACK decoder stream data", .{self.stream_id});
                // Pass the raw payload data to the connection's QPACK encoder.
                if (self.connection.qpack_encoder) |encoder| {
                    try encoder.handleDecoderStream(frame.data.payload); // Assuming DATA frame on decoder stream
                } else {
                    log.err("Stream {d}: Received decoder stream data but no QPACK encoder!", .{self.stream_id});
                    try self.connection.asyncClose(.protocol_error);
                    return Http3Error.ProtocolError;
                }
                return; // Handled by QPACK encoder
            },
            null => { // Standard bidirectional stream (likely request/response)
                switch (self.parser_state) {
                    .waiting_for_headers => {
                        // Expecting the initial HEADERS frame for a request
                        switch (@unionToTag(frame)) {
                            .headers => {
                                log.debug("Stream {d}: Processing initial HEADERS frame", .{self.stream_id});
                                // TODO: Decode headers using QPACK (from self.connection.qpack_decoder)
                                // Create a Request struct from headers (including method, path, authority).
                                if (self.connection.qpack_decoder) |decoder| {
                                    var headers = try decoder.decodeHeaders(frame.headers.encoded_block);
                                    // TODO: Use headers to create the Request object
                                    // self.request = try Request.init(self.allocator, headers, ...);
                                    // headers.deinit(); // Deinit the HeaderMap once used by Request

                                    // Determine if a request body is expected based on method/headers
                                    // if request_has_body:
                                    //     self.parser_state = .reading_body; // Next expect DATA frames
                                    // else:
                                    //     self.parser_state = .request_complete; // Request complete, no body
                                    self.parser_state = .request_complete; // Simplified for now
                                    log.info("Stream {d}: Request HEADERS received, ready to process (simplified)", .{self.stream_id});
                                } else {
                                    log.err("Stream {d}: Received HEADERS frame but no QPACK decoder!", .{self.stream_id});
                                    try self.connection.asyncClose(.protocol_error);
                                    return Http3Error.ProtocolError;
                                }
                                return http3_error.Unimplemented; // Placeholder

                            },
                            .settings, .goaway, .max_push_id, .cancel_push, .duplicate_push => {
                                // These frames are not expected before the initial HEADERS on a request stream.
                                log.err("Stream {d}: Received unexpected frame type {} before HEADERS frame", .{ self.stream_id, @tagName(@unionToTag(frame)) });
                                try self.connection.asyncClose(.frame_unexpected); // Protocol error
                                return Http3Error.FrameUnexpected;
                            },
                            .data => {
                                // DATA frame before HEADERS is a protocol error on a request stream.
                                log.err("Stream {d}: Received DATA frame before HEADERS frame", .{self.stream_id});
                                try self.connection.asyncClose(.frame_unexpected); // Protocol error
                                return Http3Error.FrameUnexpected;
                            },
                            .reserved => {
                                // Ignore reserved frames as per spec.
                                log.debug("Stream {d}: Ignoring reserved frame type {} while waiting for headers", .{ self.stream_id, @toU64(@unionToTag(frame)) });
                                return; // Do not return an error, just ignore
                            },
                            else => {
                                // Received an unknown frame type to start a stream.
                                log.err("Stream {d}: Received unknown frame type {} to start stream", .{ self.stream_id, @toU64(@unionToTag(frame)) });
                                try self.connection.asyncClose(.frame_unexpected); // Protocol error
                                return Http3Error.FrameUnexpected;
                            },
                        }
                    },
                    .reading_body => {
                        // Expecting DATA frames for the request body or possibly trailer HEADERS
                        switch (@unionToTag(frame)) {
                            .data => {
                                log.debug("Stream {d}: Processing DATA frame, payload len: {d}", .{ self.stream_id, frame.data.payload.len });
                                // TODO: Append data payload to request body buffer in self.request.body.
                                // Ensure Request struct has a mechanism to handle streaming body data.
                                return http3_error.Unimplemented; // Placeholder
                            },
                            .headers => {
                                // This could be trailer headers after the body.
                                log.debug("Stream {d}: Processing trailer HEADERS frame", .{self.stream_id});
                                // TODO: Decode and process trailer headers using QPACK.
                                // Append to the request headers or store separately.
                                // After processing trailers, the request is complete.
                                self.parser_state = .request_complete;
                                log.info("Stream {d}: Trailer HEADERS received, request complete", .{self.stream_id});
                                // Request is now fully parsed, ready for dispatch.
                                return http3_error.Unimplemented; // Placeholder
                            },
                            .reserved => {
                                // Ignore reserved frames as per spec.
                                log.debug("Stream {d}: Ignoring reserved frame type {} while reading body", .{ self.stream_id, @toU64(@unionToTag(frame)) });
                                return; // Do not return an error, just ignore
                            },
                            else => {
                                // Received an unexpected frame type while reading body.
                                log.err("Stream {d}: Received unexpected frame type {} while reading body", .{ self.stream_id, @tagName(@unionToTag(frame)) });
                                try self.connection.asyncClose(.frame_unexpected); // Protocol error
                                return Http3Error.FrameUnexpected;
                            },
                        }
                    },
                    .request_complete => {
                        // Should not receive frames after the request is complete, unless it's a late frame.
                        // DATA or HEADERS after request complete (without being trailers) is an error.
                        switch (@unionToTag(frame)) {
                            .data, .headers => {
                                log.err("Stream {d}: Received DATA or HEADERS frame after request complete", .{self.stream_id});
                                try self.connection.asyncClose(.frame_unexpected); // Protocol error
                                return Http3Error.FrameUnexpected;
                            },
                            .reserved => {
                                // Ignore reserved frames as per spec.
                                log.debug("Stream {d}: Ignoring reserved frame type {} after request complete", .{ self.stream_id, @toU64(@unionToTag(frame)) });
                                return; // Do not return an error, just ignore
                            },
                            else => {
                                log.warn("Stream {d}: Received unexpected frame type {} after request complete, ignoring", .{ self.stream_id, @tagName(@unionToTag(frame)) });
                                // Treat as ignorable if not explicitly an error frame? Check spec.
                                return; // For now, ignore
                            },
                        }
                    },
                    .processing, .sending, .half_closed_local, .half_closed_remote, .closed, .errored => {
                        // Should not receive frames that affect the request parsing state machine in these states.
                        // Some control frames (GOAWAY, RESET_STREAM, STOP_SENDING) might be received,
                        // but they apply to the connection or the stream state, not the parser state.
                        // These are generally handled by handleReadData or the connection's event loop.
                        log.warn("Stream {d}: Received frame {} in unexpected parser state {} while in stream state {}, ignoring frame for parser.", .{ self.stream_id, @tagName(@unionToTag(frame)), @tagName(self.parser_state), @tagName(self.state) });
                        // Do not return an error just for parser state, let the stream/connection state handle it.
                        return; // Ignore frame for parser state machine
                    },
                }
            },
            // TODO: Add handling for WEBTRANSPORT streams if needed
            // .webtransport => { ... }

            else => {
                // Received a frame on a stream type that is not yet handled (e.g., WEBTRANSPORT_STREAM)
                log.warn("Stream {d}: Received frame {} on unhandled stream type {}", .{ self.stream_id, @tagName(@unionToTag(frame)), self.stream_type });
                // Depending on spec/requirements, might close the stream or ignore.
                return http3_error.Unimplemented; // Placeholder
            },
        }
    }

    /// Dispatches the complete HTTP/3 request to the Http3Handler.
    /// This is called after the request (headers and body) is fully parsed.
    fn dispatchRequestToHandler(self: *QuicStream) anyerror!void {
        // Ensure the request is actually complete and available
        if (self.parser_state != .request_complete or self.request == null) {
            log.err("Stream {d}: Attempted to dispatch incomplete request!", .{self.stream_id});
            try self.connection.asyncClose(.internal_error);
            return Http3Error.InternalError; // Or Http3Error.InvalidStreamState
        }

        log.debug("Stream {d}: Dispatching request to handler", .{self.stream_id});

        // TODO: Get the Http3Handler instance (likely owned by the server or connection)
        // and call its processRequest method.
        // The processRequest method will run middleware and the route handler.
        // It will modify self.response.

        // Placeholder call (requires Http3Handler instance and proper Request object):
        // Assume Http3Handler is stored somewhere accessible, e.g., in the Server struct
        // var handler = self.connection.server.http3_handler; // Example access
        // try handler.processRequest(self, self.request.?); // Assuming self.request is populated and valid

        // After the handler call completes, the response should be populated in self.response.
        // Transition state to sending and begin sending the response.
        self.state = .processing; // Indicate handler is working

        // TODO: After the handler finishes (need async/await or task completion):
        // self.state = .sending; // Transition state
        // try self.sendResponse(self.response.?); // Send the response

        // Since the handler runs asynchronously, this function might just schedule the handler task
        // and return, or it might await the handler completion.
        // For now, it's a placeholder for the coordination logic.
        return http3_error.Unimplemented; // Placeholder
    }

    /// Sends raw data on the underlying QUIC stream.
    /// This data is typically HTTP/3 frames or parts of them.
    pub fn writeData(self: *QuicStream, data: []const u8) anyerror!void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Attempted to write data in state {}", .{ self.stream_id, @tagName(self.state) });
            return Http3Error.InvalidStreamState; // Cannot write in this state
        }
        log.debug("Stream {d}: writeData({d} bytes)", .{ self.stream_id, data.len });
        // TODO: Pass this data to the underlying QUIC connection to be sent.
        // The connection will handle QUIC stream framing and sending over UDP.
        // Note: `sendStreamData` in connection.zig currently returns error.Unimplemented.
        return self.connection.sendStreamData(self.stream_id, data, false); // is_fin=false for chunks
    }

    /// Sends the final chunk of data and signals the end of the stream from this side.
    pub fn writeDataAndEnd(self: *QuicStream, data: []const u8) anyerror!void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Attempted to write data and end in state {}", .{ self.stream_id, @tagName(self.state) });
            return Http3Error.InvalidStreamState; // Cannot write in this state
        }
        log.debug("Stream {d}: writeDataAndEnd({d} bytes)", .{ self.stream_id, data.len });
        // TODO: Pass this data to the underlying QUIC connection to be sent with the FIN flag.
        // The connection will handle QUIC stream framing and sending over UDP.
        return self.connection.sendStreamData(self.stream_id, data, true); // is_fin=true
    }

    /// Called by the Http3Handler to send an HTTP Response on this stream.
    /// This is the entry point from the application logic back to the HTTP/3 framing layer.
    pub fn sendResponse(self: *QuicStream, response: *Response) anyerror!void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Attempted to send response in state {}", .{ self.stream_id, @tagName(self.state) });
            return Http3Error.InvalidStreamState; // Cannot send response in this state
        }

        log.debug("Stream {d}: sendResponse", .{self.stream_id});
        self.response = response; // Store the response object

        // TODO: Serialize the Response struct into HTTP/3 frames (HEADERS, DATA, etc.)
        // This will involve:
        // 1. Creating HEADERS frame payload using QPACK encoder (from self.connection.qpack_encoder).
        // 2. Writing the HEADERS frame using `frame.writeFrame` to a buffer.
        // 3. Writing DATA frames for the response body using `frame.writeFrame` to a buffer.
        // 4. Writing trailer HEADERS frames if any.
        // 5. Signaling the end of the stream (FIN) after the last frame.

        // Use a buffer or writer to serialize frames
        var response_buffer = std.ArrayList(u8).init(self.allocator);
        const writer = response_buffer.writer();
        _ = writer;

        // Example flow for serializing HEADERS and DATA
        // try writer.writeAll(try frame.serializeFrame(self.allocator, headers_frame)); // Serialize and write HEADERS frame bytes

        // For response body:
        // var body_reader = response.body.reader();
        // var body_chunk_buffer = try self.allocator.alloc(u8, 4096); // Example chunk size
        // defer self.allocator.free(body_chunk_buffer);
        // while (true) {
        //      var bytes_read = try body_reader.read(body_chunk_buffer);
        //      if (bytes_read == 0) break; // End of body
        //
        //      var data_frame = Frame{ .type = .data, .data = .{ .payload = body_chunk_buffer[0..bytes_read] } };
        //      try writer.writeAll(try frame.serializeFrame(self.allocator, data_frame)); // Serialize and write DATA frame bytes
        // }

        // TODO: After serializing frames to the buffer, write the buffer content to the QUIC stream.
        // try self.writeDataAndEnd(response_buffer.items); // Send all buffered data with FIN

        response_buffer.deinit(); // Clean up serialization buffer

        self.state = .sending; // Update state

        return http3_error.Unimplemented; // Placeholder
    }

    /// Initiate a graceful closure of the stream from the local side (sending FIN).
    /// Called when the local side has finished sending data.
    pub fn closeWrite(self: *QuicStream) anyerror!void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Attempted to close write side in state {}", .{ self.stream_id, @tagName(self.state) });
            return Http3Error.InvalidStreamState; // Cannot close write in this state
        }
        log.debug("Stream {d}: closing write side", .{self.stream_id});
        // TODO: Signal the underlying QUIC stream to close the write side.
        // This typically involves sending a stream frame with the FIN bit set.
        try self.connection.sendStreamData(self.stream_id, &.{}, true); // Send FIN with no data
        self.state = .half_closed_local; // Update state

        // TODO: Check if both sides are now closed and initiate full stream deinitialization.
        // If self.state is .half_closed_remote, and we just set it to .half_closed_local,
        // then both sides are closed. Trigger deinit.
        // if (self.state == .half_closed_remote) { self.connection.closeStream(self.stream_id); } // Example

        return http3_error.Unimplemented; // Placeholder, remove once implemented
    }

    /// A peer initiated a graceful closure of the stream by sending a STOP_SENDING frame.
    /// Called by the QuicConnection when a STOP_SENDING frame is received for this stream.
    pub fn handleStopSending(self: *QuicStream, error_code: u64) anyerror!void {
        log.debug("Stream {d}: received STOP_SENDING with code {}", .{ self.stream_id, error_code });
        // TODO: Handle STOP_SENDING frame from peer.
        // This typically means the peer is no longer interested in receiving data on this stream.
        // You should stop sending data and close the write side if not already.
        try self.closeWrite();
        self.state = .half_closed_remote; // Update state if not already
        // TODO: Signal handler/application that sending is stopped.
        return; // Success
    }

    /// A peer wishes to reset this stream, potentially due to an error.
    /// Called by the QuicConnection when a RESET_STREAM frame is received for this stream.
    pub fn handleResetStream(self: *QuicStream, error_code: u64) anyerror!void {
        log.info("Stream {d}: received RESET_STREAM with code {}", .{ self.stream_id, error_code });
        // TODO: Handle RESET_STREAM frame from peer.
        // This indicates a terminal error on the stream.
        // You should cease all activity on this stream and transition to a closed or errored state.
        self.state = .errored; // Update state
        // TODO: Signal the connection to clean up the stream resources immediately.
        // self.connection.closeStream(self.stream_id); // Example call to connection
        return; // Success
    }

    // TODO: Add other stream-specific logic:
    // - Managing request body buffering
    // - State for parsing different parts of the HTTP/3 message
    // - State for serializing different parts of the HTTP/3 message
    // - Interaction with QPACK encoder/decoder instances (via connection)
};
