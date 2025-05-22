// src/http3/stream.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("types.zig");
const Frame = types.Frame;
const FrameType = types.FrameType;
const StreamType = types.StreamType;
const Http3Error = types.Http3Error;

const ErrorCode = @import("error.zig").ErrorCode;

const frame_utils = @import("frame.zig");
const readFrame = frame_utils.readFrame;
const writeFrame = frame_utils.writeFrame;

const QpackEncoder = @import("qpack/encoder.zig").QpackEncoder;
const QpackDecoder = @import("qpack/decoder.zig").QpackDecoder;

const Http3Connection = @import("connection.zig").Http3Connection;
const Http3Handler = @import("handler.zig").Http3Handler;

const Request = @import("../http/request.zig").Request;
const Response = @import("../http/response.zig").Response;
const HeaderMap = @import("../http/header_map.zig").HeaderMap;

const log = std.log.scoped(.http3_stream);

/// Represents an HTTP/3 stream over a QUIC stream.
pub const Http3Stream = struct {
    allocator: Allocator,
    connection: *Http3Connection,
    stream_id: u64,
    stream_type: ?StreamType,
    state: State,
    read_buffer: std.ArrayList(u8),
    body_buffer: std.ArrayList(u8),
    parser_state: ParserState,
    request: ?Request,
    response: ?Response,

    pub const State = enum {
        idle,
        open,
        receiving,
        processing,
        sending,
        half_closed_local,
        half_closed_remote,
        closed,
        errored,
    };

    pub const ParserState = enum {
        waiting_for_frame_header,
        reading_frame_payload,
        waiting_for_headers,
        reading_body,
        request_complete,
    };

    pub fn init(connection: *Http3Connection, stream_id: u64, stream_type: ?StreamType) !*Http3Stream {
        const self = try connection.allocator.create(Http3Stream);
        self.* = .{
            .allocator = connection.allocator,
            .connection = connection,
            .stream_id = stream_id,
            .stream_type = stream_type,
            .state = .idle,
            .read_buffer = std.ArrayList(u8).init(connection.allocator),
            .body_buffer = std.ArrayList(u8).init(connection.allocator),
            .parser_state = if (stream_type == null) .waiting_for_headers else .waiting_for_frame_header,
            .request = null,
            .response = null,
        };
        log.debug("Initialized stream {d} (type: {?})", .{ stream_id, stream_type });
        return self;
    }

    pub fn deinit(self: *Http3Stream) void {
        log.debug("Deinitializing stream {d}", .{self.stream_id});
        self.read_buffer.deinit();
        self.body_buffer.deinit();
        if (self.request) |*req| req.deinit();
        if (self.response) |*res| res.deinit();
        self.allocator.destroy(self);
    }

    pub fn handleReadData(self: *Http3Stream, data: []const u8, is_fin: bool) !void {
        log.debug("Stream {d}: Handling {d} bytes (fin: {})", .{ self.stream_id, data.len, is_fin });
        try self.read_buffer.appendSlice(data);
        self.state = .receiving;

        while (self.read_buffer.items.len > 0) {
            var stream = std.io.FixedBufferStream([]u8){ .buffer = self.read_buffer.items, .pos = 0 };
            const reader = stream.reader();

            if (self.parser_state == .waiting_for_frame_header and self.read_buffer.items.len < 2) break;

            const frame_result = readFrame(self.allocator, reader);
            const consumed = stream.pos;

            const frame = frame_result catch |err| {
                if (err == Http3Error.NeedMoreData) {
                    self.parser_state = .reading_frame_payload;
                    break;
                }
                log.err("Stream {d}: Frame parse error: {}", .{ self.stream_id, err });
                try self.connection.asyncClose(.frame_error);
                return err;
            };

            try self.handleFrame(frame);
            frame.deinit(self.allocator);
            self.parser_state = .waiting_for_frame_header;
            if (self.parser_state == .request_complete) {
                try self.dispatchRequestToHandler();
                break;
            }

            self.read_buffer.shrinkAndFree(self.read_buffer.items.len - consumed);
            if (consumed > 0 and self.read_buffer.items.len > 0) {
                std.mem.copyForwards(u8, self.read_buffer.items, self.read_buffer.items[consumed..]);
            }
        }

        if (is_fin) {
            self.state = .half_closed_remote;
            switch (self.parser_state) {
                .waiting_for_headers, .waiting_for_frame_header, .reading_frame_payload => {
                    log.err("Stream {d}: FIN received in invalid state {}", .{ self.stream_id, self.parser_state });
                    try self.connection.asyncClose(.protocol_error);
                    return Http3Error.ProtocolError;
                },
                .reading_body => {
                    self.parser_state = .request_complete;
                    try self.dispatchRequestToHandler();
                },
                .request_complete => {},
            }
            if (self.state == .half_closed_local) self.state = .closed;
        }
    }

    fn methodExpectsBody(method: []const u8) bool {
        return std.mem.eql(u8, method, "POST") or std.mem.eql(u8, method, "PUT") or std.mem.eql(u8, method, "PATCH");
    }

    fn handleFrame(self: *Http3Stream, frame: Frame) !void {
        log.debug("Stream {d}: Handling frame {} (type: {?})", .{ self.stream_id, frame, self.stream_type });

        if (self.stream_type) |stream_type| {
            switch (stream_type) {
                .control => switch (frame) {
                    .settings => {
                        log.debug("Stream {d}: Processing SETTINGS", .{self.stream_id});
                        self.connection.settings = frame.settings;
                    },
                    .goaway => {
                        log.info("Stream {d}: GOAWAY (stream_id: {d})", .{ self.stream_id, frame.goaway.stream_id });
                        try self.connection.asyncClose(.no_error);
                    },
                    .max_push_id => {
                        log.debug("Stream {d}: MAX_PUSH_ID (id: {d})", .{ self.stream_id, frame.max_push_id.push_id });
                    },
                    else => {
                        log.err("Stream {d}: Unexpected frame {} on control stream", .{ self.stream_id, frame });
                        try self.connection.asyncClose(.frame_unexpected);
                        return Http3Error.FrameUnexpected;
                    },
                },
                .push => {
                    log.err("Stream {d}: Push streams not supported", .{self.stream_id});
                    try self.connection.asyncClose(.protocol_error);
                    return Http3Error.ProtocolError;
                },
                .encoder => switch (frame) {
                    .data => if (self.connection.qpack_decoder) |decoder| {
                        try decoder.processInstructions(frame.data.payload);
                    } else {
                        log.err("Stream {d}: No QPACK decoder", .{self.stream_id});
                        try self.connection.asyncClose(.internal_error);
                        return Http3Error.FrameError;
                    },
                    .padding, .ping => {},
                    .reserved => {},
                    else => {
                        log.err("Stream {d}: Unexpected frame {} on encoder stream", .{ self.stream_id, frame });
                        try self.connection.asyncClose(.frame_unexpected);
                        return Http3Error.FrameUnexpected;
                    },
                },
                .decoder => switch (frame) {
                    .data => if (self.connection.qpack_encoder) |encoder| {
                        try encoder.processInstructions(frame.data.payload);
                    } else {
                        log.err("Stream {d}: No QPACK encoder", .{self.stream_id});
                        try self.connection.asyncClose(.internal_error);
                        return Http3Error.FrameError;
                    },
                    .padding, .ping => {},
                    .reserved => {},
                    else => {
                        log.err("Stream {d}: Unexpected frame {} on decoder stream", .{ self.stream_id, frame });
                        try self.connection.asyncClose(.frame_unexpected);
                        return Http3Error.FrameUnexpected;
                    },
                },
                .request => {
                    log.err("Stream {d}: Request stream not expected in this context", .{self.stream_id});
                    try self.connection.asyncClose(.protocol_error);
                    return Http3Error.ProtocolError;
                },
            }
        } else {
            switch (self.parser_state) {
                .waiting_for_headers => switch (frame) {
                    .headers => {
                        const decoder = self.connection.qpack_decoder orelse {
                            log.err("Stream {d}: No QPACK decoder", .{self.stream_id});
                            try self.connection.asyncClose(.internal_error);
                            return Http3Error.FrameError;
                        };
                        const headers = try decoder.decodeHeaders(self.stream_id, frame.headers.encoded_block);
                        defer headers.deinit();

                        self.request = try Request.init(self.allocator);
                        var method: ?[]const u8 = null;
                        var it = headers.iterator();
                        while (it.next()) |entry| {
                            if (std.mem.eql(u8, entry.key_ptr.*, ":method")) {
                                try self.request.?.setMethod(entry.value_ptr.*);
                                method = entry.value_ptr.*;
                            } else if (std.mem.eql(u8, entry.key_ptr.*, ":path")) {
                                try self.request.?.setPath(entry.value_ptr.*);
                            } else {
                                try self.request.?.addHeader(entry.key_ptr.*, entry.value_ptr.*);
                            }
                        }

                        self.parser_state = if (method != null and methodExpectsBody(method.?)) .reading_body else .request_complete;
                    },
                    .data, .settings, .goaway, .max_push_id, .cancel_push, .webtransport_stream => {
                        log.err("Stream {d}: Unexpected frame {} before HEADERS", .{ self.stream_id, frame });
                        try self.connection.asyncClose(.frame_unexpected);
                        return Http3Error.FrameUnexpected;
                    },
                    .padding, .ping, .reserved => {},
                },
                .reading_body => switch (frame) {
                    .data => {
                        try self.body_buffer.appendSlice(frame.data.payload);
                        if (self.request != null) self.request.?.body = self.body_buffer.items;
                    },
                    .headers => {
                        const decoder = self.connection.qpack_decoder orelse {
                            log.err("Stream {d}: No QPACK decoder", .{self.stream_id});
                            try self.connection.asyncClose(.internal_error);
                            return Http3Error.FrameError;
                        };
                        const trailers = try decoder.decodeHeaders(frame.headers.encoded_block);
                        defer trailers.deinit();

                        var it = trailers.iterator();
                        while (it.next()) |entry| {
                            try self.request.?.addHeader(entry.key_ptr.*, entry.value_ptr.*);
                        }
                        self.parser_state = .request_complete;
                    },
                    .padding, .ping, .reserved => {},
                    else => {
                        log.err("Stream {d}: Unexpected frame {} while reading body", .{ self.stream_id, frame });
                        try self.connection.asyncClose(.frame_unexpected);
                        return Http3Error.FrameUnexpected;
                    },
                },
                .request_complete => switch (frame) {
                    .padding, .ping, .reserved => {},
                    else => {
                        log.err("Stream {d}: Unexpected frame {} after request complete", .{ self.stream_id, frame });
                        try self.connection.asyncClose(.frame_unexpected);
                        return Http3Error.FrameUnexpected;
                    },
                },
                .waiting_for_frame_header, .reading_frame_payload => {
                    log.err("Stream {d}: Invalid parser state {}", .{ self.stream_id, self.parser_state });
                    try self.connection.asyncClose(.internal_error);
                    return Http3Error.FrameError;
                },
            }
        }
    }

    fn dispatchRequestToHandler(self: *Http3Stream) !void {
        if (self.parser_state != .request_complete or self.request == null) {
            log.err("Stream {d}: Invalid dispatch state", .{self.stream_id});
            try self.connection.asyncClose(.internal_error);
            return Http3Error.FrameError;
        }
        self.state = .processing;
        if (self.connection.server.http3_handler) |handler| {
            try handler.handleNewStream(self);
        } else {
            log.err("Stream {d}: No handler available", .{self.stream_id});
            try self.connection.asyncClose(.internal_error);
            return Http3Error.FrameError;
        }
    }

    pub fn writeData(self: *Http3Stream, data: []const u8) !void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Invalid write state {}", .{ self.stream_id, self.state });
            return Http3Error.FrameError;
        }
        try self.connection.sendStreamData(self.stream_id, data, false);
    }

    pub fn writeDataAndEnd(self: *Http3Stream, data: []const u8) !void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Invalid write state {}", .{ self.stream_id, self.state });
            return Http3Error.FrameError;
        }
        try self.connection.sendStreamData(self.stream_id, data, true);
        self.state = .half_closed_local;
    }

    pub fn sendResponse(self: *Http3Stream, response: *Response) !void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Invalid state {}", .{ self.stream_id, self.state });
            return Http3Error.FrameError;
        }
        self.response = response.*;
        self.state = .sending;

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();

        const encoder = self.connection.qpack_encoder orelse {
            log.err("Stream {d}: No QPACK encoder", .{self.stream_id});
            try self.connection.asyncClose(.internal_error);
            return Http3Error.FrameError;
        };

        var header_map = HeaderMap.init(self.allocator);
        defer header_map.deinit();
        try header_map.put(":status", try std.fmt.allocPrint(self.allocator, "{d}", .{response.status}));
        var it = response.headers.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |value| {
                try header_map.put(entry.key_ptr.*, value);
            }
        }

        const encoded = try encoder.encodeHeaders(header_map);
        defer self.allocator.free(encoded);
        try writeFrame(self.allocator, buf.writer(), .{ .headers = .{ .encoded_block = encoded } });

        if (response.body) |body| {
            if (body.len > 0) {
                try writeFrame(self.allocator, buf.writer(), .{ .data = .{ .payload = body } });
            }
        }

        try self.writeDataAndEnd(buf.items);
    }

    pub fn closeWrite(self: *Http3Stream) !void {
        if (self.state == .closed or self.state == .errored or self.state == .half_closed_local) {
            log.warn("Stream {d}: Invalid state {}", .{ self.stream_id, self.state });
            return Http3Error.FrameError;
        }
        try self.connection.sendStreamData(self.stream_id, &.{}, true);
        self.state = .half_closed_local;
        if (self.state == .half_closed_remote) self.state = .closed;
    }

    pub fn handleStopSending(self: *Http3Stream, error_code: u64) !void {
        log.debug("Stream {d}: STOP_SENDING (code: {d})", .{ self.stream_id, error_code });
        try self.closeWrite();
        self.state = .half_closed_remote;
    }

    pub fn handleResetStream(self: *Http3Stream, error_code: u64) !void {
        log.info("Stream {d}: RESET_STREAM (code: {d})", .{ self.stream_id, error_code });
        self.state = .errored;
        try self.connection.asyncClose(.no_error);
    }
};
