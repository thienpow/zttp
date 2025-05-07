// src/http2/client.zig - HTTP/2 client implementation
const std = @import("std");
const Allocator = std.mem.Allocator;
const net = std.net;

const frame = @import("frame.zig");
const FrameType = frame.FrameType;
const FrameHeader = frame.FrameHeader;
const Settings = @import("settings.zig").Settings;
const HPACK = @import("hpack/mod.zig").HPACK;
const Header = @import("hpack/mod.zig").Header;
const StreamCollection = @import("stream.zig").StreamCollection;
const Stream = @import("stream.zig").Stream;
const StreamState = @import("stream.zig").StreamState;
const http = @import("../http/mod.zig");
const Request = http.Request;
const Response = http.Response;
const Http2Error = @import("error.zig").Http2Error;
const ErrorCode = @import("error.zig").ErrorCode;

// HTTP/2 client connection
pub const Client = struct {
    allocator: Allocator,
    reader: std.io.Reader,
    writer: std.io.Writer,
    streams: StreamCollection,
    hpack_encoder: HPACK,
    hpack_decoder: HPACK,
    local_settings: Settings,
    remote_settings: Settings,
    last_stream_id: u31,
    connection_error: ?ErrorCode,
    closed: bool,

    // Connection preface for HTTP/2 (RFC 7540 Section 3.5)
    const CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    pub fn init(
        allocator: Allocator,
        reader: std.io.Reader,
        writer: std.io.Writer,
    ) !Client {
        var client = Client{
            .allocator = allocator,
            .reader = reader,
            .writer = writer,
            .streams = StreamCollection.init(allocator),
            .hpack_encoder = HPACK.init(allocator, 4096),
            .hpack_decoder = HPACK.init(allocator, 4096),
            .local_settings = Settings{},
            .remote_settings = Settings{},
            .last_stream_id = 0,
            .connection_error = null,
            .closed = false,
        };

        // Send connection preface
        try client.writer.writeAll(CONNECTION_PREFACE);

        // Send initial SETTINGS frame
        try client.sendSettings();

        return client;
    }

    pub fn deinit(self: *Client) void {
        self.streams.deinit();
        self.hpack_encoder.deinit();
        self.hpack_decoder.deinit();
    }

    // Send a SETTINGS frame
    fn sendSettings(self: *Client) !void {
        const payload = try self.local_settings.writePayload(self.allocator);
        defer self.allocator.free(payload);

        const header = FrameHeader{
            .length = @intCast(payload.len),
            .type = .settings,
            .flags = 0,
            .stream_id = 0,
        };

        try header.write(self.writer);
        try self.writer.writeAll(payload);
    }

    // Send a SETTINGS frame with ACK flag
    fn sendSettingsAck(self: *Client) !void {
        const header = FrameHeader{
            .length = 0,
            .type = .settings,
            .flags = frame.SettingsFlags.ACK,
            .stream_id = 0,
        };

        try header.write(self.writer);
    }

    // Process incoming frames
    pub fn processFrames(self: *Client) !void {
        while (!self.closed) {
            const header = FrameHeader.read(self.reader) catch |err| {
                if (err == error.EndOfStream) {
                    self.closed = true;
                    break;
                }
                return err;
            };

            try self.processFrame(header);
        }
    }

    // Process a single frame
    fn processFrame(self: *Client, header: FrameHeader) !void {
        const payload = try self.allocator.alloc(u8, header.length);
        defer self.allocator.free(payload);

        try self.reader.readNoEof(payload);

        switch (header.type) {
            .data => try self.processDataFrame(header, payload),
            .headers => try self.processHeadersFrame(header, payload),
            .settings => try self.processSettingsFrame(header, payload),
            .ping => try self.processPingFrame(header, payload),
            .goaway => try self.processGoawayFrame(header, payload),
            .window_update => try self.processWindowUpdateFrame(header, payload),
            .rst_stream => try self.processRstStreamFrame(header, payload),
            else => {}, // Ignore other frame types for now
        }
    }

    // Process a DATA frame
    fn processDataFrame(self: *Client, header: FrameHeader, payload: []const u8) !void {
        _ = payload;
        const stream = self.streams.getStream(header.stream_id) orelse return;

        if (stream.state == .half_closed_remote or stream.state == .closed) {
            return error.StreamClosed;
        }

        // TODO: Process data frame payload and update stream state
    }

    // Process a HEADERS frame
    fn processHeadersFrame(self: *Client, header: FrameHeader, payload: []const u8) !void {
        _ = payload;
        const stream = self.streams.getStream(header.stream_id) orelse return;
        _ = stream;
        // TODO: Process headers frame payload and update stream state
    }

    // Process a SETTINGS frame
    fn processSettingsFrame(self: *Client, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id != 0) {
            return error.InvalidStreamId;
        }

        if (header.flags & frame.SettingsFlags.ACK == frame.SettingsFlags.ACK) {
            // Settings acknowledgment - no action needed
            return;
        }

        // Parse settings payload
        self.remote_settings = try Settings.readPayload(self.allocator, payload);

        // Update HPACK dynamic table size
        self.hpack_decoder.dynamic_table.updateMaxSize(self.remote_settings.header_table_size);

        // Send SETTINGS acknowledgment
        try self.sendSettingsAck();
    }

    // Process a PING frame
    fn processPingFrame(self: *Client, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id != 0) {
            return error.InvalidStreamId;
        }

        if (header.flags & frame.SettingsFlags.ACK == frame.SettingsFlags.ACK) {
            // Ping acknowledgment - no action needed
            return;
        }

        // Send PING acknowledgment
        const ping_header = FrameHeader{
            .length = @intCast(payload.len),
            .type = .ping,
            .flags = frame.SettingsFlags.ACK,
            .stream_id = 0,
        };

        try ping_header.write(self.writer);
        try self.writer.writeAll(payload);
    }

    // Process a GOAWAY frame
    fn processGoawayFrame(self: *Client, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id != 0) {
            return error.InvalidStreamId;
        }

        if (payload.len < 8) {
            return error.InvalidFrameHeader;
        }

        // Extract last-stream-ID and error code
        const last_stream_id = (@as(u31, payload[0] & 0x7F) << 24) |
            (@as(u31, payload[1]) << 16) |
            (@as(u31, payload[2]) << 8) |
            @as(u31, payload[3]);

        const error_code = (@as(u32, payload[4]) << 24) |
            (@as(u32, payload[5]) << 16) |
            (@as(u32, payload[6]) << 8) |
            @as(u32, payload[7]);

        self.connection_error = @enumFromInt(error_code);
        self.last_stream_id = last_stream_id;
        self.closed = true;
    }

    // Process a WINDOW_UPDATE frame
    fn processWindowUpdateFrame(self: *Client, header: FrameHeader, payload: []const u8) !void {
        if (payload.len != 4) {
            return error.InvalidFrameHeader;
        }

        const increment = (@as(u31, payload[0] & 0x7F) << 24) |
            (@as(u31, payload[1]) << 16) |
            (@as(u31, payload[2]) << 8) |
            @as(u31, payload[3]);

        if (increment == 0) {
            return error.FlowControlError;
        }

        if (header.stream_id == 0) {
            // Connection-level flow control
            // TODO: Update connection window size
        } else {
            // Stream-level flow control
            if (self.streams.getStream(header.stream_id)) |stream| {
                stream.updateWindowSize(@intCast(increment));
            }
        }
    }

    // Process a RST_STREAM frame
    fn processRstStreamFrame(self: *Client, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id == 0) {
            return error.InvalidStreamId;
        }

        if (payload.len != 4) {
            return error.InvalidFrameHeader;
        }

        const error_code = (@as(u32, payload[0]) << 24) |
            (@as(u32, payload[1]) << 16) |
            (@as(u32, payload[2]) << 8) |
            @as(u32, payload[3]);

        _ = error_code;
        if (self.streams.getStream(header.stream_id)) |stream| {
            stream.updateState(.closed);
        }
    }

    // Send a request
    pub fn sendRequest(self: *Client, request: *Request) !*Stream {
        const stream = try self.streams.createStream();
        stream.setRequest(request);
        stream.updateState(.open);

        // TODO: Serialize request headers and send HEADERS frame

        return stream;
    }

    // Close the connection
    pub fn close(self: *Client) !void {
        if (self.closed) return;

        // Send GOAWAY frame
        const goaway_header = FrameHeader{
            .length = 8,
            .type = .goaway,
            .flags = 0,
            .stream_id = 0,
        };

        var payload: [8]u8 = undefined;
        // Last processed stream ID
        payload[0] = @intCast((self.last_stream_id >> 24) & 0x7F);
        payload[1] = @intCast((self.last_stream_id >> 16) & 0xFF);
        payload[2] = @intCast((self.last_stream_id >> 8) & 0xFF);
        payload[3] = @intCast(self.last_stream_id & 0xFF);
        // Error code (NO_ERROR)
        payload[4] = 0;
        payload[5] = 0;
        payload[6] = 0;
        payload[7] = 0;

        try goaway_header.write(self.writer);
        try self.writer.writeAll(&payload);

        self.closed = true;
    }
};
