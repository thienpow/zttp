const std = @import("std");
const Allocator = std.mem.Allocator;

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

pub const log = std.log.scoped(.http2);

pub const Http2Connection = struct {
    allocator: Allocator,
    reader: std.io.AnyReader,
    writer: std.io.AnyWriter,
    streams: StreamCollection,
    hpack_encoder: HPACK,
    hpack_decoder: HPACK,
    local_settings: Settings,
    remote_settings: Settings,
    last_stream_id: u31,
    connection_error: ?ErrorCode,
    closed: bool,
    connection_window: u31,
    pending_headers: ?struct {
        stream_id: u31,
        buffer: std.ArrayList(u8),
    },

    const CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    pub fn init(
        allocator: Allocator,
        reader: std.io.AnyReader,
        writer: std.io.AnyWriter,
    ) !Http2Connection {
        var conn = Http2Connection{
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
            .connection_window = 65535,
            .pending_headers = null,
        };

        try conn.writer.writeAll(CONNECTION_PREFACE);
        try conn.sendSettings();

        return conn;
    }

    pub fn deinit(self: *Http2Connection) void {
        self.streams.deinit();
        self.hpack_encoder.deinit();
        self.hpack_decoder.deinit();
        if (self.pending_headers) |*ph| {
            ph.buffer.deinit();
        }
    }

    fn sendSettings(self: *Http2Connection) !void {
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

    fn sendSettingsAck(self: *Http2Connection) !void {
        const header = FrameHeader{
            .length = 0,
            .type = .settings,
            .flags = frame.SettingsFlags.ACK,
            .stream_id = 0,
        };

        try header.write(self.writer);
    }

    pub fn processFrames(self: *Http2Connection) !void {
        while (!self.closed) {
            const header = FrameHeader.read(self.reader) catch |err| {
                if (err == error.EndOfStream) {
                    self.closed = true;
                    break;
                }
                try self.sendGoaway(.protocol_error);
                return err;
            };

            if (header.length > self.remote_settings.max_frame_size) {
                try self.sendGoaway(.frame_size_error);
                return;
            }

            try self.processFrame(header);
        }
    }

    fn processFrame(self: *Http2Connection, header: FrameHeader) !void {
        if (self.closed and header.type != .goaway) {
            return;
        }

        const payload = try self.allocator.alloc(u8, header.length);
        defer self.allocator.free(payload);

        try self.reader.readNoEof(payload);

        switch (header.type) {
            .data => try self.processDataFrame(header, payload),
            .headers => try self.processHeadersFrame(header, payload),
            .priority => try self.processPriorityFrame(header, payload),
            .rst_stream => try self.processRstStreamFrame(header, payload),
            .settings => try self.processSettingsFrame(header, payload),
            .push_promise => try self.processPushPromiseFrame(header, payload),
            .ping => try self.processPingFrame(header, payload),
            .goaway => try self.processGoawayFrame(header, payload),
            .window_update => try self.processWindowUpdateFrame(header, payload),
            .continuation => try self.processContinuationFrame(header, payload),
        }
    }

    fn processDataFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        const stream = self.streams.getStream(header.stream_id) orelse {
            try self.sendRstStream(header.stream_id, .stream_closed);
            return;
        };

        if (stream.state == .half_closed_remote or stream.state == .closed) {
            try self.sendRstStream(header.stream_id, .stream_closed);
            return;
        }

        if (payload.len > self.connection_window or payload.len > stream.window_size) {
            try self.sendGoaway(.flow_control_error);
            return;
        }

        if (payload.len > self.remote_settings.max_frame_size) {
            try self.sendRstStream(header.stream_id, .frame_size_error);
            return;
        }

        self.connection_window -= @intCast(payload.len);
        stream.updateWindowSize(-@as(i32, @intCast(payload.len)));

        if (stream.request) |req| {
            if (req.body) |existing_body| {
                const new_body = try self.allocator.alloc(u8, existing_body.len + payload.len);
                @memcpy(new_body[0..existing_body.len], existing_body);
                @memcpy(new_body[existing_body.len..], payload);
                self.allocator.free(existing_body);
                req.body = new_body;
            } else {
                req.body = try self.allocator.dupe(u8, payload);
            }
        }

        if (header.flags & 0x1 != 0) {
            stream.updateState(.half_closed_remote);
        }

        if (self.connection_window < self.remote_settings.initial_window_size / 2) {
            const increment = @as(u31, @min(self.remote_settings.initial_window_size - self.connection_window, 0x7FFFFFFF));
            try self.sendWindowUpdate(0, increment);
            self.connection_window += increment;
        }
    }

    fn processHeadersFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (self.pending_headers != null) {
            try self.sendGoaway(.protocol_error);
            return;
        }

        var stream: *Stream = undefined;
        if (self.streams.getStream(header.stream_id)) |existing_stream| {
            stream = existing_stream;
        } else {
            if (header.stream_id > self.last_stream_id and header.stream_id % 2 == 1) {
                stream = try self.streams.createStream();
                self.last_stream_id = header.stream_id;
                stream.updateState(.open);
            } else {
                try self.sendRstStream(header.stream_id, .stream_closed);
                return;
            }
        }

        if (stream.state != .open and stream.state != .half_closed_local) {
            try self.sendRstStream(header.stream_id, .stream_closed);
            return;
        }

        var header_buffer = std.ArrayList(u8).init(self.allocator);
        try header_buffer.appendSlice(payload);

        if (header.flags & 0x4 == 0) {
            self.pending_headers = .{
                .stream_id = header.stream_id,
                .buffer = header_buffer,
            };
            return;
        }

        try self.processCompleteHeaders(stream, header, header_buffer);
    }

    fn processContinuationFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (self.pending_headers == null or self.pending_headers.?.stream_id != header.stream_id) {
            try self.sendGoaway(.protocol_error);
            return;
        }

        try self.pending_headers.?.buffer.appendSlice(payload);

        if (header.flags & 0x4 != 0) {
            const stream = self.streams.getStream(header.stream_id) orelse {
                try self.sendRstStream(header.stream_id, .stream_closed);
                return;
            };
            try self.processCompleteHeaders(stream, header, self.pending_headers.?.buffer);
            self.pending_headers.?.buffer.deinit();
            self.pending_headers = null;
        }
    }

    fn processCompleteHeaders(self: *Http2Connection, stream: *Stream, header: FrameHeader, header_buffer: std.ArrayList(u8)) !void {
        defer header_buffer.deinit();

        var payload_stream = std.io.fixedBufferStream(header_buffer.items);
        const headers = try self.hpack_decoder.decode(payload_stream.reader(), self.allocator);
        defer {
            for (headers.items) |h| {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            headers.deinit();
        }

        var req = try self.allocator.create(Request);
        req.* = Request{
            .allocator = self.allocator,
            .method = .get,
            .path = "",
            .version = "HTTP/2.0",
            .headers = http.HeaderMap.init(self.allocator),
            .query = std.StringHashMap([]const u8).init(self.allocator),
            .cookies = std.StringHashMap([]const u8).init(self.allocator),
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
                const path_parts = try http.parsePath(self.allocator, h.value);
                req.path = path_parts.path;
                req.query = path_parts.query;
            } else {
                try req.headers.put(h.name, h.value);
            }
        }

        stream.setRequest(req);

        if (header.flags & 0x1 != 0) {
            stream.updateState(.half_closed_remote);
        }
    }

    fn processPriorityFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id == 0 or payload.len != 5) {
            try self.sendGoaway(.frame_size_error);
            return;
        }

        const stream = self.streams.getStream(header.stream_id) orelse {
            try self.sendRstStream(header.stream_id, .stream_closed);
            return;
        };

        const exclusive = (payload[0] & 0x80) != 0;
        const dep_stream_id = (@as(u31, payload[0] & 0x7F) << 24) |
            (@as(u31, payload[1]) << 16) |
            (@as(u31, payload[2]) << 8) |
            @as(u31, payload[3]);
        const weight = payload[4];

        stream.priority = .{
            .exclusive = exclusive,
            .dependency_stream_id = dep_stream_id,
            .weight = weight,
        };
    }

    fn processPushPromiseFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id == 0 or payload.len < 4) {
            try self.sendGoaway(.frame_size_error);
            return;
        }

        if (!self.local_settings.enable_push) {
            try self.sendGoaway(.protocol_error);
            return;
        }

        const promised_stream_id = (@as(u31, payload[0] & 0x7F) << 24) |
            (@as(u31, payload[1]) << 16) |
            (@as(u31, payload[2]) << 8) |
            @as(u31, payload[3]);

        if (promised_stream_id % 2 != 0 or promised_stream_id <= self.last_stream_id) {
            try self.sendGoaway(.protocol_error);
            return;
        }

        var header_buffer = std.ArrayList(u8).init(self.allocator);
        try header_buffer.appendSlice(payload[4..]);

        if (header.flags & 0x4 == 0) {
            self.pending_headers = .{
                .stream_id = header.stream_id,
                .buffer = header_buffer,
            };
            return;
        }

        const stream = try self.streams.createStream();
        stream.id = promised_stream_id;
        stream.updateState(.reserved_remote);
        self.last_stream_id = promised_stream_id;

        try self.processCompleteHeaders(stream, header, header_buffer);
    }

    fn processSettingsFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id != 0) {
            try self.sendGoaway(.protocol_error);
            return;
        }

        if (header.flags & frame.SettingsFlags.ACK != 0) {
            return;
        }

        self.remote_settings = try Settings.readPayload(self.allocator, payload);
        self.hpack_decoder.dynamic_table.updateMaxSize(self.remote_settings.header_table_size);
        try self.sendSettingsAck();
    }

    fn processPingFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id != 0 or payload.len != 8) {
            try self.sendGoaway(.frame_size_error);
            return;
        }

        if (header.flags & frame.SettingsFlags.ACK != 0) {
            return;
        }

        const ping_header = FrameHeader{
            .length = 8,
            .type = .ping,
            .flags = frame.SettingsFlags.ACK,
            .stream_id = 0,
        };

        try ping_header.write(self.writer);
        try self.writer.writeAll(payload);
    }

    fn processGoawayFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id != 0 or payload.len < 8) {
            try self.sendGoaway(.frame_size_error);
            return;
        }

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

    fn processWindowUpdateFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (payload.len != 4) {
            try self.sendGoaway(.frame_size_error);
            return;
        }

        const increment = (@as(u31, payload[0] & 0x7F) << 24) |
            (@as(u31, payload[1]) << 16) |
            (@as(u31, payload[2]) << 8) |
            @as(u31, payload[3]);

        if (increment == 0 or increment > 0x7FFFFFFF) {
            try self.sendGoaway(.flow_control_error);
            return;
        }

        if (header.stream_id == 0) {
            if (@as(u64, self.connection_window) + increment > 0x7FFFFFFF) {
                try self.sendGoaway(.flow_control_error);
                return;
            }
            self.connection_window += increment;
        } else {
            if (self.streams.getStream(header.stream_id)) |stream| {
                if (@as(i64, stream.window_size) + @as(i64, increment) > 0x7FFFFFFF) {
                    try self.sendRstStream(header.stream_id, .flow_control_error);
                    return;
                }
                stream.updateWindowSize(@intCast(increment));
            }
        }
    }

    fn processRstStreamFrame(self: *Http2Connection, header: FrameHeader, payload: []const u8) !void {
        if (header.stream_id == 0 or payload.len != 4) {
            try self.sendGoaway(.frame_size_error);
            return;
        }

        if (self.streams.getStream(header.stream_id)) |stream| {
            stream.updateState(.closed);
        }
    }

    fn sendRstStream(self: *Http2Connection, stream_id: u31, error_code: ErrorCode) !void {
        const header = FrameHeader{
            .length = 4,
            .type = .rst_stream,
            .flags = 0,
            .stream_id = stream_id,
        };

        var payload: [4]u8 = undefined;
        payload[0] = @intCast((@intFromEnum(error_code) >> 24) & 0xFF);
        payload[1] = @intCast((@intFromEnum(error_code) >> 16) & 0xFF);
        payload[2] = @intCast((@intFromEnum(error_code) >> 8) & 0xFF);
        payload[3] = @intCast(@intFromEnum(error_code) & 0xFF);

        try header.write(self.writer);
        try self.writer.writeAll(&payload);
    }

    fn sendGoaway(self: *Http2Connection, error_code: ErrorCode) !void {
        const header = FrameHeader{
            .length = 8,
            .type = .goaway,
            .flags = 0,
            .stream_id = 0,
        };

        var payload: [8]u8 = undefined;
        payload[0] = @intCast((self.last_stream_id >> 24) & 0x7F);
        payload[1] = @intCast((self.last_stream_id >> 16) & 0xFF);
        payload[2] = @intCast((self.last_stream_id >> 8) & 0xFF);
        payload[3] = @intCast(self.last_stream_id & 0xFF);
        payload[4] = @intCast((@intFromEnum(error_code) >> 24) & 0xFF);
        payload[5] = @intCast((@intFromEnum(error_code) >> 16) & 0xFF);
        payload[6] = @intCast((@intFromEnum(error_code) >> 8) & 0xFF);
        payload[7] = @intCast(@intFromEnum(error_code) & 0xFF);

        try header.write(self.writer);
        try self.writer.writeAll(&payload);
        self.closed = true;
    }

    fn sendWindowUpdate(self: *Http2Connection, stream_id: u31, increment: u31) !void {
        const header = FrameHeader{
            .length = 4,
            .type = .window_update,
            .flags = 0,
            .stream_id = stream_id,
        };

        var payload: [4]u8 = undefined;
        payload[0] = @intCast((increment >> 24) & 0x7F);
        payload[1] = @intCast((increment >> 16) & 0xFF);
        payload[2] = @intCast((increment >> 8) & 0xFF);
        payload[3] = @intCast(increment & 0xFF);

        try header.write(self.writer);
        try self.writer.writeAll(&payload);
    }

    pub fn sendRequest(self: *Http2Connection, request: *Request) !*Stream {
        const stream = try self.streams.createStream();
        stream.setRequest(request);
        stream.updateState(.open);

        var headers = std.ArrayList(Header).init(self.allocator);
        defer headers.deinit();

        const method_str = request.method.toString();
        try headers.append(.{ .name = ":method", .value = method_str });
        try headers.append(.{ .name = ":path", .value = request.path });
        try headers.append(.{ .name = ":scheme", .value = "https" });
        try headers.append(.{ .name = ":authority", .value = request.headers.get("Host") orelse "localhost" });

        var header_it = request.headers.iterator();
        while (header_it.next()) |entry| {
            for (entry.value_ptr.items) |value| {
                try headers.append(.{ .name = entry.key_ptr.*, .value = value });
            }
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        try self.hpack_encoder.encode(headers, buf.writer());

        var flags: u8 = 0x4;
        if (request.body == null) {
            flags |= 0x1;
        }

        const header = FrameHeader{
            .length = @intCast(buf.items.len),
            .type = .headers,
            .flags = flags,
            .stream_id = stream.id,
        };

        try header.write(self.writer);
        try self.writer.writeAll(buf.items);

        if (request.body) |body| {
            const data_header = FrameHeader{
                .length = @intCast(body.len),
                .type = .data,
                .flags = 0x1,
                .stream_id = stream.id,
            };

            try data_header.write(self.writer);
            try self.writer.writeAll(body);
        }

        return stream;
    }

    pub fn sendResponse(self: *Http2Connection, stream: *Stream, response: *Response) !void {
        var headers = std.ArrayList(Header).init(self.allocator);
        defer headers.deinit();

        const status_str = try std.fmt.allocPrint(self.allocator, "{}", .{@intFromEnum(response.status)});
        defer self.allocator.free(status_str);
        try headers.append(.{ .name = ":status", .value = status_str });

        var header_it = response.headers.iterator();
        while (header_it.next()) |entry| {
            for (entry.value_ptr.items) |value| {
                try headers.append(.{ .name = entry.key_ptr.*, .value = value });
            }
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        try self.hpack_encoder.encode(headers, buf.writer());

        var flags: u8 = 0x4;
        if (response.body == null) {
            flags |= 0x1;
        }

        const header = FrameHeader{
            .length = @intCast(buf.items.len),
            .type = .headers,
            .flags = flags,
            .stream_id = stream.id,
        };

        try header.write(self.writer);
        try self.writer.writeAll(buf.items);

        if (response.body) |body| {
            const data_header = FrameHeader{
                .length = @intCast(body.len),
                .type = .data,
                .flags = 0x1,
                .stream_id = stream.id,
            };

            try data_header.write(self.writer);
            try self.writer.writeAll(body);
        }

        stream.updateState(.half_closed_local);
        if (stream.state == .half_closed_remote) {
            stream.updateState(.closed);
            _ = self.streams.removeStream(stream.id);
        }
    }

    pub fn close(self: *Http2Connection) !void {
        if (self.closed) return;

        const goaway_header = FrameHeader{
            .length = 8,
            .type = .goaway,
            .flags = 0,
            .stream_id = 0,
        };

        var payload: [8]u8 = undefined;
        payload[0] = @intCast((self.last_stream_id >> 24) & 0x7F);
        payload[1] = @intCast((self.last_stream_id >> 16) & 0xFF);
        payload[2] = @intCast((self.last_stream_id >> 8) & 0xFF);
        payload[3] = @intCast(self.last_stream_id & 0xFF);
        payload[4] = 0;
        payload[5] = 0;
        payload[6] = 0;
        payload[7] = 0;

        try goaway_header.write(self.writer);
        try self.writer.writeAll(&payload);

        self.closed = true;
    }
};
