// src/http3/quic/stream.zig
// QUIC stream management

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.quic_stream);

const Connection = @import("connection.zig").Connection;
const Event = @import("event.zig").Event;
const packet = @import("packet.zig");
const Frame = packet.Frame;
const StreamFrame = packet.StreamFrame;

/// Stream state
pub const StreamState = enum {
    ready,
    send_only,
    recv_only,
    closing,
    closed,
};

/// QUIC stream structure
pub const Stream = struct {
    allocator: Allocator,
    conn: *Connection,
    stream_id: u64,
    is_unidirectional: bool,
    state: StreamState,
    send_offset: u64,
    recv_offset: u64,
    max_send_offset: u64,
    max_recv_offset: u64,
    send_buffer: std.ArrayList(u8),
    recv_buffer: std.ArrayList(u8),
    fin_sent: bool,
    fin_received: bool,

    /// Initialize a new QUIC stream
    pub fn init(allocator: Allocator, conn: *Connection, stream_id: u64, is_unidirectional: bool) !*Stream {
        const stream = try allocator.create(Stream);
        errdefer allocator.destroy(stream);

        const initial_max_data = if (is_unidirectional)
            conn.initial_max_stream_data_uni
        else if (stream_id % 2 == (if (conn.role == .client) @as(u1, 0) else @as(u1, 1)))
            conn.initial_max_stream_data_bidi_local
        else
            conn.initial_max_stream_data_bidi_remote;

        stream.* = .{
            .allocator = allocator,
            .conn = conn,
            .stream_id = stream_id,
            .is_unidirectional = is_unidirectional,
            .state = if (is_unidirectional and conn.role == .server) .recv_only else .ready,
            .send_offset = 0,
            .recv_offset = 0,
            .max_send_offset = initial_max_data,
            .max_recv_offset = initial_max_data,
            .send_buffer = std.ArrayList(u8).init(allocator),
            .recv_buffer = std.ArrayList(u8).init(allocator),
            .fin_sent = false,
            .fin_received = false,
        };

        return stream;
    }

    /// Clean up stream resources
    pub fn deinit(self: *Stream) void {
        self.send_buffer.deinit();
        self.recv_buffer.deinit();
    }

    /// Read data from the stream
    pub fn read(self: *Stream, buffer: []u8) !usize {
        if (self.state == .send_only or self.state == .closed) {
            return error.StreamRecvClosed;
        }

        if (self.recv_buffer.items.len == 0) {
            if (self.fin_received) return 0;
            return error.WouldBlock;
        }

        const bytes_to_read = @min(buffer.len, self.recv_buffer.items.len);
        @memcpy(buffer[0..bytes_to_read], self.recv_buffer.items[0..bytes_to_read]);

        self.recv_buffer.shrinkRetainingCapacity(self.recv_buffer.items.len - bytes_to_read);
        self.recv_offset += bytes_to_read;

        return bytes_to_read;
    }

    /// Write data to the stream
    pub fn write(self: *Stream, data: []const u8, is_fin: bool) !usize {
        if (self.is_unidirectional and self.conn.role != .client) {
            return error.StreamSendNotAllowed;
        }
        if (self.state == .recv_only or self.state == .closed or self.fin_sent) {
            return error.StreamSendClosed;
        }

        const available_window = self.max_send_offset - self.send_offset;
        if (available_window == 0) {
            return error.StreamBlocked;
        }

        const bytes_to_write = @min(data.len, available_window);
        try self.send_buffer.appendSlice(data[0..bytes_to_write]);
        self.send_offset += bytes_to_write;

        if (is_fin and bytes_to_write == data.len) {
            self.fin_sent = true;
        }

        try self.queueStreamFrame(data[0..bytes_to_write], self.send_offset - bytes_to_write, self.fin_sent);

        return bytes_to_write;
    }

    /// Queue a STREAM frame for sending
    fn queueStreamFrame(self: *Stream, data: []const u8, offset: u64, is_fin: bool) !void {
        var pkt = try packet.Packet.create(self.allocator, .short_header);
        errdefer {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        const frame = Frame{ .stream = .{
            .stream_id = self.stream_id,
            .offset = offset,
            .length = @as(u64, data.len),
            .fin = is_fin,
            .data = data,
        } };
        try pkt.frames.append(frame);
        try self.conn.outgoing_packets.append(pkt);
    }

    /// Handle incoming STREAM frame
    pub fn processStreamData(self: *Stream, data: []const u8, offset: u64, is_fin: bool) !void {
        if (self.is_unidirectional and self.conn.role == .client) {
            return error.StreamRecvNotAllowed;
        }
        if (self.state == .send_only or self.state == .closed) {
            log.warn("Received data on stream {} in state {}", .{ self.stream_id, self.state });
            return error.StreamRecvClosed;
        }

        if (offset != self.recv_offset) {
            log.warn("Out-of-order data on stream {}: expected {}, got {}", .{ self.stream_id, self.recv_offset, offset });
            return error.OutOfOrderStreamData;
        }

        if (self.recv_offset + data.len > self.max_recv_offset) {
            log.warn("Flow control violation on stream {}: current {}, data {}, max {}", .{ self.stream_id, self.recv_offset, data.len, self.max_recv_offset });
            try self.conn.close(0x03, "Flow control error"); // QUIC_FLOW_CONTROL_ERROR
            return error.FlowControlError;
        }

        try self.recv_buffer.appendSlice(data);
        self.recv_offset += data.len;

        if (is_fin) {
            self.fin_received = true;
            if (self.state == .ready) {
                self.state = .send_only;
            } else if (self.state == .closing) self.state = .closed;
        }

        self.conn.event_callback(self.conn, .{ .stream_data = .{
            .stream_id = self.stream_id,
            .data = self.recv_buffer.items,
            .is_fin = self.fin_received,
        } }, self.conn.user_ctx);

        self.recv_buffer.clearRetainingCapacity();

        if (self.fin_sent and self.fin_received and self.state != .closed) {
            self.state = .closed;
            self.conn.event_callback(self.conn, .{
                .stream_closed = .{
                    .stream_id = self.stream_id,
                    .error_code = 0, // No error, clean closure
                },
            }, self.conn.user_ctx);
        }
    }

    /// Open a stream
    pub fn open(allocator: Allocator, conn: *Connection, stream_id: u64, is_unidirectional: bool) !*Stream {
        log.debug("Opening stream {} (unidirectional: {})", .{ stream_id, is_unidirectional });
        return try Stream.init(allocator, conn, stream_id, is_unidirectional);
    }

    /// Send data on a stream
    pub fn sendData(self: *Stream, data: []const u8, is_fin: bool) !usize {
        log.debug("Sending {} bytes on stream {} (is_fin: {})", .{ data.len, self.stream_id, is_fin });
        return try self.write(data, is_fin);
    }

    /// Handle STOP_SENDING frame
    pub fn handleStopSending(self: *Stream, error_code: u64) !void {
        log.debug("Handling STOP_SENDING for stream {d}, error_code={d}", .{ self.stream_id, error_code });

        if (self.state == .send_only or self.state == .closed) {
            return; // Already in a state where sending is not allowed
        }

        self.fin_sent = true;
        if (self.state == .ready) {
            self.state = .recv_only;
        } else if (self.state == .closing) {
            self.state = .closed;
        }

        self.conn.event_callback(self.conn, .{ .stream_closed = .{
            .stream_id = self.stream_id,
            .error_code = error_code,
        } }, self.conn.user_ctx);
    }

    /// Update the maximum stream data limit (MAX_STREAM_DATA frame)
    pub fn updateMaxStreamData(self: *Stream, max_data: u64) !void {
        log.debug("Updating MAX_STREAM_DATA for stream {d}, new max={d}", .{ self.stream_id, max_data });

        if (self.state == .send_only or self.state == .closed) {
            log.warn("Received MAX_STREAM_DATA for stream {d} in state {s}, ignoring", .{ self.stream_id, @tagName(self.state) });
            return;
        }

        if (max_data < self.max_send_offset) {
            log.warn("Received invalid MAX_STREAM_DATA for stream {d}: new max {d} < current {d}", .{ self.stream_id, max_data, self.max_send_offset });
            try self.conn.close(0x03, "Flow control error"); // QUIC_FLOW_CONTROL_ERROR
            return error.FlowControlError;
        }

        self.max_send_offset = max_data;
    }

    /// Close the send side of the stream
    pub fn closeSend(self: *Stream) !void {
        log.debug("Closing send side of stream {}", .{self.stream_id});
        if (self.state == .recv_only or self.state == .closed or self.fin_sent) {
            return error.StreamSendClosed;
        }

        self.fin_sent = true;
        try self.queueStreamFrame(&[_]u8{}, self.send_offset, true);

        if (self.state == .ready) {
            self.state = .recv_only;
        } else if (self.state == .closing) self.state = .closed;
    }

    /// Close the receive side of the stream
    pub fn closeRecv(self: *Stream, error_code: u64) !void {
        log.debug("Closing receive side of stream {}", .{self.stream_id});
        if (self.state == .send_only or self.state == .closed or self.fin_received) {
            return;
        }

        self.fin_received = true;

        // TODO: Queue STOP_SENDING frame
        var pkt = try packet.Packet.create(self.allocator, .short_header);
        errdefer {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        // Placeholder for STOP_SENDING frame (type 0x05)
        const frame = Frame{ .raw = &[_]u8{ 0x05, @as(u8, @intCast(self.stream_id)), @as(u8, @intCast(error_code)) } };
        try pkt.frames.append(frame);
        try self.conn.outgoing_packets.append(pkt);

        if (self.state == .ready) {
            self.state = .send_only;
        } else if (self.state == .closing) self.state = .closed;
    }
};

/// Create a new QUIC stream
pub fn createStream(allocator: Allocator, conn: *Connection, stream_id: u64, is_unidirectional: bool) !*Stream {
    return try Stream.init(allocator, conn, stream_id, is_unidirectional);
}

/// Destroy a QUIC stream
pub fn destroyStream(stream: *Stream) void {
    log.debug("Destroying stream {}", .{stream.stream_id});
    stream.deinit();
    stream.allocator.destroy(stream);
}

/// Open a new stream on the connection
pub fn openStream(conn: *Connection, is_unidirectional: bool) !*Stream {
    const stream_id_type_offset: u64 = if (conn.role == .client)
        if (is_unidirectional) 1 else 0
    else if (is_unidirectional) 0 else 1;
    const stream_id = conn.next_local_stream_id + stream_id_type_offset;

    const max_streams = if (is_unidirectional) conn.initial_max_streams_uni else conn.initial_max_streams_bidi;
    if (conn.next_local_stream_id / 4 >= max_streams) {
        return error.StreamLimitExceeded;
    }
    conn.next_local_stream_id += 4;

    const stream = try Stream.open(conn.allocator, conn, stream_id, is_unidirectional);
    try conn.streams.put(stream_id, stream);

    conn.event_callback(conn, .{ .new_stream = .{
        .stream_id = stream_id,
        .is_unidirectional = is_unidirectional,
    } }, conn.user_ctx);

    return stream;
}

/// Send data on a specific stream
pub fn sendStreamData(stream: *Stream, data: []const u8, is_fin: bool) !usize {
    return try stream.sendData(data, is_fin);
}
