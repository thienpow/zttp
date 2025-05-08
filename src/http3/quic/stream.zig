// src/quic/stream.zig
// QUIC stream management

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.quic_stream);

const Connection = @import("connection.zig").Connection;
const Event = @import("event.zig").Event;

/// Stream state
pub const StreamState = enum {
    ready,      // Open and ready for I/O
    send_only,  // Can only send data (recv side closed)
    recv_only,  // Can only receive data (send side closed)
    closing,    // Both sides closing
    closed,     // Fully closed
};

/// QUIC stream structure
pub const Stream = struct {
    allocator: Allocator,
    conn: *Connection,
    stream_id: u64,
    is_unidirectional: bool,
    state: StreamState,

    // Flow control
    send_offset: u64,
    recv_offset: u64,
    max_send_offset: u64,
    max_recv_offset: u64,

    // Data buffers
    send_buffer: std.ArrayList(u8),
    recv_buffer: std.ArrayList(u8),

    // Flags
    fin_sent: bool,
    fin_received: bool,

    /// Initialize a new QUIC stream
    pub fn init(allocator: Allocator, conn: *Connection, stream_id: u64, is_unidirectional: bool) !*Stream {
        var stream = try allocator.create(Stream);
        errdefer allocator.destroy(stream);

        // Determine initial flow control limits based on connection settings
        const initial_max_data = if (is_unidirectional)
            conn.initial_max_stream_data_uni
        else if (stream_id % 2 == 0)
            conn.initial_max_stream_data_bidi_local
        else
            conn.initial_max_stream_data_bidi_remote;

        stream.* = .{
            .allocator = allocator,
            .conn = conn,
            .stream_id = stream_id,
            .is_unidirectional = is_unidirectional,
            .state = .ready,
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
            if (self.fin_received) {
                return 0; // End of stream
            }
            return error.WouldBlock; // No data available
        }

        const bytes_to_read = @min(buffer.len, self.recv_buffer.items.len);
        std.mem.copy(u8, buffer[0..bytes_to_read], self.recv_buffer.items[0..bytes_to_read]);

        // Remove read data from buffer
        _ = self.recv_buffer.orderedRemove(0);
        for (1..bytes_to_read) |_| {
            _ = self.recv_buffer.orderedRemove(0);
        }

        self.recv_offset += bytes_to_read;

        return bytes_to_read;
    }

    /// Write data to the stream
    pub fn write(self: *Stream, data: []const u8, is_fin: bool) !usize {
        if (self.state == .recv_only or self.state == .closed or self.fin_sent) {
            return error.StreamSendClosed;
        }

        // Check flow control
        const available_window = self.max_send_offset - self.send_offset;
        if (available_window == 0) {
            return error.StreamBlocked;
        }

        const bytes_to_write = @min(data.len, available_window);

        // Buffer data for sending
        try self.send_buffer.appendSlice(data[0..bytes_to_write]);
        self.send_offset += bytes_to_write;

        if (is_fin) {
            self.fin_sent = true;
            // TODO: Signal stream closure or queue a STREAM frame with FIN bit
        }

        // TODO: Trigger packet assembly to send buffered data

        return bytes_to_write;
    }

    /// Handle incoming STREAM or STREAM_DATA frame
    pub fn processStreamData(self: *Stream, data: []const u8, offset: u64, is_fin: bool) !void {
        if (self.state == .send_only or self.state == .closed) {
            log.warn("Received data on stream in state {}: {}", .{ self.state, self.stream_id });
            return error.StreamRecvClosed; // Or send STOP_SENDING frame
        }

        // Ensure data is in order (very basic check for now)
        if (offset != self.recv_offset) {
             log.warn("Received out-of-order data on stream {}: expected offset {}, got {}", .{ self.stream_id, self.recv_offset, offset });
             // TODO: Buffer out-of-order data, send MAX_STREAM_DATA updates
             return error.OutOfOrderStreamData; // Placeholder
        }

        // Check flow control
        if (self.recv_offset + data.len > self.max_recv_offset) {
            log.warn("Received data exceeds flow control limit on stream {}: current {}, data len {}, max {}", .{ self.stream_id, self.recv_offset, data.len, self.max_recv_offset });
            // TODO: Send STREAM_DATA_BLOCKED or connection close
            return error.FlowControlError; // Placeholder
        }

        // Append data to receive buffer
        try self.recv_buffer.appendSlice(data);
        self.recv_offset += data.len;

        // Handle FIN
        if (is_fin) {
            self.fin_received = true;
        }

        // Notify connection about received data
        self.conn.event_callback(self.conn, .{ .stream_data = .{
            .stream_id = self.stream_id,
            .data = self.recv_buffer.items, // Pass the whole buffer for now
            .is_fin = self.fin_received,
        } }, self.conn.user_ctx);

        // Clear buffer after notifying (assuming callback processes it fully)
        // In a real implementation, this would be more complex with peek/consume
        if (self.recv_buffer.items.len > 0) {
             self.recv_buffer.clear();
             // TODO: Send MAX_STREAM_DATA updates
        }

        // Check if stream is fully closed
        if (self.fin_sent and self.fin_received and self.state != .closed) {
            self.state = .closed;
            // TODO: Notify connection about stream closure
        }
    }

    /// Open a stream (client-side) or accept a stream (server-side)
    pub fn open(allocator: Allocator, conn: *Connection, stream_id: u64, is_unidirectional: bool) !*Stream {
        log.debug("Opening stream {} (unidirectional: {})", .{ stream_id, is_unidirectional });
        var stream = try Stream.init(allocator, conn, stream_id, is_unidirectional);
        // State is already 'ready' from init

        // TODO: Send STREAM frame with FIN=true if just opening for closure

        return stream;
    }

    /// Send data on a stream
    pub fn sendData(self: *Stream, data: []const u8, is_fin: bool) !usize {
        log.debug("Sending {} bytes on stream {} (is_fin: {})", .{ data.len, self.stream_id, is_fin });
        return self.write(data, is_fin);
    }

    /// Close the stream gracefully
    pub fn closeSend(self: *Stream) !void {
        log.debug("Closing send side of stream {}", .{ self.stream_id });
        if (self.state == .recv_only or self.state == .closed or self.fin_sent) {
            return error.StreamSendClosed;
        }

        self.fin_sent = true;
        // TODO: Queue STREAM frame with FIN bit

        // Update state
        if (self.state == .ready) self.state = .recv_only;
        else if (self.state == .closing) self.state = .closed;
    }

    /// Close the receive side of the stream (send STOP_SENDING)
    pub fn closeRecv(self: *Stream, error_code: u64) !void {
        log.debug("Closing receive side of stream {}", .{ self.stream_id });
        if (self.state == .send_only or self.state == .closed or self.fin_received) {
            // Already closed or FIN received, no need to send STOP_SENDING
            return;
        }

        self.fin_received = true;
        // TODO: Queue STOP_SENDING frame

        // Update state
        if (self.state == .ready) self.state = .send_only;
        else if (self.state == .closing) self.state = .closed;
    }
};

/// Creates a new QUIC stream structure (primarily for internal use or when a stream is initiated by the peer)
pub fn createStream(allocator: Allocator, conn: *Connection, stream_id: u64, is_unidirectional: bool) !*Stream {
    return Stream.init(allocator, conn, stream_id, is_unidirectional);
}

/// Destroys a QUIC stream and frees associated resources
pub fn destroyStream(stream: *Stream) void {
    log.debug("Destroying stream {}", .{stream.stream_id});
    stream.deinit();
    stream.allocator.destroy(stream);
}

/// Opens a new stream on the connection (client-initiated)
pub fn openStream(conn: *Connection, is_unidirectional: bool) !*Stream {
    // Determine the next stream ID based on connection role and type
    // Client initiates even-numbered bidirectional (0, 4, 8...)
    // Client initiates odd-numbered unidirectional (1, 5, 9...)
    // Server initiates odd-numbered bidirectional (1, 5, 9...)
    // Server initiates even-numbered unidirectional (0, 4, 8...)
    const stream_id_type_offset = if (conn.role == .client) {
        if (is_unidirectional) 1 else 0
    } else {
        if (is_unidirectional) 0 else 1
    };
    const stream_id = conn.next_local_stream_id + stream_id_type_offset; // Basic ID allocation

    if (is_unidirectional) {
        if (conn.next_local_stream_id / 4 >= conn.initial_max_streams_uni) {
            return error.StreamLimitExceeded;
        }
        conn.next_local_stream_id += 4;
    } else {
         if (conn.next_local_stream_id / 4 >= conn.initial_max_streams_bidi) {
            return error.StreamLimitExceeded;
        }
        conn.next_local_stream_id += 4;
    }

    // Check stream limits
    // TODO: Implement actual stream count tracking

    // Create stream object
    var stream = try Stream.open(conn.allocator, conn, stream_id, is_unidirectional);
    try conn.streams.put(stream_id, stream);

    // Notify about the new stream
    conn.event_callback(conn, .{ .new_stream = .{
        .stream_id = stream_id,
        .is_unidirectional = is_unidirectional,
    } }, conn.user_ctx);

    return stream;
}

/// Sends data on a specific stream
pub fn sendStreamData(stream: *Stream, data: []const u8, is_fin: bool) !usize {
    return stream.sendData(data, is_fin);
}
