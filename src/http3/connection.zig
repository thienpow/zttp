// src/http3/connection.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.http3_connection);

// Async I/O system integration
const AsyncIo = @import("../async/async.zig").AsyncIo;
const Task = @import("../async/task.zig").Task;
const AsyncContext = @import("../async/async.zig").AsyncContext;
const Timespec = @import("../async/async.zig").Timespec;

const Server = @import("../core/server.zig").Server;

// Import types from http3 sub-modules
const types = @import("types.zig");
const FrameType = types.FrameType;
const StreamType = types.StreamType;
const Frame = types.Frame;

const http3_error = @import("error.zig");
const Http3Error = http3_error.Http3Error;
const ErrorCode = http3_error.ErrorCode;

const settings = @import("settings.zig");
const Settings = settings.Settings;

const frame = @import("frame.zig");
const readFrame = frame.readFrame;
const writeFrame = frame.writeFrame;

const qpack = @import("qpack/mod.zig");
const QpackEncoder = qpack.QpackEncoder;
const QpackDecoder = qpack.QpackDecoder;

// Import stream definition
const Stream = @import("stream.zig").QuicStream;

const handler = @import("handler.zig");
const Http3Handler = handler.Http3Handler;

// Import QUIC library interface from our implementation
const quic = @import("../quic/mod.zig");

/// Represents a HTTP/3 connection over QUIC
pub const QuicConnection = struct {
    allocator: Allocator,
    server: *Server,
    async_io: *AsyncIo,
    udp_fd: std.posix.fd_t,
    remote_address: std.net.Address,

    // QUIC library connection state
    quic_conn: ?*quic.Connection,

    // Connection lifecycle state
    state: State,

    // Active HTTP/3 streams associated with this connection
    streams: std.AutoHashMap(u64, *Stream),

    // HTTP/3 specific connection state
    settings: Settings,

    // QPACK encoder and decoder instances
    qpack_encoder: ?*QpackEncoder,
    qpack_decoder: ?*QpackDecoder,

    // Control streams
    control_stream: ?*Stream,
    qpack_encoder_stream: ?*Stream,
    qpack_decoder_stream: ?*Stream,

    // Reference to the current timer task
    timer_task: ?*Task,

    pub const State = enum {
        connecting, // QUIC handshake in progress
        active, // Connection established, ready for streams
        closing, // Graceful shutdown initiated
        closed, // Connection fully closed
    };

    /// Initializes a new HTTP/3 connection wrapping a QUIC connection.
    /// Called by the server when a new QUIC connection needs to be managed.
    pub fn init(allocator: Allocator, server: *Server, async_io: *AsyncIo, udp_fd: std.posix.fd_t, remote_address: std.net.Address) !*QuicConnection {
        const self = try allocator.create(QuicConnection);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .server = server,
            .async_io = async_io,
            .udp_fd = udp_fd,
            .remote_address = remote_address,
            .quic_conn = null,
            .state = .connecting,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
            .settings = Settings{}, // Default settings
            .qpack_encoder = null,
            .qpack_decoder = null,
            .control_stream = null,
            .qpack_encoder_stream = null,
            .qpack_decoder_stream = null,
            .timer_task = null,
        };

        // Initialize QUIC library connection
        self.quic_conn = try quic.createConnection(allocator, .{
            .role = .server,
            .udp_fd = udp_fd,
            .remote_address = remote_address,
            .user_ctx = self,
            .event_callback = quicEventCallback,
        });

        return self;
    }

    /// Deinitializes the HTTP/3 connection and associated resources.
    pub fn deinit(self: *QuicConnection) void {
        log.debug("Deinitializing HTTP/3 connection for {}", .{self.remote_address});

        // Cancel any pending timer
        if (self.timer_task) |task| {
            self.async_io.cancel(task, .{}) catch {};
            self.timer_task = null;
        }

        // Clean up QUIC library connection resources
        if (self.quic_conn) |conn| {
            quic.destroyConnection(conn);
            self.quic_conn = null;
        }

        // Deinitialize and free all associated streams
        var stream_it = self.streams.valueIterator();
        while (stream_it.next()) |stream| {
            stream.*.deinit();
            self.allocator.destroy(stream.*);
        }
        self.streams.deinit();

        // Deinitialize QPACK encoder/decoder
        if (self.qpack_encoder) |enc| {
            enc.deinit();
            self.allocator.destroy(enc);
        }

        if (self.qpack_decoder) |dec| {
            dec.deinit();
            self.allocator.destroy(dec);
        }

        self.allocator.destroy(self);
    }

    /// Starts the QUIC connection handshake and sets up initial I/O.
    pub fn start(self: *QuicConnection) !void {
        if (self.quic_conn == null) return error.QuicConnectionNotInitialized;

        log.info("Starting HTTP/3 connection for {}", .{self.remote_address});

        // Start QUIC handshake
        try quic.startHandshake(self.quic_conn.?);

        // Schedule the initial timer for connection management
        try self.scheduleTimer();

        // Flush any initial packets (likely TLS ClientHello/ServerHello)
        try self.flushOutgoingPackets();
    }

    /// Timer callback function used by AsyncIo
    fn onTimer(async_io: *AsyncIo, task: *Task) anyerror!void {
        _ = async_io;
        const conn = @as(*QuicConnection, @ptrCast(task.userdata.?));
        conn.timer_task = null;

        // Process any timeouts in the QUIC connection
        if (conn.quic_conn) |quic_conn| {
            try quic.processTimeouts(quic_conn);

            // Handle any events, schedule packets, etc.
            try conn.flushOutgoingPackets();

            // Schedule the next timer
            try conn.scheduleTimer();
        }
    }

    /// Schedules the next timer event for this connection based on QUIC needs
    fn scheduleTimer(self: *QuicConnection) !void {
        if (self.quic_conn == null) return;

        // Cancel any existing timer
        if (self.timer_task) |task| {
            self.async_io.cancel(task, .{}) catch {};
            self.timer_task = null;
        }

        // Get the next timeout from QUIC library
        const next_timeout = quic.getNextTimeout(self.quic_conn.?);
        if (next_timeout) |timeout| {
            // Convert to AsyncIo Timespec
            const timespec = Timespec{
                .sec = @intCast(timeout / std.time.ns_per_s),
                .nsec = @intCast(timeout % std.time.ns_per_s),
            };

            // Schedule timer with AsyncIo
            self.timer_task = try self.async_io.setTimer(timespec, .{
                .ptr = self,
                .cb = onTimer,
            });
        }
    }

    /// Handles incoming UDP data that belongs to this specific QUIC connection.
    /// Called by the server's main UDP receive loop after identifying this connection.
    pub fn handleUdpData(self: *QuicConnection, data: []const u8) !void {
        if (self.quic_conn == null) return error.QuicConnectionNotInitialized;

        log.debug("Connection {*}: Received {} bytes from {}", .{ self, data.len, self.remote_address });

        // Pass the received UDP data to the QUIC library
        try quic.receivePacket(self.quic_conn.?, data);

        // Process any events that might have been triggered by receiving data
        // (events are handled via the callback registered with the QUIC connection)

        // Send any outgoing packets generated as a response
        try self.flushOutgoingPackets();

        // Update the timer as packet processing may have changed timeouts
        try self.scheduleTimer();
    }

    /// Sends any pending outgoing packets from the QUIC library
    fn flushOutgoingPackets(self: *QuicConnection) !void {
        if (self.quic_conn == null) return;

        while (true) {
            // Get next packet from QUIC library
            const packet = quic.getNextOutgoingPacket(self.quic_conn.?) orelse break;
            defer packet.deinit();

            // Use AsyncIo to send the packet
            _ = try self.async_io.write(self.udp_fd, packet.data, .{
                .ptr = self,
                .cb = onPacketSent,
            });
        }
    }

    /// Callback for packet sending completion
    fn onPacketSent(async_io: *AsyncIo, task: *Task) anyerror!void {
        _ = async_io;
        const conn = @as(*QuicConnection, @ptrCast(task.userdata.?));

        if (task.result) |res| {
            const bytes_sent = res.write catch |err| {
                log.err("Error sending QUIC packet: {}", .{err});
                return err;
            };

            log.debug("Sent {} bytes to {}", .{ bytes_sent, conn.remote_address });
        }
    }

    /// Called by the QUIC library via callback when events occur on the connection
    fn quicEventCallback(_: *quic.Connection, event: quic.Event, user_ctx: ?*anyopaque) void {
        const http_conn = @as(*QuicConnection, @ptrCast(user_ctx.?));

        switch (event) {
            .handshake_completed => {
                http_conn.onHandshakeCompleted() catch |err| {
                    log.err("Error handling handshake completion: {}", .{err});
                    http_conn.asyncClose(ErrorCode.internal_error) catch {};
                };
            },
            .new_stream => |stream_info| {
                http_conn.handleNewStream(stream_info.stream_id, stream_info.is_unidirectional) catch |err| {
                    log.err("Error handling new stream: {}", .{err});
                    http_conn.asyncClose(ErrorCode.stream_creation_error) catch {};
                };
            },
            .stream_data => |stream_data| {
                if (http_conn.streams.get(stream_data.stream_id)) |stream| {
                    stream.handleReadData(stream_data.data, stream_data.is_fin) catch |err| {
                        log.err("Error handling stream data: {}", .{err});
                        http_conn.asyncClose(ErrorCode.internal_error) catch {};
                    };
                } else {
                    log.err("Received data for unknown stream {}", .{stream_data.stream_id});
                    http_conn.asyncClose(ErrorCode.protocol_error) catch {};
                }
            },
            .stream_closed => |stream_close| {
                http_conn.handleStreamClose(stream_close.stream_id, stream_close.error_code) catch |err| {
                    log.err("Error handling stream close: {}", .{err});
                };
            },
            .connection_state_change => |state| {
                http_conn.handleConnectionStateChange(state) catch |err| {
                    log.err("Error handling connection state change: {}", .{err});
                };
            },
            .connection_closed => |close_info| {
                log.info("QUIC connection closed: code={d}, reason={s}", .{ close_info.error_code, close_info.reason });
                http_conn.state = .closed;
                http_conn.server.handleHttp3ConnectionClosed(http_conn);
            },
            // Handle other event types as needed
            else => {
                log.debug("Unhandled QUIC event: {}", .{@tagName(event)});
            },
        }
    }

    /// Called when the QUIC handshake is completed successfully
    fn onHandshakeCompleted(self: *QuicConnection) !void {
        log.info("QUIC handshake completed for {}", .{self.remote_address});
        self.state = .active;

        // Initialize QPACK encoder/decoder with default capacity
        self.qpack_encoder = try self.allocator.create(QpackEncoder);
        self.qpack_encoder.* = try QpackEncoder.init(self.allocator, 4096, 100);

        self.qpack_decoder = try self.allocator.create(QpackDecoder);
        self.qpack_decoder.* = try QpackDecoder.init(self.allocator, 4096, 100);

        // Open control streams
        try self.openControlStreams();
    }

    /// Opens the necessary control streams for HTTP/3
    fn openControlStreams(self: *QuicConnection) !void {
        // Open unidirectional control stream
        const control_stream_id = try quic.openStream(self.quic_conn.?, true);
        self.control_stream = try Stream.init(self.allocator, self, control_stream_id, .control);
        try self.streams.put(control_stream_id, self.control_stream.?);

        // Send initial SETTINGS frame on control stream
        try self.sendSettingsFrame();

        // Open QPACK encoder and decoder streams
        const encoder_stream_id = try quic.openStream(self.quic_conn.?, true);
        self.qpack_encoder_stream = try Stream.init(self.allocator, self, encoder_stream_id, .encoder);
        try self.streams.put(encoder_stream_id, self.qpack_encoder_stream.?);

        const decoder_stream_id = try quic.openStream(self.quic_conn.?, true);
        self.qpack_decoder_stream = try Stream.init(self.allocator, self, decoder_stream_id, .decoder);
        try self.streams.put(decoder_stream_id, self.qpack_decoder_stream.?);
    }

    /// Sends the initial SETTINGS frame on the control stream
    fn sendSettingsFrame(self: *QuicConnection) !void {
        if (self.control_stream == null) return error.ControlStreamNotInitialized;

        const settings_frame = Frame{ .settings = .{
            .max_field_section_size = self.settings.max_field_section_size,
            .qpack_max_table_capacity = self.settings.qpack_max_table_capacity,
            .qpack_blocked_streams = self.settings.qpack_blocked_streams,
            .enable_connect_protocol = self.settings.enable_connect_protocol,
            .h3_datagram = self.settings.h3_datagram,
        } };

        var buf: [128]u8 = undefined;
        const written = try writeFrame(&buf, settings_frame);
        try self.sendStreamData(self.control_stream.?.stream_id, buf[0..written], false);
    }

    /// Called by the QUIC library when a new stream is received from the peer.
    fn handleNewStream(self: *QuicConnection, stream_id: u64, is_unidirectional: bool) !void {
        // Determine the HTTP/3 stream type based on ID and direction
        var stream_type: ?StreamType = null;

        if (is_unidirectional) {
            // For unidirectional streams, we'll read the stream type from the first byte
            // But for known control streams, we can predict their type:
            if (stream_id == 0) stream_type = .control else if (stream_id == 2) stream_type = .encoder else if (stream_id == 3) stream_type = .decoder;
            // For other unidirectional streams, the type will be determined when first data arrives
        }

        log.info("New QUIC stream {} opened (unidirectional: {}, H3 type: {})", .{ stream_id, is_unidirectional, stream_type });

        if (self.streams.contains(stream_id)) {
            log.warn("Received new stream with existing ID {}", .{stream_id});
            return self.asyncClose(ErrorCode.stream_creation_error);
        }

        // Create a new internal Stream instance
        const new_stream = try Stream.init(self.allocator, self, stream_id, stream_type);
        errdefer {
            new_stream.deinit();
            self.allocator.destroy(new_stream);
        }

        // Store the stream in our map
        try self.streams.put(stream_id, new_stream);

        // Delegate stream handling to the Http3Handler
        if (self.server.http3_handler) |h3_handler| {
            try h3_handler.handleNewStream(new_stream);
        } else {
            log.err("Http3Handler not initialized on server", .{});
            return error.HandlerNotInitialized;
        }
    }

    /// Called by a Stream when it needs to send data over the underlying QUIC stream.
    pub fn sendStreamData(self: *QuicConnection, stream_id: u64, data: []const u8, is_fin: bool) !void {
        if (self.quic_conn == null) return error.QuicConnectionNotInitialized;

        log.debug("Connection {*}: Sending {} bytes on stream {} (fin={})", .{ self, data.len, stream_id, is_fin });

        try quic.sendStreamData(self.quic_conn.?, stream_id, data, is_fin);

        // Make sure to flush any generated packets
        try self.flushOutgoingPackets();
    }

    /// Handles connection state changes from the QUIC library
    fn handleConnectionStateChange(self: *QuicConnection, state: quic.ConnectionState) !void {
        log.debug("QUIC connection state changed to {}", .{@tagName(state)});

        switch (state) {
            .handshaking => {
                self.state = .connecting;
            },
            .connected => {
                self.state = .active;
            },
            .closing => {
                self.state = .closing;
            },
            .closed => {
                self.state = .closed;
                self.server.handleHttp3ConnectionClosed(self);
            },
            // Other states as needed
        }
    }

    /// Called when a stream is closed by the peer
    fn handleStreamClose(self: *QuicConnection, stream_id: u64, error_code: u64) !void {
        if (self.streams.get(stream_id)) |stream_ptr| {
            log.info("QUIC stream {} closed (error code: {})", .{ stream_id, error_code });

            // For control streams, this might be fatal
            if (stream_ptr.stream_type) |stream_type| {
                switch (stream_type) {
                    .control => {
                        // Control stream closure is a connection error
                        log.err("Control stream {} closed unexpectedly", .{stream_id});
                        return self.asyncClose(ErrorCode.closed_critical_stream);
                    },
                    .encoder, .decoder => {
                        // QPACK stream closures are also connection errors
                        log.err("QPACK stream {} closed unexpectedly", .{stream_id});
                        return self.asyncClose(ErrorCode.closed_critical_stream);
                    },
                    else => {}, // Other stream types can close normally
                }
            }

            // Deinitialize and clean up the stream
            stream_ptr.deinit();
            _ = self.streams.remove(stream_id);
            self.allocator.destroy(stream_ptr);
        } else {
            log.warn("Attempted to close non-existent QUIC stream {}", .{stream_id});
        }
    }

    /// Initiate a graceful or immediate closure of the connection
    pub fn asyncClose(self: *QuicConnection, error_code: ErrorCode) !void {
        if (self.state == .closed or self.state == .closing) {
            return; // Already closing or closed
        }

        self.state = .closing;
        const code_value = @intFromEnum(error_code);
        log.info("Initiating HTTP/3 connection closure with error code {}", .{code_value});

        if (self.quic_conn) |conn| {
            try quic.closeConnection(conn, code_value, "HTTP/3 error");

            // Make sure any generated packets are sent immediately
            try self.flushOutgoingPackets();
        }
    }

    /// Opens a new stream for sending data
    pub fn openStream(self: *QuicConnection, is_unidirectional: bool) !*Stream {
        if (self.quic_conn == null) return error.QuicConnectionNotInitialized;

        // Open the QUIC stream
        const stream_id = try quic.openStream(self.quic_conn.?, is_unidirectional);

        // Determine stream type based on direction and our role as server
        const stream_type: ?StreamType = if (is_unidirectional)
            .push // Server-initiated unidirectional streams are push streams
        else
            null; // Server-initiated bidirectional streams are standard streams

        // Create our Stream wrapper
        const stream = try Stream.init(self.allocator, self, stream_id, stream_type);

        // Store in our streams map
        try self.streams.put(stream_id, stream);

        return stream;
    }
};
