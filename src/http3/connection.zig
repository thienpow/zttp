// src/http3/connection.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.http3_connection);

const AsyncIo = @import("../async/async.zig").AsyncIo;
const Task = @import("../async/task.zig").Task;
const Timespec = @import("../async/async.zig").Timespec;

const Server = @import("../core/server.zig").Server;

const types = @import("types.zig");
const Http3Error = types.Http3Error;

const http3_error = @import("error.zig");
const ErrorCode = http3_error.ErrorCode;

const settings = @import("settings.zig");
const Settings = settings.Settings;

const frame = @import("frame.zig");
const readFrame = frame.readFrame;
const writeFrame = frame.writeFrame;

const qpack = @import("qpack/mod.zig");
const QpackEncoder = qpack.QpackEncoder;
const QpackDecoder = qpack.QpackDecoder;

const Http3Stream = @import("stream.zig").Http3Stream;

const handler = @import("handler.zig");
const Http3Handler = handler.Http3Handler;

const quic = @import("quic/mod.zig");

/// Manages an HTTP/3 connection over QUIC.
pub const Http3Connection = struct {
    allocator: Allocator,
    server: *Server,
    async_io: *AsyncIo,
    udp_fd: std.posix.fd_t,
    remote_address: std.net.Address,
    quic_conn: *quic.Connection,
    state: State,
    streams: std.AutoHashMap(u64, *Http3Stream),
    settings: Settings,
    qpack_encoder: ?*QpackEncoder,
    qpack_decoder: ?*QpackDecoder,
    control_stream: ?*Http3Stream,
    qpack_encoder_stream: ?*Http3Stream,
    qpack_decoder_stream: ?*Http3Stream,
    timer_task: ?*Task,

    pub const State = enum {
        connecting,
        active,
        closing,
        closed,
    };

    /// Initializes a new HTTP/3 connection.
    pub fn init(allocator: Allocator, server: *Server, async_io: *AsyncIo, udp_fd: std.posix.fd_t, remote_address: std.net.Address) !*Http3Connection {
        const self = try allocator.create(Http3Connection);
        errdefer allocator.destroy(self);

        const quic_conn = try quic.createConnection(allocator, .{
            .role = .server,
            .udp_fd = udp_fd,
            .remote_address = remote_address,
            .user_ctx = self,
            .event_callback = quicEventCallback,
        });

        self.* = .{
            .allocator = allocator,
            .server = server,
            .async_io = async_io,
            .udp_fd = udp_fd,
            .remote_address = remote_address,
            .quic_conn = quic_conn,
            .state = .connecting,
            .streams = std.AutoHashMap(u64, *Http3Stream).init(allocator),
            .settings = Settings{},
            .qpack_encoder = null,
            .qpack_decoder = null,
            .control_stream = null,
            .qpack_encoder_stream = null,
            .qpack_decoder_stream = null,
            .timer_task = null,
        };

        return self;
    }

    /// Deinitializes the connection and frees resources.
    pub fn deinit(self: *Http3Connection) void {
        log.debug("Deinitializing connection for {}", .{self.remote_address});

        if (self.timer_task) |task| {
            self.async_io.cancel(task, .{}) catch {};
        }

        quic.destroyConnection(self.quic_conn);
        defer self.streams.deinit();
        var stream_it = self.streams.valueIterator();
        while (stream_it.next()) |stream| {
            stream.*.deinit();
            self.allocator.destroy(stream.*);
        }

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

    /// Starts the QUIC handshake and schedules timers.
    pub fn start(self: *Http3Connection) !void {
        log.info("Starting connection for {}", .{self.remote_address});
        try quic.startHandshake(self.quic_conn);
        try self.scheduleTimer();
        try self.flushOutgoingPackets();
    }

    /// Handles timer events for QUIC timeouts.
    fn onTimer(async_io: *AsyncIo, task: *Task) !void {
        _ = async_io;
        const conn = @as(*Http3Connection, @ptrCast(@alignCast(task.userdata.?)));
        conn.timer_task = null;
        try quic.processTimeouts(conn.quic_conn);
        try conn.flushOutgoingPackets();
        try conn.scheduleTimer();
    }

    /// Schedules the next QUIC timeout.
    fn scheduleTimer(self: *Http3Connection) !void {
        if (self.timer_task) |task| {
            self.async_io.cancel(task, .{}) catch {};
            self.timer_task = null;
        }

        if (quic.getNextTimeout(self.quic_conn)) |timeout| {
            const timespec = Timespec{
                .sec = @intCast(@divTrunc(timeout, std.time.ns_per_s)),
                .nsec = @intCast(@rem(timeout, std.time.ns_per_s)),
            };
            self.timer_task = try self.async_io.setTimer(timespec, .{
                .ptr = self,
                .cb = onTimer,
            });
        }
    }

    /// Processes incoming UDP data.
    pub fn handleUdpData(self: *Http3Connection, data: []const u8) !void {
        log.debug("Received {d} bytes from {}", .{ data.len, self.remote_address });
        try quic.receivePacket(self.quic_conn, data);
        try self.flushOutgoingPackets();
        try self.scheduleTimer();
    }

    /// Sends queued QUIC packets.
    fn flushOutgoingPackets(self: *Http3Connection) !void {
        while (true) {
            const packet = quic.getNextOutgoingPacket(self.quic_conn) orelse break;
            defer packet.deinit();
            _ = try self.async_io.write(self.udp_fd, packet.raw_data.items, .{
                .ptr = self,
                .cb = onPacketSent,
            });
        }
    }

    /// Handles packet send completion.
    fn onPacketSent(async_io: *AsyncIo, task: *Task) !void {
        _ = async_io;
        const conn = @as(*Http3Connection, @ptrCast(@alignCast(task.userdata.?)));
        if (task.result) |res| {
            const bytes_sent = res.write catch |err| {
                log.err("Error sending packet: {}", .{err});
                return;
            };
            log.debug("Sent {d} bytes to {}", .{ bytes_sent, conn.remote_address });
        }
    }

    /// QUIC event callback dispatcher.
    fn quicEventCallback(_: *quic.Connection, event: quic.Event, user_ctx: ?*anyopaque) void {
        const conn = @as(*Http3Connection, @ptrCast(@alignCast(user_ctx.?)));
        switch (event) {
            .handshake_completed => conn.handleHandshakeCompleted() catch |err| conn.logAndClose(err, .internal_error),
            .new_stream => |info| conn.handleNewStream(info.stream_id, info.is_unidirectional) catch |err| conn.logAndClose(err, .stream_creation_error),
            .stream_data => |data| conn.handleStreamData(data.stream_id, data.data, data.is_fin) catch |err| conn.logAndClose(err, .internal_error),
            .stream_closed => |close| conn.handleStreamClose(close.stream_id, close.error_code) catch |err| conn.logAndClose(err, .internal_error),
            .connection_state_change => |state| conn.handleConnectionStateChange(state) catch |err| conn.logAndClose(err, .internal_error),
            .connection_closed => |info| {
                log.info("Connection closed: code={d}, reason={s}", .{ info.error_code, info.reason });
                conn.state = .closed;
                conn.server.handleHttp3ConnectionClosed(conn);
            },
            else => log.debug("Unhandled QUIC event: {}", .{@tagName(event)}),
        }
    }

    /// Logs error and closes connection.
    fn logAndClose(self: *Http3Connection, err: anyerror, code: ErrorCode) void {
        log.err("Error: {}", .{err});
        self.asyncClose(code) catch {};
    }

    /// Handles QUIC handshake completion.
    fn handleHandshakeCompleted(self: *Http3Connection) !void {
        log.info("Handshake completed for {}", .{self.remote_address});
        self.state = .active;

        self.qpack_encoder = try self.allocator.create(QpackEncoder);
        errdefer self.allocator.destroy(self.qpack_encoder.?);
        self.qpack_encoder.? = try QpackEncoder.init(self.allocator, self.settings.qpack_max_table_capacity, self.settings.qpack_blocked_streams);

        self.qpack_decoder = try self.allocator.create(QpackDecoder);
        errdefer self.allocator.destroy(self.qpack_decoder.?);
        self.qpack_decoder.? = try QpackDecoder.init(self.allocator, self.settings.qpack_max_table_capacity, self.settings.qpack_blocked_streams);

        if (self.server.http3_handler) |h3_handler| {
            h3_handler.setQpackInstances(self.qpack_encoder.?, self.qpack_decoder.?);
        } else {
            return error.HandlerNotInitialized;
        }

        try self.openControlStreams();
    }

    /// Opens HTTP/3 control and QPACK streams.
    fn openControlStreams(self: *Http3Connection) !void {
        const control_stream = try quic.openStream(self.quic_conn, true);
        self.control_stream = try Http3Stream.init(self, control_stream.stream_id, .control);
        try self.streams.put(control_stream.stream_id, self.control_stream.?);

        const encoder_stream = try quic.openStream(self.quic_conn, true);
        self.qpack_encoder_stream = try Http3Stream.init(self, encoder_stream.stream_id, .encoder);
        try self.streams.put(encoder_stream.stream_id, self.qpack_encoder_stream.?);

        const decoder_stream = try quic.openStream(self.quic_conn, true);
        self.qpack_decoder_stream = try Http3Stream.init(self, decoder_stream.stream_id, .decoder);
        try self.streams.put(decoder_stream.stream_id, self.qpack_decoder_stream.?);

        try self.sendSettingsFrame();
    }

    /// Sends the HTTP/3 settings frame.
    fn sendSettingsFrame(self: *Http3Connection) !void {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();
        try writeFrame(self.allocator, buf.writer(), .{ .settings = self.settings });
        try self.sendStreamData(self.control_stream.?.stream_id, buf.items, false);
    }

    /// Handles a new QUIC stream.
    fn handleNewStream(self: *Http3Connection, stream_id: u64, is_unidirectional: bool) !void {
        const stream_type: ?types.StreamType = if (is_unidirectional) .control else .request; // Adjust based on actual stream type logic
        log.info("New stream {d} (unidirectional: {}, type: {?})", .{ stream_id, is_unidirectional, stream_type });

        if (self.streams.contains(stream_id)) {
            return self.asyncClose(.stream_creation_error);
        }

        const stream = try Http3Stream.init(self, stream_id, stream_type);
        errdefer stream.deinit();
        try self.streams.put(stream_id, stream);

        if (self.server.http3_handler) |h3_handler| {
            try h3_handler.handleNewStream(stream);
        }
    }

    /// Handles incoming stream data.
    fn handleStreamData(self: *Http3Connection, stream_id: u64, data: []const u8, is_fin: bool) !void {
        if (self.streams.get(stream_id)) |stream| {
            try stream.handleReadData(data, is_fin);
        } else {
            log.err("Data for unknown stream {d}", .{stream_id});
            return self.asyncClose(.protocol_error);
        }
    }

    /// Sends data on a stream.
    pub fn sendStreamData(self: *Http3Connection, stream_id: u64, data: []const u8, is_fin: bool) !void {
        log.debug("Sending {d} bytes on stream {d} (fin={})", .{ data.len, stream_id, is_fin });
        try self.quic_conn.sendStreamData(stream_id, data, is_fin);
        try self.flushOutgoingPackets();
    }

    /// Handles QUIC connection state changes.
    fn handleConnectionStateChange(self: *Http3Connection, state: quic.ConnectionState) !void {
        log.debug("QUIC state changed to {}", .{@tagName(state)});
        self.state = switch (state) {
            .handshaking => .connecting,
            .connected => .active,
            .closing => .closing,
            .closed => .closed,
        };
        if (self.state == .closed) {
            self.server.handleHttp3ConnectionClosed(self);
        }
    }

    /// Handles stream closure.
    fn handleStreamClose(self: *Http3Connection, stream_id: u64, error_code: u64) !void {
        if (self.streams.get(stream_id)) |stream| {
            log.info("Stream {d} closed (code: {d})", .{ stream_id, error_code });
            if (stream.stream_type) |st| switch (st) {
                .control, .encoder, .decoder => {
                    return self.asyncClose(.closed_critical_stream);
                },
                else => {},
            };
            stream.deinit();
            _ = self.streams.remove(stream_id);
            self.allocator.destroy(stream);
        }
    }

    /// Closes the connection asynchronously.
    pub fn asyncClose(self: *Http3Connection, error_code: ErrorCode) !void {
        if (self.state == .closed or self.state == .closing) return;
        self.state = .closing;
        const code_value = @intFromEnum(error_code);
        log.info("Closing connection with code {d}", .{code_value});
        try quic.closeConnection(self.quic_conn, code_value, "HTTP/3 error");
        try self.flushOutgoingPackets();
    }

    /// Opens a new stream.
    pub fn openStream(self: *Http3Connection, is_unidirectional: bool) !*Http3Stream {
        const stream_id = try quic.openStream(self.quic_conn, is_unidirectional);
        const stream_type: ?types.StreamType = if (is_unidirectional) .push else .request;
        const stream = try Http3Stream.init(self, stream_id, stream_type);
        try self.streams.put(stream_id, stream);
        return stream;
    }
};
