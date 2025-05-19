// src/http3/quic/connection.zig
// QUIC connection management per RFC 9000

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.quic_connection);

const event = @import("event.zig");
const Event = event.Event;
const EventCallback = event.EventCallback;

const crypto = @import("crypto.zig");
const TlsContext = crypto.TlsContext;

const packet = @import("packet.zig");
const Packet = packet.Packet;
const PacketType = packet.PacketType;

const util = @import("util.zig");
const parse_vli = util.parseVli;
const serialize_vli = util.serializeVli;

const stream_mod = @import("stream.zig");
const Stream = stream_mod.Stream;

/// QUIC connection states
pub const ConnectionState = enum {
    handshaking,
    connected,
    closing,
    closed,
    draining,
};

/// QUIC connection role
pub const ConnectionRole = enum {
    client,
    server,
};

/// Options for creating a QUIC connection
pub const ConnectionOptions = struct {
    role: ConnectionRole,
    udp_fd: std.posix.fd_t,
    remote_address: std.net.Address,
    user_ctx: ?*anyopaque,
    event_callback: EventCallback,
    version: u32 = 0x00000001, // QUIC version 1
    max_idle_timeout_ms: u64 = 30_000,
    max_udp_payload_size: u16 = 1350,
    initial_max_data: u64 = 10_000_000,
    initial_max_stream_data_bidi_local: u64 = 1_000_000,
    initial_max_stream_data_bidi_remote: u64 = 1_000_000,
    initial_max_stream_data_uni: u64 = 1_000_000,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    initial_congestion_window: u64 = 12000,
};

/// QUIC connection structure
pub const Connection = struct {
    allocator: Allocator,
    role: ConnectionRole,
    state: ConnectionState,
    udp_fd: std.posix.fd_t,
    remote_address: std.net.Address,
    user_ctx: ?*anyopaque,
    event_callback: EventCallback,
    src_connection_id: [16]u8,
    dst_connection_id: [16]u8,
    src_connection_id_len: u8,
    dst_connection_id_len: u8,
    version: u32,
    max_idle_timeout_ms: u64,
    max_udp_payload_size: u16,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    tls_ctx: *TlsContext,
    bytes_in_flight: u64,
    congestion_window: u64, // TODO: Implement congestion control
    next_packet_number: u64,
    streams: std.AutoHashMap(u64, *Stream),
    next_local_stream_id: u64,
    outgoing_packets: std.ArrayList(*Packet),
    latest_activity_time: i64,
    next_timeout: ?i64,
    smoothed_rtt: i64, // TODO: Implement RTT estimation
    rtt_variance: i64, // TODO: Implement RTT estimation
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,

    /// Initializes a new QUIC connection.
    pub fn init(allocator: Allocator, options: ConnectionOptions) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        var src_conn_id: [16]u8 = undefined;
        std.crypto.random.bytes(&src_conn_id);
        const src_conn_id_len: u8 = if (options.role == .client) 8 else 0;

        var dst_conn_id: [16]u8 = undefined;
        if (options.role == .client) {
            std.crypto.random.bytes(&dst_conn_id);
        }

        const tls_ctx = try crypto.createTlsContext(allocator, options.role == .server);
        errdefer crypto.destroyTlsContext(tls_ctx);

        conn.* = .{
            .allocator = allocator,
            .role = options.role,
            .state = .handshaking,
            .udp_fd = options.udp_fd,
            .remote_address = options.remote_address,
            .user_ctx = options.user_ctx,
            .event_callback = options.event_callback,
            .src_connection_id = src_conn_id,
            .dst_connection_id = dst_conn_id,
            .src_connection_id_len = src_conn_id_len,
            .dst_connection_id_len = if (options.role == .client) 0 else 8,
            .version = options.version,
            .max_idle_timeout_ms = options.max_idle_timeout_ms,
            .max_udp_payload_size = options.max_udp_payload_size,
            .initial_max_data = options.initial_max_data,
            .initial_max_stream_data_bidi_local = options.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = options.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = options.initial_max_stream_data_uni,
            .initial_max_streams_bidi = options.initial_max_streams_bidi,
            .initial_max_streams_uni = options.initial_max_streams_uni,
            .tls_ctx = tls_ctx,
            .bytes_in_flight = 0,
            .congestion_window = options.initial_congestion_window,
            .next_packet_number = 0,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
            .next_local_stream_id = if (options.role == .client) 0 else 1,
            .outgoing_packets = std.ArrayList(*Packet).init(allocator),
            .latest_activity_time = @intCast(std.time.nanoTimestamp()),
            .next_timeout = null,
            .smoothed_rtt = 500 * std.time.ns_per_ms,
            .rtt_variance = 250 * std.time.ns_per_ms,
            .packets_sent = 0,
            .packets_received = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
        };

        return conn;
    }

    /// Cleans up connection resources.
    pub fn deinit(self: *Connection) void {
        defer self.streams.deinit();
        var stream_it = self.streams.valueIterator();
        while (stream_it.next()) |stream| {
            stream_mod.destroyStream(stream.*);
        }

        defer self.outgoing_packets.deinit();
        for (self.outgoing_packets.items) |pkt| {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        crypto.destroyTlsContext(self.tls_ctx);
        self.allocator.destroy(self);
    }

    /// Processes incoming packet data.
    pub fn processPacket(self: *Connection, data: []const u8) !void {
        if (data.len == 0) return error.EmptyPacket;

        const pkt = try packet.parsePacket(self.allocator, data);
        defer packet.destroyPacket(pkt);

        self.latest_activity_time = @intCast(std.time.nanoTimestamp());
        self.bytes_received += data.len;
        self.packets_received += 1;

        log.debug("Processing packet type: {}", .{pkt.packet_type});

        switch (pkt.packet_type) {
            .initial, .handshake, .zero_rtt, .retry => try self.processLongHeaderPacket(pkt),
            .short_header => try self.processShortHeaderPacket(pkt),
            .version_negotiation => return error.VersionNegotiation,
            .connection_close => try self.processConnectionClosePacket(pkt),
        }

        self.updateTimeout();
    }

    /// Processes long header packets (Initial, Handshake, 0-RTT, Retry).
    fn processLongHeaderPacket(self: *Connection, pkt: *Packet) !void {
        const header_result = try self.removeHeaderProtection(pkt.packet_type, pkt.raw_data.items, 0, 0);
        pkt.packet_number = header_result.packet_number;

        const decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, pkt.raw_data.items);
        defer self.allocator.free(decrypted_payload);

        try self.processFrames(decrypted_payload);

        if (self.state == .handshaking) {
            if (self.role == .server and pkt.packet_type == .initial) {
                self.state = .connected;
                self.event_callback(self, .handshake_completed, self.user_ctx);
                try self.simulateClientStreams();
            } else if (pkt.packet_type == .handshake) {
                self.state = .connected;
                self.event_callback(self, .handshake_completed, self.user_ctx);
            }
        }
    }

    /// Processes short header packets (1-RTT).
    fn processShortHeaderPacket(self: *Connection, pkt: *Packet) !void {
        const header_result = try self.removeHeaderProtection(pkt.packet_type, pkt.raw_data.items, 0, 0);
        pkt.packet_number = header_result.packet_number;

        const decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, pkt.raw_data.items);
        defer self.allocator.free(decrypted_payload);

        try self.processFrames(decrypted_payload);
    }

    /// Processes CONNECTION_CLOSE packets.
    fn processConnectionClosePacket(self: *Connection, pkt: *Packet) !void {
        var cursor: usize = 0;
        var bytes_read: usize = 0;
        var error_code: u64 = 0;
        var reason: []const u8 = "Malformed CONNECTION_CLOSE packet";

        if (pkt.raw_data.items.len > cursor) {
            error_code = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
            cursor += bytes_read;

            if (pkt.raw_data.items.len > cursor) {
                _ = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read); // Frame type
                cursor += bytes_read;

                if (pkt.raw_data.items.len > cursor) {
                    const reason_len = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
                    cursor += bytes_read;

                    if (pkt.raw_data.items.len >= cursor + @as(usize, reason_len)) {
                        reason = pkt.raw_data.items[cursor .. cursor + @as(usize, reason_len)];
                    }
                }
            }
        }

        if (self.state != .closed) {
            self.state = .closed;
            self.event_callback(self, .{ .connection_closed = .{
                .error_code = error_code,
                .reason = reason,
            } }, self.user_ctx);
        }
    }

    /// Parses a single QUIC frame from payload.
    fn parseFrame(self: *Connection, data: []const u8, bytes_read_out: *usize) !packet.Frame {
        if (data.len == 0) return error.BufferTooShort;

        var cursor: usize = 0;
        const frame_type_byte = data[0];

        if (frame_type_byte == 0x00) {
            bytes_read_out.* = 1;
            return .{ .padding = {} };
        }
        if (frame_type_byte == 0x01) {
            bytes_read_out.* = 1;
            return .{ .ping = {} };
        }

        var vli_read_len: usize = 0;
        const frame_type = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;

        switch (frame_type) {
            0x02, 0x03 => return try self.parseAckFrame(data, cursor, bytes_read_out),
            0x05 => return try self.parseStopSendingFrame(data, cursor, bytes_read_out),
            0x06 => return try self.parseCryptoFrame(data, cursor, bytes_read_out),
            0x08...0x0f => return try self.parseStreamFrame(data, cursor, frame_type, bytes_read_out),
            0x0c => return try self.parseMaxStreamDataFrame(data, cursor, bytes_read_out),
            else => return error.UnknownFrameType,
        }
    }

    /// Parses ACK frame.
    fn parseAckFrame(self: *Connection, data: []const u8, cursor_in: usize, bytes_read_out: *usize) !packet.Frame {
        var cursor = cursor_in;
        var vli_read_len: usize = 0;

        const largest_ack = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;
        const ack_delay = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;
        const ack_range_count = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;
        const first_ack_range = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;

        var ack_ranges = std.ArrayList(struct { gap: u64, length: u64 }).init(self.allocator);
        errdefer ack_ranges.deinit();

        var i: u64 = 0;
        while (i < ack_range_count) : (i += 1) {
            const gap = try parse_vli(data[cursor..], &vli_read_len);
            cursor += vli_read_len;
            const length = try parse_vli(data[cursor..], &vli_read_len);
            cursor += vli_read_len;
            try ack_ranges.append(.{ .gap = gap, .length = length });
        }

        bytes_read_out.* = cursor;
        return .{ .ack = .{
            .largest_acknowledged = largest_ack,
            .ack_delay = ack_delay,
            .ack_range_count = ack_range_count,
            .first_ack_range = first_ack_range,
            .ack_ranges = ack_ranges,
        } };
    }

    /// Parses STOP_SENDING frame.
    fn parseStopSendingFrame(self: *Connection, data: []const u8, cursor_in: usize, bytes_read_out: *usize) !packet.Frame {
        _ = self;
        var cursor = cursor_in;
        var vli_read_len: usize = 0;

        const stream_id = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;
        const error_code = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;

        bytes_read_out.* = cursor;
        return .{ .stop_sending = .{
            .stream_id = stream_id,
            .error_code = error_code,
        } };
    }

    /// Parses CRYPTO frame.
    fn parseCryptoFrame(self: *Connection, data: []const u8, cursor_in: usize, bytes_read_out: *usize) !packet.Frame {
        _ = self;
        var cursor = cursor_in;
        var vli_read_len: usize = 0;

        const offset = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;
        const length = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;
        if (data.len < cursor + @as(usize, length)) return error.BufferTooShort;
        const crypto_data = data[cursor .. cursor + @as(usize, length)];
        cursor += @as(usize, length);

        bytes_read_out.* = cursor;
        return .{ .crypto = .{ .offset = offset, .data = crypto_data } };
    }

    /// Parses STREAM frame.
    fn parseStreamFrame(self: *Connection, data: []const u8, cursor_in: usize, frame_type: u64, bytes_read_out: *usize) !packet.Frame {
        _ = self;
        var cursor = cursor_in;
        var vli_read_len: usize = 0;

        const flags = @as(u8, @intCast(frame_type)) & 0x07;
        const has_offset = (flags & 0x01) != 0;
        const has_length = (flags & 0x02) != 0;
        const is_fin = (flags & 0x04) != 0;

        const stream_id = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;

        var offset: u64 = 0;
        if (has_offset) {
            offset = try parse_vli(data[cursor..], &vli_read_len);
            cursor += vli_read_len;
        }

        var stream_data_end: usize = data.len;
        var length: u64 = 0;
        if (has_length) {
            length = try parse_vli(data[cursor..], &vli_read_len);
            cursor += vli_read_len;
            stream_data_end = cursor + @as(usize, length);
            if (data.len < stream_data_end) return error.BufferTooShort;
        }

        const stream_data = data[cursor..stream_data_end];
        cursor = stream_data_end;

        bytes_read_out.* = cursor;
        return .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .length = @as(u64, stream_data.len),
            .fin = is_fin,
            .data = stream_data,
        } };
    }

    /// Parses MAX_STREAM_DATA frame.
    fn parseMaxStreamDataFrame(self: *Connection, data: []const u8, cursor_in: usize, bytes_read_out: *usize) !packet.Frame {
        _ = self;
        var cursor = cursor_in;
        var vli_read_len: usize = 0;

        const stream_id = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;
        const max_data = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;

        bytes_read_out.* = cursor;
        return .{ .max_stream_data = .{
            .stream_id = stream_id,
            .max_data = max_data,
        } };
    }

    /// Processes frames from decrypted payload.
    fn processFrames(self: *Connection, payload: []const u8) !void {
        var cursor: usize = 0;
        while (cursor < payload.len) {
            var bytes_read: usize = 0;
            const frame = try self.parseFrame(payload[cursor..], &bytes_read);
            log.debug("Processing frame: {}", .{@tagName(frame)});
            try self.processFrame(frame);
            cursor += bytes_read;
        }
    }

    /// Processes a single QUIC frame.
    fn processFrame(self: *Connection, frame: packet.Frame) !void {
        switch (frame) {
            .padding => log.debug("Received PADDING frame", .{}),
            .ping => log.debug("Received PING frame", .{}),
            .ack => |ack_frame| {
                log.debug("Received ACK frame, largest_ack={d}", .{ack_frame.largest_acknowledged});
                // TODO: Mark packets as acknowledged for congestion control
                ack_frame.ack_ranges.deinit();
            },
            .crypto => |crypto_frame| try self.processCryptoFrame(crypto_frame),
            .stream => |stream_frame| try self.processStreamFrame(stream_frame),
            .stop_sending => |stop_sending| {
                log.debug("Received STOP_SENDING for stream {d}, code={d}", .{ stop_sending.stream_id, stop_sending.error_code });
                if (self.streams.get(stop_sending.stream_id)) |stream| {
                    try stream.handleStopSending(stop_sending.error_code);
                }
            },
            .max_stream_data => |max_stream_data| {
                log.debug("Received MAX_STREAM_DATA for stream {d}, max={d}", .{ max_stream_data.stream_id, max_stream_data.max_data });
                if (self.streams.get(max_stream_data.stream_id)) |stream| {
                    try stream.updateMaxStreamData(max_stream_data.max_data);
                }
            },
            .raw => log.warn("Received unprocessed frame type", .{}),
        }
    }

    /// Processes CRYPTO frame for TLS handshake.
    fn processCryptoFrame(self: *Connection, frame: packet.CryptoFrame) !void {
        log.debug("Processing CRYPTO frame, offset={d}, len={d}", .{ frame.offset, frame.data.len });
        try crypto.processCryptoData(self.tls_ctx, frame.data, frame.offset);
        if (crypto.isHandshakeComplete(self.tls_ctx)) {
            self.state = .connected;
            self.event_callback(self, .handshake_completed, self.user_ctx);
        }
    }

    /// Processes STREAM frame for stream data.
    fn processStreamFrame(self: *Connection, frame: packet.StreamFrame) !void {
        const is_client_initiated = (frame.stream_id % 2) == 0;
        const is_unidirectional = (frame.stream_id & 0x02) != 0;
        const is_peer_initiated = (self.role == .client and !is_client_initiated) or
            (self.role == .server and is_client_initiated);

        log.debug("Processing STREAM frame, stream={d}, offset={d}, len={d}, fin={}", .{
            frame.stream_id, frame.offset, frame.length, frame.fin,
        });

        var stream = self.streams.get(frame.stream_id);
        if (stream == null and is_peer_initiated) {
            if (is_unidirectional and frame.stream_id >= self.initial_max_streams_uni * 4) {
                return error.StreamLimitExceeded;
            }
            if (!is_unidirectional and frame.stream_id >= self.initial_max_streams_bidi * 4) {
                return error.StreamLimitExceeded;
            }
            stream = try stream_mod.createStream(self.allocator, self, frame.stream_id, is_unidirectional);
            try self.streams.put(frame.stream_id, stream.?);
            self.event_callback(self, .{ .new_stream = .{
                .stream_id = frame.stream_id,
                .is_unidirectional = is_unidirectional,
            } }, self.user_ctx);
        } else if (stream == null) {
            return error.UnknownStream;
        }

        try stream.?.processStreamData(frame.data, frame.offset, frame.fin);
    }

    /// Removes header protection per RFC 9001, Section 5.4.
    fn removeHeaderProtection(
        self: *Connection,
        packet_type: PacketType,
        packet_data: []u8,
        offset_to_first_byte: usize,
        offset_to_pn: usize,
    ) !struct { unprotected_first_byte: u8, pn_length: usize, packet_number: u64 } {
        _ = packet_type;
        if (packet_data.len < offset_to_first_byte + 5) return error.BufferTooShort;

        const hp_key = try crypto.deriveHeaderProtectionKey(self.tls_ctx);
        defer self.allocator.free(hp_key);

        const sample_offset = offset_to_pn + 4;
        if (packet_data.len < sample_offset + 16) return error.BufferTooShort;
        const sample = packet_data[sample_offset .. sample_offset + 16];

        var mask: [5]u8 = undefined;
        try crypto.generateHeaderProtectionMask(hp_key, sample, &mask);

        const first_byte = packet_data[offset_to_first_byte] ^ mask[0];
        const pn_length = @as(usize, (first_byte & 0x03) + 1);

        var packet_number: u64 = 0;
        for (0..pn_length) |i| {
            packet_data[offset_to_pn + i] ^= mask[i + 1];
            packet_number = (packet_number << 8) | @as(u64, packet_data[offset_to_pn + i]);
        }

        return .{
            .unprotected_first_byte = first_byte,
            .pn_length = pn_length,
            .packet_number = packet_number,
        };
    }

    /// Decrypts packet payload per RFC 9001, Section 5.3.
    fn decryptPacketPayload(self: *Connection, packet_type: PacketType, packet_number: u64, encrypted_payload: []const u8) ![]u8 {
        const pp_key = try crypto.derivePacketProtectionKey(self.tls_ctx, packet_type);
        defer self.allocator.free(pp_key);
        const pp_iv = try crypto.derivePacketProtectionIv(self.tls_ctx, packet_type);
        defer self.allocator.free(pp_iv);

        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, pp_iv[0..12]);
        for (0..8) |i| {
            nonce[nonce.len - 1 - i] ^= @as(u8, @intCast((packet_number >> (i * 8)) & 0xFF));
        }

        const header_len = try self.getHeaderLength(packet_type, encrypted_payload);
        const associated_data = encrypted_payload[0..header_len];

        return try crypto.decryptAead(
            self.allocator,
            pp_key,
            nonce,
            encrypted_payload[header_len..],
            associated_data,
        );
    }

    /// Calculates header length for associated data per RFC 9001.
    fn getHeaderLength(self: *Connection, packet_type: PacketType, packet_data: []const u8) !usize {
        var cursor: usize = 0;
        switch (packet_type) {
            .initial, .handshake, .zero_rtt => {
                if (packet_data.len < 6) return error.BufferTooShort;
                cursor += 1; // First byte
                cursor += 4; // Version
                const dcid_len = @as(usize, packet_data[cursor]);
                cursor += 1;
                if (packet_data.len < cursor + dcid_len) return error.BufferTooShort;
                cursor += dcid_len;
                const scid_len = @as(usize, packet_data[cursor]);
                cursor += 1;
                if (packet_data.len < cursor + scid_len) return error.BufferTooShort;
                cursor += scid_len;

                if (packet_type == .initial) {
                    var vli_read_len: usize = 0;
                    const token_len = try parse_vli(packet_data[cursor..], &vli_read_len);
                    cursor += vli_read_len;
                    if (packet_data.len < cursor + @as(usize, token_len)) return error.BufferTooShort;
                    cursor += @as(usize, token_len);
                }

                var vli_read_len: usize = 0;
                _ = try parse_vli(packet_data[cursor..], &vli_read_len);
                cursor += vli_read_len;
                return cursor;
            },
            .retry => {
                if (packet_data.len < 6) return error.BufferTooShort;
                cursor += 1; // First byte
                cursor += 4; // Version
                const dcid_len = @as(usize, packet_data[cursor]);
                cursor += 1;
                if (packet_data.len < cursor + dcid_len) return error.BufferTooShort;
                cursor += dcid_len;
                const scid_len = @as(usize, packet_data[cursor]);
                cursor += 1;
                if (packet_data.len < cursor + scid_len) return error.BufferTooShort;
                cursor += scid_len;
                if (packet_data.len < cursor + 16) return error.BufferTooShort;
                cursor = packet_data.len - 16;
                cursor += 16;
                return cursor;
            },
            .short_header => {
                if (packet_data.len < 2) return error.BufferTooShort;
                const first_byte = packet_data[0];
                const pn_length = @as(usize, (first_byte & 0x03) + 1);
                const header_len = 1 + @as(usize, self.dst_connection_id_len) + pn_length;
                if (packet_data.len < header_len) return error.BufferTooShort;
                return header_len;
            },
            else => return error.InvalidPacketType,
        }
    }

    /// Queues TLS handshake response for clients.
    fn queueHandshakeResponse(self: *Connection) !void {
        const pkt = try Packet.create(self.allocator, .handshake);
        errdefer {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        const crypto_data = try crypto.generateTlsHandshakeData(self.tls_ctx, self.allocator);
        defer self.allocator.free(crypto_data);

        const frame = packet.Frame{ .crypto = .{
            .offset = 0,
            .data = crypto_data,
        } };
        try pkt.frames.append(frame);
        try self.outgoing_packets.append(pkt);
    }

    /// Simulates client-initiated streams for server.
    fn simulateClientStreams(self: *Connection) !void {
        try self.notifyNewStream(0, true); // Control stream
        try self.notifyNewStream(2, true); // Encoder stream
        try self.notifyNewStream(3, true); // Decoder stream
        try self.notifyNewStream(4, false); // Request stream
    }

    /// Notifies about a new stream.
    fn notifyNewStream(self: *Connection, stream_id: u64, is_unidirectional: bool) !void {
        const stream = try stream_mod.createStream(self.allocator, self, stream_id, is_unidirectional);
        try self.streams.put(stream_id, stream);
        self.event_callback(self, .{ .new_stream = .{
            .stream_id = stream_id,
            .is_unidirectional = is_unidirectional,
        } }, self.user_ctx);
    }

    /// Retrieves the next outgoing packet.
    pub fn getNextOutgoingPacket(self: *Connection) ?*Packet {
        if (self.outgoing_packets.items.len == 0) return null;
        const pkt = self.outgoing_packets.orderedRemove(0);
        self.packets_sent += 1;
        self.bytes_sent += pkt.raw_data.items.len;
        return pkt;
    }

    /// Updates the idle timeout.
    fn updateTimeout(self: *Connection) void {
        const idle_timeout_ns: i64 = @intCast(self.max_idle_timeout_ms * std.time.ns_per_ms);
        self.next_timeout = self.latest_activity_time + idle_timeout_ns;
    }

    /// Processes connection timeouts.
    pub fn processTimeouts(self: *Connection) !void {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        const idle_timeout_ns = self.max_idle_timeout_ms * std.time.ns_per_ms;
        if (now - self.latest_activity_time > idle_timeout_ns) {
            try self.close(0, "Idle timeout");
        }
        self.updateTimeout();
    }

    /// Closes the connection with an error code and reason.
    pub fn close(self: *Connection, error_code: u64, reason: []const u8) !void {
        if (self.state == .closed or self.state == .draining) return;
        self.state = .closing;

        const pkt = try Packet.create(self.allocator, .connection_close);
        errdefer {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        var buffer = try self.allocator.alloc(u8, 32 + reason.len);
        defer self.allocator.free(buffer);
        var cursor: usize = 0;

        cursor += try serialize_vli(error_code, buffer[cursor..]);
        cursor += try serialize_vli(0x1c, buffer[cursor..]); // CONNECTION_CLOSE frame type
        cursor += try serialize_vli(@as(u64, reason.len), buffer[cursor..]);
        @memcpy(buffer[cursor .. cursor + reason.len], reason);
        cursor += reason.len;

        try pkt.raw_data.appendSlice(buffer[0..cursor]);
        try self.outgoing_packets.append(pkt);

        self.event_callback(self, .{ .connection_closed = .{
            .error_code = error_code,
            .reason = reason,
        } }, self.user_ctx);

        self.state = .draining;
    }

    /// Opens a new stream and returns its ID.
    pub fn openStream(self: *Connection, is_unidirectional: bool) !u64 {
        const stream_id = self.next_local_stream_id;
        const stream_type_bit: u64 = if (is_unidirectional) 0x02 else 0x00;
        const initiator_bit: u64 = if (self.role == .client) 0x00 else 0x01;
        if (stream_id >= (if (is_unidirectional) self.initial_max_streams_uni else self.initial_max_streams_bidi) * 4) {
            return error.StreamLimitExceeded;
        }

        const stream = try stream_mod.createStream(self.allocator, self, stream_id | stream_type_bit | initiator_bit, is_unidirectional);
        try self.streams.put(stream_id, stream);
        self.next_local_stream_id += 4; // Increment by 4 per QUIC stream ID rules

        self.event_callback(self, .{ .new_stream = .{
            .stream_id = stream_id,
            .is_unidirectional = is_unidirectional,
        } }, self.user_ctx);

        return stream_id;
    }

    /// Sends data on a stream.
    pub fn sendStreamData(self: *Connection, stream_id: u64, data: []const u8, is_fin: bool) !void {
        if (self.streams.get(stream_id)) |stream| {
            const pkt = try Packet.create(self.allocator, .short_header);
            errdefer {
                pkt.deinit();
                self.allocator.destroy(pkt);
            }

            const frame = packet.Frame{ .stream = .{
                .stream_id = stream_id,
                .offset = stream.send_offset,
                .length = @as(u64, data.len),
                .fin = is_fin,
                .data = data,
            } };
            try pkt.frames.append(frame);
            try self.outgoing_packets.append(pkt);


        } else {
            return error.UnknownStream;
        }
    }
};

/// Creates a new QUIC connection.
pub fn createConnection(allocator: Allocator, options: ConnectionOptions) !*Connection {
    return try Connection.init(allocator, options);
}

/// Destroys a QUIC connection.
pub fn destroyConnection(conn: *Connection) void {
    conn.deinit();
}

/// Starts the TLS handshake.
pub fn startHandshake(conn: *Connection) !void {
    if (conn.state != .handshaking) return error.InvalidConnectionState;
    if (conn.role == .client) try conn.queueHandshakeResponse();
}

/// Receives a UDP packet.
pub fn receivePacket(conn: *Connection, data: []const u8) !void {
    try conn.processPacket(data);
}

/// Gets the next timeout.
pub fn getNextTimeout(conn: *Connection) ?i64 {
    return conn.next_timeout;
}

/// Processes connection timeouts.
pub fn processTimeouts(conn: *Connection) !void {
    try conn.processTimeouts();
}

/// Gets the next outgoing packet.
pub fn getNextOutgoingPacket(conn: *Connection) ?*Packet {
    return conn.getNextOutgoingPacket();
}

/// Closes the connection with an error.
pub fn closeConnection(conn: *Connection, error_code: u64, reason: []const u8) !void {
    try conn.close(error_code, reason);
}
