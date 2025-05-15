// src/http3/quic/connection.zig
// QUIC connection management

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
const Frame = packet.Frame;
const StreamFrame = packet.StreamFrame;
const CryptoFrame = packet.CryptoFrame;

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
    max_idle_timeout_ms: u64 = 30_000,
    max_udp_payload_size: u16 = 1350,
    initial_max_data: u64 = 10_000_000,
    initial_max_stream_data_bidi_local: u64 = 1_000_000,
    initial_max_stream_data_bidi_remote: u64 = 1_000_000,
    initial_max_stream_data_uni: u64 = 1_000_000,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
};

/// QUIC Connection structure
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
    tls_ctx: ?*TlsContext,
    bytes_in_flight: u64,
    congestion_window: u64,
    next_packet_number: u64,
    streams: std.AutoHashMap(u64, *Stream),
    next_local_stream_id: u64,
    outgoing_packets: std.ArrayList(*Packet),
    latest_activity_time: i64,
    next_timeout: ?i64,
    smoothed_rtt: i64,
    rtt_variance: i64,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,

    /// Initialize a new QUIC connection
    pub fn init(allocator: Allocator, options: ConnectionOptions) !*Connection {
        var conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        var src_conn_id: [16]u8 = undefined;
        std.crypto.random.bytes(&src_conn_id);
        const src_conn_id_len: u8 = if (options.role == .client) 8 else 0;

        var dst_conn_id: [16]u8 = undefined;
        if (options.role == .client) {
            std.crypto.random.bytes(&dst_conn_id);
        }

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
            .version = 0x00000001, // QUIC version 1
            .max_idle_timeout_ms = options.max_idle_timeout_ms,
            .max_udp_payload_size = options.max_udp_payload_size,
            .initial_max_data = options.initial_max_data,
            .initial_max_stream_data_bidi_local = options.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = options.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = options.initial_max_stream_data_uni,
            .initial_max_streams_bidi = options.initial_max_streams_bidi,
            .initial_max_streams_uni = options.initial_max_streams_uni,
            .tls_ctx = null,
            .bytes_in_flight = 0,
            .congestion_window = 12000,
            .next_packet_number = 0,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
            .next_local_stream_id = if (options.role == .client) 0 else 1,
            .outgoing_packets = std.ArrayList(*Packet).init(allocator),
            .latest_activity_time = std.time.nanoTimestamp(),
            .next_timeout = null,
            .smoothed_rtt = 500 * std.time.ns_per_ms,
            .rtt_variance = 250 * std.time.ns_per_ms,
            .packets_sent = 0,
            .packets_received = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
        };

        conn.tls_ctx = try crypto.createTlsContext(allocator, options.role == .server);
        errdefer crypto.destroyTlsContext(conn.tls_ctx.?);

        return conn;
    }

    /// Clean up connection resources
    pub fn deinit(self: *Connection) void {
        var stream_it = self.streams.valueIterator();
        while (stream_it.next()) |stream| {
            stream_mod.destroyStream(stream.*);
        }
        self.streams.deinit();

        for (self.outgoing_packets.items) |pkt| {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }
        self.outgoing_packets.deinit();

        if (self.tls_ctx) |ctx| {
            crypto.destroyTlsContext(ctx);
        }

        self.allocator.destroy(self);
    }

    /// Process incoming packet data
    pub fn processPacket(self: *Connection, data: []const u8) !void {
        if (data.len == 0) return error.EmptyPacket;

        const pkt = try packet.parsePacket(self.allocator, data);
        defer packet.destroyPacket(pkt);

        self.latest_activity_time = std.time.nanoTimestamp();
        self.bytes_received += data.len;
        self.packets_received += 1;

        switch (pkt.packet_type) {
            .initial, .handshake, .zero_rtt, .retry => try self.processLongHeaderPacket(pkt),
            .short_header => try self.processShortHeaderPacket(pkt),
            .version_negotiation => return error.VersionNegotiation,
            .connection_close => try self.processConnectionClosePacket(pkt),
        }

        self.updateTimeout();
    }

    /// Process Long Header packet
    fn processLongHeaderPacket(self: *Connection, pkt: *Packet) !void {
        const header_result = try self.removeHeaderProtection(pkt.packet_type, pkt.raw_data.items, 0, 0);
        pkt.packet_number = header_result.packet_number;

        const decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, pkt.raw_data.items);
        defer self.allocator.free(decrypted_payload);

        try self.processFrames(decrypted_payload);

        if (self.state == .handshaking) {
            if (self.role == .server) {
                self.state = .connected;
                self.event_callback(self, .handshake_completed, self.user_ctx);
                try self.simulateClientStreams();
            } else if (pkt.packet_type == .handshake) {
                self.state = .connected;
                self.event_callback(self, .handshake_completed, self.user_ctx);
            }
        }
    }

    /// Process Short Header packet
    fn processShortHeaderPacket(self: *Connection, pkt: *Packet) !void {
        const header_result = try self.removeHeaderProtection(pkt.packet_type, pkt.raw_data.items, 0, 0);
        pkt.packet_number = header_result.packet_number;

        const decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, pkt.raw_data.items);
        defer self.allocator.free(decrypted_payload);

        try self.processFrames(decrypted_payload);
    }

    /// Process Connection Close packet
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

    /// Parse a single QUIC frame
    fn parseFrame(self: *Connection, data: []const u8, bytes_read_out: *usize) !Frame {
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
            0x02, 0x03 => {
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
            },
            0x05 => {
                if (data.len < cursor + 1) return error.BufferTooShort;
                const stream_id = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;
                const error_code = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                bytes_read_out.* = cursor;
                return .{ .stop_sending = .{
                    .stream_id = stream_id,
                    .error_code = error_code,
                } };
            },
            0x06 => {
                if (data.len < cursor + 1) return error.BufferTooShort;
                const offset = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;
                const length = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;
                if (data.len < cursor + @as(usize, length)) return error.BufferTooShort;
                const crypto_data = data[cursor .. cursor + @as(usize, length)];
                cursor += @as(usize, length);

                bytes_read_out.* = cursor;
                return .{ .crypto = .{ .offset = offset, .data = crypto_data } };
            },
            0x08...0x0f => {
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
            },
            0x0c => {
                if (data.len < cursor + 1) return error.BufferTooShort;
                const stream_id = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;
                const max_data = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                bytes_read_out.* = cursor;
                return .{ .max_stream_data = .{
                    .stream_id = stream_id,
                    .max_data = max_data,
                } };
            },
            else => return error.UnknownFrameType,
        }
    }

    /// Process frames from decrypted payload
    fn processFrames(self: *Connection, payload: []const u8) !void {
        var cursor: usize = 0;
        while (cursor < payload.len) {
            var bytes_read: usize = 0;
            const frame = try self.parseFrame(payload[cursor..], &bytes_read);
            try self.processFrame(frame);
            cursor += bytes_read;
        }
    }

    /// Process a single QUIC frame
    fn processFrame(self: *Connection, frame: Frame) !void {
        switch (frame) {
            .padding => {},
            .ping => {},
            .ack => |ack_frame| {
                // Update congestion control and retransmission
                for (ack_frame.ack_ranges.items) |range| {
                    // TODO: Mark packets in range as acknowledged
                    _ = range;
                }
                ack_frame.ack_ranges.deinit();
            },
            .crypto => |crypto_frame| try self.processCryptoFrame(crypto_frame),
            .stream => |stream_frame| try self.processStreamFrame(stream_frame),
            .stop_sending => |stop_sending| {
                // Notify stream to stop sending
                if (self.streams.get(stop_sending.stream_id)) |stream| {
                    try stream.handleStopSending(stop_sending.error_code);
                }
            },
            .max_stream_data => |max_stream_data| {
                // Update stream's flow control window
                if (self.streams.get(max_stream_data.stream_id)) |stream| {
                    try stream.updateMaxStreamData(max_stream_data.max_data);
                }
            },
            .raw => log.warn("Received unprocessed frame type", .{}),
        }
    }

    /// Process CRYPTO frame
    fn processCryptoFrame(self: *Connection, frame: CryptoFrame) !void {
        if (self.tls_ctx == null) return error.NoTlsContext;
        // Pass crypto data to TLS context for handshake processing
        try crypto.processCryptoData(self.tls_ctx.?, frame.data, frame.offset);
        // Check if handshake is complete
        if (crypto.isHandshakeComplete(self.tls_ctx.?)) {
            self.state = .connected;
            self.event_callback(self, .handshake_completed, self.user_ctx);
        }
    }

    /// Process STREAM frame
    fn processStreamFrame(self: *Connection, frame: StreamFrame) !void {
        const is_client_initiated = (frame.stream_id % 2) == 0;
        const is_unidirectional = (frame.stream_id & 0x02) != 0;
        const is_peer_initiated = (self.role == .client and !is_client_initiated) or
            (self.role == .server and is_client_initiated);

        var stream = self.streams.get(frame.stream_id);
        if (stream == null and is_peer_initiated) {
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

    /// Remove header protection (RFC 9001, Section 5.4)
    fn removeHeaderProtection(
        self: *Connection,
        packet_type: PacketType,
        packet_data: []u8,
        offset_to_first_byte: usize,
        offset_to_pn: usize,
    ) !struct { unprotected_first_byte: u8, pn_length: usize, packet_number: u64 } {
        _ = packet_type;
        if (self.tls_ctx == null) return error.NoTlsContext;
        if (packet_data.len < offset_to_first_byte + 5) return error.BufferTooShort;

        // Derive header protection key from TLS context
        const hp_key = try crypto.deriveHeaderProtectionKey(self.tls_ctx.?);
        defer self.allocator.free(hp_key);

        // Sample for AEAD mask (16 bytes, starting 4 bytes after packet number)
        const sample_offset = offset_to_pn + 4;
        if (packet_data.len < sample_offset + 16) return error.BufferTooShort;
        const sample = packet_data[sample_offset .. sample_offset + 16];

        // Generate mask using AES or ChaCha20
        var mask: [5]u8 = undefined;
        try crypto.generateHeaderProtectionMask(hp_key, sample, &mask);

        // Unmask first byte
        const first_byte = packet_data[offset_to_first_byte] ^ mask[0];
        const pn_length = @as(usize, (first_byte & 0x03) + 1);

        // Unmask packet number
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

    /// Decrypt packet payload (RFC 9001, Section 5.3)
    fn decryptPacketPayload(self: *Connection, packet_type: PacketType, packet_number: u64, encrypted_payload: []const u8) ![]u8 {
        if (self.tls_ctx == null) return error.NoTlsContext;

        // Derive packet protection key and IV
        const pp_key = try crypto.derivePacketProtectionKey(self.tls_ctx.?, packet_type);
        defer self.allocator.free(pp_key);
        const pp_iv = try crypto.derivePacketProtectionIv(self.tls_ctx.?, packet_type);
        defer self.allocator.free(pp_iv);

        // Construct nonce (IV XOR packet number)
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, pp_iv[0..12]);
        for (0..8) |i| {
            nonce[nonce.len - 1 - i] ^= @as(u8, @intCast((packet_number >> (i * 8)) & 0xFF));
        }

        // Prepare associated data (header)
        const header_len = try self.getHeaderLength(packet_type, encrypted_payload);
        const associated_data = encrypted_payload[0..header_len];

        // Perform AEAD decryption (AES-GCM or ChaCha20-Poly1305)
        const decrypted = try crypto.decryptAead(
            self.allocator,
            pp_key,
            nonce,
            encrypted_payload[header_len..],
            associated_data,
        );

        return decrypted;
    }

    /// Get header length for associated data (RFC 9001)
    fn getHeaderLength(self: *Connection, packet_type: PacketType, packet_data: []const u8) !usize {
        var cursor: usize = 0;
        switch (packet_type) {
            .initial, .handshake, .zero_rtt => {
                // Long header: first byte + version (4) + DCID len (1) + DCID + SCID len (1) + SCID + token (for Initial) + length
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
                    // Initial packets have a variable-length token
                    var vli_read_len: usize = 0;
                    const token_len = try parse_vli(packet_data[cursor..], &vli_read_len);
                    cursor += vli_read_len;
                    if (packet_data.len < cursor + @as(usize, token_len)) return error.BufferTooShort;
                    cursor += @as(usize, token_len);
                }

                // Length field (variable-length integer, includes packet number + payload)
                var vli_read_len: usize = 0;
                _ = try parse_vli(packet_data[cursor..], &vli_read_len);
                cursor += vli_read_len;
                return cursor;
            },
            .retry => {
                // Retry header: first byte + version (4) + DCID len (1) + DCID + SCID len (1) + SCID + Retry Token + Retry Integrity Tag (16 bytes)
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
                // Retry Token length is implicit (until 16 bytes before end)
                if (packet_data.len < cursor + 16) return error.BufferTooShort;
                cursor = packet_data.len - 16; // Skip to before Retry Integrity Tag
                cursor += 16; // Include Retry Integrity Tag
                return cursor;
            },
            .short_header => {
                // Short header: first byte + DCID + packet number
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

    /// Queue handshake response
    fn queueHandshakeResponse(self: *Connection) !void {
        var pkt = try Packet.create(self.allocator, .handshake);
        errdefer {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        const crypto_data = try crypto.generateTlsHandshakeData(self.tls_ctx.?, self.allocator);
        defer self.allocator.free(crypto_data);

        const frame = Frame{ .crypto = .{
            .offset = 0,
            .data = crypto_data,
        } };
        try pkt.frames.append(frame);
        try self.outgoing_packets.append(pkt);
    }

    /// Simulate client streams
    fn simulateClientStreams(self: *Connection) !void {
        try self.notifyNewStream(0, true); // Control stream
        try self.notifyNewStream(2, true); // Encoder stream
        try self.notifyNewStream(3, true); // Decoder stream
        try self.notifyNewStream(4, false); // Request stream
    }

    /// Notify about new stream
    fn notifyNewStream(self: *Connection, stream_id: u64, is_unidirectional: bool) !void {
        const stream = try stream_mod.createStream(self.allocator, self, stream_id, is_unidirectional);
        try self.streams.put(stream_id, stream);
        self.event_callback(self, .{ .new_stream = .{
            .stream_id = stream_id,
            .is_unidirectional = is_unidirectional,
        } }, self.user_ctx);
    }

    /// Get next outgoing packet
    pub fn getNextOutgoingPacket(self: *Connection) ?*Packet {
        if (self.outgoing_packets.items.len == 0) return null;
        const pkt = self.outgoing_packets.orderedRemove(0);
        self.packets_sent += 1;
        self.bytes_sent += pkt.raw_data.items.len;
        return pkt;
    }

    /// Update timeout
    fn updateTimeout(self: *Connection) void {
        const idle_timeout_ns = self.max_idle_timeout_ms * std.time.ns_per_ms;
        self.next_timeout = self.latest_activity_time + idle_timeout_ns;
    }

    /// Process timeouts
    pub fn processTimeouts(self: *Connection) !void {
        const now = std.time.nanoTimestamp();
        const idle_timeout_ns = self.max_idle_timeout_ms * std.time.ns_per_ms;
        if (now - self.latest_activity_time > idle_timeout_ns) {
            try self.close(0, "Idle timeout");
        }
        self.updateTimeout();
    }

    /// Close connection
    pub fn close(self: *Connection, error_code: u64, reason: []const u8) !void {
        if (self.state == .closed or self.state == .draining) return;

        self.state = .closing;

        // var pkt = try Packet.create(self.allocator, .connection_close);
        // errdefer {
        //     pkt.deinit();
        //     self.allocator.destroy(pkt);
        // }

        var buffer: [32]u8 = undefined;
        var cursor: usize = 0;

        cursor += try serialize_vli(error_code, buffer[cursor..]);
        cursor += try serialize_vli(0x1c, buffer[cursor..]);
        cursor += try serialize_vli(reason.len, buffer[cursor..]);
        //try pkt.raw_data.appendSlice(buffer[0..cursor]);
        //try pkt.raw_data.appendSlice(reason);

        //try self.outgoing_packets.append(pkt);

        self.event_callback(self, .{ .connection_closed = .{
            .error_code = error_code,
            .reason = reason,
        } }, self.user_ctx);

        self.state = .draining;
    }
};

/// Create a new QUIC connection
pub fn createConnection(allocator: Allocator, options: ConnectionOptions) !*Connection {
    return try Connection.init(allocator, options);
}

/// Destroy a QUIC connection
pub fn destroyConnection(conn: *Connection) void {
    conn.deinit();
}

/// Start TLS handshake
pub fn startHandshake(conn: *Connection) !void {
    if (conn.state != .handshaking) return error.InvalidConnectionState;
    if (conn.role == .client) try conn.queueHandshakeResponse();
}

/// Receive UDP packet
pub fn receivePacket(conn: *Connection, data: []const u8) !void {
    try conn.processPacket(data);
}

/// Get next timeout
pub fn getNextTimeout(conn: *Connection) ?i64 {
    return conn.next_timeout;
}

/// Process connection timeouts
pub fn processTimeouts(conn: *Connection) !void {
    try conn.processTimeouts();
}

/// Get next outgoing packet
pub fn getNextOutgoingPacket(conn: *Connection) ?*Packet {
    return conn.getNextOutgoingPacket();
}

/// Close connection with error
pub fn closeConnection(conn: *Connection, error_code: u64, reason: []const u8) !void {
    try conn.close(error_code, reason);
}
