// src/quic/connection.zig
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

const util = @import("util.zig");
const parse_vli = util.parseVli;

const stream_mod = @import("stream.zig");
const Stream = stream_mod.Stream;

/// Represents a QUIC ACK frame (Type 0x02, 0x03)
/// Defined locally as packet.zig Frame does not yet include this variant.
pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64, // In units of the ACK Delay Exponent
    ack_range_count: u64,
    first_ack_range: u64,
    // Sequence of (Gap, ACK Range Length) pairs
    // Gap and ACK Range Length are VLIs
    ack_ranges: std.ArrayList(struct { gap: u64, length: u64 }),
};


/// QUIC connection states
pub const ConnectionState = enum {
    handshaking, // TLS handshake in progress
    connected, // Fully established connection
    closing, // Connection closure initiated
    closed, // Connection fully closed
    draining, // Waiting for in-flight packets to be lost
};

/// QUIC connection role (client or server)
pub const ConnectionRole = enum {
    client,
    server,
};

/// Options for creating a new QUIC connection
pub const ConnectionOptions = struct {
    role: ConnectionRole,
    udp_fd: std.posix.fd_t,
    remote_address: std.net.Address,
    user_ctx: ?*anyopaque,
    event_callback: EventCallback,
    max_idle_timeout_ms: u64 = 30_000, // 30 seconds
    max_udp_payload_size: u16 = 1350,
    initial_max_data: u64 = 10_000_000, // 10MB
    initial_max_stream_data_bidi_local: u64 = 1_000_000, // 1MB
    initial_max_stream_data_bidi_remote: u64 = 1_000_000, // 1MB
    initial_max_stream_data_uni: u64 = 1_000_000, // 1MB
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
};

/// QUIC Connection structure
pub const Connection = struct {
    allocator: Allocator,
    role: ConnectionRole,
    state: ConnectionState,

    // I/O details
    udp_fd: std.posix.fd_t,
    remote_address: std.net.Address,

    // Callback for events
    user_ctx: ?*anyopaque,
    event_callback: EventCallback,

    // Connection identifiers
    src_connection_id: [16]u8,
    dst_connection_id: [16]u8,
    src_connection_id_len: u8,
    dst_connection_id_len: u8,

    // Protocol version
    version: u32,

    // Connection parameters
    max_idle_timeout_ms: u64,
    max_udp_payload_size: u16,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,

    // TLS crypto context
    tls_ctx: ?*TlsContext,

    // Flow control
    bytes_in_flight: u64,
    congestion_window: u64,

    // Packet number spaces
    next_packet_number: u64,

    // Stream management
    streams: std.AutoHashMap(u64, *Stream),
    next_local_stream_id: u64,

    // Packet queues
    outgoing_packets: std.ArrayList(*Packet),

    // Timers and RTT management
    latest_activity_time: i64, // timestamp in nanoseconds
    next_timeout: ?i64, // timestamp in nanoseconds
    smoothed_rtt: i64, // in nanoseconds
    rtt_variance: i64, // in nanoseconds

    // Statistics
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,

    /// Initialize a new QUIC connection structure
    pub fn init(allocator: Allocator, options: ConnectionOptions) !*Connection {
        var conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        // Generate random connection IDs
        var src_conn_id: [16]u8 = undefined;
        std.crypto.random.bytes(&src_conn_id);
        const src_conn_id_len: u8 = if (options.role == .client) 8 else 0;

        var dst_conn_id: [16]u8 = undefined;
        if (options.role == .client) {
            std.crypto.random.bytes(&dst_conn_id);
        }
        const dst_conn_id_len: u8 = if (options.role == .client) 0 else 8;

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
            .dst_connection_id_len = dst_conn_id_len,
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
            .congestion_window = 12000, // Initial congestion window
            .next_packet_number = 0,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
            .next_local_stream_id = if (options.role == .client) 0 else 1,
            .outgoing_packets = std.ArrayList(*Packet).init(allocator),
            .latest_activity_time = std.time.nanoTimestamp(),
            .next_timeout = null,
            .smoothed_rtt = 500 * std.time.ns_per_ms, // Initial RTT guess: 500ms
            .rtt_variance = 250 * std.time.ns_per_ms, // Initial variance
            .packets_sent = 0,
            .packets_received = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
        };

        // Initialize TLS context
        conn.tls_ctx = try crypto.createTlsContext(allocator, options.role == .server);
        errdefer {
            crypto.destroyTlsContext(conn.tls_ctx.?);
            conn.tls_ctx = null;
        }

        return conn;
    }

    /// Clean up resources associated with a connection
    pub fn deinit(self: *Connection) void {
        log.debug("Deinitializing QUIC connection to {}", .{self.remote_address});

        // Clean up streams
        var stream_it = self.streams.valueIterator();
        while (stream_it.next()) |stream| {
            stream_mod.destroyStream(stream.*);
        }
        self.streams.deinit();

        // Clean up packet queue
        for (self.outgoing_packets.items) |pkt| {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }
        self.outgoing_packets.deinit();

        // Clean up TLS context
        if (self.tls_ctx) |ctx| {
            crypto.destroyTlsContext(ctx);
            self.tls_ctx = null;
        }

        self.allocator.destroy(self);
    }

    /// Handle incoming packet data
    /// This is the main entry point for processing received UDP data.
    pub fn processPacket(self: *Connection, data: []const u8) !void {
        if (data.len == 0) return error.EmptyPacket;

        // Attempt to parse the packet header to determine the packet type and connection ID.
        // This initial parse might not fully validate or decrypt, especially for Short Headers.
        var parsed_pkt = packet.parsePacket(self.allocator, data) catch |err| {
             log.error("Failed initial packet parse from {}: {}", .{ self.remote_address, err });
             // TODO: Handle parsing errors appropriately based on error type (e.g., Version Negotiation,
             // Stateless Reset, invalid format) and connection state.
             // For now, return the error or potentially send a stateless reset if applicable.
             if (err == error.VersionNegotiation) {
                  log.info("Received Version Negotiation packet, need to respond", .{});
                  // TODO: Handle version negotiation response
                  return err; // Or continue specific VN handling
             }
             // Other errors might warrant dropping the packet or sending a CONNECTION_CLOSE
             return err;
        };
        defer packet.destroyPacket(parsed_pkt); // Ensure packet resources are freed


        self.latest_activity_time = std.time.nanoTimestamp();
        self.bytes_received += data.len;
        self.packets_received += 1;

        log.debug("Received {} bytes from {}", .{ data.len, self.remote_address });

        // Parse the raw UDP data into a QUIC packet structure
        var parsed_pkt = packet.parsePacket(self.allocator, data) catch |err| {
            log.error("Failed to parse packet from {}: {}", .{ self.remote_address, err });
            // TODO: Handle parsing errors appropriately based on error type and connection state.
            // Could send a stateless reset, connection close, or just drop the packet.
            // For now, just return the error.
            return err;
        };
        defer packet.destroyPacket(parsed_pkt); // Ensure packet resources are freed

        // Dispatch packet processing based on type
        switch (parsed_pkt.packet_type) {
            .initial, .handshake, .zero_rtt, .retry => {
                try self.processLongHeaderPacket(parsed_pkt);
            },
            .short_header => {
                try self.processShortHeaderPacket(parsed_pkt);
            },
            .version_negotiation => {
                // Version Negotiation packets are special and handled early.
                // parsePacket should return error.VersionNegotiation in this case.
                // If we reach here with type .version_negotiation, something is wrong
                // with the parsePacket logic or the packet itself.
                log.warn("Received unexpected Version Negotiation packet type in processPacket switch", .{});
                return error.UnexpectedPacketType; // Or handle specifically
            },
            .connection_close => {
                 try self.processConnectionClosePacket(parsed_pkt);
            },
        }

        // Update timeout based on activity
        self.updateTimeout();
    }

    /// Process a Long Header packet (Initial, Handshake, 0-RTT, Retry)
    fn processLongHeaderPacket(self: *Connection, pkt: *packet.Packet) !void {
        log.debug("Processing Long Header packet (type: {}) from {}", .{pkt.packet_type, self.remote_address});

        // Acknowledge packet reception for this packet number space (Initial, Handshake, or 0-RTT)
        // TODO: Add packet number tracking and ACK generation

        // 1. Remove Header Protection (Packet Number and certain flags are protected)
        // This is complex and depends on the packet type (Initial, Handshake, 0-RTT)
        // and the current encryption level keys. The raw_data contains the full packet bytes.
        // Need to identify the header portion vs the protected payload.
        // For Long Headers, the protected part starts after the Length field (if present) or SCID (for Retry).
        // 1. Remove Header Protection (Packet Number and certain flags are protected)
        // This is complex and depends on the packet type (Initial, Handshake, 0-RTT)
        // and the current encryption level keys. The raw_data contains the full packet bytes.
        // Need to identify the header portion vs the protected payload.
        // For Long Headers, the protected part starts after the Length field (if present) or SCID (for Retry).
        // 1. Remove Header Protection (Packet Number and certain flags are protected)
        // This is complex and depends on the packet type (Initial, Handshake, 0-RTT)
        // and the current encryption level keys.
        // The raw_data contains the full packet bytes. Header protection is applied to
        // the first byte (flags) and the Packet Number field. The location of these fields
        // depends on the packet type and variable-length header fields (DCID, SCID, Token, Length).
        // Accurately identifying the protected header bytes and the Packet Number field
        // requires detailed header parsing, including VLIs.

        // TODO: Implement precise slicing to get the protected header bytes and the PN field offset.
        // For now, pass the full raw data and dummy offsets as a placeholder.
        // Header protection typically operates in-place on a copy of the header bytes.
        var header_protection_result = try self.removeHeaderProtection(
            pkt.packet_type,
            pkt.raw_data.items, // Need to pass the mutable raw data
            0, // Placeholder offset to the first byte
            0  // Placeholder offset to the Packet Number field
        );
        // After this step, the Packet Number field in pkt.raw_data.items at the calculated PN offset
        // is unprotected. The Packet Number length is signaled in the unprotected first byte.

        // TODO: Recover Packet Number from the unprotected header bytes at the correct offset.
        // This involves reading the PN length from header_protection_result.unprotected_first_byte
        // and then reading the PN field from pkt.raw_data.items at the PN offset.
        // Also need to apply packet number decoding based on the largest received PN.
        pkt.packet_number = 0; // Placeholder, should be recovered here

        // 2. Decrypt Packet Payload
        // The payload bytes start after the fixed and variable parts of the header.
        // The 'Length' field (for Initial, Handshake, 0-RTT) indicates the length of the
        // Packet Number + Protected Payload. The encrypted payload is the bytes after
        // the packet number field, up to the end indicated by the 'Length' field,
        // and includes the authentication tag.
        // For Retry packets, the format is different (Retry Token + Tag).

        // TODO: Calculate the exact slice for the encrypted payload based on packet type
        // and the parsed header fields (including the Length field and PN length).
        var encrypted_payload_slice = pkt.raw_data.items; // This slice is wrong, needs actual payload offset/length

        var decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, encrypted_payload_slice);
        defer self.allocator.free(decrypted_payload); // Free the allocated decrypted buffer

        // 3. Process Frames from the decrypted payload
        try self.processFrames(decrypted_payload);


        // Placeholder: Simulate handshake completion for server
        if (self.role == .server and self.state == .handshaking) {
            // In a real handshake, receiving CRYPTO frames would lead to this state transition
            log.info("Simulating Handshake Completion (Server)", .{});
            self.state = .connected;
            self.event_callback(self, .handshake_completed, self.user_ctx);
            try self.simulateClientStreams(); // Simulate peer opening streams post-handshake
        }
        // Placeholder: Simulate handshake completion for client (based on receiving server Handshake packet)
        if (self.role == .client and self.state == .handshaking and pkt.packet_type == .handshake) {
            // In a real handshake, receiving server Handshake/CRYPTO frames would lead to this
            log.info("Simulating Handshake Completion (Client)", .{});
            self.state = .connected;
            self.event_callback(self, .handshake_completed, self.user_ctx);
        }
    }

    /// Process a Short Header packet (1-RTT)
    fn processShortHeaderPacket(self: *Connection, pkt: *packet.Packet) !void {
        log.debug("Processing Short Header packet from {}", .{self.remote_address});

        // Acknowledge packet reception for the 1-RTT packet number space
        // TODO: Add packet number tracking and ACK generation

        // Short Header packets require connection state lookup based on DCID
        // to get decryption keys. This lookup happens *before* this function
        // is called in a real implementation, identifying the connection.
        // The `pkt.header` contains a placeholder ShortHeader struct.

        // 1. Remove Header Protection (Packet Number and Key Phase bit are protected)
        // 1. Remove Header Protection (Packet Number and Key Phase bit are protected)
        // This is complex and depends on the current encryption level keys.
        // The raw_data contains the full packet bytes. Header protection is applied to
        // the first byte (flags including Key Phase and PN Length) and the Packet Number field.
        // The location of the Packet Number field depends on the optional DCID length.
        // The DCID length is not in the Short Header and must be known from connection state.
        // Accurately identifying the protected bytes requires this state and PN length from flags.

        // TODO: Obtain DCID length from connection state.
        // TODO: Calculate precise slices for the protected header bytes and the PN field offset.
        // For now, pass the full raw data and dummy offsets as a placeholder.
        var protected_header_slice = pkt.raw_data.items[0..]; // This slice is wrong, needs correct offset and length
        var header_protection_result = try self.removeHeaderProtection(
            pkt.packet_type,
            pkt.raw_data.items, // Need to pass the mutable raw data
            0, // Placeholder offset to the first byte
            0  // Placeholder offset to the Packet Number field (depends on ODCID length)
        );
        // After this step, the Packet Number field in pkt.raw_data.items at the calculated PN offset
        // is unprotected. The Packet Number length is signaled in header_protection_result.unprotected_first_byte.

        // TODO: Recover Packet Number from the unprotected header bytes at the correct offset.
        // This involves reading the PN length from header_protection_result.unprotected_first_byte
        // and then reading the PN field from pkt.raw_data.items at the PN offset.
        // Also need to apply packet number decoding based on the largest received PN.
        pkt.packet_number = 0; // Placeholder, should be recovered here

        // 2. Decrypt Packet Payload
        // The payload bytes start after the DCID and Packet Number fields.
        // The encrypted payload is the bytes after these fields, including the authentication tag.

        // TODO: Calculate the exact slice for the encrypted payload based on DCID length
        // and the recovered Packet Number length.
        var encrypted_payload = pkt.raw_data.items; // This is incorrect, need exact slice after DCID + PN
        var decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, encrypted_payload);
        defer self.allocator.free(decrypted_payload); // Free the allocated decrypted buffer

        // 3. Process Frames from the decrypted payload
        try self.processFrames(decrypted_payload);
    }

    /// Process a Connection Close packet
    fn processConnectionClosePacket(self: *Connection, pkt: *packet.Packet) !void {
         log.info("Received Connection Close packet from {}", .{self.remote_address});
         // Connection Close packets contain an error code and reason in their payload.
         // These packets are authenticated but not encrypted (except the packet number).
         // We expect the raw payload bytes to be available in pkt.raw_data.items.

         // TODO: Parse the error code and reason from the raw payload bytes.
         // Need to skip the packet header first to get to the payload.
         // The payload format for CONNECTION_CLOSE (0x1c, 0x1d) is:
         // Error Code (VLI) | Frame Type (VLI) | Reason Phrase Length (VLI) | Reason Phrase (bytes)
         // The initial parsePacket might not give us the exact header length easily for all types.
         // For now, assume the payload starts after a basic Long Header structure or use raw data start.

         var cursor: usize = 0; // Start at the beginning of raw data
         // In a real implementation, calculate the actual header length to find payload start.
         // For simplicity here, let's try to parse from the beginning of raw_data,
         // acknowledging this is not robust for all packet types/versions.
         // A better approach is to get the payload slice from a more complete parsePacket or after decryption.

         if (pkt.raw_data.items.len == 0) {
              log.warn("Connection Close packet has no data payload", .{});
              try self.close(0, "No data in CONNECTION_CLOSE packet"); // Treat as protocol violation?
              return error.MalformedPacket; // Or a specific error
         }

         var error_code: u64 = 0;
         var reason: []const u8 = "Malformed CONNECTION_CLOSE packet"; // Default reason
         var bytes_read: usize = 0;


         // Attempt to parse fields directly from raw_data after an assumed header offset.
         // This is highly simplified and likely incorrect for many packet types/versions.
         // A proper implementation needs the exact payload start offset after the header.
         // Let's assume, for this placeholder, that the error code VLI is near the start of the payload.

         // We need to determine the actual start of the payload data AFTER the packet header.
         // This is complex and depends on the packet type (LH vs SH) and specific header fields.
         // As a rough placeholder:
         // For LH, payload starts after Type, Version, DCID, SCID, [Token], Length.
         // For SH, payload starts after Type, [ODCID], Packet Number.
         // Calculating these offsets correctly is part of the full packet parsing.
         // Let's use the raw_data for parsing, knowing the cursor logic is a simplification.

         cursor = 0; // Reset cursor, will try parsing from start of raw data
         // In a real impl, cursor would be set to the start of the unencrypted payload

         if (pkt.raw_data.items.len <= cursor) {
              log.warn("Connection Close packet raw data too short to parse error code", .{});
              try self.close(0, "Malformed CONNECTION_CLOSE packet: too short");
              return error.MalformedPacket;
         }

         // Error Code (VLI)
         error_code = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
         cursor += bytes_read;

         if (pkt.raw_data.items.len <= cursor) {
              log.warn("Connection Close packet raw data too short after error code", .{});
              reason = "No reason phrase or frame type provided";
         } else {
             // Frame Type (VLI) - Should be 0x1c or 0x1d. Read and ignore for getting reason.
             var frame_type: u64 = 0;
             frame_type = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
             cursor += bytes_read;

             if (pkt.raw_data.items.len <= cursor) {
                  log.warn("Connection Close packet raw data too short after frame type", .{});
                  reason = "No reason phrase length provided";
             } else {
                  // Reason Phrase Length (VLI)
                  var reason_len: u64 = 0;
                  reason_len = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
                  cursor += bytes_read;

                  // Reason Phrase Bytes
                  if (pkt.raw_data.items.len < cursor + @as(usize, reason_len)) {
                      log.warn("Connection Close packet raw data too short for reason phrase", .{});
                      reason = "Malformed reason phrase";
                      // Or return an error if strict
                      // return error.MalformedPacket;
                  } else {
                      reason = pkt.raw_data.items[cursor .. cursor + @as(usize, reason_len)];
                      cursor += @as(usize, reason_len);
                  }
             }
         }

         log.info("Peer closing connection: error={d}, reason={s}", .{ error_code, reason });

         // Transition connection state
         if (self.state != .closed) {
             self.state = .closed;
             // Emit event
             self.event_callback(self, .{ .connection_closed = .{
                 .error_code = error_code,
                 .reason = reason,
             } }, self.user_ctx));

             // TODO: Initiate local cleanup/deallocation
             // This might be done by the connection manager holding this connection.
         } else {
              log.debug("Received CONNECTION_CLOSE in closed state, ignoring.", .{});
         }\n    }
        }\n
        // defer { if (unprotected_header_bytes.ptr != protected_header_slice.ptr) self.allocator.free(unprotected_header_bytes); } // Need to track allocation


        // TODO: Recover Packet Number from the unprotected header bytes.
        // This involves reading the PN length (part of the first byte flags) and the PN field.
        // And also potentially decoding the actual packet number based on the largest received PN.
        pkt.packet_number = 0; // Placeholder, should be recovered here

        // 2. Decrypt Packet Payload
        // The payload bytes start after the fixed and variable parts of the header.
        // The 'Length' field in the header indicates the length of the Packet Number + Protected Payload.
        // Need to extract the actual encrypted payload slice based on the parsed header lengths.
        // This requires knowing where the header ends. This is complex and tied to header parsing.
        var encrypted_payload = pkt.raw_data.items; // This is incorrect slice, needs actual payload offset/length
        var decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, encrypted_payload);
        defer self.allocator.free(decrypted_payload); // Free the allocated decrypted buffer

        // TODO: Recover Packet Number from the unprotected header bytes.
        // This involves reading the PN length (part of the first byte flags) and the PN field.
        // And also potentially decoding the actual packet number based on the largest received PN.
        pkt.packet_number = 0; // Placeholder, should be recovered here

        // 2. Decrypt Packet Payload
        // The payload bytes start after the fixed and variable parts of the header.
        // The 'Length' field in the header indicates the length of the Packet Number + Protected Payload.
        // Need to extract the actual payload slice based on the parsed header lengths.
        var encrypted_payload = pkt.raw_data.items; // This is incorrect, need exact slice
        var decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, encrypted_payload);
        defer self.allocator.free(decrypted_payload); // Free the allocated decrypted buffer

        // 3. Process Frames from the decrypted payload
        try self.processFrames(decrypted_payload);

        // Placeholder: Simulate handshake completion for server
        if (self.role == .server and self.state == .handshaking) {
            // In a real handshake, receiving CRYPTO frames would lead to this state transition
            log.info("Simulating Handshake Completion (Server)", .{});
            self.state = .connected;
            self.event_callback(self, .handshake_completed, self.user_ctx);
            try self.simulateClientStreams(); // Simulate peer opening streams post-handshake
        }
        // Placeholder: Simulate handshake completion for client (based on receiving server Handshake packet)
        if (self.role == .client and self.state == .handshaking and pkt.packet_type == .handshake) {
            // In a real handshake, receiving server Handshake/CRYPTO frames would lead to this
            log.info("Simulating Handshake Completion (Client)", .{});
            self.state = .connected;
            self.event_callback(self, .handshake_completed, self.user_ctx);
        }
    }

    /// Process a Short Header packet (1-RTT)
    fn processShortHeaderPacket(self: *Connection, pkt: *packet.Packet) !void {
        log.debug("Processing Short Header packet from {}", .{self.remote_address});

        // Acknowledge packet reception for the 1-RTT packet number space
        // TODO: Add packet number tracking and ACK generation

        // Short Header packets require connection state lookup based on DCID
        // to get decryption keys. This lookup happens *before* this function
        // is called in a real implementation, identifying the connection.
        // The `pkt.header` contains a placeholder ShortHeader struct.

        // 1. Remove Header Protection (Packet Number and Key Phase bit are protected)
        // This is complex and depends on the current encryption level keys.
        // The raw_data contains the full packet bytes. Need to identify the header portion.
        // For Short Headers, the protected part starts after the DCID.
        // The DCID length is implicit or known from connection state.
        var protected_header_slice = pkt.raw_data.items[0..]; // This slice is wrong, needs correct offset and length
        var unprotected_header_bytes = try self.removeHeaderProtection(pkt.packet_type, protected_header_slice);
        // After this step, the Packet Number field in unprotected_header_bytes (a copy or modified slice) is clear.
        // The Packet Number length is signaled in the first byte flags.
        // defer { if (unprotected_header_bytes.ptr != protected_header_slice.ptr) self.allocator.free(unprotected_header_bytes); } // Need to track allocation


        // TODO: Recover Packet Number from the unprotected header bytes.
        // This involves reading the PN length (part of the first byte flags) and the PN field.
        // And also potentially decoding the actual packet number based on the largest received PN.
        pkt.packet_number = 0; // Placeholder, should be recovered here

        // 2. Decrypt Packet Payload
        // The payload bytes start after the DCID and Packet Number.
        // The lengths of DCID and Packet Number need to be known.
        var encrypted_payload = pkt.raw_data.items; // This is incorrect, need exact slice after DCID + PN
        var decrypted_payload = try self.decryptPacketPayload(pkt.packet_type, pkt.packet_number, encrypted_payload);
        defer self.allocator.free(decrypted_payload); // Free the allocated decrypted buffer

        // 3. Process Frames from the decrypted payload
        try self.processFrames(decrypted_payload);
    }

    /// Process a Connection Close packet
        // TODO: Use pkt.header (packet.LongHeader) to access version, DCID, SCID.
        // Need to verify DCID matches our SCID if role is server, or peer's DCID if role is client.
        // For Initial packets, need to process Token.
        // For Initial/Handshake/0-RTT, the payload (pkt.frames.items) is encrypted.

        // TODO: Decrypt packet payload using appropriate keys (Initial, Handshake, 0-RTT).
        // The packet number is part of the protected payload.

        // TODO: Recover packet number and verify. Update packet number space state.

        // TODO: Process frames from the *decrypted* payload.
        // For now, we will call processFrames with the raw (potentially encrypted) payload
        // that parsePacket stored in pkt.frames (as .raw type). This is incorrect and
        // needs to be replaced with decryption and actual frame iteration.
         log.warn("Processing potentially encrypted payload as raw frames - Decryption needed!", .{});
        if (pkt.frames.items.len > 0) {
            try self.processFrames(pkt.frames.items); // Incorrect: should process frames from decrypted data
        }

         // Placeholder: Simulate handshake completion for server
         if (self.role == .server and self.state == .handshaking) {
             // In a real handshake, receiving CRYPTO frames would lead to this state transition
             log.info("Simulating Handshake Completion (Server)", .{});
             self.state = .connected;
             self.event_callback(self, .handshake_completed, self.user_ctx);
             try self.simulateClientStreams(); // Simulate peer opening streams post-handshake
         }
         // Placeholder: Simulate handshake completion for client (based on receiving server Handshake packet)
         if (self.role == .client and self.state == .handshaking and pkt.packet_type == .handshake) {
             // In a real handshake, receiving server Handshake/CRYPTO frames would lead to this
             log.info("Simulating Handshake Completion (Client)", .{});
              self.state = .connected;
              self.event_callback(self, .handshake_completed, self.user_ctx);
         }
    }

    /// Process a Short Header packet (1-RTT)
    fn processShortHeaderPacket(self: *Connection, pkt: *packet.Packet) !void {
        log.debug("Processing Short Header packet from {}", .{self.remote_address});

        // TODO: Extract Destination Connection ID (DCID) from the packet.
        // The length of the DCID is implicit or known from connection establishment.
        // Use the DCID to confirm this packet belongs to this connection.

        // TODO: Decrypt packet payload using 1-RTT keys.

        // TODO: Recover packet number from the protected payload and header flags (PN Length).
        // Update 1-RTT packet number space state.

        // TODO: Process frames from the *decrypted* payload.
         log.warn("Processing potentially encrypted payload in Short Header packet - Decryption needed!", .{});
        if (pkt.frames.items.len > 0) {
             try self.processFrames(pkt.frames.items); // Incorrect: should process frames from decrypted data
        }
    }

    /// Process a Connection Close packet
    fn processConnectionClosePacket(self: *Connection, pkt: *packet.Packet) !void {
         log.info("Received Connection Close packet from {}", .{self.remote_address});
         // Connection Close packets contain an error code and reason in their payload.
         // These packets are authenticated but not encrypted (except the packet number).
         // We expect the raw payload bytes to be available.

         // TODO: Parse the error code and reason from the raw payload bytes.
         // Based on current simplified packet structure, payload is stored in pkt.raw_data
         // or possibly as a .raw frame. This needs refinement in packet.zig.
         // Assuming for now we can access the relevant data.

         // The raw payload bytes are stored in pkt.raw_data.items.
         // The format is: Error Code (VLI) | Frame Type (VLI) | Reason Phrase Length (VLI) | Reason Phrase (bytes)
         var cursor: usize = packet.getHeaderLength(pkt); // Assuming getHeaderLength exists or is calculated
         if (pkt.raw_data.items.len <= cursor) {
              log.warn("Connection Close packet payload too short", .{});
              return error.MalformedPacket;
         }

         var bytes_read: usize = 0;
         const error_code = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
         cursor += bytes_read;

         if (pkt.raw_data.items.len <= cursor) {
              log.warn("Connection Close packet payload too short after error code", .{});
              // A zero-length reason is valid if the error code is present.
              // Set a default reason string.
              reason = "No reason provided";
         } else {
             // Frame Type (usually 0x1c or 0x1d for CONNECTION_CLOSE) - Read and ignore for now
             var frame_type: u64 = 0;
             frame_type = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
             cursor += bytes_read;

             if (pkt.raw_data.items.len <= cursor) {
                  log.warn("Connection Close packet payload too short after frame type", .{});
                  reason = "No reason phrase provided";
             } else {
                  // Reason Phrase Length (VLI)
                  var reason_len: u64 = 0;
                  reason_len = try parse_vli(pkt.raw_data.items[cursor..], &bytes_read);
                  cursor += bytes_read;

                  // Reason Phrase Bytes
                  if (pkt.raw_data.items.len < cursor + @as(usize, reason_len)) {
                      log.warn("Connection Close packet payload too short for reason phrase", .{});
                      reason = "Malformed reason phrase";
                      // Or return an error if strict
                      // return error.MalformedPacket;
                  } else {
                      reason = pkt.raw_data.items[cursor .. cursor + @as(usize, reason_len)];
                      cursor += @as(usize, reason_len);
                  }
             }
         }

         // In a real implementation, parse error_code (VLI) and reason (VLI length + bytes)
         // from the packet payload bytes. This is a basic implementation above.

         log.info("Peer closing connection: error={d}, reason={s}", .{ error_code, reason });

         // Transition connection state
         if (self.state != .closed) {
             self.state = .closed;
             // Emit event
             self.event_callback(self, .{ .connection_closed = .{
                 .error_code = error_code,
                 .reason = reason,
             } }, self.user_ctx);

             // TODO: Initiate local cleanup/deallocation
             // This might be done by the connection manager holding this connection.
         } else {
              log.debug("Received CONNECTION_CLOSE in closed state, ignoring.", .{});
         }
    }


    /// Process a single QUIC frame
    fn processFrame(self: *Connection, frame: packet.Frame) !void {
         switch (frame) {
             .padding => {
                 log.debug("Processing PADDING frame", .{});
                 // Nothing to do for padding - it's just ignored.
             },
             .ping => {
                 log.debug("Processing PING frame", .{});
                 // The recipient of a PING frame MUST send a packet containing an ACK frame
                 // in response as soon as possible. This is handled implicitly by sending
             },
             .ack => |ack_frame| {
                 try self.processAckFrame(ack_frame);
             },
                 // any packet, but explicit ACK generation logic is needed elsewhere.
             },
             .stream => |stream_frame| {
                 try self.processStreamFrame(stream_frame);
             },
+            // TODO: Add cases for other important frame types:
             // ACK, CRYPTO, NEW_CONNECTION_ID, MAX_DATA, MAX_STREAMS, DATA_BLOCKED,
             // STREAM_DATA_BLOCKED, STREAMS_BLOCKED, STOP_SENDING, RESET_STREAM,
             // PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE (transport/application),
             // HANDSHAKE_DONE, NEW_TOKEN, RETIRE_CONNECTION_ID, etc.
-            .raw => {
-                // This case existed in the old parsePacket output structure but
-                // should not be reachable with the new frame parsing logic in parseFrame.
-                // If it is reached, it indicates a parsing issue.
-                log.err("Encountered unexpected raw frame in processFrame. Parsing error?", .{});
-                return error.InternalError; // Should not happen
-            },
+             .raw => {
+                  // This case exists in the current parsePacket output because
+                  // frame parsing from the encrypted payload is not implemented.
+                  // In a proper implementation, this case should not be reachable
+                  // after decryption and correct frame parsing.
+                  log.warn("Encountered unexpected raw frame placeholder during processing", .{});
+                  // Ignore or return error depending on strictness
+             },
          }
+    }
+
+    /// Process an incoming ACK frame
+    fn processAckFrame(self: *Connection, frame: packet.AckFrame) !void {
+        log.debug("Processing ACK frame: largest_acknowledged={}, ack_delay={}, ack_range_count={}, first_ack_range={}", .{ frame.largest_acknowledged, frame.ack_delay, frame.ack_range_count, frame.first_ack_range });
+
+        // TODO: Implement ACK processing logic:
+        // 1. Identify the packet number space (Initial, Handshake, 1-RTT) this ACK applies to.
+        // 2. Mark packets up to largest_acknowledged as acknowledged in the corresponding packet number space.
+        // 3. Use ack_ranges to mark additional packets as acknowledged.
+        // 4. Calculate RTT using the ack_delay and the time the acknowledged packet was sent. Update smoothed_rtt and rtt_variance.
+        // 5. Remove acknowledged packets from the unacknowledged packets list and reduce bytes_in_flight.
+        // 6. Trigger congestion control updates based on acknowledged packets.
+
+        // Example basic logging of ranges
+        log.debug("ACK ranges:", .{});
+        for (frame.ack_ranges.items) |range| {
+             log.debug("  Gap: {}, Length: {}", .{ range.gap, range.length });
+        }
+
+        // IMPORTANT: The `frame.ack_ranges` ArrayList was allocated by `parseFrame`.
+        // Ownership is transferred to this function. It must be deinitialised.
+        frame.ack_ranges.deinit();
     }
 
     /// Process frames contained within a packet payload
             // ACK, CRYPTO, NEW_CONNECTION_ID, MAX_DATA, MAX_STREAMS, DATA_BLOCKED,
             // STREAM_DATA_BLOCKED, STREAMS_BLOCKED, STOP_SENDING, RESET_STREAM,
             // PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE (transport/application),
             // HANDSHAKE_DONE, NEW_TOKEN, RETIRE_CONNECTION_ID, etc.
             .raw => {
                  // This case exists in the current parsePacket output because
                  // frame parsing from the encrypted payload is not implemented.
                  // In a proper implementation, this case should not be reachable
                  // after decryption and correct frame parsing.
                  log.warn("Encountered unexpected raw frame placeholder during processing", .{});
                  // Ignore or return error depending on strictness
             },
         }
    }

    /// Parses a single QUIC frame from the provided byte slice.
    /// Returns the parsed frame and the number of bytes consumed from the slice.
    /// Parses a single QUIC frame from the provided byte slice.
    /// Returns the parsed frame and the number of bytes consumed from the slice.
    fn parseFrame(self: *Connection, data: []const u8, bytes_read_out: *usize) !packet.Frame {
        if (data.len == 0) return error.BufferTooShort;

        const frame_type_byte = data[0];
        var cursor: usize = 0;
        var vli_read_len: usize = 0;

        // Handle PADDING and PING as they are single-byte frames
        if (frame_type_byte == 0x00) { // PADDING (Type 0x00)
            *bytes_read_out = 1;
            return .{ .padding = {} };
        }
        if (frame_type_byte == 0x01) { // PING (Type 0x01)
            *bytes_read_out = 1;
            return .{ .ping = {} };
        }

        // For other frames, the type is encoded as a Variable-Length Integer (VLI)
        var frame_type_vli: u64 = 0;
        frame_type_vli = try parse_vli(data[cursor..], &vli_read_len);
        cursor += vli_read_len;

        switch (frame_type_vli) {
            0x06 => { // CRYPTO frame (Type 0x06)
                // Format: Type | Offset | Crypto Data
                // Offset and Length are VLIs.

                var offset_val: u64 = 0;
                var vli_read_len: usize = 0; // Reuse VLI read length variable

                // Offset (VLI)
                if (data.len < cursor + 1) return error.BufferTooShort;\
                offset_val = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                // Crypto Data (extends to the end of the packet payload)
                // CRYPTO frames do not have a Length field. The data is implicitly
                // the rest of the packet payload after the Offset field.
                const crypto_data = data[cursor..];
                cursor = data.len; // Consume the rest of the data slice

                *bytes_read_out = cursor; // Total bytes consumed by this frame

                return .{ .crypto = .{
                    .offset = offset_val,
                    .data = crypto_data, // Slice pointing into the input data
                } };
            },

            0x02, 0x03 => { // ACK frames (Type 0x02, 0x03)
                // Format: Type | Largest Acknowledged | ACK Delay | ACK Range Count | First ACK Range | ACK Ranges...
                // ACK Ranges: (Gap | ACK Range Length) repeated ACK Range Count times.

                // Largest Acknowledged (VLI)
                if (data.len < cursor + 1) return error.BufferTooShort;
                const largest_acknowledged = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                // ACK Delay (VLI)
                if (data.len < cursor + 1) return error.BufferTooShort;
                const ack_delay = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                // ACK Range Count (VLI)
                if (data.len < cursor + 1) return error.BufferTooShort;
                const ack_range_count = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                // First ACK Range (VLI)
                if (data.len < cursor + 1) return error.BufferTooShort;
                const first_ack_range = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                // Subsequent ACK Ranges (Gap | ACK Range Length) * ACK Range Count times
                var ack_ranges = std.ArrayList(struct { gap: u64, length: u64 }).init(self.allocator);
                errdefer ack_ranges.deinit();

                var i: u64 = 0;
                while (i < ack_range_count) : (i += 1) {
                    // Gap (VLI)
                    if (data.len < cursor + 1) return error.BufferTooShort;
                    const gap = try parse_vli(data[cursor..], &vli_read_len);
                    cursor += vli_read_len;

                    // ACK Range Length (VLI)
                    if (data.len < cursor + 1) return error.BufferTooShort;
                    const length = try parse_vli(data[cursor..], &vli_read_len);
                    cursor += vli_read_len;

                    try ack_ranges.append(.{ .gap = gap, .length = length });
                }

                *bytes_read_out = cursor; // Total bytes consumed by this ACK frame

                // Note: This requires the 'ack' variant to be added to packet.Frame
                return .{ .ack = AckFrame{
                    .largest_acknowledged = largest_acknowledged,
                    .ack_delay = ack_delay,
                    .ack_range_count = ack_range_count,
                    .first_ack_range = first_ack_range,
                    .ack_ranges = ack_ranges, // Ownership is transferred
                } };
            },

            0x08...0x0f => { // STREAM frames (Type | Stream ID | [Offset] | [Length] | Stream Data)
                const flags = @as(u8, frame_type_vli) & 0x07; // Flags are in the low bits of the first byte of the type VLI
                const has_offset = (flags & 0x01) != 0; // OFFSET flag
                const has_length = (flags & 0x02) != 0; // LEN flag
                const is_fin = (flags & 0x04) != 0; // FIN flag

                var stream_id: u64 = 0;
                var offset_val: u64 = 0;
                var length_val: u64 = 0;
                var stream_data_end: usize = data.len; // Default if no length field

                // Stream ID (VLI)
                if (data.len < cursor + 1) return error.BufferTooShort;
                stream_id = try parse_vli(data[cursor..], &vli_read_len);
                cursor += vli_read_len;

                // Offset (VLI, if present)
                if (has_offset) {
                    if (data.len < cursor + 1) return error.BufferTooShort;
                    offset_val = try parse_vli(data[cursor..], &vli_read_len);
                    cursor += vli_read_len;
                }

                // Length (VLI, if present)
                if (has_length) {
                    if (data.len < cursor + 1) return error.BufferTooShort;
                    length_val = try parse_vli(data[cursor..], &vli_read_len);
                    cursor += vli_read_len;
                    stream_data_end = cursor + @as(usize, length_val);
                    if (data.len < stream_data_end) return error.BufferTooShort; // Not enough data for specified length
                } else {
                    // If no Length field, the data extends to the end of the packet payload.
                    // The STREAM frame MUST be the last frame in the packet in this case.
                    // Our processFrames loop will naturally handle this by the while loop condition.
                    stream_data_end = data.len; // Data goes to the end of the input slice
                }

                const stream_data = data[cursor .. stream_data_end];
                cursor = stream_data_end; // Move cursor to the end of the frame data

                *bytes_read_out = cursor; // Total bytes consumed by this frame

                return .{ .stream = .{
                    .stream_id = stream_id,
                    .offset = offset_val,
                    .length = @as(u64, stream_data.len), // Store the actual length of the data slice
                    .fin = is_fin,
                    .data = stream_data, // Slice pointing into the input data
                } };
            }

            // TODO: Add cases for other important frame types (ACK, CRYPTO, MAX_DATA, etc.)

            else => {
                // Unknown or unimplemented frame type.
                // According to RFC 9000 Section 19, an endpoint that receives a frame type
                // it does not support MUST treat this as a connection error of type FRAME_ENCODING_ERROR,
                // unless the frame type is an extension frame and the endpoint is willing to ignore it.
                // For now, we'll treat any unknown type as an error.
                log.warn("Encountered unknown or unimplemented frame type: {x}", .{frame_type_vli});
                // To correctly skip an unknown frame, we would need to know its format.
                // For this minimal implementation, returning an error is simplest.
                return error.UnknownFrameType;
            }
        }
        frame.ack_ranges.deinit();
    }

    /// Removes header protection from a packet\'s header bytes.
    /// This is a placeholder and needs actual cryptographic implementation.
    /// It takes the full packet data, the offset to the first byte (flags), and the offset to the Packet Number field.
    /// It returns the unprotected first byte and the determined Packet Number length.
    /// Note: This function assumes `packet_data` is a mutable copy if header protection is applied in-place.
    /// Removes header protection from a packet\'s header bytes.
    /// This is a placeholder and needs actual cryptographic implementation.
    /// It takes the full packet data, the offset to the first byte (flags), and the offset to the Packet Number field.
    /// It returns the unprotected first byte and the determined Packet Number length.
    /// Note: This function operates directly on the `packet_data` slice (modifying in-place).
    fn removeHeaderProtection(self: *Connection, packet_type: packet.PacketType, packet_data: []u8, offset_to_first_byte: usize, offset_to_pn: usize) !struct {unprotected_first_byte: u8, pn_length: usize} {
        log.debug("Removing header protection for packet type {}", .{packet_type});
        // TODO: Implement QUIC Header Protection using keys derived from TLS.
        // This involves selecting the correct key and mask based on packet type and key phase,
        // and applying the mask to the protected fields (Packet Number and some flags).
        // The PN length (1, 2, or 4) is signaled in the unprotected first byte.
        // For now, return a placeholder unprotected first byte and a default PN length.
        _ = self; // Avoid unused variable warning
        _ = packet_data; // Avoid unused variable warning
        _ = offset_to_first_byte; // Avoid unused variable warning
        _ = offset_to_pn; // Avoid unused variable warning

        // Placeholder: Assume a fixed PN length and return the original first byte
        const assumed_pn_length: usize = 4; // Common for Initial/Handshake, but needs to be dynamic
        // In a real implementation, the mask would be generated and XORed with packet_data[offset_to_first_byte]
        // and packet_data[offset_to_pn .. offset_to_pn + pn_length].
        const unprotected_first_byte = packet_data[offset_to_first_byte]; // Placeholder - should be result of masking

        log.warn("removeHeaderProtection is a placeholder, not performing actual crypto", .{});

        return .{
            .unprotected_first_byte = unprotected_first_byte, // Placeholder
            .pn_length = assumed_pn_length, // Placeholder
        };
    }

    /// Decrypts the payload of a QUIC packet.
    /// This is a placeholder and needs actual cryptographic implementation.
    /// Returns a newly allocated buffer containing the decrypted payload.
    fn decryptPacketPayload(self: *Connection, packet_type: packet.PacketType, packet_number: u64, encrypted_payload: []const u8) ![]u8 {
        log.debug(\"Decrypting payload for packet type {} pn {}\", .{packet_type, packet_number});
        // TODO: Implement QUIC packet decryption using keys derived from TLS.
        // This involves selecting the correct key and AEAD algorithm based on packet type and key phase.
        // Need to verify the Authentication Tag.
        // For now, just copy the input bytes to simulate returning a new buffer.
        var decrypted_payload = try self.allocator.dupe(u8, encrypted_payload);
        _ = self; // Avoid unused variable warning
        _ = packet_type;
        _ = packet_number;
        return decrypted_payload; // Placeholder (undecrypted copy)
    frame.ack_ranges.deinit();
}

/// Removes header protection from a packet's header bytes.
/// This is a placeholder and needs actual cryptographic implementation.
/// Returns the unprotected header bytes (could be a slice or a new buffer).
fn removeHeaderProtection(self: *Connection, packet_type: packet.PacketType, header_bytes: []const u8) ![]const u8 {
    log.debug("Removing header protection for packet type {}", .{packet_type});
    // TODO: Implement QUIC Header Protection using keys derived from TLS
    // This involves selecting the correct key and mask based on packet type and key phase,
    // and applying the mask to the protected fields (Packet Number and some flags).
    // For now, just return the original bytes.
    _ = self; // Avoid unused variable warning
    _ = packet_type;
    return header_bytes; // Placeholder
}

/// Decrypts the payload of a QUIC packet.
/// This is a placeholder and needs actual cryptographic implementation.
/// Returns a newly allocated buffer containing the decrypted payload.
fn decryptPacketPayload(self: *Connection, packet_type: packet.PacketType, packet_number: u64, encrypted_payload: []const u8) ![]u8 {
    log.debug("Decrypting payload for packet type {} pn {}", .{packet_type, packet_number});
    // TODO: Implement QUIC packet decryption using keys derived from TLS.
    // This involves selecting the correct key and AEAD algorithm based on packet type and key phase.
    // Need to verify the Authentication Tag.
    // For now, just copy the input bytes to simulate returning a new buffer.
    var decrypted_payload = try self.allocator.dupe(u8, encrypted_payload);
    _ = self; // Avoid unused variable warning
    _ = packet_type;
    _ = packet_number;
    return decrypted_payload; // Placeholder (undecrypted copy)
}

/// Process an incoming CRYPTO frame
fn processCryptoFrame(self: *Connection, frame: packet.CryptoFrame) !void {
    log.debug("Processing CRYPTO frame: offset={}, len={}", .{ frame.offset, frame.data.len });

    // TODO: Pass this data to the TLS context for handshake processing.
    // The offset indicates the position within the TLS handshake stream.
    // The data contains the TLS handshake messages.

    // Example: crypto.processHandshakeData(self.tls_ctx, frame.data);

    // TODO: Handle TLS handshake state transitions (e.g., handshake complete, alerts).
    // If the handshake completes, transition connection state to .connected.
    // If TLS produces outgoing handshake data, queue it in CRYPTO frames.
}

/// Process frames contained within a packet payload
/// This function iterates through the decrypted payload bytes,
/// parses each frame, and dispatches it for processing.
fn processFrames(self: *Connection, payload_bytes: []const u8) !void {
    log.debug("Processing frames from payload ({} bytes)", .{payload_bytes.len});
        var cursor: usize = 0;
        while (cursor < payload_bytes.len) {
            var bytes_read: usize = 0;
            const frame = try self.parseFrame(payload_bytes[cursor..], &bytes_read); // Call the new parseFrame method
            try self.processFrame(frame); // Process the parsed frame
            cursor += bytes_read;
            // Note: frame might contain slices into payload_bytes, these are valid
            // as long as payload_bytes is valid (which it is until the defer in
            // processLongHeaderPacket/processShortHeaderPacket).
            // If a frame needs to live longer than the packet processing, its data
            // needs to be copied. The current StreamFrame .data field holds a slice,
            // which is fine for immediate processing within processStreamFrame.
        }
    }

    /// Process a single QUIC frame
    fn processFrame(self: *Connection, frame: packet.Frame) !void {
        switch (frame) {
            .padding => {
                log.debug("Processing PADDING frame", .{});
                // Nothing to do for padding - it's just ignored.
            },
            .ping => {
                log.debug("Processing PING frame", .{});
                // The recipient of a PING frame MUST send a packet containing an ACK frame
                // in response as soon as possible. This is handled implicitly by sending
                // any packet, but explicit ACK generation logic is needed elsewhere.
            },
            .ack => |ack_frame| {
                try self.processAckFrame(ack_frame);
            },
            .crypto => |crypto_frame| {
                try self.processCryptoFrame(crypto_frame);
            },
            .stream => |stream_frame| {
                try self.processStreamFrame(stream_frame);
            },
            // TODO: Add cases for other important frame types:
            // ACK, CRYPTO, NEW_CONNECTION_ID, MAX_DATA, MAX_STREAMS, DATA_BLOCKED,
            // STREAM_DATA_BLOCKED, STREAMS_BLOCKED, STOP_SENDING, RESET_STREAM,
            // PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE (transport/application),
            // HANDSHAKE_DONE, NEW_TOKEN, RETIRE_CONNECTION_ID, etc.
            .raw => {
                // This case existed in the old parsePacket output structure but
                // should not be reachable with the new frame parsing logic in parseFrame.
                // If it is reached, it indicates a parsing issue.
                log.err("Encountered unexpected raw frame in processFrame. Parsing error?", .{});
                return error.InternalError; // Should not happen
            },
        }
    }

    /// Process a STREAM frame
    fn processStreamFrame(self: *Connection, frame: packet.StreamFrame) !void {
        log.debug("Processing STREAM frame on stream {} (offset: {}, len: {}, fin: {})", .{ frame.stream_id, frame.offset, frame.length, frame.fin });

        // Find the stream or create it if it's a new peer-initiated stream.
        // Stream IDs: Client-initiated Bidi (0,4,8...), Client-initiated Uni (1,5,9...)
        //             Server-initiated Bidi (1,5,9...), Server-initiated Uni (0,4,8...)
        // Peer-initiated streams have the opposite number parity based on our role.
        // Bidi: If our role is client, peer stream ID is odd. If our role is server, peer stream ID is even.
        // Uni: If our role is client, peer stream ID is even. If our role is server, peer stream ID is odd.

        const is_peer_initiated_bidi = (self.role == .client and (frame.stream_id % 4 == 1 or frame.stream_id % 4 == 3)) or
                                       (self.role == .server and (frame.stream_id % 4 == 0 or frame.stream_id % 4 == 2));
        const is_peer_initiated_uni = (self.role == .client and (frame.stream_id % 4 == 2 or frame.stream_id % 4 == 0)) or // Uni client stream ID is 1 mod 4
                                      (self.role == .server and (frame.stream_id % 4 == 3 or frame.stream_id % 4 == 1)); // Uni server stream ID is 3 mod 4

        // Correct peer-initiated stream ID parity check based on RFC 9000 Section 2.1
        // Client-initiated: 0x00 (bidi), 0x01 (uni) -> 0 and 1 mod 4
        // Server-initiated: 0x02 (bidi), 0x03 (uni) -> 2 and 3 mod 4

        const is_client_initiated = (frame.stream_id % 2) == 0; // Low bit 0 for client-initiated
        const is_unidirectional = (frame.stream_id & 0x02) != 0; // Bit 1 set for unidirectional

        const is_peer_initiated = (self.role == .client and !is_client_initiated) or
                                  (self.role == .server and is_client_initiated);


        var stream = self.streams.get(frame.stream_id);
        if (stream == null) {
             if (is_peer_initiated) {
                log.info("Peer initiated new stream {}", .{frame.stream_id});
                // TODO: Check stream count limits (initial_max_streams_bidi/uni) before creating
                 var new_stream = try stream_mod.createStream(self.allocator, self, frame.stream_id, is_unidirectional);
                 try self.streams.put(frame.stream_id, new_stream);
                 stream = new_stream;

                 // Notify through the connection event callback
                 self.event_callback(self, .{ .new_stream = .{
                     .stream_id = frame.stream_id,
                     .is_unidirectional = is_unidirectional,
                 } }, self.user_ctx);

             } else {
                 // Received data on a stream ID that wasn't initiated by us or the peer correctly.
                 // This could be an error.
                 log.warn("Received data on unknown or invalid stream ID {} (is_peer_initiated: {})", .{frame.stream_id, is_peer_initiated});
                 // TODO: Send STREAM_STATE error or close connection with PROTOCOL_VIOLATION
                 return error.UnknownStream;
             }
        }

        // Process data and FIN flag within the stream
        // The `frame.data` here is a slice into the potentially encrypted payload
        // or the raw bytes if decryption hasn't happened correctly yet.
        // The stream\'s processStreamData should handle buffering, ordering, and flow control.
        try stream.?.processStreamData(frame.data, frame.offset, frame.fin);
    }

    /// Queue a handshake response packet
    fn queueHandshakeResponse(self: *Connection) !void {
        var pkt = try Packet.create(self.allocator, .handshake);
        errdefer {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        // Just create some dummy handshake content
        try pkt.data.appendSlice(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

        try self.outgoing_packets.append(pkt);
    }

    /// Simulate client opening streams to test the HTTP/3 handler
    fn simulateClientStreams(self: *Connection) !void {
        // Simulate client opening a control stream
        const control_stream_id = 0;
        try self.notifyNewStream(control_stream_id, true);

        // Simulate client opening QPACK streams
        const encoder_stream_id = 2;
        try self.notifyNewStream(encoder_stream_id, true);

        const decoder_stream_id = 3;
        try self.notifyNewStream(decoder_stream_id, true);

        // Simulate a regular request stream
        const request_stream_id = 4;
        try self.notifyNewStream(request_stream_id, false);
    }

    /// Notify about a new stream
    fn notifyNewStream(self: *Connection, stream_id: u64, is_unidirectional: bool) !void {
        // Create stream object
        var stream = try stream_mod.createStream(self.allocator, self, stream_id, is_unidirectional);
        try self.streams.put(stream_id, stream);

        // Notify through callback
        self.event_callback(self, .{ .new_stream = .{
            .stream_id = stream_id,
            .is_unidirectional = is_unidirectional,
        } }, self.user_ctx);
    }

    /// Get the next outgoing packet
    pub fn getNextOutgoingPacket(self: *Connection) ?*Packet {
        if (self.outgoing_packets.items.len == 0) return null;

        // Take the first packet
        const pkt = self.outgoing_packets.orderedRemove(0);

        // Update stats
        self.packets_sent += 1;
        self.bytes_sent += pkt.data.items.len;

        return pkt;
    }

    /// Update the next timeout
    fn updateTimeout(self: *Connection) void {
        const now = std.time.nanoTimestamp();

        // Basic idle timeout
        const idle_timeout_ns = self.max_idle_timeout_ms * std.time.ns_per_ms;
        const idle_deadline = self.latest_activity_time + idle_timeout_ns;

        // Set next timeout
        self.next_timeout = idle_deadline;
    }

    /// Process any timeouts
    pub fn processTimeouts(self: *Connection) !void {
        const now = std.time.nanoTimestamp();

        // Check idle timeout
        const idle_timeout_ns = self.max_idle_timeout_ms * std.time.ns_per_ms;
        if (now - self.latest_activity_time > idle_timeout_ns) {
            log.info("Connection idle timeout", .{});
            try self.close(0, "Idle timeout");
            return;
        }

        // Update timeout
        self.updateTimeout();
    }

    /// Close the connection
    pub fn close(self: *Connection, error_code: u64, reason: []const u8) !void {
        if (self.state == .closed or self.state == .draining) return;

        log.info("Closing connection: error={d}, reason={s}", .{ error_code, reason });

        // Change state
        self.state = .closing;

        // Queue connection close packet
        var pkt = try Packet.create(self.allocator, .connection_close);
        errdefer {
            pkt.deinit();
            self.allocator.destroy(pkt);
        }

        // Add error code and reason to packet
        try pkt.data.appendSlice(&std.mem.toBytes(error_code));
        try pkt.data.appendSlice(reason);

        try self.outgoing_packets.append(pkt);

        // Notify about connection closing
        self.event_callback(self, .{ .connection_closed = .{
            .error_code = error_code,
            .reason = reason,
        } }, self.user_ctx);

        // Move to draining state
        self.state = .draining;

        // In a real implementation, we'd start the draining timer here
    }
};

/// Creates a new QUIC connection
pub fn createConnection(allocator: Allocator, options: ConnectionOptions) !*Connection {
    log.info("Creating new QUIC connection to {}", .{options.remote_address});
    return Connection.init(allocator, options);
}

/// Destroys a QUIC connection and frees associated resources
pub fn destroyConnection(conn: *Connection) void {
    conn.deinit();
}

/// Starts the TLS handshake process for a QUIC connection
pub fn startHandshake(conn: *Connection) !void {
    log.info("Starting QUIC handshake with {}", .{conn.remote_address});

    if (conn.state != .handshaking) {
        return error.InvalidConnectionState;
    }

    // In a real implementation, this would prepare and queue initial packets
    // For this example, just create a simple handshake packet if we're a client
    if (conn.role == .client) {
        try conn.queueHandshakeResponse();
    }
}

/// Handles an incoming UDP packet for a QUIC connection
pub fn receivePacket(conn: *Connection, data: []const u8) !void {
    try conn.processPacket(data);
}

/// Gets the next timeout for this connection
pub fn getNextTimeout(conn: *Connection) ?i64 {
    return conn.next_timeout;
}

/// Process any connection timeouts
pub fn processTimeouts(conn: *Connection) !void {
    try conn.processTimeouts();
}

/// Gets the next outgoing packet to be sent
pub fn getNextOutgoingPacket(conn: *Connection) ?*Packet {
    return conn.getNextOutgoingPacket();
}

/// Closes the connection with an error code and reason
pub fn closeConnection(conn: *Connection, error_code: u64, reason: []const u8) !void {
    try conn.close(error_code, reason);
}
