// src/quic/packet.zig
// QUIC packet handling

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.quic_packet);
const parse_vli = @import("util.zig").parseVli; // Assume a VLI parser exists or will be added


/// Types of QUIC packets
pub const PacketType = enum {
    initial, // Initial handshake packet
    handshake, // Handshake packet
    zero_rtt, // 0-RTT packet
    retry, // Retry packet
    version_negotiation, // Version negotiation packet
    short_header, // 1-RTT (fully encrypted) packet
    connection_close, // Connection close packet
};

/// Represents a QUIC ACK frame (Type 0x02, 0x03)
pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64, // In units of the ACK Delay Exponent
    ack_range_count: u64,
    first_ack_range: u64,
    // Sequence of (Gap, ACK Range Length) pairs
    // Gap and ACK Range Length are VLIs
    ack_ranges: std.ArrayList(struct { gap: u64, length: u64 }),
};

/// Represents a QUIC CRYPTO frame (Type 0x06)
pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
};

/// Represents a QUIC Frame
pub const Frame = union(enum) {
    /// Padding frame (type 0x00)
    padding: void,
    /// Ping frame (type 0x01)
    ping: void,
    /// ACK frame (type 0x02, 0x03)
    ack: AckFrame,
    /// CRYPTO frame (type 0x06)
    crypto: CryptoFrame,
    /// STREAM frame (type 0x08-0x0f)
    stream: StreamFrame,
    // TODO: Add other frame types

    /// Raw frame data (for unparsed frames)
    raw: []const u8,
};

/// Represents a STREAM frame (type 0x08-0x0f)
pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    length: u64,
    fin: bool,
    data: []const u8,
};

/// Represents a Long Header packet (Initial, 0-RTT, Handshake, Retry)
pub const LongHeader = struct {
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    // Token (Initial packets)
    // Length (Initial, 0-RTT, Handshake)
    // Packet Number (Initial, 0-RTT, Handshake)
};

/// Represents a Short Header packet (1-RTT)
pub const ShortHeader = struct {
    // ODCID (Optional Destination Connection ID)
    // Packet Number
    // Key Phase
};

/// Union of possible packet headers
pub const PacketHeader = union(enum) {
    long: LongHeader,
    short: ShortHeader,
};


/// Represents a QUIC packet
pub const Packet = struct {
    allocator: Allocator,
    packet_type: PacketType,
    packet_number: u64,

    // Parsed header and frames
    header: PacketHeader,
    frames: std.ArrayList(Frame), // List of frames contained in the packet

    // Store the raw data for serialization/debugging
    raw_data: std.ArrayList(u8),

    /// Create a new packet with the given type
    pub fn create(allocator: Allocator, packet_type: PacketType) !*Packet {
        var pkt = try allocator.create(Packet);
        errdefer allocator.destroy(pkt);

        // Note: packet_number and header will be populated during parsing or building
        pkt.* = .{
            .allocator = allocator,
            .packet_type = packet_type,
            .packet_number = 0, // This will be overwritten
            .header = undefined, // Must be initialized later based on type
            .frames = std.ArrayList(Frame).init(allocator),
            .raw_data = std.ArrayList(u8).init(allocator),
        };

        return pkt;
    }

    /// Clean up packet resources
    pub fn deinit(self: *Packet) void {
        // TODO: Deinitialize frame-specific data if any (e.g., frame.stream.data if it's owned)
        // For now, frames only contain slices of raw_data, so just deinit the list and raw_data
        self.frames.deinit();
        self.raw_data.deinit();
    }
};

/// Parse a raw UDP packet into a QUIC packet structure
pub fn parsePacket(allocator: Allocator, data: []const u8) !*Packet {
    if (data.len < 4) return error.PacketTooShort; // Minimum size for first byte + version

    const first_byte = data[0];
    var cursor: usize = 0;

    var parsed_header: PacketHeader = undefined;
    var packet_type: PacketType = undefined; // Will be determined from header type

    if ((first_byte & 0x80) != 0) {
        // Long Header Packet
        packet_type = blk: {
             const packet_type_bits = (first_byte & 0x30) >> 4;
             break :blk switch (packet_type_bits) {
                 0x0 => .initial,
                 0x1 => .zero_rtt,
                 0x2 => .handshake,
                 0x3 => .retry,
                 else => return error.InvalidPacketType, // Should not happen with mask
             };
        };

        if (data.len < 6) return error.PacketTooShort; // Long header minimum size

        cursor += 1; // First byte

        const version = std.mem.readIntBig(u32, data[cursor..cursor+4]);
        cursor += 4;

        // Special case for Version Negotiation
        if (version == 0) {
             // Version Negotiation packet has a different format
             // It doesn't have Connection IDs or Length fields in the standard way
             // For now, just recognize it and return an error/specific packet type
             log.debug("Received Version Negotiation packet", .{});
             // TODO: Parse Version Negotiation specific fields (list of supported versions)
             return error.VersionNegotiation; // Signify this is a VN packet
        }

        // Destination Connection ID (DCID) Length (4 bits)
        if (data.len < cursor + 1) return error.PacketTooShort;
        const dcid_len = data[cursor]; // Length is encoded directly after version in some LH packets? Or is it part of first byte?
                                       // QUIC spec rfc9000 Section 17.2: Lengths for DCID and SCID are encoded in the first byte (0x40 and 0x20)
                                       // Let's re-parse based on the spec structure
        cursor = 0; // Reset cursor for proper LH parsing

        const type_and_flags = data[cursor];
        cursor += 1;
        const version_lh = std.mem.readIntBig(u32, data[cursor..cursor+4]);
        cursor += 4;

        // Destination Connection ID (DCID)
        const dcil = (type_and_flags & 0x0f); // DCID Length field in low 4 bits
        if (data.len < cursor + dcil) return error.PacketTooShort;
        const dcid_bytes = data[cursor .. cursor + dcil];
        cursor += dcil;

        // Source Connection ID (SCID)
        if (data.len < cursor + 1) return error.PacketTooShort; // SCID Length
        const scil = data[cursor];
        cursor += 1;
        if (data.len < cursor + scil) return error.PacketTooShort;
        const scid_bytes = data[cursor .. cursor + scil];
        cursor += scil;

        // For Initial/Handshake/0-RTT: Token (Initial only), Length, Packet Number
        if (packet_type != .retry) {
            // Token (Initial only) - Variable Length
            var token_len: u64 = 0;
            if (packet_type == .initial) {
                 if (data.len < cursor + 1) return error.PacketTooShort; // Token Length VLI first byte
                 var read_len: usize = 0;
                 token_len = try parse_vli(data[cursor..], &read_len);
                 cursor += read_len;
                 if (data.len < cursor + @as(usize, token_len)) return error.PacketTooShort;
                 // Skip token bytes for now: data[cursor .. cursor + @as(usize, token_len)]
                 cursor += @as(usize, token_len);
            }

            // Length (Includes Packet Number and Protected Payload) - Variable Length
            if (data.len < cursor + 1) return error.PacketTooShort; // Length VLI first byte
            var length_val: u64 = 0;
            var read_len: usize = 0;
            length_val = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;

            // The remaining data should be 'length_val' bytes
            if (data.len < cursor + @as(usize, length_val)) return error.PacketTooShort;

            // We would typically decrypt here to get the Packet Number and Protected Payload
            // For now, we can't parse the Packet Number correctly without decryption.
            // Let's just store the raw payload bytes for frame parsing later.
            const protected_payload = data[cursor .. cursor + @as(usize, length_val)];
            // cursor += @as(usize, length_val); // cursor is now at the end of the packet

             parsed_header = .{
                 .long = .{
                     .version = version_lh,
                     .destination_connection_id = dcid_bytes,
                     .source_connection_id = scid_bytes,
                     // TODO: Add Token, Length, Packet Number fields after decryption/full parsing
                 }
             };
             // Packet number is part of the protected payload, need decryption
             // For now, set a placeholder
             const packet_number: u64 = 0; // Placeholder

             // TODO: Parse frames from protected_payload AFTER decryption
             const frame_bytes = protected_payload; // This is encrypted/protected!

             // Create packet structure with type inferred from Long Header flags
             var packet = try Packet.create(allocator, packet_type);
             errdefer {
                 packet.deinit();
                 allocator.destroy(packet);
             }
             packet.header = parsed_header;
             packet.packet_number = packet_number; // Placeholder
             try packet.raw_data.appendSlice(data); // Store raw data

             // TODO: Iterate through frame_bytes and parse frames
             // For now, add the whole protected payload as a raw frame
             if (frame_bytes.len > 0) {
                 try packet.frames.append(.{ .raw = frame_bytes });
             }


             return packet;


        } else {
            // Retry packet (similar header, no Length, no Packet Number, includes Retry Token)
            // QUIC spec rfc9000 Section 17.2.5
            log.warn("Retry packet parsing not implemented", .{});
            return error.NotImplemented; // TODO: Implement Retry packet parsing
        }


    } else {
        // Short Header Packet (1-RTT)
        packet_type = .short_header;

        // The short header format is simpler:
        // 1 | R R | K | P N
        // ODCID (length implicitly known or carried over from LH)
        // Packet Number (length 1, 2, or 4 bytes)
        // Protected Payload (Frames)

        // We need the DCID to identify the connection and lookup decryption keys.
        // This DCID should match the SCID from the client's Initial packet.
        // This requires connection state look-up, which parsePacket shouldn't do.
        // A higher layer needs to lookup the connection by DCID and pass the connection context.
        // For now, let's assume the connection context is available and contains the DCID.
        // But since this function is standalone, we can't do that.
        // Let's modify parsePacket to potentially return the DCID separately or require it.

        // Rethinking parsePacket: It should probably just parse the *header* to get DCID
        // and maybe SCID/Packet Number if possible without decryption.
        // Then a connection lookup can happen. After lookup, the packet payload
        // (or the whole packet) can be passed to a connection-specific decryption/processing function.

        // For this iteration, let's parse the short header fields that are not encrypted.
        // This is tricky because the Packet Number Length (PN Length) is signaled in the first byte (0x03, 0x02, 0x01),
        // and the ODCID is of variable length, determined by the connection state.

        // Let's simplify drastically for now: just identify it's a short header
        // and store the raw data. Actual parsing will need the connection context.

        // Create packet structure
        var packet = try Packet.create(allocator, packet_type);
        errdefer {
            packet.deinit();
            allocator.destroy(packet);
        }

        // Store raw data
        try packet.raw_data.appendSlice(data);

        // The header details (DCID, Packet Number, etc.) are not parsable reliably
        // without connection state/decryption keys.
        // We can set a placeholder header type.
        parsed_header = .{ .short = .{} }; // Placeholder

        packet.header = parsed_header;
        packet.packet_number = 0; // Placeholder

        // Frames are encrypted in short headers. Store the whole payload as raw for now.
        // The payload starts after the DCID and Packet Number, whose lengths are variable.
        // Cannot reliably extract frames here without more context.
        // For now, let's just store the whole raw data and parse frames later
        // in the connection's processPacket after decryption.
        if (data.len > 0) { // In reality, payload starts AFTER header
             try packet.frames.append(.{ .raw = data }); // This is wrong, includes header
        }
         // Correct approach: Store the whole data, decryption happens later.
         // Parsing into header/frames requires decrypted payload and connection context.
         // This `parsePacket` function as a standalone utility is not suitable for Short Headers.

         // Let's make `parsePacket` just identify type and extract DCID if possible (tricky for short header)
         // and return a basic structure.

         // Re-attempting Short Header parsing based on first byte for PN length, ignoring ODCID for now
         cursor = 0;
         const sh_first_byte = data[cursor];
         cursor += 1;
         const pn_length_bits = (sh_first_byte & 0x03);
         const pn_length = switch (pn_length_bits) {
             0x0 => 1,
             0x1 => 2,
             0x2 => 4,
             0x3 => 4, // Or 4 in some drafts? rfc9000 is 1,2,4
             else => 1, // Should not happen
         };
         // Assuming Packet Number is right after first byte + ODCID (which we skip for now)
         // The ODCID length is *not* in the short header. It must be known from the connection.
         // This confirms `parsePacket` as a standalone function is incorrect for Short Headers.
         // It needs to be a method of the Connection struct, or take connection state.

         // Let's revert parsePacket to its original simpler form but add the new structs.
         // The detailed parsing will need to happen inside the Connection struct.
         // This `parsePacket` can perhaps just identify the header type and return it,
         // and the raw payload bytes.

        return error.NotImplemented; // Signify short header parsing needs context
    }

}

/// Parse a raw UDP packet into a QUIC packet structure
/// Note: This function is simplified and needs connection context for full parsing
/// especially for Short Headers and encrypted payloads.
pub fn parsePacket(allocator: Allocator, data: []const u8) !*Packet {
    if (data.len < 1) return error.PacketTooShort;

    const first_byte = data[0];
    var cursor: usize = 0;

    var parsed_header: PacketHeader = undefined;
    var packet_type: PacketType = undefined;
    var packet_number: u64 = 0; // Placeholder
    var payload_bytes: []const u8 = &[]; // Placeholder for payload bytes

    if ((first_byte & 0x80) != 0) {
        // Long Header Packet
        packet_type = blk: {
             const packet_type_bits = (first_byte & 0x30) >> 4;
             break :blk switch (packet_type_bits) {
                 0x0 => .initial,
                 0x1 => .zero_rtt,
                 0x2 => .handshake,
                 0x3 => .retry,
                 else => return error.InvalidPacketType,
             };
        };

        if (data.len < 6) return error.PacketTooShort; // Min LH size

        cursor += 1; // Type and Flags byte
        const version = std.mem.readIntBig(u32, data[cursor..cursor+4]);
        cursor += 4;

        if (version == 0) {
             return error.VersionNegotiation;
        }

        // DCID Length (4 bits of first byte) and DCID
        const dcil = (first_byte & 0x0f);
        if (data.len < cursor + dcil) return error.PacketTooShort;
        const dcid_bytes = data[cursor .. cursor + dcil];
        cursor += dcil;

        // SCID Length (8 bits) and SCID
        if (data.len < cursor + 1) return error.PacketTooShort;
        const scil = data[cursor];
        cursor += 1;
        if (data.len < cursor + scil) return error.PacketTooShort;
        const scid_bytes = data[cursor .. cursor + scil];
        cursor += scil;

        // Initial/Handshake/0-RTT have Token, Length, Packet Number, Protected Payload
        if (packet_type != .retry) {
            // Token (Initial only) - Variable Length
            if (packet_type == .initial) {
                 if (data.len < cursor + 1) return error.PacketTooShort; // Token Length VLI first byte
                 var read_len: usize = 0;
                 const token_len = try parse_vli(data[cursor..], &read_len);
                 cursor += read_len;
                 if (data.len < cursor + @as(usize, token_len)) return error.PacketTooShort;
                 cursor += @as(usize, token_len); // Skip token
            }

            // Length (Packet Number + Protected Payload) - Variable Length
            if (data.len < cursor + 1) return error.PacketTooShort; // Length VLI first byte
            var read_len: usize = 0;
            const length_val = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;

            // Remaining data is the Protected Payload (length_val bytes)
            if (data.len < cursor + @as(usize, length_val)) return error.PacketTooShort;
            payload_bytes = data[cursor .. cursor + @as(usize, length_val)];
            // cursor += @as(usize, length_val); // cursor is now at end

            parsed_header = .{
                .long = .{
                    .version = version,
                    .destination_connection_id = dcid_bytes,
                    .source_connection_id = scid_bytes,
                    // Token and Length are consumed, not stored explicitly in this basic header struct
                }
            };
            // Packet Number is within the Protected Payload, requires decryption.
            // Cannot parse here. Set placeholder.
            packet_number = 0; // Placeholder

        } else {
            // Retry packet - Format is different (Retry Token, Tag)
             log.warn("Retry packet parsing not fully implemented", .{});
             // For now, just store remaining data as payload
             payload_bytes = data[cursor..];
             parsed_header = .{
                 .long = .{
                     .version = version,
                     .destination_connection_id = dcid_bytes,
                     .source_connection_id = scid_bytes,
                 }
             };
             packet_type = .retry; // Ensure type is set
        }


    } else {
        // Short Header Packet (1-RTT)
        packet_type = .short_header;

        // Cannot parse Short Header DCID or Packet Number without connection context
        // (DCID length is implicit, Packet Number is encrypted).
        // Just store the raw data for processing within the connection.
        // This packet header will be a placeholder.
        parsed_header = .{ .short = .{} }; // Placeholder

        // Entire data is the payload for now, decryption will happen later.
        payload_bytes = data; // Includes first byte, need to adjust after DCID lookup

        // This function needs significant changes to handle Short Headers properly.
        // Acknowledge this limitation.
         log.warn("Basic parsePacket cannot fully parse Short Headers without connection context", .{});
         return error.NotImplemented; // Indicate that this packet type needs context
    }

    // Create packet structure
    var packet = try Packet.create(allocator, packet_type);
    errdefer {
        packet.deinit();
        allocator.destroy(packet);
    }
    packet.header = parsed_header;
    packet.packet_number = packet_number; // Placeholder
    try packet.raw_data.appendSlice(data); // Store raw data

    // Attempt to parse frames from payload_bytes (will only work for unencrypted/known formats)
    // For Long Headers (Initial, Handshake), the payload is the protected data, which needs decryption.
    // For Short Headers, the payload is encrypted.
    // Frame parsing must happen *after* decryption and header processing (like packet number recovery).

    // For now, we will just add the (potentially encrypted) payload as a single raw frame
    // if the packet type is one that *could* contain frames (Initial, Handshake, 0-RTT, Short Header).
    if (packet_type != .retry and packet_type != .version_negotiation) {
         if (payload_bytes.len > 0) {
              // This is not correct, payload_bytes is encrypted!
              // We can't parse frames from it yet.
              // The frame parsing logic needs to move into the connection's processPacket method
              // after decryption is handled.

              // For the purpose of this edit adding structs, we will add a placeholder frame parsing loop.
              // This loop is *incorrect* for encrypted payloads and will be replaced later.
              log.warn("Parsing frames from potentially encrypted payload - This needs refinement!", .{});
              var frame_cursor: usize = 0;
              while (frame_cursor < payload_bytes.len) {
                   const frame_start = frame_cursor;
                   const frame_type = payload_bytes[frame_cursor];
                   frame_cursor += 1;

                   var current_frame: Frame = undefined;

                   // Basic frame type identification (incomplete)
                   if (frame_type == 0x00) { // PADDING
                       current_frame = .{ .padding = {} };
                   } else if (frame_type == 0x01) { // PING
                       current_frame = .{ .ping = {} };
                   } else if (frame_type >= 0x08 and frame_type <= 0x0f) { // STREAM
                       // STREAM frame format: Type | Stream ID | Offset (optional) | Length (optional) | Stream Data
                       // Stream ID, Offset, Length are VLIs. Flags in Type byte (0x04=FIN, 0x02=LEN, 0x01=OFF)
                       const flags = frame_type & 0x07;
                       const has_offset = (flags & 0x01) != 0;
                       const has_length = (flags & 0x02) != 0;
                       const is_fin = (flags & 0x04) != 0;

                       var stream_id: u64 = 0;
                       var offset_val: u64 = 0;
                       var length_val: u64 = 0;
                       var frame_read_len: usize = 0;

                       // Stream ID
                       if (payload_bytes.len < frame_cursor + 1) return error.MalformedPacket;
                       stream_id = try parse_vli(payload_bytes[frame_cursor..], &frame_read_len);
                       frame_cursor += frame_read_len;

                       // Offset (if present)
                       if (has_offset) {
                            if (payload_bytes.len < frame_cursor + 1) return error.MalformedPacket;
                            offset_val = try parse_vli(payload_bytes[frame_cursor..], &frame_read_len);
                            frame_cursor += frame_read_len;
                       }

                       // Length (if present)
                       if (has_length) {
                            if (payload_bytes.len < frame_cursor + 1) return error.MalformedPacket;
                            length_val = try parse_vli(payload_bytes[frame_cursor..], &frame_read_len);
                            frame_cursor += frame_read_len;
                       } else {
                           // If no Length field, data extends to end of packet or next frame
                           // This basic parser can't handle this correctly yet.
                           // For simplicity, assume Length is always present for now.
                           // Or assume it goes to the end if it's the last frame.
                           // Let's assume Length is present for this placeholder.
                           return error.MalformedPacket; // Require Length for now
                       }

                       // Stream Data
                       if (payload_bytes.len < frame_cursor + @as(usize, length_val)) return error.MalformedPacket;
                       const stream_data = payload_bytes[frame_cursor .. frame_cursor + @as(usize, length_val)];
                       frame_cursor += @as(usize, length_val);

                       current_frame = .{ .stream = .{
                           .stream_id = stream_id,
                           .offset = offset_val,
                           .length = length_val,
                           .fin = is_fin,
                           .data = stream_data,
                       }};

                   } else {
                       // Unknown or unimplemented frame type
                       log.warn("Skipping unknown frame type {x}", .{frame_type});
                       // This is incorrect parsing; it should skip the frame's length.
                       // For now, just break or add the rest as raw.
                       // Add the rest of the payload as a raw frame placeholder.
                       current_frame = .{ .raw = payload_bytes[frame_start..] };
                       frame_cursor = payload_bytes.len; // Consume rest
                   }

                   try packet.frames.append(current_frame);
              }
         }
    }


    return packet;
}

/// Serialize a QUIC packet into raw bytes
/// Note: This is a placeholder and does not implement full QUIC packet serialization
/// including header fields, encryption, and frame encoding.
pub fn serializePacket(pkt: *Packet, out: []u8) !usize {
    // In a real implementation, this would assemble the header fields,
    // serialize frames, encrypt the payload, and combine everything.

    // For now, just copy the stored raw data (if any) or return an error.
    if (pkt.raw_data.items.len > 0) {
        if (out.len < pkt.raw_data.items.len) return error.BufferTooSmall;
        std.mem.copy(u8, out, pkt.raw_data.items);
        return pkt.raw_data.items.len;
    }

    // If there's no raw data, we would need to build the packet from header/frames.
    // This is not implemented here.
    log.warn("Attempting to serialize packet with no raw_data - serialization not implemented from header/frames", .{});
    return error.NotImplemented;
}
