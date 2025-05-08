// src/quic/packet.zig
// QUIC packet handling

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.quic_packet);
const parse_vli = @import("util.zig").parseVli;

/// Types of QUIC packets
pub const PacketType = enum {
    initial,
    handshake,
    zero_rtt,
    retry,
    version_negotiation,
    short_header,
    connection_close,
};

/// Represents a QUIC ACK frame (Type 0x02, 0x03)
pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_range_count: u64,
    first_ack_range: u64,
    ack_ranges: std.ArrayList(struct { gap: u64, length: u64 }),
};

/// Represents a QUIC CRYPTO frame (Type 0x06)
pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
};

/// Represents a QUIC STREAM frame (Type 0x08-0x0f)
pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    length: u64,
    fin: bool,
    data: []const u8,
};

/// Represents a QUIC Frame
pub const Frame = union(enum) {
    padding: void,
    ping: void,
    ack: AckFrame,
    crypto: CryptoFrame,
    stream: StreamFrame,
    raw: []const u8,
};

/// Represents a Long Header packet
pub const LongHeader = struct {
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
};

/// Represents a Short Header packet
pub const ShortHeader = struct {};

/// Union of packet headers
pub const PacketHeader = union(enum) {
    long: LongHeader,
    short: ShortHeader,
};

/// Represents a QUIC packet
pub const Packet = struct {
    allocator: Allocator,
    packet_type: PacketType,
    packet_number: u64,
    header: PacketHeader,
    frames: std.ArrayList(Frame),
    raw_data: std.ArrayList(u8),

    /// Create a new packet
    pub fn init(allocator: Allocator, packet_type: PacketType) !*Packet {
        var pkt = try allocator.create(Packet);
        errdefer allocator.destroy(pkt);

        pkt.* = .{
            .allocator = allocator,
            .packet_type = packet_type,
            .packet_number = 0,
            .header = undefined,
            .frames = std.ArrayList(Frame).init(allocator),
            .raw_data = std.ArrayList(u8).init(allocator),
        };

        return pkt;
    }

    /// Clean up packet resources
    pub fn deinit(self: *Packet) void {
        for (self.frames.items) |frame| {
            if (frame == .ack) frame.ack.ack_ranges.deinit();
        }
        self.frames.deinit();
        self.raw_data.deinit();
    }
};

/// Destroy a packet
pub fn destroyPacket(pkt: *Packet) void {
    pkt.deinit();
    pkt.allocator.destroy(pkt);
}

/// Parse a raw UDP packet into a QUIC packet structure
pub fn parsePacket(allocator: Allocator, data: []const u8) !*Packet {
    if (data.len < 1) return error.PacketTooShort;

    var cursor: usize = 0;
    const first_byte = data[0];
    var packet_type: PacketType = undefined;
    var parsed_header: PacketHeader = undefined;
    var payload_bytes: []const u8 = &[];

    if ((first_byte & 0x80) != 0) {
        // Long Header Packet
        packet_type = switch ((first_byte & 0x30) >> 4) {
            0x0 => .initial,
            0x1 => .zero_rtt,
            0x2 => .handshake,
            0x3 => .retry,
            else => return error.InvalidPacketType,
        };

        if (data.len < 6) return error.PacketTooShort;
        cursor += 1;
        const version = std.mem.readIntBig(u32, data[cursor .. cursor + 4]);
        cursor += 4;

        if (version == 0) return error.VersionNegotiation;

        const dcil = first_byte & 0x0f;
        if (data.len < cursor + dcil) return error.PacketTooShort;
        const dcid_bytes = data[cursor .. cursor + dcil];
        cursor += dcil;

        if (data.len < cursor + 1) return error.PacketTooShort;
        const scil = data[cursor];
        cursor += 1;
        if (data.len < cursor + scil) return error.PacketTooShort;
        const scid_bytes = data[cursor .. cursor + scil];
        cursor += scil;

        if (packet_type != .retry) {
            if (packet_type == .initial) {
                if (data.len < cursor + 1) return error.PacketTooShort;
                var read_len: usize = 0;
                const token_len = try parse_vli(data[cursor..], &read_len);
                cursor += read_len;
                if (data.len < cursor + @as(usize, token_len)) return error.PacketTooShort;
                cursor += @as(usize, token_len);
            }

            if (data.len < cursor + 1) return error.PacketTooShort;
            var read_len: usize = 0;
            const length_val = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;

            if (data.len < cursor + @as(usize, length_val)) return error.PacketTooShort;
            payload_bytes = data[cursor .. cursor + @as(usize, length_val)];

            parsed_header = .{
                .long = .{
                    .version = version,
                    .destination_connection_id = dcid_bytes,
                    .source_connection_id = scid_bytes,
                },
            };
        } else {
            payload_bytes = data[cursor..];
            parsed_header = .{
                .long = .{
                    .version = version,
                    .destination_connection_id = dcid_bytes,
                    .source_connection_id = scid_bytes,
                },
            };
        }
    } else {
        // Short Header Packet
        packet_type = .short_header;
        parsed_header = .{ .short = .{} };
        payload_bytes = data;
        log.warn("Short header parsing requires connection context", .{});
    }

    var packet = try Packet.create(allocator, packet_type);
    errdefer destroyPacket(packet);

    packet.header = parsed_header;
    packet.packet_number = 0; // Requires decryption
    try packet.raw_data.appendSlice(data);

    if (packet_type != .retry and packet_type != .version_negotiation and payload_bytes.len > 0) {
        try packet.frames.append(.{ .raw = payload_bytes });
    }

    return packet;
}

/// Serialize a QUIC packet into raw bytes
pub fn serializePacket(pkt: *Packet, out: []u8) !usize {
    // TODO: Implement full serialization with header, frame encoding, and encryption
    if (pkt.raw_data.items.len > 0) {
        if (out.len < pkt.raw_data.items.len) return error.BufferTooSmall;
        @memcpy(out[0..pkt.raw_data.items.len], pkt.raw_data.items);
        return pkt.raw_data.items.len;
    }
    return error.NotImplemented;
}
