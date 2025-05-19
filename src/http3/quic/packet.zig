// QUIC packet handling per RFC 9000

const std = @import("std");
const builtin = @import("std").builtin;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.quic_packet);

const util = @import("util.zig");
const parse_vli = util.parseVli;
const serialize_vli = util.serializeVli;

/// Types of QUIC packets per RFC 9000, Section 17
pub const PacketType = enum(u8) {
    initial = 0x00,
    handshake = 0x02,
    zero_rtt = 0x01,
    retry = 0x03,
    version_negotiation = 0x04,
    short_header = 0x05,
    connection_close = 0x1c,
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

/// Represents a QUIC STOP_SENDING frame (Type 0x05)
pub const StopSendingFrame = struct {
    stream_id: u64,
    error_code: u64,
};

/// Represents a QUIC MAX_STREAM_DATA frame (Type 0x0c)
pub const MaxStreamDataFrame = struct {
    stream_id: u64,
    max_data: u64,
};

/// Represents a QUIC frame per RFC 9000, Section 19
pub const Frame = union(enum) {
    padding: void,
    ping: void,
    ack: AckFrame,
    crypto: CryptoFrame,
    stream: StreamFrame,
    stop_sending: StopSendingFrame,
    max_stream_data: MaxStreamDataFrame,
    connection_close: struct { error_code: u64, reason: []const u8 },
};

/// Represents a QUIC Long Header per RFC 9000, Section 17.2
pub const LongHeader = struct {
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8 = &.{}, // Only for Initial packets
};

/// Represents a QUIC Short Header per RFC 9000, Section 17.3
pub const ShortHeader = struct {
    destination_connection_id: []const u8,
};

/// Union of QUIC packet headers
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

    /// Creates a new QUIC packet.
    pub fn create(allocator: Allocator, packet_type: PacketType) !*Packet {
        const pkt = try allocator.create(Packet);
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

    /// Cleans up packet resources.
    pub fn deinit(self: *Packet) void {
        for (self.frames.items) |*frame| {
            switch (frame.*) {
                .ack => |*ack| ack.ack_ranges.deinit(),
                else => {},
            }
        }
        self.frames.deinit();
        self.raw_data.deinit();
    }
};

/// Destroys a QUIC packet.
pub fn destroyPacket(pkt: *Packet) void {
    pkt.deinit();
    pkt.allocator.destroy(pkt);
}

/// Parses a raw UDP packet into a QUIC packet structure per RFC 9000, Section 17.
pub fn parsePacket(allocator: Allocator, data: []const u8, expected_dcid_len: usize) !*Packet {
    if (data.len < 1) return error.PacketTooShort;

    var cursor: usize = 0;
    const first_byte = data[0];
    var packet_type: PacketType = undefined;
    var parsed_header: PacketHeader = undefined;
    var payload_start: usize = 0;
    var packet_number: u64 = 0;

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
        const version = std.mem.readInt(u32, @ptrCast(data[cursor .. cursor + 4]), .big);
        cursor += 4;

        if (version == 0) {
            packet_type = .version_negotiation;
            if (data.len < cursor + 1) return error.PacketTooShort;
            const dcil = @as(usize, data[cursor]);
            cursor += 1;
            if (data.len < cursor + dcil or dcil > 20) return error.InvalidConnectionId;
            const dcid_bytes = data[cursor .. cursor + dcil];
            cursor += dcil;
            const scil = @as(usize, data[cursor]);
            cursor += 1;
            if (data.len < cursor + scil or scil > 20) return error.InvalidConnectionId;
            const scid_bytes = data[cursor .. cursor + scil];
            cursor += scil;
            parsed_header = .{ .long = .{
                .version = 0,
                .destination_connection_id = dcid_bytes,
                .source_connection_id = scid_bytes,
            } };
            payload_start = cursor;
        } else {
            if (data.len < cursor + 1) return error.PacketTooShort;
            const dcil = @as(usize, data[cursor]);
            cursor += 1;
            if (data.len < cursor + dcil or dcil > 20) return error.InvalidConnectionId;
            const dcid_bytes = data[cursor .. cursor + dcil];
            cursor += dcil;

            if (data.len < cursor + 1) return error.PacketTooShort;
            const scil = @as(usize, data[cursor]);
            cursor += 1;
            if (data.len < cursor + scil or scil > 20) return error.InvalidConnectionId;
            const scid_bytes = data[cursor .. cursor + scil];
            cursor += scil;

            var token_bytes: []const u8 = &.{};
            if (packet_type == .initial) {
                var read_len: usize = 0;
                const token_len = try parse_vli(data[cursor..], &read_len);
                cursor += read_len;
                if (data.len < cursor + @as(usize, token_len)) return error.PacketTooShort;
                token_bytes = data[cursor .. cursor + @as(usize, token_len)];
                cursor += @as(usize, token_len);
            }

            if (packet_type != .retry) {
                var read_len: usize = 0;
                const length_val = try parse_vli(data[cursor..], &read_len);
                cursor += read_len;
                if (data.len < cursor + @as(usize, length_val)) return error.PacketTooShort;
                payload_start = cursor;
                cursor += @as(usize, length_val);
                // Packet number (1-4 bytes)
                if (cursor - payload_start < 1) return error.PacketTooShort;
                packet_number = try parse_vli(data[payload_start..cursor], &read_len);
                payload_start += read_len;
            } else {
                payload_start = cursor;
            }

            parsed_header = .{ .long = .{
                .version = version,
                .destination_connection_id = dcid_bytes,
                .source_connection_id = scid_bytes,
                .token = token_bytes,
            } };
        }
    } else {
        // Short Header Packet
        packet_type = .short_header;
        if (data.len < 1 + expected_dcid_len) return error.PacketTooShort;
        cursor += 1;
        const dcid_bytes = data[cursor .. cursor + expected_dcid_len];
        cursor += expected_dcid_len;

        // Parse packet number (1-4 bytes)
        const pn_len = @as(usize, (first_byte & 0x03) + 1);
        if (data.len < cursor + pn_len) return error.PacketTooShort;
        var pn_bytes: [4]u8 = .{0} ** 4;
        @memcpy(pn_bytes[4 - pn_len ..], data[cursor .. cursor + pn_len]);
        packet_number = std.mem.readInt(u64, &pn_bytes, .big);
        cursor += pn_len;
        payload_start = cursor;
        parsed_header = .{ .short = .{ .destination_connection_id = dcid_bytes } };
        log.debug("Parsed short header with DCID len={d}, PN={d}", .{ expected_dcid_len, packet_number });
    }

    const packet = try Packet.create(allocator, packet_type);
    errdefer destroyPacket(packet);

    packet.header = parsed_header;
    packet.packet_number = packet_number;
    try packet.raw_data.appendSlice(data);

    // Parse frames for non-retry/version_negotiation packets
    if (packet_type != .retry and packet_type != .version_negotiation and payload_start < data.len) {
        var frame_cursor = payload_start;
        while (frame_cursor < data.len) {
            const frame = try parseFrame(allocator, data, &frame_cursor);
            try packet.frames.append(frame);
        }
    }

    log.debug("Parsed packet type={s}, payload_len={d}", .{ @tagName(packet_type), data.len - payload_start });
    return packet;
}

/// Parses a single QUIC frame from payload.
fn parseFrame(allocator: Allocator, data: []const u8, cursor_inout: *usize) !Frame {
    var cursor = cursor_inout.*;
    if (cursor >= data.len) return error.BufferTooShort;

    const frame_type_byte = data[cursor];
    cursor += 1;

    switch (frame_type_byte) {
        0x00 => {
            cursor_inout.* = cursor;
            return .{ .padding = {} };
        },
        0x01 => {
            cursor_inout.* = cursor;
            return .{ .ping = {} };
        },
        0x1c => {
            var read_len: usize = 0;
            const error_code = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            const frame_type = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            if (frame_type != 0x1c) return error.InvalidFrameType;
            const reason_len = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            if (cursor + @as(usize, reason_len) > data.len) return error.BufferTooShort;
            const reason = data[cursor .. cursor + @as(usize, reason_len)];
            cursor += @as(usize, reason_len);
            cursor_inout.* = cursor;
            return .{ .connection_close = .{ .error_code = error_code, .reason = reason } };
        },
        else => {},
    }

    var read_len: usize = 0;
    const frame_type = try parse_vli(data[cursor - 1 ..], &read_len);
    cursor = cursor_inout.* + read_len - 1;

    switch (frame_type) {
        0x02, 0x03 => {
            const largest_ack = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            const ack_delay = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            const ack_range_count = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            const first_ack_range = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;

            var ack_ranges = std.ArrayList(struct { gap: u64, length: u64 }).init(allocator);
            errdefer ack_ranges.deinit();

            var i: u64 = 0;
            while (i < ack_range_count) : (i += 1) {
                const gap = try parse_vli(data[cursor..], &read_len);
                cursor += read_len;
                const length = try parse_vli(data[cursor..], &read_len);
                cursor += read_len;
                try ack_ranges.append(.{ .gap = gap, .length = length });
            }

            cursor_inout.* = cursor;
            return .{ .ack = .{
                .largest_acknowledged = largest_ack,
                .ack_delay = ack_delay,
                .ack_range_count = ack_range_count,
                .first_ack_range = first_ack_range,
                .ack_ranges = ack_ranges,
            } };
        },
        0x05 => {
            const stream_id = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            const error_code = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;

            cursor_inout.* = cursor;
            return .{ .stop_sending = .{
                .stream_id = stream_id,
                .error_code = error_code,
            } };
        },
        0x06 => {
            const offset = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            const length = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            if (cursor + @as(usize, length) > data.len) return error.BufferTooShort;
            const crypto_data = data[cursor .. cursor + @as(usize, length)];
            cursor += @as(usize, length);

            cursor_inout.* = cursor;
            return .{ .crypto = .{ .offset = offset, .data = crypto_data } };
        },
        0x08...0x0f => {
            const flags = @as(u8, @intCast(frame_type)) & 0x07;
            const has_offset = (flags & 0x01) != 0;
            const has_length = (flags & 0x02) != 0;
            const is_fin = (flags & 0x04) != 0;

            const stream_id = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;

            var offset: u64 = 0;
            if (has_offset) {
                offset = try parse_vli(data[cursor..], &read_len);
                cursor += read_len;
            }

            var stream_data_end: usize = data.len;
            var length: u64 = 0;
            if (has_length) {
                length = try parse_vli(data[cursor..], &read_len);
                cursor += read_len;
                stream_data_end = cursor + @as(usize, length);
                if (stream_data_end > data.len) return error.BufferTooShort;
            }

            const stream_data = data[cursor..stream_data_end];
            cursor = stream_data_end;

            cursor_inout.* = cursor;
            return .{ .stream = .{
                .stream_id = stream_id,
                .offset = offset,
                .length = @as(u64, stream_data.len),
                .fin = is_fin,
                .data = stream_data,
            } };
        },
        0x0c => {
            const stream_id = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;
            const max_data = try parse_vli(data[cursor..], &read_len);
            cursor += read_len;

            cursor_inout.* = cursor;
            return .{ .max_stream_data = .{
                .stream_id = stream_id,
                .max_data = max_data,
            } };
        },
        else => return error.UnknownFrameType,
    }
}

/// Serializes a QUIC packet into raw bytes per RFC 9000, Section 17.
pub fn serializePacket(pkt: *Packet, out: []u8) !usize {
    if (out.len < 128) return error.BufferTooSmall;

    var cursor: usize = 0;
    var first_byte: u8 = 0;

    switch (pkt.packet_type) {
        .initial, .handshake, .zero_rtt, .retry => {
            const long_header = pkt.header.long;
            first_byte |= 0x80; // Long header flag
            first_byte |= switch (pkt.packet_type) {
                .initial => 0x00,
                .zero_rtt => 0x10,
                .handshake => 0x20,
                .retry => 0x30,
                else => unreachable,
            } << 4;

            const dcil = @min(long_header.destination_connection_id.len, 20);
            out[cursor] = first_byte;
            cursor += 1;

            std.mem.writeInt(u32, out[cursor .. cursor + 4], long_header.version, .big);
            cursor += 4;

            out[cursor] = @as(u8, @intCast(dcil));
            cursor += 1;
            @memcpy(out[cursor .. cursor + dcil], long_header.destination_connection_id[0..dcil]);
            cursor += dcil;

            const scil = @min(long_header.source_connection_id.len, 20);
            out[cursor] = @as(u8, @intCast(scil));
            cursor += 1;
            @memcpy(out[cursor .. cursor + scil], long_header.source_connection_id[0..scil]);
            cursor += scil;

            if (pkt.packet_type == .initial) {
                cursor += try serialize_vli(@as(u64, long_header.token.len), out[cursor..]);
                @memcpy(out[cursor .. cursor + long_header.token.len], long_header.token);
                cursor += long_header.token.len;
            }

            // Reserve space for length
            const length_pos = cursor;
            cursor += 4; // Reserve up to 4 bytes for length
            const payload_start = cursor;

            // Serialize frames
            for (pkt.frames.items) |frame| {
                cursor += try serializeFrame(frame, out[cursor..]);
            }

            // Update length field
            const payload_len = cursor - payload_start;
            const length_bytes = try serialize_vli(@as(u64, payload_len + (@as(u64, pkt.packet_number) & 0x03) + 1), out[length_pos..]);
            if (length_bytes > 4) return error.BufferTooSmall;
            @memcpy(out[length_pos + length_bytes .. cursor], out[payload_start..cursor]);
            cursor = length_pos + length_bytes + payload_len;

            // Serialize packet number
            const pn_len = (@as(u8, @intCast(pkt.packet_number & 0x03)) + 1);
            for (0..pn_len) |i| {
                out[length_pos + length_bytes + i] = @as(u8, @intCast((pkt.packet_number >> (8 * (pn_len - 1 - i))) & 0xFF));
            }
            cursor = length_pos + length_bytes + pn_len + payload_len;
        },
        .short_header => {
            const short_header = pkt.header.short;
            first_byte |= 0x40; // Short header flag
            const pn_len = (@as(u8, @intCast(pkt.packet_number & 0x03)) + 1);
            first_byte |= pn_len - 1;
            out[cursor] = first_byte;
            cursor += 1;

            const dcil = @min(short_header.destination_connection_id.len, 20);
            @memcpy(out[cursor .. cursor + dcil], short_header.destination_connection_id[0..dcil]);
            cursor += dcil;

            // Packet number
            for (0..pn_len) |i| {
                out[cursor + i] = @as(u8, @intCast((pkt.packet_number >> (8 * (pn_len - 1 - i))) & 0xFF));
            }
            cursor += pn_len;

            // Serialize frames
            for (pkt.frames.items) |frame| {
                cursor += try serializeFrame(frame, out[cursor..]);
            }
        },
        .connection_close => {
            first_byte |= 0x80;
            out[cursor] = first_byte;
            cursor += 1;
            std.mem.writeInt(u32, out[cursor .. cursor + 4], 0x00000001, .big);
            cursor += 4;
            out[cursor] = 0; // DCIL
            cursor += 1;
            out[cursor] = 0; // SCIL
            cursor += 1;

            for (pkt.frames.items) |frame| {
                cursor += try serializeFrame(frame, out[cursor..]);
            }
        },
        else => return error.UnsupportedPacketType,
    }

    if (cursor > out.len) return error.BufferTooSmall;
    log.debug("Serialized packet type={s}, len={d}", .{ @tagName(pkt.packet_type), cursor });
    return cursor;
}

/// Serializes a single QUIC frame into raw bytes.
fn serializeFrame(frame: Frame, out: []u8) !usize {
    var cursor: usize = 0;
    switch (frame) {
        .padding => {
            out[cursor] = 0x00;
            return 1;
        },
        .ping => {
            out[cursor] = 0x01;
            return 1;
        },
        .ack => |ack| {
            cursor += try serialize_vli(if (ack.ack_delay > 0) 0x03 else 0x02, out[cursor..]);
            cursor += try serialize_vli(ack.largest_acknowledged, out[cursor..]);
            cursor += try serialize_vli(ack.ack_delay, out[cursor..]);
            cursor += try serialize_vli(ack.ack_range_count, out[cursor..]);
            cursor += try serialize_vli(ack.first_ack_range, out[cursor..]);
            for (ack.ack_ranges.items) |range| {
                cursor += try serialize_vli(range.gap, out[cursor..]);
                cursor += try serialize_vli(range.length, out[cursor..]);
            }
            return cursor;
        },
        .crypto => |crypto| {
            cursor += try serialize_vli(0x06, out[cursor..]);
            cursor += try serialize_vli(crypto.offset, out[cursor..]);
            cursor += try serialize_vli(@as(u64, crypto.data.len), out[cursor..]);
            @memcpy(out[cursor .. cursor + crypto.data.len], crypto.data);
            cursor += crypto.data.len;
            return cursor;
        },
        .stream => |stream| {
            var frame_type: u8 = 0x08;
            if (stream.offset > 0) frame_type |= 0x01;
            if (stream.length > 0) frame_type |= 0x02;
            if (stream.fin) frame_type |= 0x04;
            cursor += try serialize_vli(frame_type, out[cursor..]);
            cursor += try serialize_vli(stream.stream_id, out[cursor..]);
            if (stream.offset > 0) {
                cursor += try serialize_vli(stream.offset, out[cursor..]);
            }
            if (stream.length > 0) {
                cursor += try serialize_vli(stream.length, out[cursor..]);
            }
            @memcpy(out[cursor .. cursor + stream.data.len], stream.data);
            cursor += stream.data.len;
            return cursor;
        },
        .stop_sending => |stop| {
            cursor += try serialize_vli(0x05, out[cursor..]);
            cursor += try serialize_vli(stop.stream_id, out[cursor..]);
            cursor += try serialize_vli(stop.error_code, out[cursor..]);
            return cursor;
        },
        .max_stream_data => |max_data| {
            cursor += try serialize_vli(0x0c, out[cursor..]);
            cursor += try serialize_vli(max_data.stream_id, out[cursor..]);
            cursor += try serialize_vli(max_data.max_data, out[cursor..]);
            return cursor;
        },
        .connection_close => |close| {
            cursor += try serialize_vli(0x1c, out[cursor..]);
            cursor += try serialize_vli(close.error_code, out[cursor..]);
            cursor += try serialize_vli(0x1c, out[cursor..]);
            cursor += try serialize_vli(@as(u64, close.reason.len), out[cursor..]);
            @memcpy(out[cursor .. cursor + close.reason.len], close.reason);
            cursor += close.reason.len;
            return cursor;
        },
    }
}
