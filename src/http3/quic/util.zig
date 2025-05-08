// src/http3/quic/util.zig
// Utility functions for the QUIC implementation

const std = @import("std");
const log = std.log.scoped(.quic_util);

/// Parses a Variable-Length Integer (VLI) from a byte slice according to RFC 9000 Section 16.
///
/// The first two bits of the first byte indicate the length of the encoding:
/// - `00`: 1-byte encoding (6 bits, values 0 to 63).
/// - `01`: 2-byte encoding (14 bits, values 0 to 16383).
/// - `10`: 4-byte encoding (30 bits, values 0 to 1073741823).
/// - `11`: 8-byte encoding (62 bits, values 0 to 4611686018427387903).
///
/// Args:
///   - data: Input byte slice containing the VLI at the start.
///   - bytes_read_out: Pointer to store the number of bytes consumed.
///
/// Returns:
///   - The parsed u64 value on success.
///   - Error if the input slice is too short for the specified encoding.
pub fn parseVli(data: []const u8, bytes_read_out: *usize) !u64 {
    if (data.len == 0) {
        return error.VliBufferTooShort;
    }

    const first_byte = data[0];
    const prefix = first_byte >> 6;

    switch (prefix) {
        0b00 => {
            bytes_read_out.* = 1;
            return first_byte & 0x3F;
        },
        0b01 => {
            if (data.len < 2) return error.VliBufferTooShort;
            bytes_read_out.* = 2;
            return (@as(u64, first_byte & 0x3F) << 8) | @as(u64, data[1]);
        },
        0b10 => {
            if (data.len < 4) return error.VliBufferTooShort;
            bytes_read_out.* = 4;
            return (@as(u64, first_byte & 0x3F) << 24) |
                (@as(u64, data[1]) << 16) |
                (@as(u64, data[2]) << 8) |
                (@as(u64, data[3]));
        },
        0b11 => {
            if (data.len < 8) return error.VliBufferTooShort;
            bytes_read_out.* = 8;
            return (@as(u64, first_byte & 0x3F) << 56) |
                (@as(u64, data[1]) << 48) |
                (@as(u64, data[2]) << 40) |
                (@as(u64, data[3]) << 32) |
                (@as(u64, data[4]) << 24) |
                (@as(u64, data[5]) << 16) |
                (@as(u64, data[6]) << 8) |
                (@as(u64, data[7]));
        },
        else => unreachable,
    }
}

/// Serializes a u64 value into a Variable-Length Integer (VLI) according to RFC 9000 Section 16.
///
/// The encoding uses the smallest possible length based on the value:
/// - Values ≤ 63: 1 byte (prefix `00`).
/// - Values ≤ 16383: 2 bytes (prefix `01`).
/// - Values ≤ 1073741823: 4 bytes (prefix `10`).
/// - Values ≤ 4611686018427387903: 8 bytes (prefix `11`).
///
/// Args:
///   - value: The u64 value to serialize.
///   - out: Output byte slice to write the VLI to (must be at least 8 bytes for largest encoding).
///
/// Returns:
///   - The number of bytes written to `out` on success.
///   - Error if the output buffer is too small or the value is too large for VLI encoding.
pub fn serializeVli(value: u64, out: []u8) !usize {
    if (value > (1 << 62) - 1) {
        return error.VliValueTooLarge;
    }

    if (value <= 63) {
        if (out.len < 1) return error.VliBufferTooSmall;
        out[0] = @as(u8, @intCast(value)) & 0x3F;
        return 1;
    } else if (value <= 16383) {
        if (out.len < 2) return error.VliBufferTooSmall;
        out[0] = 0x40 | @as(u8, @intCast((value >> 8) & 0x3F));
        out[1] = @as(u8, @intCast(value & 0xFF));
        return 2;
    } else if (value <= 1073741823) {
        if (out.len < 4) return error.VliBufferTooSmall;
        out[0] = 0x80 | @as(u8, @intCast((value >> 24) & 0x3F));
        out[1] = @as(u8, @intCast((value >> 16) & 0xFF));
        out[2] = @as(u8, @intCast((value >> 8) & 0xFF));
        out[3] = @as(u8, @intCast(value & 0xFF));
        return 4;
    } else {
        if (out.len < 8) return error.VliBufferTooSmall;
        out[0] = 0xC0 | @as(u8, @intCast((value >> 56) & 0x3F));
        out[1] = @as(u8, @intCast((value >> 48) & 0xFF));
        out[2] = @as(u8, @intCast((value >> 40) & 0xFF));
        out[3] = @as(u8, @intCast((value >> 32) & 0xFF));
        out[4] = @as(u8, @intCast((value >> 24) & 0xFF));
        out[5] = @as(u8, @intCast((value >> 16) & 0xFF));
        out[6] = @as(u8, @intCast((value >> 8) & 0xFF));
        out[7] = @as(u8, @intCast(value & 0xFF));
        return 8;
    }
}
