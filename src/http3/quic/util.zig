```zig
// src/quic/util.zig
// Utility functions for the QUIC implementation

const std = @import("std");
const log = std.log.scoped(.quic_util);

/// Parses a Variable-Length Integer (VLI) from a byte slice according to RFC 9000 Section 16.
///
/// The first two bits of the first byte indicate the length of the encoding:
/// - `00`: 1-byte encoding. The value is the 6 least significant bits of the first byte.
/// - `01`: 2-byte encoding. The value is the 14 least significant bits of the first two bytes.
/// - `10`: 4-byte encoding. The value is the 30 least significant bits of the first four bytes.
/// - `11`: 8-byte encoding. The value is the 62 least significant bits of the first eight bytes.
///
/// The function reads the VLI from the beginning of the input slice `data`.
/// The number of bytes consumed from the input slice is written to `bytes_read_out`.
///
/// Returns the parsed integer value on success, or an error if the input slice is too short.
pub fn parseVli(data: []const u8, bytes_read_out: *usize) !u64 {
    if (data.len == 0) {
        return error.BufferTooShort;
    }

    const first_byte = data[0];
    const prefix = (first_byte >> 6);

    switch (prefix) {
        0b00 => {
            // 1-byte encoding
            *bytes_read_out = 1;
            return first_byte & 0x3f;
        },
        0b01 => {
            // 2-byte encoding
            if (data.len < 2) {
                return error.BufferTooShort;
            }
            *bytes_read_out = 2;
            const value = @as(u64, first_byte & 0x3f) << 8 | @as(u64, data[1]);
            return value;
        },
        0b10 => {
            // 4-byte encoding
            if (data.len < 4) {
                return error.BufferTooShort;
            }
            *bytes_read_out = 4;
            const value = @as(u64, first_byte & 0x3f) << 24 |
                          @as(u64, data[1]) << 16 |
                          @as(u64, data[2]) << 8 |
                          @as(u64, data[3]);
            return value;
        },
        0b11 => {
            // 8-byte encoding
            if (data.len < 8) {
                return error.BufferTooShort;
            }
            *bytes_read_out = 8;
            const value = @as(u64, first_byte & 0x3f) << 56 |
                          @as(u64, data[1]) << 48 |
                          @as(u64, data[2]) << 40 |
                          @as(u64, data[3]) << 32 |
                          @as(u64, data[4]) << 24 |
                          @as(u64, data[5]) << 16 |
                          @as(u64, data[6]) << 8 |
                          @as(u64, data[7]);
            return value;
        },
        else => unreachable, // Prefix is only 2 bits, switch covers all cases
    }
}

// TODO: Add serializeVli function
// pub fn serializeVli(value: u64, out: []u8) !usize { ... }

// TODO: Add other utility functions as needed

```