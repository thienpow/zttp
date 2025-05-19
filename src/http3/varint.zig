const std = @import("std");
const Allocator = std.mem.Allocator;

pub const VarIntError = error{
    BufferTooShort,
    ValueTooLarge,
    InvalidEncoding,
};

/// Result of decoding a variable-length integer
pub const DecodeResult = struct {
    value: u64,
    bytes_read: usize,
};

/// Encodes a u64 value as a variable-length integer into the provided buffer.
/// Returns the number of bytes written.
pub fn encode(value: u64, buffer: *std.ArrayList(u8)) !void {
    var val = value;
    while (true) {
        var byte: u8 = @truncate(val & 0x7F);
        val >>= 7;
        if (val == 0) {
            try buffer.append(byte);
            return;
        }
        byte |= 0x80;
        try buffer.append(byte);
    }
}

/// Decodes a variable-length integer from the provided buffer.
/// Returns the decoded value and the number of bytes read.
pub fn decode(buffer: []const u8) !DecodeResult {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;

    for (buffer) |byte| {
        if (bytes_read >= 10) return error.ValueTooLarge;
        bytes_read += 1;

        result |= @as(u64, byte & 0x7F) << shift;
        shift += 7;

        if (byte & 0x80 == 0) {
            return DecodeResult{
                .value = result,
                .bytes_read = bytes_read,
            };
        }

        if (shift >= 64) return error.ValueTooLarge;
    }

    return error.BufferTooShort;
}
