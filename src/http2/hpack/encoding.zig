// src/http2/hpack/encoding.zig - HPACK integer and string encoding/decoding
const std = @import("std");
const Allocator = std.mem.Allocator;

// Write an integer to the output stream as specified in HPACK (RFC 7541 Section 5.1)
pub fn writeInteger(writer: anytype, value: usize, prefix_bits: u3, prefix: u8) !void {
    const max_prefix = @as(usize, 1) << prefix_bits - 1;

    if (value < max_prefix) {
        // Value fits within prefix bits
        try writer.writeByte(@intCast(prefix | value));
    } else {
        // Value doesn't fit within prefix bits, use multiple octets
        try writer.writeByte(@intCast(prefix | max_prefix));
        var remaining = value - max_prefix;

        while (remaining >= 128) {
            try writer.writeByte(@intCast((remaining % 128) | 128));
            remaining /= 128;
        }
        try writer.writeByte(@intCast(remaining));
    }
}

// Read an integer from the input stream as specified in HPACK (RFC 7541 Section 5.1)
pub fn readInteger(reader: anytype, first_byte: u8, prefix_bits: u3) !usize {
    // Calculate the maximum value that fits in the prefix (2^N - 1)
    const max_prefix: u8 = @as(u8, 1) << prefix_bits - 1;
    // Extract the prefix bits from first_byte
    var value: usize = @as(usize, first_byte & max_prefix);

    // If the value fits in the prefix, return it
    if (value < max_prefix) return value;

    // Read additional bytes for larger integers
    var m: u6 = 0;
    while (true) {
        const b = try reader.readByte();
        // Add the 7-bit contribution of the byte, shifted by m
        value += @as(usize, b & 0x7F) << m;
        // If the continuation bit is 0, stop
        if (b & 0x80 == 0) break;
        // Increment shift amount, capped at 63 (max for u6)
        m = @min(m + 7, std.math.maxInt(u6));
    }
    return value;
}

// Write a string to the output stream as specified in HPACK (RFC 7541 Section 5.2)
pub fn writeString(writer: anytype, str: []const u8) !void {
    // Write string length as integer with 7-bit prefix and no prefix bits set (Huffman encoding not supported yet)
    try writeInteger(writer, str.len, 7, 0);
    // Write the string content directly
    try writer.writeAll(str);
}

// Read a string from the input stream as specified in HPACK (RFC 7541 Section 5.2)
pub fn readString(reader: anytype, allocator: Allocator) ![]const u8 {
    const first_byte = try reader.readByte();
    const huffman_encoded = (first_byte & 0x80) != 0; // Check if Huffman encoding is used

    // Read string length
    const len = try readInteger(reader, first_byte, 7);

    // Allocate buffer for the string
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);

    // Read the string content
    try reader.readNoEof(buf);

    // If Huffman encoded, we should decode it (not implemented here)
    if (huffman_encoded) {
        return error.HuffmanDecodingNotImplemented;
    }

    return buf;
}
