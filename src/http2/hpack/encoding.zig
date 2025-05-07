const std = @import("std");
const Allocator = std.mem.Allocator;
const huffman_table = @import("huffman_table.zig").huffman_table;

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

    // If the value is less than the maximum prefix value, return it
    // If it equals the maximum, we need to read more bytes
    if (value < max_prefix) return value;

    // Read additional bytes for larger integers
    var m: u6 = 0;
    while (true) {
        const b = try reader.readByte();
        // Add the 7-bit contribution of the byte, shifted by m (equivalent to * 2^m)
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

// Decode a Huffman-encoded string as specified in RFC 7541 Appendix B
fn decodeHuffman(input: []const u8, allocator: Allocator) ![]const u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var current_code: u32 = 0;
    var current_bits: u8 = 0;

    for (input) |byte| {
        // Process each bit of the input byte
        var bit_pos: i8 = 7;
        while (bit_pos >= 0) : (bit_pos -= 1) {
            // Extract the next bit
            const bit = (byte >> @intCast(bit_pos)) & 1;
            current_code = (current_code << 1) | bit;
            current_bits += 1;

            // Check if we have a complete Huffman code
            for (huffman_table, 0..) |entry, char| {
                if (current_bits == entry.bits and current_code == entry.code) {
                    try result.append(@intCast(char));
                    current_code = 0;
                    current_bits = 0;
                    break;
                }
            }
        }
    }

    // Check for valid termination (should have consumed all bits or have a valid prefix)
    if (current_bits > 0) {
        for (huffman_table, 0..) |entry, char| {
            if (current_bits <= entry.bits and current_code == (entry.code >> @intCast(entry.bits - current_bits))) {
                try result.append(@intCast(char));
                return result.toOwnedSlice();
            }
        }
        return error.InvalidHuffmanCode;
    }

    return result.toOwnedSlice();
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

    if (huffman_encoded) {
        // Decode Huffman-encoded string
        const decoded = try decodeHuffman(buf, allocator);
        allocator.free(buf); // Free the input buffer
        return decoded;
    }

    return buf;
}
