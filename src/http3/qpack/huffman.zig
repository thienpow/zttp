// src/http3/qpack/huffman.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

const http3_error = @import("../error.zig");
const Http3Error = http3_error.Http3Error;

/// Huffman code table entry.
const HuffmanCode = struct {
    code: u32,
    bits: u8,
    value: u8,
};

/// Huffman encoding/decoding table per RFC 7541 Appendix B.
const huffman_table = [_]HuffmanCode{
    .{ .code = 0x1ff8, .bits = 13, .value = 0 },      .{ .code = 0x7fffd8, .bits = 23, .value = 1 },
    .{ .code = 0xfffffe2, .bits = 28, .value = 2 },   .{ .code = 0xfffffe3, .bits = 28, .value = 3 },
    .{ .code = 0xfffffe4, .bits = 28, .value = 4 },   .{ .code = 0xfffffe5, .bits = 28, .value = 5 },
    .{ .code = 0xfffffe6, .bits = 28, .value = 6 },   .{ .code = 0xfffffe7, .bits = 28, .value = 7 },
    .{ .code = 0xfffffe8, .bits = 28, .value = 8 },   .{ .code = 0xffffea, .bits = 24, .value = 9 },
    .{ .code = 0x3ffffffc, .bits = 30, .value = 10 }, .{ .code = 0xfffffe9, .bits = 28, .value = 11 },
    .{ .code = 0xfffffea, .bits = 28, .value = 12 },  .{ .code = 0x3ffffffd, .bits = 30, .value = 13 },
    .{ .code = 0xfffffeb, .bits = 28, .value = 14 },  .{ .code = 0xfffffec, .bits = 28, .value = 15 },
    .{ .code = 0xfffffed, .bits = 28, .value = 16 },  .{ .code = 0xfffffee, .bits = 28, .value = 17 },
    .{ .code = 0xfffffef, .bits = 28, .value = 18 },  .{ .code = 0xffffff0, .bits = 28, .value = 19 },
    .{ .code = 0xffffff1, .bits = 28, .value = 20 },  .{ .code = 0xffffff2, .bits = 28, .value = 21 },
    .{ .code = 0x3ffffffe, .bits = 30, .value = 22 }, .{ .code = 0xffffff3, .bits = 28, .value = 23 },
    .{ .code = 0xffffff4, .bits = 28, .value = 24 },  .{ .code = 0xffffff5, .bits = 28, .value = 25 },
    .{ .code = 0xffffff6, .bits = 28, .value = 26 },  .{ .code = 0xffffff7, .bits = 28, .value = 27 },
    .{ .code = 0xffffff8, .bits = 28, .value = 28 },  .{ .code = 0xffffff9, .bits = 28, .value = 29 },
    .{ .code = 0xffffffa, .bits = 28, .value = 30 },  .{ .code = 0xffffffb, .bits = 28, .value = 31 },
    .{ .code = 0x14, .bits = 5, .value = 32 },        .{ .code = 0x3f8, .bits = 10, .value = 33 },
    .{ .code = 0x3f9, .bits = 10, .value = 34 },      .{ .code = 0xffa, .bits = 12, .value = 35 },
    .{ .code = 0x1ff9, .bits = 13, .value = 36 },     .{ .code = 0x15, .bits = 5, .value = 37 },
    .{ .code = 0xf8, .bits = 8, .value = 38 },        .{ .code = 0x7fa, .bits = 11, .value = 39 },
    .{ .code = 0x3fa, .bits = 10, .value = 40 },      .{ .code = 0x3fb, .bits = 10, .value = 41 },
    .{ .code = 0xf9, .bits = 8, .value = 42 },        .{ .code = 0x7fb, .bits = 11, .value = 43 },
    .{ .code = 0xfa, .bits = 8, .value = 44 },        .{ .code = 0x16, .bits = 5, .value = 45 },
    .{ .code = 0x17, .bits = 5, .value = 46 },        .{ .code = 0x18, .bits = 5, .value = 47 },
    .{ .code = 0x0, .bits = 2, .value = 48 },         .{ .code = 0x1, .bits = 2, .value = 49 },
    .{ .code = 0x2, .bits = 2, .value = 50 },         .{ .code = 0xfb, .bits = 8, .value = 51 },
    .{ .code = 0x7fc, .bits = 11, .value = 52 },      .{ .code = 0x7fd, .bits = 11, .value = 53 },
    .{ .code = 0x7fe, .bits = 11, .value = 54 },      .{ .code = 0x7ff, .bits = 11, .value = 55 },
    .{ .code = 0x19, .bits = 5, .value = 56 },        .{ .code = 0x1a, .bits = 5, .value = 57 },
    .{ .code = 0x1b, .bits = 5, .value = 58 },        .{ .code = 0x1c, .bits = 5, .value = 59 },
    .{ .code = 0x1d, .bits = 5, .value = 60 },        .{ .code = 0x1e, .bits = 5, .value = 61 },
    .{ .code = 0x1f, .bits = 5, .value = 62 },        .{ .code = 0x5, .bits = 4, .value = 63 },
    .{ .code = 0x6, .bits = 4, .value = 64 },         .{ .code = 0x7, .bits = 4, .value = 65 },
    .{ .code = 0x8, .bits = 4, .value = 66 },         .{ .code = 0x9, .bits = 4, .value = 67 },
    .{ .code = 0xa, .bits = 4, .value = 68 },         .{ .code = 0xb, .bits = 4, .value = 69 },
    .{ .code = 0xc, .bits = 4, .value = 70 },         .{ .code = 0xd, .bits = 4, .value = 71 },
    .{ .code = 0xe, .bits = 4, .value = 72 },         .{ .code = 0xf, .bits = 4, .value = 73 },
    .{ .code = 0x10, .bits = 4, .value = 74 },        .{ .code = 0x11, .bits = 4, .value = 75 },
    .{ .code = 0x12, .bits = 4, .value = 76 },        .{ .code = 0x13, .bits = 4, .value = 77 },
    .{ .code = 0x3, .bits = 3, .value = 78 },         .{ .code = 0x4, .bits = 3, .value = 79 },
    .{ .code = 0x20, .bits = 6, .value = 80 },        .{ .code = 0x21, .bits = 6, .value = 81 },
    .{ .code = 0x22, .bits = 6, .value = 82 },        .{ .code = 0x23, .bits = 6, .value = 83 },
    .{ .code = 0x24, .bits = 6, .value = 84 },        .{ .code = 0x25, .bits = 6, .value = 85 },
    .{ .code = 0x26, .bits = 6, .value = 86 },        .{ .code = 0x27, .bits = 6, .value = 87 },
    .{ .code = 0x28, .bits = 6, .value = 88 },        .{ .code = 0x29, .bits = 6, .value = 89 },
    .{ .code = 0x2a, .bits = 6, .value = 90 },        .{ .code = 0x2b, .bits = 6, .value = 91 },
    .{ .code = 0x2c, .bits = 6, .value = 92 },        .{ .code = 0x2d, .bits = 6, .value = 93 },
    .{ .code = 0x2e, .bits = 6, .value = 94 },        .{ .code = 0x2f, .bits = 6, .value = 95 },
    .{ .code = 0x30, .bits = 6, .value = 96 },        .{ .code = 0x31, .bits = 6, .value = 97 },
    .{ .code = 0x32, .bits = 6, .value = 98 },        .{ .code = 0x33, .bits = 6, .value = 99 },
    .{ .code = 0x34, .bits = 6, .value = 100 },       .{ .code = 0x35, .bits = 6, .value = 101 },
    .{ .code = 0x36, .bits = 6, .value = 102 },       .{ .code = 0x37, .bits = 6, .value = 103 },
    .{ .code = 0x38, .bits = 6, .value = 104 },       .{ .code = 0x39, .bits = 6, .value = 105 },
    .{ .code = 0x3a, .bits = 6, .value = 106 },       .{ .code = 0x3b, .bits = 6, .value = 107 },
    .{ .code = 0x3c, .bits = 6, .value = 108 },       .{ .code = 0x3d, .bits = 6, .value = 109 },
    .{ .code = 0x3e, .bits = 6, .value = 110 },       .{ .code = 0x3f, .bits = 6, .value = 111 },
    .{ .code = 0x40, .bits = 7, .value = 112 },       .{ .code = 0x41, .bits = 7, .value = 113 },
    .{ .code = 0x42, .bits = 7, .value = 114 },       .{ .code = 0x43, .bits = 7, .value = 115 },
    .{ .code = 0x44, .bits = 7, .value = 116 },       .{ .code = 0x45, .bits = 7, .value = 117 },
    .{ .code = 0x46, .bits = 7, .value = 118 },       .{ .code = 0x47, .bits = 7, .value = 119 },
    .{ .code = 0x48, .bits = 7, .value = 120 },       .{ .code = 0x49, .bits = 7, .value = 121 },
    .{ .code = 0x4a, .bits = 7, .value = 122 },       .{ .code = 0x4b, .bits = 7, .value = 123 },
    .{ .code = 0x4c, .bits = 7, .value = 124 },       .{ .code = 0x4d, .bits = 7, .value = 125 },
    .{ .code = 0x4e, .bits = 7, .value = 126 },       .{ .code = 0x4f, .bits = 7, .value = 127 },
    .{ .code = 0x50, .bits = 7, .value = 128 },       .{ .code = 0x51, .bits = 7, .value = 129 },
    .{ .code = 0x52, .bits = 7, .value = 130 },       .{ .code = 0x53, .bits = 7, .value = 131 },
    .{ .code = 0x54, .bits = 7, .value = 132 },       .{ .code = 0x55, .bits = 7, .value = 133 },
    .{ .code = 0x56, .bits = 7, .value = 134 },       .{ .code = 0x57, .bits = 7, .value = 135 },
    .{ .code = 0x58, .bits = 7, .value = 136 },       .{ .code = 0x59, .bits = 7, .value = 137 },
    .{ .code = 0x5a, .bits = 7, .value = 138 },       .{ .code = 0x5b, .bits = 7, .value = 139 },
    .{ .code = 0x5c, .bits = 7, .value = 140 },       .{ .code = 0x5d, .bits = 7, .value = 141 },
    .{ .code = 0x5e, .bits = 7, .value = 142 },       .{ .code = 0x5f, .bits = 7, .value = 143 },
    .{ .code = 0x60, .bits = 7, .value = 144 },       .{ .code = 0x61, .bits = 7, .value = 145 },
    .{ .code = 0x62, .bits = 7, .value = 146 },       .{ .code = 0x63, .bits = 7, .value = 147 },
    .{ .code = 0x64, .bits = 7, .value = 148 },       .{ .code = 0x65, .bits = 7, .value = 149 },
    .{ .code = 0x66, .bits = 7, .value = 150 },       .{ .code = 0x67, .bits = 7, .value = 151 },
    .{ .code = 0x68, .bits = 7, .value = 152 },       .{ .code = 0x69, .bits = 7, .value = 153 },
    .{ .code = 0x6a, .bits = 7, .value = 154 },       .{ .code = 0x6b, .bits = 7, .value = 155 },
    .{ .code = 0x6c, .bits = 7, .value = 156 },       .{ .code = 0x6d, .bits = 7, .value = 157 },
    .{ .code = 0x6e, .bits = 7, .value = 158 },       .{ .code = 0x6f, .bits = 7, .value = 159 },
    .{ .code = 0x70, .bits = 7, .value = 160 },       .{ .code = 0x71, .bits = 7, .value = 161 },
    .{ .code = 0x72, .bits = 7, .value = 162 },       .{ .code = 0x73, .bits = 7, .value = 163 },
    .{ .code = 0x74, .bits = 7, .value = 164 },       .{ .code = 0x75, .bits = 7, .value = 165 },
    .{ .code = 0x76, .bits = 7, .value = 166 },       .{ .code = 0x77, .bits = 7, .value = 167 },
    .{ .code = 0x78, .bits = 7, .value = 168 },       .{ .code = 0x79, .bits = 7, .value = 169 },
    .{ .code = 0x7a, .bits = 7, .value = 170 },       .{ .code = 0x7b, .bits = 7, .value = 171 },
    .{ .code = 0x7c, .bits = 7, .value = 172 },       .{ .code = 0x7d, .bits = 7, .value = 173 },
    .{ .code = 0x7e, .bits = 7, .value = 174 },       .{ .code = 0x7f, .bits = 7, .value = 175 },
    .{ .code = 0x80, .bits = 8, .value = 176 },       .{ .code = 0x81, .bits = 8, .value = 177 },
    .{ .code = 0x82, .bits = 8, .value = 178 },       .{ .code = 0x83, .bits = 8, .value = 179 },
    .{ .code = 0x84, .bits = 8, .value = 180 },       .{ .code = 0x85, .bits = 8, .value = 181 },
    .{ .code = 0x86, .bits = 8, .value = 182 },       .{ .code = 0x87, .bits = 8, .value = 183 },
    .{ .code = 0x88, .bits = 8, .value = 184 },       .{ .code = 0x89, .bits = 8, .value = 185 },
    .{ .code = 0x8a, .bits = 8, .value = 186 },       .{ .code = 0x8b, .bits = 8, .value = 187 },
    .{ .code = 0x8c, .bits = 8, .value = 188 },       .{ .code = 0x8d, .bits = 8, .value = 189 },
    .{ .code = 0x8e, .bits = 8, .value = 190 },       .{ .code = 0x8f, .bits = 8, .value = 191 },
    .{ .code = 0x90, .bits = 8, .value = 192 },       .{ .code = 0x91, .bits = 8, .value = 193 },
    .{ .code = 0x92, .bits = 8, .value = 194 },       .{ .code = 0x93, .bits = 8, .value = 195 },
    .{ .code = 0x94, .bits = 8, .value = 196 },       .{ .code = 0x95, .bits = 8, .value = 197 },
    .{ .code = 0x96, .bits = 8, .value = 198 },       .{ .code = 0x97, .bits = 8, .value = 199 },
    .{ .code = 0x98, .bits = 8, .value = 200 },       .{ .code = 0x99, .bits = 8, .value = 201 },
    .{ .code = 0x9a, .bits = 8, .value = 202 },       .{ .code = 0x9b, .bits = 8, .value = 203 },
    .{ .code = 0x9c, .bits = 8, .value = 204 },       .{ .code = 0x9d, .bits = 8, .value = 205 },
    .{ .code = 0x9e, .bits = 8, .value = 206 },       .{ .code = 0x9f, .bits = 8, .value = 207 },
    .{ .code = 0xa0, .bits = 8, .value = 208 },       .{ .code = 0xa1, .bits = 8, .value = 209 },
    .{ .code = 0xa2, .bits = 8, .value = 210 },       .{ .code = 0xa3, .bits = 8, .value = 211 },
    .{ .code = 0xa4, .bits = 8, .value = 212 },       .{ .code = 0xa5, .bits = 8, .value = 213 },
    .{ .code = 0xa6, .bits = 8, .value = 214 },       .{ .code = 0xa7, .bits = 8, .value = 215 },
    .{ .code = 0xa8, .bits = 8, .value = 216 },       .{ .code = 0xa9, .bits = 8, .value = 217 },
    .{ .code = 0xaa, .bits = 8, .value = 218 },       .{ .code = 0xab, .bits = 8, .value = 219 },
    .{ .code = 0xac, .bits = 8, .value = 220 },       .{ .code = 0xad, .bits = 8, .value = 221 },
    .{ .code = 0xae, .bits = 8, .value = 222 },       .{ .code = 0xaf, .bits = 8, .value = 223 },
    .{ .code = 0xb0, .bits = 8, .value = 224 },       .{ .code = 0xb1, .bits = 8, .value = 225 },
    .{ .code = 0xb2, .bits = 8, .value = 226 },       .{ .code = 0xb3, .bits = 8, .value = 227 },
    .{ .code = 0xb4, .bits = 8, .value = 228 },       .{ .code = 0xb5, .bits = 8, .value = 229 },
    .{ .code = 0xb6, .bits = 8, .value = 230 },       .{ .code = 0xb7, .bits = 8, .value = 231 },
    .{ .code = 0xb8, .bits = 8, .value = 232 },       .{ .code = 0xb9, .bits = 8, .value = 233 },
    .{ .code = 0xba, .bits = 8, .value = 234 },       .{ .code = 0xbb, .bits = 8, .value = 235 },
    .{ .code = 0xbc, .bits = 8, .value = 236 },       .{ .code = 0xbd, .bits = 8, .value = 237 },
    .{ .code = 0xbe, .bits = 8, .value = 238 },       .{ .code = 0xbf, .bits = 8, .value = 239 },
    .{ .code = 0xc0, .bits = 8, .value = 240 },       .{ .code = 0xc1, .bits = 8, .value = 241 },
    .{ .code = 0xc2, .bits = 8, .value = 242 },       .{ .code = 0xc3, .bits = 8, .value = 243 },
    .{ .code = 0xc4, .bits = 8, .value = 244 },       .{ .code = 0xc5, .bits = 8, .value = 245 },
    .{ .code = 0xc6, .bits = 8, .value = 246 },       .{ .code = 0xc7, .bits = 8, .value = 247 },
    .{ .code = 0xc8, .bits = 8, .value = 248 },       .{ .code = 0xc9, .bits = 8, .value = 249 },
    .{ .code = 0xca, .bits = 8, .value = 250 },       .{ .code = 0xcb, .bits = 8, .value = 251 },
    .{ .code = 0xcc, .bits = 8, .value = 252 },       .{ .code = 0xcd, .bits = 8, .value = 253 },
    .{ .code = 0xce, .bits = 8, .value = 254 },       .{ .code = 0x3ffffff, .bits = 30, .value = 255 },
};

/// Decodes a Huffman-encoded string per RFC 7541.
pub fn decodeHuffman(reader: anytype, allocator: Allocator) ![]u8 {
    const len = try readInt(reader, u64, 7);
    const input = try allocator.alloc(u8, len);
    defer allocator.free(input);
    try reader.readNoEof(input);

    var output = try std.ArrayList(u8).initCapacity(allocator, len);
    defer output.deinit();

    var current_code: u32 = 0;
    var current_bits: u8 = 0;

    for (input) |byte| {
        for (0..8) |bit| {
            const bit_u3: u3 = @intCast(bit);
            const shift_amount: u3 = 7 - bit_u3;
            current_code = (current_code << 1) | ((byte >> shift_amount) & 1);
            current_bits += 1;

            for (huffman_table) |entry| {
                if (current_bits == entry.bits and current_code == entry.code) {
                    try output.append(entry.value);
                    current_code = 0;
                    current_bits = 0;
                    break;
                }
            }
        }
    }

    if (current_bits > 0) {
        for (huffman_table) |entry| {
            if (current_bits == entry.bits and current_code == entry.code) {
                try output.append(entry.value);
                return output.toOwnedSlice();
            }
        }
        return Http3Error.InvalidHuffmanCode;
    }

    return output.toOwnedSlice();
}

/// Encodes a string using Huffman encoding per RFC 7541.
pub fn encodeHuffman(writer: anytype, input: []const u8, allocator: Allocator) !void {
    var bits = try std.ArrayList(u8).initCapacity(allocator, input.len * 4);
    defer bits.deinit();

    var bit_count: u64 = 0;
    for (input) |byte| {
        for (huffman_table) |entry| {
            if (entry.value == byte) {
                var code = entry.code;
                var bits_left = entry.bits;
                while (bits_left > 0) {
                    const shift = @min(bits_left, 8);
                    const byte_to_write = @as(u8, @intCast(code >> @intCast(bits_left - shift)));
                    try bits.append(byte_to_write);
                    bit_count += shift;
                    bits_left -= shift;
                    code &= (@as(u32, 1) << @as(u5, @intCast(bits_left))) - 1;
                }
                break;
            }
        }
    }

    // Pad with EOS (0xFF) if needed
    if (bit_count % 8 != 0) {
        const padding_bits = 8 - (bit_count % 8);
        const eos_code = huffman_table[255].code;
        const eos_bits = huffman_table[255].bits;
        const pad_code = eos_code >> @as(u5, @intCast(eos_bits - padding_bits));
        try bits.append(@intCast(pad_code));
        bit_count += padding_bits;
    }

    try writeInt(writer, bit_count / 8, 7);
    try writer.appendSlice(bits.items);
}

/// Reads an integer with the given prefix length.
fn readInt(reader: anytype, comptime T: type, prefix_len: u6) !T {
    const first_byte = try reader.readByte();
    const mask = (@as(u64, 1) << prefix_len) - 1;
    var value = @as(T, first_byte) & mask;
    if (value < mask) {
        return value;
    }
    var shift: u6 = prefix_len;
    while (true) {
        const byte = try reader.readByte();
        value += @as(T, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) {
            return value;
        }
        shift += 7;
    }
}

/// Writes an integer with the given prefix length.
fn writeInt(writer: anytype, value: u64, prefix_len: u8) !void {
    const mask = @as(u64, 1) << @as(u6, @intCast(prefix_len - 1));
    if (value < mask) {
        try writer.append(@intCast(value)); // Changed from writeByte
        return;
    }
    try writer.append(@intCast(mask | (value & (mask - 1)))); // Changed from writeByte
    var remaining = value >> @as(u6, @intCast(prefix_len));
    while (remaining >= 128) {
        try writer.append(@intCast((remaining & 0x7F) | 0x80)); // Changed from writeByte
        remaining >>= 7;
    }
    try writer.append(@intCast(remaining)); // Changed from writeByte
}
