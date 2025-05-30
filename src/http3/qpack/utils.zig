// src/http3/qpack/utils.zig
const std = @import("std");
const ArrayList = std.ArrayList;

pub fn writeInt(writer: *ArrayList(u8), value: u64, prefix_len: u6) !void {
    const mask = (@as(u64, 1) << prefix_len) - 1;
    if (value < mask) {
        try writer.append(@intCast(value));
        return;
    }
    try writer.append(@intCast(mask));
    var remaining = value - mask;
    while (remaining >= 128) {
        try writer.append(@intCast((remaining & 127) | 128));
        remaining >>= 7;
    }
    try writer.append(@intCast(remaining));
}

pub fn readInt(reader: anytype, comptime T: type, prefix_len: u6) !T {
    const first_byte = try reader.readByte();
    const mask = (@as(T, 1) << prefix_len) - 1;
    var value = @as(T, first_byte) & mask;
    if (value < mask) return value;
    var shift: u6 = prefix_len;
    while (true) {
        const byte = try reader.readByte();
        value += @as(T, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) return value;
        shift += 7;
    }
}
