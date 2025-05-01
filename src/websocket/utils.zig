const std = @import("std");
const Allocator = std.mem.Allocator;

/// Computes the WebSocket accept key from the client's key.
pub fn computeAcceptKey(allocator: Allocator, key: []const u8) ![]u8 {
    const uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(key);
    hasher.update(uuid);
    var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    hasher.final(&hash);

    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(hash.len));
    errdefer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, &hash);
    return encoded;
}
