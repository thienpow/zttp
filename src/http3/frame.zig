// src/http3/frame.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.http3_frame);

const settings = @import("settings.zig");
const types = @import("types.zig");
pub const FrameType = types.FrameType;
pub const Frame = types.Frame;
pub const Http3Error = types.Http3Error;
pub const Settings = settings.Settings;

const varint = @import("varint.zig");

/// Reads and parses a single HTTP/3 frame from a reader.
/// Payload slices are allocated and must be freed by caller using Frame.deinit.
pub fn readFrame(allocator: Allocator, reader: anytype) !Frame {
    // Read frame type
    const frame_type_val = try readVliFromReader(reader);
    const frame_type = @as(FrameType, @enumFromInt(frame_type_val));

    // Read frame length
    const frame_length = try readVliFromReader(reader);
    if (frame_length > std.math.maxInt(usize)) return Http3Error.FrameError;

    // Read payload
    const payload = try allocator.alloc(u8, @intCast(frame_length));
    errdefer allocator.free(payload);
    if (frame_length > 0) {
        try reader.readNoEof(payload);
    }

    // Parse based on frame type
    switch (frame_type) {
        .data => return Frame{ .data = .{ .payload = payload } },
        .headers => return Frame{ .headers = .{ .encoded_block = payload } },
        .cancel_push => {
            if (payload.len == 0) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            var cursor: usize = 0;
            const push_id = (try varint.decode(payload)).value;
            cursor += (try varint.decode(payload)).bytes_read;
            if (cursor != payload.len or push_id > (1 << 62) - 1) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            allocator.free(payload);
            return Frame{ .cancel_push = .{ .push_id = push_id } };
        },
        .settings => {
            const settings_struct = Settings.parse(allocator, payload) catch |err| {
                allocator.free(payload);
                log.err("readFrame: Failed to parse SETTINGS: {}", .{err});
                return Http3Error.FrameError;
            };
            allocator.free(payload);
            return Frame{ .settings = settings_struct };
        },
        .goaway => {
            if (payload.len == 0) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            var cursor: usize = 0;
            const stream_id = (try varint.decode(payload)).value;
            cursor += (try varint.decode(payload)).bytes_read;
            if (cursor != payload.len or stream_id > (1 << 62) - 1) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            allocator.free(payload);
            return Frame{ .goaway = .{ .stream_id = stream_id } };
        },
        .max_push_id => {
            if (payload.len == 0) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            var cursor: usize = 0;
            const push_id = (try varint.decode(payload)).value;
            cursor += (try varint.decode(payload)).bytes_read;
            if (cursor != payload.len or push_id > (1 << 62) - 1) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            allocator.free(payload);
            return Frame{ .max_push_id = .{ .push_id = push_id } };
        },
        .duplicate_push => {
            if (payload.len == 0) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            var cursor: usize = 0;
            const push_id = (try varint.decode(payload)).value;
            cursor += (try varint.decode(payload)).bytes_read;
            if (cursor != payload.len or push_id > (1 << 62) - 1) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            allocator.free(payload);
            return Frame{ .duplicate_push = .{ .push_id = push_id } };
        },
        .webtransport_stream => {
            if (payload.len != 0) {
                allocator.free(payload);
                return Http3Error.FrameError;
            }
            allocator.free(payload);
            return Frame{ .webtransport_stream = .{} };
        },
        else => return Frame{ .reserved = .{ .frame_type = frame_type_val, .payload = payload } },
    }
}

/// Serializes an HTTP/3 Frame into a writer.
pub fn writeFrame(allocator: Allocator, writer: anytype, frame: Frame) !void {
    var vli_buffer: [8]u8 = undefined;
    var payload = std.ArrayList(u8).init(allocator);
    defer payload.deinit();

    const frame_type_val = @intFromEnum(frame);
    var payload_slice: []const u8 = &.{};

    switch (frame) {
        .data => |f| payload_slice = f.payload,
        .headers => |f| payload_slice = f.encoded_block,
        .cancel_push => |f| {
            try varint.encode(f.push_id, &payload);
            payload_slice = payload.items;
        },
        .settings => |f| {
            payload_slice = try Settings.serialize(allocator, f);
            defer allocator.free(payload_slice);
        },
        .goaway => |f| {
            try varint.encode(f.stream_id, &payload);
            payload_slice = payload.items;
        },
        .max_push_id => |f| {
            try varint.encode(f.push_id, &payload);
            payload_slice = payload.items;
        },
        .duplicate_push => |f| {
            try varint.encode(f.push_id, &payload);
            payload_slice = payload.items;
        },
        .webtransport_stream => {},
        .priority => |f| { payload_slice = &.{ (@as(u8, if (f.incremental) 1 else 0)) << 7 | f.urgency }; },
        .push_promise => |f| { try varint.encode(f.push_id, &payload); try payload.appendSlice(f.encoded_headers); payload_slice = payload.items; },
        .ping => |f| { payload_slice = f.opaque_data[0..]; },
        .window_update => |f| { try varint.encode(f.window_size_increment, &payload); payload_slice = payload.items; },
        .continuation => |f| { payload_slice = f.encoded_block; },
        .webtransport_bi => |f| { try varint.encode(f.session_id, &payload); payload_slice = payload.items; },
        .webtransport_uni => |f| { try varint.encode(f.session_id, &payload); payload_slice = payload.items; },
        .reserved => |f| payload_slice = f.payload,
    }

    // Write frame type
    const type_len = blk: {
        var temp_buf = std.ArrayList(u8).init(allocator);
        defer temp_buf.deinit();
        try varint.encode(frame_type_val, &temp_buf);
        const len = temp_buf.items.len;
        @memcpy(vli_buffer[0..len], temp_buf.items);
        break :blk len;
    };
    try writer.writeAll(vli_buffer[0..type_len]);

    // Write frame length
    const len_len = blk: {
        var temp_buf = std.ArrayList(u8).init(allocator);
        defer temp_buf.deinit();
        try varint.encode(payload_slice.len, &temp_buf);
        const len = temp_buf.items.len;
        @memcpy(vli_buffer[0..len], temp_buf.items);
        break :blk len;
    };
    try writer.writeAll(vli_buffer[0..len_len]);

    // Write payload
    if (payload_slice.len > 0) {
        try writer.writeAll(payload_slice);
    }

    log.debug("writeFrame: Serialized frame type {x}, len {}", .{ frame_type_val, payload_slice.len });
}

// Reads a variable-length integer from a reader
fn readVliFromReader(reader: anytype) !u64 {
    const first_byte = reader.readByte() catch |err| {
        if (err == error.EndOfStream) return Http3Error.NeedMoreData;
        return err;
    };
    const prefix = first_byte >> 6;
    var result: u64 = first_byte & 0x3F;
    const bytes_to_read: u8 = switch (prefix) {
        0b00 => 0,
        0b01 => 1,
        0b10 => 3,
        0b11 => 7,
        else => unreachable,
    };

    var i: u8 = 0;
    var shift: u6 = 6;
    while (i < bytes_to_read) : (i += 1) {
        const byte = reader.readByte() catch |err| {
            if (err == error.EndOfStream) return Http3Error.NeedMoreData;
            return err;
        };
        result |= @as(u64, byte) << shift;
        shift += 8;
    }
    return result;
}
