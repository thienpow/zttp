// src/http2/mod.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("../http/mod.zig");
const Request = http.Request;
const Response = http.Response;

const log = std.log.scoped(.http2);

// HTTP/2 Frame Types
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

// HTTP/2 Frame Header (9 bytes)
pub const FrameHeader = struct {
    length: u24,
    type: FrameType,
    flags: u8,
    stream_id: u31,

    pub fn read(reader: anytype) !FrameHeader {
        var buf: [9]u8 = undefined;
        try reader.readNoEof(&buf);
        const length = (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | @as(u24, buf[2]);
        const frame_type: FrameType = @enumFromInt(buf[3]);
        const flags = buf[4];
        const stream_id = (@as(u31, buf[5] & 0x7F) << 24) | (@as(u31, buf[6]) << 16) | (@as(u31, buf[7]) << 8) | @as(u31, buf[8]);
        return .{
            .length = length,
            .type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        };
    }

    pub fn write(self: FrameHeader, writer: anytype) !void {
        var buf: [9]u8 = undefined;
        buf[0] = @intCast((self.length >> 16) & 0xFF);
        buf[1] = @intCast((self.length >> 8) & 0xFF);
        buf[2] = @intCast(self.length & 0xFF);
        buf[3] = @intFromEnum(self.type);
        buf[4] = self.flags;
        buf[5] = @intCast((self.stream_id >> 24) & 0x7F);
        buf[6] = @intCast((self.stream_id >> 16) & 0xFF);
        buf[7] = @intCast((self.stream_id >> 8) & 0xFF);
        buf[8] = @intCast(self.stream_id & 0xFF);
        try writer.writeAll(&buf);
    }
};

// HTTP/2 Settings
pub const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: u32 = 1,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 0xFFFFFFFF,

    pub fn readPayload(_: Allocator, payload: []const u8) !Settings {
        var settings = Settings{};
        if (payload.len % 6 != 0) return error.InvalidSettingsPayload;
        var i: usize = 0;
        while (i < payload.len) : (i += 6) {
            const id = (@as(u16, payload[i]) << 8) | @as(u16, payload[i + 1]);
            const value = (@as(u32, payload[i + 2]) << 24) | (@as(u32, payload[i + 3]) << 16) |
                (@as(u32, payload[i + 4]) << 8) | @as(u32, payload[i + 5]);
            switch (id) {
                0x1 => settings.header_table_size = value,
                0x2 => settings.enable_push = value,
                0x3 => settings.max_concurrent_streams = value,
                0x4 => settings.initial_window_size = value,
                0x5 => settings.max_frame_size = value,
                0x6 => settings.max_header_list_size = value,
                else => {}, // Ignore unknown settings
            }
        }
        return settings;
    }

    pub fn writePayload(self: Settings, allocator: Allocator) ![]u8 {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        const settings = [_]struct { id: u16, value: u32 }{
            .{ .id = 0x1, .value = self.header_table_size },
            .{ .id = 0x2, .value = self.enable_push },
            .{ .id = 0x3, .value = self.max_concurrent_streams },
            .{ .id = 0x4, .value = self.initial_window_size },
            .{ .id = 0x5, .value = self.max_frame_size },
            .{ .id = 0x6, .value = self.max_header_list_size },
        };
        for (settings) |s| {
            try buf.append(@intCast((s.id >> 8) & 0xFF));
            try buf.append(@intCast(s.id & 0xFF));
            try buf.append(@intCast((s.value >> 24) & 0xFF));
            try buf.append(@intCast((s.value >> 16) & 0xFF));
            try buf.append(@intCast((s.value >> 8) & 0xFF));
            try buf.append(@intCast(s.value & 0xFF));
        }
        return try buf.toOwnedSlice();
    }
};

// HPACK Header Compression
pub const HPACK = struct {
    // Named struct for headers to avoid anonymous struct type mismatches
    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };

    // Define the header entry struct for the dynamic table
    const HeaderEntry = struct {
        name: []const u8,
        value: []const u8,
    };

    const StaticTableEntry = struct { name: []const u8, value: []const u8 };
    const static_table = [_]StaticTableEntry{
        .{ .name = ":authority", .value = "" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        // Add more static table entries as per RFC 7541
    };

    dynamic_table: std.ArrayList(HeaderEntry),
    dynamic_table_size: usize,
    max_table_size: usize,

    pub fn init(allocator: Allocator, max_table_size: usize) HPACK {
        return .{
            .dynamic_table = std.ArrayList(HeaderEntry).init(allocator),
            .dynamic_table_size = 0,
            .max_table_size = max_table_size,
        };
    }

    pub fn deinit(self: *HPACK) void {
        for (self.dynamic_table.items) |entry| {
            self.dynamic_table.allocator.free(entry.name);
            self.dynamic_table.allocator.free(entry.value);
        }
        self.dynamic_table.deinit();
    }

    pub fn encode(self: *HPACK, headers: std.ArrayList(Header), writer: anytype) !void {
        for (headers.items) |header| {
            // Simplified: Encode as literal header with indexing
            var name_index: ?usize = null;
            var value_index: ?usize = null;

            // Check static table
            for (static_table, 0..) |entry, i| {
                if (std.mem.eql(u8, header.name, entry.name)) {
                    if (std.mem.eql(u8, header.value, entry.value)) {
                        value_index = i + 1;
                        break;
                    }
                    name_index = i + 1;
                }
            }

            if (value_index) |idx| {
                // Indexed header field
                try writeInteger(writer, idx, 7, 0x80);
            } else {
                // Literal header field
                if (name_index) |n_idx| {
                    // Literal with indexed name
                    try writeInteger(writer, n_idx, 6, 0x40);
                    try writeString(writer, header.value);
                } else {
                    // Literal with new name
                    try writeInteger(writer, 0, 6, 0x40);
                    try writeString(writer, header.name);
                    try writeString(writer, header.value);
                }
                // Add to dynamic table if space allows
                try self.addToDynamicTable(header.name, header.value);
            }
        }
    }

    pub fn decode(self: *HPACK, reader: anytype, allocator: Allocator) !std.ArrayList(Header) {
        var headers = std.ArrayList(Header).init(allocator);
        errdefer {
            for (headers.items) |h| {
                allocator.free(h.name);
                allocator.free(h.value);
            }
            headers.deinit();
        }

        while (true) {
            const first_byte = reader.readByte() catch |err| {
                if (err == error.EndOfStream) break;
                return err;
            };
            if (first_byte & 0x80 == 0x80) {
                // Indexed Header Field
                const index = try readInteger(reader, first_byte, 7);
                const header = try self.getHeader(index, allocator);
                try headers.append(.{ .name = header.name, .value = header.value });
            } else if (first_byte & 0x40 == 0x40) {
                // Literal Header Field with Incremental Indexing
                const name_index = try readInteger(reader, first_byte, 6);
                var name: []const u8 = undefined;
                if (name_index == 0) {
                    name = try readString(reader, allocator);
                } else {
                    name = try self.getHeaderName(name_index, allocator);
                }
                const value = try readString(reader, allocator);
                try headers.append(.{ .name = name, .value = value });
                try self.addToDynamicTable(name, value);
            } else {
                // Other cases (e.g., without indexing, dynamic table size update)
                return error.UnsupportedHPACKOperation;
            }
        }
        return headers;
    }

    fn addToDynamicTable(self: *HPACK, name: []const u8, value: []const u8) !void {
        const entry_size = name.len + value.len + 32;
        while (self.dynamic_table_size + entry_size > self.max_table_size and self.dynamic_table.items.len > 0) {
            // Access the last element directly and shrink the list
            const last = self.dynamic_table.items[self.dynamic_table.items.len - 1];
            self.dynamic_table.shrinkRetainingCapacity(self.dynamic_table.items.len - 1);
            self.dynamic_table_size -= (last.name.len + last.value.len + 32);
            self.dynamic_table.allocator.free(last.name);
            self.dynamic_table.allocator.free(last.value);
        }
        if (self.dynamic_table_size + entry_size <= self.max_table_size) {
            const name_copy = try self.dynamic_table.allocator.dupe(u8, name);
            const value_copy = try self.dynamic_table.allocator.dupe(u8, value);
            try self.dynamic_table.append(.{ .name = name_copy, .value = value_copy });
            self.dynamic_table_size += entry_size;
        }
    }

    fn getHeader(self: *HPACK, index: usize, allocator: Allocator) !Header {
        if (index == 0) return error.InvalidHeaderIndex;
        const idx = index - 1;
        if (idx < static_table.len) {
            return .{
                .name = try allocator.dupe(u8, static_table[idx].name),
                .value = try allocator.dupe(u8, static_table[idx].value),
            };
        }
        const dyn_idx = idx - static_table.len;
        if (dyn_idx < self.dynamic_table.items.len) {
            const entry = self.dynamic_table.items[self.dynamic_table.items.len - 1 - dyn_idx];
            return .{
                .name = try allocator.dupe(u8, entry.name),
                .value = try allocator.dupe(u8, entry.value),
            };
        }
        return error.InvalidHeaderIndex;
    }

    fn getHeaderName(self: *HPACK, index: usize, allocator: Allocator) ![]const u8 {
        if (index == 0) return error.InvalidHeaderIndex;
        const idx = index - 1;
        if (idx < static_table.len) {
            return try allocator.dupe(u8, static_table[idx].name);
        }
        const dyn_idx = idx - static_table.len;
        if (dyn_idx < self.dynamic_table.items.len) {
            return try allocator.dupe(u8, self.dynamic_table.items[self.dynamic_table.items.len - 1 - dyn_idx].name);
        }
        return error.InvalidHeaderIndex;
    }

    fn writeInteger(writer: anytype, value: usize, prefix_bits: u3, prefix: u8) !void {
        const max_prefix = @as(usize, 1) << prefix_bits - 1;
        if (value < max_prefix) {
            try writer.writeByte(@intCast(prefix | value));
        } else {
            try writer.writeByte(@intCast(prefix | max_prefix));
            var remaining = value - max_prefix;
            while (remaining >= 128) {
                try writer.writeByte(@intCast((remaining % 128) | 128));
                remaining /= 128;
            }
            try writer.writeByte(@intCast(remaining));
        }
    }

    fn readInteger(reader: anytype, first_byte: u8, prefix_bits: u3) !usize {
        const max_prefix: usize = @as(usize, 1) << prefix_bits - 1;
        var value: usize = @as(usize, first_byte & max_prefix);
        if (value < max_prefix) return value;
        var m: u6 = 0;
        while (true) {
            const b = try reader.readByte();
            value += @as(usize, b & 0x7F) << m;
            if (b & 0x80 == 0) break;
            m = @min(m + 7, std.math.maxInt(u6));
        }
        return value;
    }

    fn writeString(writer: anytype, str: []const u8) !void {
        try writeInteger(writer, str.len, 7, 0);
        try writer.writeAll(str);
    }

    fn readString(reader: anytype, allocator: Allocator) ![]const u8 {
        const len = try readInteger(reader, try reader.readByte(), 7);
        const buf = try allocator.alloc(u8, len);
        try reader.readNoEof(buf);
        return buf;
    }
};

// HTTP/2 Stream States
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

// HTTP/2 Stream
pub const Stream = struct {
    id: u31,
    state: StreamState,
    request: ?*Request, // Modified Request struct
    response: ?*Response, // Modified Response struct
    window_size: i32,

    pub fn init(allocator: Allocator, id: u31) !*Stream {
        const stream = try allocator.create(Stream);
        stream.* = .{
            .id = id,
            .state = .idle,
            .request = null,
            .response = null,
            .window_size = 65535,
        };
        return stream;
    }

    pub fn deinit(self: *Stream, allocator: Allocator) void {
        if (self.request) |req| {
            req.deinit();
            allocator.destroy(req);
        }
        if (self.response) |res| {
            res.deinit();
            allocator.destroy(res);
        }
        allocator.destroy(self);
    }
};
