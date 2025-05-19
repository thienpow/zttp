// src/http3/qpack/encoder.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Http3Error = @import("../error.zig").Http3Error;
const ErrorCode = @import("../error.zig").ErrorCode;
const HeaderMap = @import("../../http/header_map.zig").HeaderMap;

const static_table = @import("static_table.zig");
const huffman = @import("huffman.zig");

const utils = @import("utils.zig");

const log = std.log.scoped(.qpack_encoder);

/// Represents a single entry in the dynamic table.
const DynamicTableEntry = struct {
    name: []const u8,
    value: []const u8,
};

/// QPACK encoder for HTTP/3 header compression per RFC 9204.
pub const QpackEncoder = struct {
    allocator: Allocator,
    max_table_capacity: u64,
    max_blocked_streams: u64,
    dynamic_table: ArrayList(DynamicTableEntry),
    dynamic_table_size: u64,
    encoder_instructions: ArrayList(u8),
    insert_count: u64,
    blocked_streams: u64,

    /// Initializes a QPACK encoder.
    pub fn init(allocator: Allocator, max_table_capacity: u64, max_blocked_streams: u64) !*QpackEncoder {
        const self = try allocator.create(QpackEncoder);
        self.* = .{
            .allocator = allocator,
            .max_table_capacity = max_table_capacity,
            .max_blocked_streams = max_blocked_streams,
            .dynamic_table = try ArrayList(DynamicTableEntry).initCapacity(allocator, 32),
            .dynamic_table_size = 0,
            .encoder_instructions = try ArrayList(u8).initCapacity(allocator, 128),
            .insert_count = 0,
            .blocked_streams = 0,
        };
        log.debug("Initialized QPACK encoder (capacity={d}, max_blocked={d})", .{ max_table_capacity, max_blocked_streams });
        return self;
    }

    /// Deinitializes the QPACK encoder.
    pub fn deinit(self: *QpackEncoder) void {
        log.debug("Deinitializing QPACK encoder", .{});
        for (self.dynamic_table.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.dynamic_table.deinit();
        self.encoder_instructions.deinit();
        self.allocator.destroy(self);
    }

    /// Encodes headers into a QPACK header block.
    pub fn encodeHeaders(self: *QpackEncoder, headers: HeaderMap) ![]u8 {
        log.debug("Encoding headers (count={d})", .{headers.map.count()});
        var header_block = try ArrayList(u8).initCapacity(self.allocator, 128);
        errdefer header_block.deinit();
        self.encoder_instructions.clearRetainingCapacity();

        // Write prefix: Required Insert Count and Base
        const ric = self.insert_count;
        try utils.writeInt(&header_block, ric, 8);
        try header_block.append(0); // Base sign bit (0)
        try utils.writeInt(&header_block, 0, 7); // Delta Base = 0

        // Process headers
        var it = headers.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            // Use first value if multiple exist (per RFC 9204, single value expected)
            const value = if (entry.value_ptr.items.len > 0) entry.value_ptr.items[0] else continue;

            // Try encoding strategies
            if (try self.tryEncodeStaticTable(&header_block, name, value)) continue;
            if (try self.tryEncodeDynamicTable(&header_block, name, value)) continue;
            if (try self.tryEncodeStaticNameRef(&header_block, name, value)) continue;
            if (try self.tryEncodeDynamicNameRef(&header_block, name, value)) continue;

            // Encode as literal and add to dynamic table
            try self.encodeLiteralWithLiteralName(&header_block, name, value);
            try self.addToDynamicTable(name, value);
        }

        return try header_block.toOwnedSlice();
    }

    /// Processes QPACK decoder instructions from the encoder stream.
    pub fn processInstructions(self: *QpackEncoder, data: []const u8) !void {
        log.debug("Processing encoder stream data (len={d})", .{data.len});
        var stream = std.io.fixedBufferStream(data);
        var reader = stream.reader();

        while (stream.pos < data.len) {
            const first_byte = try reader.readByte();
            if (first_byte & 0x80 != 0) {
                // Section Acknowledgment
                const stream_id = try utils.readInt(&reader, u64, 7);
                if (self.blocked_streams > 0) self.blocked_streams -= 1;
                log.debug("Acknowledged stream {d}", .{stream_id});
            } else if (first_byte & 0x40 != 0) {
                // Stream Cancellation
                const stream_id = try utils.readInt(&reader, u64, 6);
                if (self.blocked_streams > 0) self.blocked_streams -= 1;
                log.debug("Cancelled stream {d}", .{stream_id});
            } else {
                // Insert Count Increment
                const increment = try utils.readInt(&reader, u64, 6);
                self.insert_count += increment;
                log.debug("Incremented insert_count by {d} to {d}", .{ increment, self.insert_count });
            }
        }

        if (self.blocked_streams > self.max_blocked_streams) {
            log.err("Blocked streams exceed limit ({d} > {d})", .{ self.blocked_streams, self.max_blocked_streams });
            return Http3Error.QpackStreamError;
        }
    }

    /// Drains pending encoder instructions.
    pub fn drainEncoderStream(self: *QpackEncoder) ?[]u8 {
        if (self.encoder_instructions.items.len == 0) return null;
        return self.encoder_instructions.toOwnedSlice() catch null;
    }

    fn tryEncodeStaticTable(_: *QpackEncoder, header_block: *ArrayList(u8), name: []const u8, value: []const u8) !bool {
        const index = static_table.findEntry(name, value) catch return false;
        try header_block.append(0x80 | 0x40); // Indexed Static
        try utils.writeInt(header_block, index, 6);
        return true;
    }

    fn tryEncodeDynamicTable(self: *QpackEncoder, header_block: *ArrayList(u8), name: []const u8, value: []const u8) !bool {
        for (self.dynamic_table.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
                try header_block.append(0x80); // Indexed Dynamic
                try utils.writeInt(header_block, i, 6);
                return true;
            }
        }
        return false;
    }

    fn tryEncodeStaticNameRef(_: *QpackEncoder, header_block: *ArrayList(u8), name: []const u8, value: []const u8) !bool {
        const name_index = static_table.findName(name) catch return false;
        try header_block.append(0x50); // Literal with Static Name
        try utils.writeInt(header_block, name_index, 4);
        try encodeLiteral(header_block, value);
        return true;
    }

    fn tryEncodeDynamicNameRef(self: *QpackEncoder, header_block: *ArrayList(u8), name: []const u8, value: []const u8) !bool {
        for (self.dynamic_table.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) {
                try header_block.append(0x40); // Literal with Dynamic Name
                try utils.writeInt(header_block, i, 4);
                try encodeLiteral(header_block, value);
                return true;
            }
        }
        return false;
    }

    fn encodeLiteralWithLiteralName(_: *QpackEncoder, header_block: *ArrayList(u8), name: []const u8, value: []const u8) !void {
        try header_block.append(0x20); // Literal with Literal Name
        try encodeLiteral(header_block, name);
        try encodeLiteral(header_block, value);
    }

    fn encodeLiteral(header_block: *ArrayList(u8), value: []const u8) !void {
        if (value.len <= 7) {
            try header_block.append(@intCast(value.len));
            try header_block.appendSlice(value);
        } else {
            try header_block.append(0x08 | @as(u8, @intCast(value.len)));
            try huffman.encodeHuffman(header_block, value);
        }
    }

    fn addToDynamicTable(self: *QpackEncoder, name: []const u8, value: []const u8) !void {
        const entry_size = name.len + value.len + 32;
        while (self.dynamic_table_size + entry_size > self.max_table_capacity and !self.dynamic_table.isEmpty()) {
            const oldest = self.dynamic_table.pop();
            self.dynamic_table_size -= oldest.name.len + oldest.value.len + 32;
            self.allocator.free(oldest.name);
            self.allocator.free(oldest.value);
        }
        if (entry_size > self.max_table_capacity) {
            log.warn("Skipping dynamic table entry (size={d} > capacity={d})", .{ entry_size, self.max_table_capacity });
            return;
        }

        // Generate instruction: Insert with Literal Name
        try self.encoder_instructions.append(0x40);
        try encodeLiteral(&self.encoder_instructions, name);
        try encodeLiteral(&self.encoder_instructions, value);

        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        try self.dynamic_table.append(.{ .name = name_copy, .value = value_copy });
        self.dynamic_table_size += entry_size;
        self.insert_count += 1;
        self.blocked_streams += 1;

        log.debug("Added to dynamic table: {s}={s} (size={d}, count={d})", .{ name, value, self.dynamic_table_size, self.insert_count });
    }
};
