// src/http3/qpack/decoder.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Http3Error = @import("../error.zig").Http3Error;
const ErrorCode = @import("../error.zig").ErrorCode;
const HeaderMap = @import("../../http/header_map.zig").HeaderMap;

const static_table = @import("static_table.zig");
const huffman = @import("huffman.zig");

const utils = @import("utils.zig");

const log = std.log.scoped(.qpack_decoder);

/// Represents a single entry in the dynamic table.
const DynamicTableEntry = struct {
    name: []const u8,
    value: []const u8,
};

/// Structure to represent a blocked stream
const BlockedStream = struct {
    stream_id: u64,
    header_block: []const u8,
};

/// QPACK decoder for HTTP/3 header decompression per RFC 9204.
pub const QpackDecoder = struct {
    allocator: Allocator,
    max_table_capacity: u64,
    max_blocked_streams: u64,
    dynamic_table: ArrayList(DynamicTableEntry),
    dynamic_table_size: u64,
    blocked_streams: ArrayList(BlockedStream),

    /// Initializes a QPACK decoder.
    pub fn init(allocator: Allocator, max_table_capacity: u64, max_blocked_streams: u64) !*QpackDecoder {
        const self = try allocator.create(QpackDecoder);
        self.* = .{
            .allocator = allocator,
            .max_table_capacity = max_table_capacity,
            .max_blocked_streams = max_blocked_streams,
            .dynamic_table = try ArrayList(DynamicTableEntry).initCapacity(allocator, 32),
            .dynamic_table_size = 0,
            .blocked_streams = try ArrayList(BlockedStream).initCapacity(allocator, max_blocked_streams),
        };
        log.debug("Initialized QPACK decoder (capacity={d}, max_blocked={d})", .{ max_table_capacity, max_blocked_streams });
        return self;
    }

    /// Deinitializes the QPACK decoder.
    pub fn deinit(self: *QpackDecoder) void {
        log.debug("Deinitializing QPACK decoder", .{});
        for (self.dynamic_table.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.dynamic_table.deinit();
        for (self.blocked_streams.items) |blocked| {
            self.allocator.free(blocked.header_block);
        }
        self.blocked_streams.deinit();
        self.allocator.destroy(self);
    }

    /// Decodes a QPACK header block.
    pub fn decodeHeaders(self: *QpackDecoder, stream_id: u64, header_block: []const u8) !HeaderMap {
        log.debug("Decoding header block for stream {d} (len={d})", .{ stream_id, header_block.len });
        var headers = HeaderMap.init(self.allocator);
        errdefer headers.deinit();
        var stream = std.io.fixedBufferStream(header_block);
        var reader = stream.reader();

        // Read prefix: Required Insert Count and Base
        const ric = try utils.readInt(&reader, u64, 8);
        const base_sign = try reader.readByte();
        const delta_base = try utils.readInt(&reader, u64, 7);
        const base = if (base_sign & 0x80 == 0) ric + delta_base else ric - delta_base;

        // Process header block representations
        while (stream.pos < header_block.len) {
            const first_byte = try reader.readByte();
            if (first_byte & 0x80 != 0) {
                // Indexed Field Line (Static or Dynamic)
                const is_static = first_byte & 0x40 != 0;
                const index = try utils.readInt(&reader, u64, 6);
                const entry = try self.getTableEntry(is_static, index);
                try headers.put(entry.name, entry.value);
            } else if (first_byte & 0x40 != 0) {
                // Literal Field Line With Name Reference
                const is_static = first_byte & 0x20 != 0;
                const name_index = try utils.readInt(&reader, u64, 4);
                const value = try self.decodeLiteral(&reader);
                defer self.allocator.free(value);
                const name = (try self.getTableEntry(is_static, name_index)).name;
                try headers.put(name, value);
            } else if (first_byte & 0x20 != 0) {
                // Literal Field Line With Literal Name
                const name = try self.decodeLiteral(&reader);
                errdefer self.allocator.free(name);
                const value = try self.decodeLiteral(&reader);
                errdefer self.allocator.free(value);
                try headers.put(name, value);
            } else {
                // Indexed Field Line With Post-Base Index
                const index = try utils.readInt(&reader, u64, 4);
                const entry = try self.getDynamicTableEntry(base - index);
                try headers.put(entry.name, entry.value);
            }
        }

        // Check for blocked stream
        if (ric > self.dynamic_table.items.len) {
            if (self.blocked_streams.items.len >= self.max_blocked_streams) {
                log.err("Too many blocked streams (max={d})", .{self.max_blocked_streams});
                return Http3Error.QpackStreamError;
            }
            const header_copy = try self.allocator.dupe(u8, header_block);
            try self.blocked_streams.append(.{ .stream_id = stream_id, .header_block = header_copy });
            return Http3Error.QpackStreamError;
        }

        // Send Section Acknowledgment
        try self.sendSectionAcknowledgment(stream_id);

        return headers;
    }

    /// Processes QPACK encoder instructions from the decoder stream.
    pub fn processInstructions(self: *QpackDecoder, data: []const u8) !void {
        log.debug("Processing decoder stream data (len={d})", .{data.len});
        var stream = std.io.fixedBufferStream(data);
        var reader = stream.reader();

        while (stream.pos < data.len) {
            const first_byte = try reader.readByte();
            if (first_byte & 0x80 != 0) {
                // Insert With Name Reference
                const is_static = first_byte & 0x40 != 0;
                const name_index = try utils.readInt(&reader, u64, 6);
                const value = try self.decodeLiteral(&reader);
                const name = (try self.getTableEntry(is_static, name_index)).name;
                try self.insertDynamicTableEntry(name, value);
            } else if (first_byte & 0x40 != 0) {
                // Insert With Literal Name
                const name = try self.decodeLiteral(&reader);
                errdefer self.allocator.free(name);
                const value = try self.decodeLiteral(&reader);
                errdefer self.allocator.free(value);
                try self.insertDynamicTableEntry(name, value);
            } else if (first_byte & 0x20 != 0) {
                // Duplicate
                const index = try utils.readInt(&reader, u64, 5);
                const entry = try self.getDynamicTableEntry(index);
                try self.insertDynamicTableEntry(entry.name, entry.value);
            } else {
                // Set Dynamic Table Capacity
                const capacity = try utils.readInt(&reader, u64, 5);
                if (capacity > self.max_table_capacity) {
                    log.err("Invalid table capacity ({d} > {d})", .{ capacity, self.max_table_capacity });
                    return Http3Error.QpackDecompressionFailed;
                }
                try self.setDynamicTableCapacity(capacity);
            }
        }

        try self.unblockStreams();
    }

    /// Sends a Section Acknowledgment for a processed header block.
    fn sendSectionAcknowledgment(self: *QpackDecoder, stream_id: u64) !void {
        var buf = try ArrayList(u8).initCapacity(self.allocator, 16);
        defer buf.deinit();
        try buf.append(0x80); // Section Acknowledgment
        try utils.writeInt(&buf, stream_id, 7);
        // Assumed: Connection sends this on decoder stream
        // try self.connection.sendStreamData(decoder_stream_id, buf.items, false);
    }

    /// Attempts to unblock streams with pending header blocks.
    fn unblockStreams(self: *QpackDecoder) !void {
        log.debug("Unblocking streams (count={d})", .{self.blocked_streams.items.len});
        var i: usize = 0;
        while (i < self.blocked_streams.items.len) {
            const blocked = self.blocked_streams.items[i];
            const headers = self.decodeHeaders(blocked.stream_id, blocked.header_block) catch |err| {
                if (err == Http3Error.QpackStreamError) {
                    i += 1;
                    continue;
                }
                self.allocator.free(blocked.header_block);
                _ = self.blocked_streams.swapRemove(i);
                return err;
            };
            self.allocator.free(blocked.header_block);
            _ = self.blocked_streams.swapRemove(i);
            // Placeholder: Dispatch to stream.zig
            // try self.connection.dispatchHeaders(blocked.stream_id, headers);
            headers.deinit();
        }
    }

    fn getTableEntry(self: *QpackDecoder, is_static: bool, index: u64) !DynamicTableEntry {
        if (is_static) {
            return static_table.getEntry(index) catch return Http3Error.QpackDecompressionFailed;
        }
        return self.getDynamicTableEntry(index);
    }

    fn getDynamicTableEntry(self: *QpackDecoder, index: u64) !DynamicTableEntry {
        if (index >= self.dynamic_table.items.len) {
            return Http3Error.QpackDecompressionFailed;
        }
        return self.dynamic_table.items[index];
    }

    fn insertDynamicTableEntry(self: *QpackDecoder, name: []const u8, value: []const u8) !void {
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
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);
        try self.dynamic_table.append(.{ .name = name_copy, .value = value_copy });
        self.dynamic_table_size += entry_size;
    }

    fn setDynamicTableCapacity(self: *QpackDecoder, capacity: u64) !void {
        while (self.dynamic_table_size > capacity and !self.dynamic_table.isEmpty()) {
            const oldest = self.dynamic_table.pop();
            self.dynamic_table_size -= oldest.name.len + oldest.value.len + 32;
            self.allocator.free(oldest.name);
            self.allocator.free(oldest.value);
        }
        self.max_table_capacity = capacity;
        log.debug("Set dynamic table capacity to {d}", .{capacity});
    }

    fn decodeLiteral(self: *QpackDecoder, reader: anytype) ![]const u8 {
        const first_byte = try reader.readByte();
        const is_huffman = first_byte & 0x08 != 0;
        const length = if (is_huffman) first_byte & 0x07 else first_byte;
        if (is_huffman) {
            return try huffman.decodeHuffman(reader, self.allocator, length);
        }
        const buf = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(buf);
        try reader.readNoEof(buf);
        return buf;
    }
};
