// src/http3/qpack/decoder.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const HeaderMap = std.http.HeaderMap;

const http3_error = @import("../error.zig");
const Http3Error = http3_error.Http3Error;
const ErrorCode = http3_error.ErrorCode;

const log = std.log.scoped(.qpack_decoder);

/// Implements the QPACK header decompression logic.
/// Defined in RFC 9204.
pub const QpackDecoder = struct {
    allocator: Allocator,
    /// The maximum capacity of the dynamic table, as negotiated via SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    max_table_capacity: u64,
    /// The maximum number of streams that can be blocked, as negotiated via SETTINGS_QPACK_BLOCKED_STREAMS.
    max_blocked_streams: u64,

    // TODO: Add fields for QPACK decoder state.
    // This will likely include:
    // - The dynamic table (e.g., a list or ring buffer of header entries).
    // - State for handling the decoder stream (receiving acknowledgments, etc.).
    // - State for blocked streams.

    /// Initializes a new QPACK decoder.
    /// max_table_capacity and max_blocked_streams are from the peer's SETTINGS frame.
    pub fn init(allocator: Allocator, max_table_capacity: u64, max_blocked_streams: u64) !QpackDecoder {
        log.debug("Initializing QPACK Decoder with max_table_capacity={} and max_blocked_streams={}", .{ max_table_capacity, max_blocked_streams });
        // TODO: Initialize QPACK decoder state and structures.
        // This includes setting up the dynamic table with the given capacity.

        return error.Unimplemented; // Placeholder
    }

    /// Deinitializes the QPACK decoder.
    pub fn deinit(self: *QpackDecoder) void {
        log.debug("Deinitializing QPACK Decoder", .{});
        _ = self; // Unused
        // TODO: Clean up QPACK decoder resources (e.g., dynamic table).
    }

    /// Decodes a QPACK-formatted header block.
    /// This is used to decode the payload of a HEADERS frame received on a request/response stream.
    /// May require state from the decoder stream if dynamic table entries are referenced that haven't been acknowledged.
    pub fn decodeHeaders(self: *QpackDecoder, header_block: []const u8) anyerror!HeaderMap {
        _ = self; // Unused
        _ = header_block; // Unused
        log.debug("Decoding QPACK header block (len={d})", .{header_block.len});
        // TODO: Implement QPACK header decoding according to RFC 9204 Section 3.3.1.
        // This involves processing prefix, static/dynamic table references, and literal headers.
        // If a dynamic table entry is referenced that hasn't been acknowledged via the decoder stream,
        // the stream becomes "blocked". You'll need to manage blocked streams.

        // Placeholder: return an empty HeaderMap for now
        // var headers = HeaderMap.init(self.allocator);
        // return headers;

        return Http3Error.Unimplemented; // Placeholder
    }

    /// Processes incoming decoder instructions from the decoder stream.
    /// This function is called by the connection or stream handling the decoder stream.
    pub fn handleDecoderStreamData(self: *QpackDecoder, data: []const u8) anyerror!void {
        _ = self; // Unused
        _ = data; // Unused
        log.debug("Handling QPACK decoder stream data (len={d})", .{data.len});
        // TODO: Parse and apply decoder instructions (e.g., Insert With Name Ref, Insert Without Name Ref, Duplicate, Set Dynamic Table Capacity, Stream Cancellation).
        // These instructions update the dynamic table or decoder state.
        // After processing instructions, check if any blocked streams can now be unblocked.
        return Http3Error.Unimplemented; // Placeholder
    }

    /// Handles header blocks that were blocked waiting for dynamic table entries.
    /// This function is typically called after processing decoder stream data
    /// that unblocks one or more streams.
    pub fn unblockStreams(self: *QpackDecoder) anyerror!void {
        _ = self; // Unused
        log.debug("Attempting to unblock streams", .{});
        // TODO: Iterate through blocked streams and attempt to decode their header blocks again.
        // If successful, unblock the stream and resume processing (e.g., dispatch to Http3Handler).
        return Http3Error.Unimplemented; // Placeholder
    }
};
