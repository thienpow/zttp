// src/http3/types.zig

// This file contains core type definitions for the HTTP/3 protocol,
// focusing on fundamental concepts like frame types and stream types,
// and the structure of an HTTP/3 frame.

const std = @import("std");
const Allocator = std.mem.Allocator;
const HeaderMap = std.http.HeaderMap;

// Import types defined in other files within the http3 module
const settings = @import("settings.zig");
pub const Settings = settings.Settings;
const http3_error = @import("error.zig");
pub const Http3Error = http3_error.Http3Error;
pub const ErrorCode = http3_error.ErrorCode;

// Import QPACK types
const qpack = @import("qpack/mod.zig");
pub const QpackEncoder = qpack.QpackEncoder;
pub const QpackDecoder = qpack.QpackDecoder;

/// HTTP/3 Frame Types
/// Defined in RFC 9114 Section 7.2
pub const FrameType = enum(u64) {
    data = 0x00, // carries payload data
    headers = 0x01, // carries header and trailer blocks
    cancel_push = 0x03, // indicates a client will not process a server push
    settings = 0x04, // carries configuration parameters
    goaway = 0x07, // indicates a connection is being closed
    max_push_id = 0x0D, // indicates the maximum push ID the sender is willing to receive
    duplicate_push = 0x0E, // indicates a server is attempting to push a resource that has already been pushed (deprecated?)

    // Reserved frame types - MUST be ignored if received
    reserved_02 = 0x02,
    reserved_05 = 0x05,
    reserved_06 = 0x06,
    reserved_08 = 0x08,
    reserved_09 = 0x09,
    reserved_0A = 0x0A,
    reserved_0B = 0x0B,
    reserved_0C = 0x0C,
    reserved_0F = 0x0F,
    reserved_10 = 0x10,
    reserved_11 = 0x11,
    reserved_12 = 0x12,
    reserved_13 = 0x13,
    reserved_14 = 0x14,
    reserved_15 = 0x15,
    reserved_16 = 0x16,
    reserved_17 = 0x17,
    reserved_18 = 0x18,
    reserved_19 = 0x19,
    reserved_1A = 0x1A,
    reserved_1B = 0x1B,
    reserved_1C = 0x1C,
    reserved_1D = 0x1D,
    reserved_1E = 0x1E,
    reserved_1F = 0x1F,

    // TODO: Add potentially other frame types like WEBTRANSPORT_STREAM (0x41, RFC 9297)
    webtransport_stream = 0x41,
};

/// Represents the different stream types in QUIC used by HTTP/3.
/// Defined in RFC 9114 Section 6
pub const StreamType = enum(u64) {
    /// Control Stream (unidirectional)
    /// Used to carry control frames.
    control = 0x00,
    /// Push Stream (unidirectional from server to client)
    /// Used to carry responses to server pushes.
    push = 0x01,
    /// QPACK Encoder Stream (unidirectional)
    /// Used to carry QPACK encoder instructions.
    encoder = 0x02,
    /// QPACK Decoder Stream (unidirectional)
    /// Used to carry QPACK decoder instructions.
    decoder = 0x03,

    // Standard HTTP/3 request/response streams are bidirectional and do not have
    // a type encoded in the stream ID itself, their purpose is defined by the
    // initial frames sent on them (HEADERS frame initiates a request).
};

/// Represents a single HTTP/3 frame.
/// Defined in RFC 9114 Section 7.2
pub const Frame = union(FrameType) {
    /// DATA frame payload
    data: struct {
        /// The actual payload data.
        payload: []const u8, // This slice points to data owned elsewhere (e.g., stream buffer)
        // No deinit needed if payload is a slice of an external buffer.
        // pub fn deinit(self: *@This(), allocator: Allocator) void { allocator.free(self.payload); }
    },
    /// HEADERS frame payload
    headers: struct {
        /// The QPACK-encoded header block.
        encoded_block: []const u8, // This slice points to data owned elsewhere
        // No deinit needed if encoded_block is a slice of an external buffer.
        // pub fn deinit(self: *@This(), allocator: Allocator) void { allocator.free(self.encoded_block); }
    },
    /// CANCEL_PUSH frame payload
    cancel_push: struct {
        /// The ID of the push stream to cancel.
        push_id: u66, // Variable-length integer
    },
    /// SETTINGS frame payload
    settings: Settings, // Settings struct is defined in settings.zig
    goaway: struct {
        /// The stream ID of the last processed stream.
        stream_id: u62, // Variable-length integer
    },
    max_push_id: struct {
        /// The maximum Push ID the sender is willing to accept.
        push_id: u66, // Variable-length integer
    },
    duplicate_push: struct {
        // DUPLICATE_PUSH frame payload is a Push ID.
        push_id: u66, // Variable-length integer
    },
    webtransport_stream: struct {
        // WEBTRANSPORT_STREAM frame payload
        // Defined in RFC 9297 Section 2.2
        // This frame has no payload, it just signals a new WebTransport stream.
    },

    // Catch-all for reserved frames or unknown frames that must be ignored
    reserved: struct {
        payload: []const u8, // This slice points to data owned elsewhere
        // No deinit needed if payload is a slice of an external buffer.
        // pub fn deinit(self: *@This(), allocator: Allocator) void { allocator.free(self.payload); }
    },

    /// Placeholder deinit for frames. Currently, slices point to shared buffers,
    /// so no deinit is strictly needed for the Frame union itself.
    /// If frame payloads were ever copied, this would need implementation.
    pub fn deinit(self: *Frame, allocator: Allocator) void {
        _ = self; // Unused
        _ = allocator; // Unused
        // Example if payloads were owned:
        // switch (self.*) {
        //     .data => |*data| allocator.free(data.payload),
        //     .headers => |*headers| allocator.free(headers.encoded_block),
        //     .reserved => |*reserved| allocator.free(reserved.payload),
        //     else => {}, // No deinit needed for other variants
        // }
    }
};

// The actual frame parsing and serialization logic will live in frame.zig
// QPACK related types are now in qpack/mod.zig
// Error types are now in error.zig
// Settings struct is now in settings.zig
