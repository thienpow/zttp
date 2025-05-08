// src/http3/frame.zig

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import types from http3 sub-modules
const types = @import("types.zig");
const FrameType = types.FrameType;
pub const Frame = types.Frame; // Use the Frame union defined in types.zig

const http3_error = @import("error.zig");
const Http3Error = http3_error.Http3Error;
const ErrorCode = http3_error.ErrorCode;

const settings = @import("settings.zig");
pub const Settings = settings.Settings; // Use the Settings struct defined in settings.zig

const qpack = @import("qpack/mod.zig");
pub const QpackEncoder = qpack.QpackEncoder; // Use QpackEncoder from qpack/mod.zig
pub const QpackDecoder = qpack.QpackDecoder; // Use QpackDecoder from qpack/mod.zig

// Logic for parsing and serializing HTTP/3 frames

/// Reads and parses a single HTTP/3 frame from a reader.
/// Requires a reader that supports variable-length integer reads.
/// Returns the parsed Frame or error. Needs to handle variable-length integers.
pub fn readFrame(allocator: Allocator, reader: anytype) !Frame {
    _ = allocator; // Unused for now
    _ = reader; // Unused for now
}

// TODO: Implement variable-length integer reading for type and length
// TODO: Read payload based on length
// TODO: Based on frame type, parse payload into the correct Frame union variant
// This will likely involve reading the type (u64), then the length (u64)
// using `std.leb128`.\n    // Then read `length` bytes as the payload.\n    // Finally, interpret the payload based on the frame type.\n    // Handle reserved frame types by returning the `reserved` variant with the payload.\n    // Handle unknown frame types similarly or return a ProtocolError depending on strictness.\n\n    return Http3Error.Unimplemented;\n}\n\n/// Serializes an HTTP/3 Frame into a writer.\n/// Requires a writer that supports variable-length integer writes.\n/// Writes the frame type, length, and payload.\npub fn writeFrame(writer: anytype, frame: Frame) !void {\n    _ = writer; // Unused for now\n    _ = frame; // Unused for now\n    // TODO: Implement variable-length integer writing for type and length\n    // TODO: Write payload\n    // This will involve writing the frame type (u64), then the payload length (u64)\n    // using `std.leb128`.\n    // Then write the frame\'s payload bytes based on the frame variant.\n\n    return Http3Error.Unimplemented;\n}\n\n// Note: Settings, QpackEncoder, and QpackDecoder structs are now defined in\n// their respective files and imported via mod.zig and types.zig.\n\n/*\n// SETTINGS frame payload structure and methods - NOW IN settings.zig\npub const Settings = struct { ... };\n*/\n\n/*\n// QPACK (Header Compression) integration structs and methods - NOW IN qpack/mod.zig\n\npub const QpackEncoder = struct { ... };\n\npub const QpackDecoder = struct { ... };\n*/\n\n// The Frame and FrameType definitions are now in types.zig\n
