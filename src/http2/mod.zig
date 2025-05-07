// src/http2/mod.zig - Main entry point for HTTP/2 implementation
const std = @import("std");
const Allocator = std.mem.Allocator;

// Export frame types and functions
pub const frame = @import("frame.zig");
pub const FrameType = frame.FrameType;
pub const FrameHeader = frame.FrameHeader;

// Export settings
pub const settings = @import("settings.zig");
pub const Settings = settings.Settings;

// Export HPACK
pub const hpack = @import("hpack/mod.zig");
pub const HPACK = hpack.HPACK;

// Export stream handling
pub const stream = @import("stream.zig");
pub const StreamState = stream.StreamState;
pub const Stream = stream.Stream;
pub const StreamCollection = stream.StreamCollection;

// Export error codes
pub const error_types = @import("error.zig");
pub const ErrorCode = error_types.ErrorCode;
pub const Http2Error = error_types.Http2Error;

// Export connection functionality
pub const connection = @import("connection.zig");
pub const Http2Connection = connection.Http2Connection;

// Configure logging
pub const log = std.log.scoped(.http2);
