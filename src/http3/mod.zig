// src/http3/mod.zig

const std = @import("std");

// Import and re-export public types and functions from http3 sub-modules

// Error types
const http3_error = @import("error.zig");
pub const ErrorCode = http3_error.ErrorCode;
pub const Http3Error = http3_error.Http3Error;

// Settings
const settings = @import("settings.zig");
pub const Settings = settings.Settings;

// Core types (FrameType, StreamType, Frame)
const types = @import("types.zig");
pub const FrameType = types.FrameType;
pub const StreamType = types.StreamType;
pub const Frame = types.Frame; // Re-export Frame struct/union

// QUIC Connection representation (likely managed internally, but type might be needed)
const connection = @import("connection.zig");
pub const QuicConnection = connection.QuicConnection; // Represents a single QUIC connection

// Stream representation (likely managed internally by connection/handler)
// const stream = @import("stream.zig");
// pub const QuicStream = stream.QuicStream; // Streams are likely managed internally

// Frame parsing and serialization (likely internal to stream)
// const frame = @import("frame.zig");
// pub const readFrame = frame.readFrame;
// pub const writeFrame = frame.writeFrame;

// QPACK (Header Compression) (likely internal to frame/stream/connection)
// const qpack = @import("qpack/mod.zig");
// pub const QpackEncoder = qpack.QpackEncoder;
// pub const QpackDecoder = qpack.QpackDecoder;

// High-level HTTP/3 handler
const handler = @import("handler.zig");
pub const Http3Handler = handler.Http3Handler;

// TODO: Add public functions for initializing the HTTP/3 subsystem within the server
// This might involve starting the UDP listener and the main HTTP/3 event loop,
// and potentially creating the Http3Handler instance.
