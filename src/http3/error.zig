// src/http3/error.zig

// This file contains error definitions specific to the HTTP/3 protocol
// and its underlying QUIC transport context.

const std = @import("std");

/// HTTP/3 Error Codes
/// Defined in RFC 9114 Section 8.1
pub const ErrorCode = enum(u62) {
    no_error = 0x00, // No error.
    general_protocol_error = 0x01, // A generic error, used when a more specific error code is not available.
    internal_error = 0x02, // An internal error has occurred in the HTTP/3 stack.
    stream_creation_error = 0x03, // The server refused to create the stream (HTTP/2 equivalent).
    closed_critical_stream = 0x04, // A stream required for the connection to remain open was closed.
    frame_unexpected = 0x05, // A frame was received that was not permitted in the current state.
    frame_error = 0x06, // A frame was received with an invalid syntax.
    excessive_load = 0x07, // The peer's processing load is too high.
    id_error = 0x08, // An ID in a frame was invalid.
    settings_error = 0x09, // A SETTINGS frame was invalid.
    missing_settings = 0x0a, // A mandatory SETTINGS value was not received.
    request_rejected = 0x0b, // The request was rejected.
    request_canceled = 0x0c, // The request was canceled.
    incompatible_version = 0x0d, // The requested version is not supported.
    qpack_decompression_failed = 0x0e, // The QPACK decoder failed.
    qpack_encoder_stream_error = 0x10, // The QPACK encoder stream error.
    qpack_decoder_stream_error = 0x11, // The QPACK decoder stream error.

    // Quic-related errors that can map to HTTP/3 errors
    quic_protocol_error = 0x100, // Generic QUIC protocol error
    quic_idle_timeout = 0x101, // QUIC idle timeout
    quic_connection_close = 0x102, // QUIC connection closed
    // Add other relevant QUIC error codes as needed, mapping them to a higher range
};

/// Error set for HTTP/3 operations.
pub const Http3Error = error{
    /// Operation is not yet implemented.
    Unimplemented,
    /// Received an invalid frame.
    InvalidFrame,
    /// Received an invalid HTTP/3 protocol sequence or state.
    ProtocolError,
    /// An error occurred at the underlying QUIC layer.
    QuicError,
    /// An error occurred specific to a stream.
    StreamError,
    /// Received a frame type unexpected for the current state or stream type.
    UnexpectedFrameType,
    /// Need more data to parse a complete frame or header block.
    NeedMoreData,
    /// A GOAWAY frame was received, indicating the peer is closing the connection.
    GoAwayReceived,
    /// Maximum allowed connections reached.
    MaxConnectionsReached,
    /// QPACK header decompression failed.
    QpackDecompressionFailed,
    /// QPACK encoder/decoder stream error.
    QpackStreamError,
    /// Attempted to use a stream in an invalid state.
    InvalidStreamState,
    /// Attempted to perform an operation on a non-existent stream.
    UnknownStream,
};