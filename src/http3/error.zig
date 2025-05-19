// src/http3/error.zig
const std = @import("std");

/// HTTP/3 error codes per RFC 9114 Section 8.1 and QUIC mappings.
pub const ErrorCode = enum(u62) {
    no_error = 0x100,
    general_protocol_error = 0x101,
    internal_error = 0x102,
    stream_creation_error = 0x103,
    closed_critical_stream = 0x104,
    frame_unexpected = 0x105,
    frame_error = 0x106,
    excessive_load = 0x107,
    id_error = 0x108,
    settings_error = 0x109,
    missing_settings = 0x10A,
    request_rejected = 0x10B,
    request_canceled = 0x10C,
    request_incomplete = 0x10D,
    message_error = 0x10E,
    connect_error = 0x10F,
    version_fallback = 0x110,
    qpack_decompression_failed = 0x200,
    qpack_encoder_stream_error = 0x201,
    qpack_decoder_stream_error = 0x202,
    quic_protocol_error = 0x300,
    quic_idle_timeout = 0x301,
    quic_connection_close = 0x302,

    pub fn fromHttp3Error(err: Http3Error) ?ErrorCode {
        return switch (err) {
            error.ProtocolError => .general_protocol_error,
            error.InvalidFrame, error.UnexpectedFrameType => .frame_error,
            error.QpackDecompressionFailed => .qpack_decompression_failed,
            error.QpackStreamError => .qpack_encoder_stream_error,
            error.InvalidStreamState, error.UnknownStream => .stream_creation_error,
            error.QuicError => .quic_protocol_error,
            error.GoAwayReceived => .no_error,
            else => null,
        };
    }
};

/// Error set for HTTP/3 operations.
pub const Http3Error = error{
    Unimplemented,
    InvalidFrame,
    ProtocolError,
    QuicError,
    StreamError,
    UnexpectedFrameType,
    NeedMoreData,
    GoAwayReceived,
    MaxConnectionsReached,
    QpackDecompressionFailed,
    QpackStreamError,
    InvalidStreamState,
    UnknownStream,
};
