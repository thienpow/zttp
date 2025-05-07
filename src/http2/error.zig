// src/http2/error.zig - HTTP/2 error definitions
const std = @import("std");

// HTTP/2 Error Codes (RFC 7540 Section 7)
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,

    // Custom internal error codes can be defined here as needed
    _,

    pub fn toString(self: ErrorCode) []const u8 {
        return switch (self) {
            .no_error => "No Error",
            .protocol_error => "Protocol Error",
            .internal_error => "Internal Error",
            .flow_control_error => "Flow Control Error",
            .settings_timeout => "Settings Timeout",
            .stream_closed => "Stream Closed",
            .frame_size_error => "Frame Size Error",
            .refused_stream => "Refused Stream",
            .cancel => "Cancel",
            .compression_error => "Compression Error",
            .connect_error => "Connect Error",
            .enhance_your_calm => "Enhance Your Calm",
            .inadequate_security => "Inadequate Security",
            .http_1_1_required => "HTTP/1.1 Required",
            _ => "Unknown Error",
        };
    }
};

// HTTP/2 specific errors
pub const Http2Error = error{
    // Protocol errors
    InvalidFrameHeader,
    InvalidPadding,
    InvalidStreamId,
    StreamClosed,
    FrameTooLarge,

    // HPACK errors
    InvalidHuffmanEncoding,
    InvalidHeaderIndex,
    InvalidHeaderName,
    InvalidDynamicTableSize,

    // Settings errors
    InvalidSettingsValue,
    InvalidSettingsPayload,

    // Connection errors
    ConnectionError,
    FlowControlError,
    StreamStateError,

    // Implementation specific errors
    UnsupportedHPACKOperation,
    HuffmanDecodingNotImplemented,
};

// Convert HTTP/2 errors to error codes
pub fn toErrorCode(err: Http2Error) ErrorCode {
    return switch (err) {
        .InvalidFrameHeader, .InvalidPadding, .InvalidStreamId, .InvalidHeaderName => .protocol_error,

        .StreamClosed => .stream_closed,
        .FrameTooLarge => .frame_size_error,

        .InvalidHuffmanEncoding, .InvalidHeaderIndex, .InvalidDynamicTableSize => .compression_error,

        .InvalidSettingsValue, .InvalidSettingsPayload => .protocol_error,

        .ConnectionError => .internal_error,
        .FlowControlError => .flow_control_error,
        .StreamStateError => .protocol_error,

        .UnsupportedHPACKOperation, .HuffmanDecodingNotImplemented => .internal_error,
    };
}
