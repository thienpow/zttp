// src/quic/event.zig
// QUIC event definitions

const std = @import("std");
const Connection = @import("connection.zig").Connection;

/// Event types for QUIC connections
pub const Event = union(enum) {
    /// TLS handshake has completed successfully
    handshake_completed: void,

    /// A new stream has been opened by the peer
    new_stream: struct {
        stream_id: u64,
        is_unidirectional: bool,
    },

    /// Data has been received on a stream
    stream_data: struct {
        stream_id: u64,
        data: []const u8,
        is_fin: bool,
    },

    /// A stream has been closed by the peer
    stream_closed: struct {
        stream_id: u64,
        error_code: u64,
    },

    /// Connection state has changed
    connection_state_change: @import("connection.zig").ConnectionState,

    /// Connection has been closed
    connection_closed: struct {
        error_code: u64,
        reason: []const u8,
    },

    /// Datagram has been received
    datagram_received: []const u8,

    /// Path challenge received
    path_challenge: []const u8,

    /// Path response received
    path_response: []const u8,

    /// Connection migration completed
    migration_completed: void,

    /// Connection migration failed
    migration_failed: void,

    /// Key update completed
    key_update_completed: void,

    /// Packet with unknown connection ID received
    unknown_connection_id: []const u8,

    /// Stateless reset received
    stateless_reset: void,

    /// Version negotiation received
    version_negotiation: []const u32,

    /// Transport parameters received
    transport_parameters: void,
};

/// Callback function type for QUIC events
pub const EventCallback = *const fn (conn: *Connection, event: Event, user_ctx: ?*anyopaque) void;
