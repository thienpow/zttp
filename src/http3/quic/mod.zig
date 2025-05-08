// src/http3/quic/mod.zig
// Main QUIC module exporting all public components of the QUIC implementation.
//
// This module provides a complete interface for building QUIC-based applications,
// including connection management, stream handling, and packet processing, as
// defined in RFC 9000. It re-exports core types and functions from the connection,
// packet, stream, and event modules, serving as the primary entry point for the
// QUIC library.
//
// Usage example:
//   const quic = @import("quic");
//   var conn = try quic.createConnection(allocator, .{
//       .role = .client,
//       .udp_fd = udp_socket,
//       .remote_address = remote_addr,
//       .event_callback = myCallback,
//       .user_ctx = null,
//   });
//   defer quic.destroyConnection(conn);
//   try quic.startHandshake(conn);
//   var stream = try quic.openStream(conn, false);
//   _ = try quic.sendStreamData(stream, "Hello, QUIC!", true);

const std = @import("std");

// Re-export core QUIC types
pub const Connection = @import("connection.zig").Connection;
pub const ConnectionState = @import("connection.zig").ConnectionState;
pub const ConnectionOptions = @import("connection.zig").ConnectionOptions;
pub const ConnectionRole = @import("connection.zig").ConnectionRole;
pub const Packet = @import("packet.zig").Packet;
pub const PacketType = @import("packet.zig").PacketType;
pub const Frame = @import("packet.zig").Frame;
pub const StreamFrame = @import("packet.zig").StreamFrame;
pub const CryptoFrame = @import("packet.zig").CryptoFrame;
pub const AckFrame = @import("packet.zig").AckFrame;
pub const Stream = @import("stream.zig").Stream;
pub const StreamState = @import("stream.zig").StreamState;
pub const Event = @import("event.zig").Event;
pub const EventCallback = @import("event.zig").EventCallback;

// Re-export library entry points
pub const createConnection = @import("connection.zig").createConnection;
pub const destroyConnection = @import("connection.zig").destroyConnection;
pub const startHandshake = @import("connection.zig").startHandshake;
pub const receivePacket = @import("connection.zig").receivePacket;
pub const processTimeouts = @import("connection.zig").processTimeouts;
pub const getNextTimeout = @import("connection.zig").getNextTimeout;
pub const getNextOutgoingPacket = @import("connection.zig").getNextOutgoingPacket;
pub const closeConnection = @import("connection.zig").closeConnection;
pub const openStream = @import("stream.zig").openStream;
pub const sendStreamData = @import("stream.zig").sendStreamData;
pub const createStream = @import("stream.zig").createStream;
pub const destroyStream = @import("stream.zig").destroyStream;
pub const closeSend = @import("stream.zig").Stream.closeSend;
pub const closeRecv = @import("stream.zig").Stream.closeRecv;
