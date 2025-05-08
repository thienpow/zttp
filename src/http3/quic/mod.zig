// src/http3/quic/mod.zig
// Main QUIC module that exports all components

const std = @import("std");

// Re-export core QUIC types and functionality
pub const Connection = @import("connection.zig").Connection;
pub const ConnectionState = @import("connection.zig").ConnectionState;
pub const ConnectionOptions = @import("connection.zig").ConnectionOptions;
pub const Event = @import("event.zig").Event;
pub const EventCallback = @import("event.zig").EventCallback;
pub const Packet = @import("packet.zig").Packet;

// Library entry points
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
