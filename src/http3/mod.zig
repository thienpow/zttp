// src/http3/mod.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

const Server = @import("../core/server.zig").Server;
const Router = @import("../core/router.zig").Router;
const AsyncIo = @import("../async/async.zig").AsyncIo;

// Re-export public HTTP/3 types and functions
pub const ErrorCode = @import("error.zig").ErrorCode;
pub const Http3Error = @import("error.zig").Http3Error;
pub const Settings = @import("settings.zig").Settings;
pub const FrameType = @import("types.zig").FrameType;
pub const StreamType = @import("types.zig").StreamType;
pub const Frame = @import("types.zig").Frame;
pub const Http3Connection = @import("connection.zig").Http3Connection;
pub const Http3Stream = @import("stream.zig").Http3Stream;
pub const readFrame = @import("frame.zig").readFrame;
pub const writeFrame = @import("frame.zig").writeFrame;
pub const QpackEncoder = @import("qpack/encoder.zig").QpackEncoder;
pub const QpackDecoder = @import("qpack/decoder.zig").QpackDecoder;
pub const Http3Handler = @import("handler.zig").Http3Handler;

/// Initializes the HTTP/3 subsystem for a server.
pub fn initHttp3(server: *Server, allocator: Allocator, router: *Router, async_io: *AsyncIo, udp_fd: std.posix.fd_t) !*Http3Handler {
    const handler = try Http3Handler.init(server, allocator, router);
    server.http3_handler = handler;
    try server.addUdpListener(udp_fd, async_io, handleUdpData, allocator);
    return handler;
}

/// Handles incoming UDP data for HTTP/3, creating or routing to Http3Connection.
fn handleUdpData(server: *Server, data: []const u8, addr: std.net.Address, allocator: Allocator) !void {
    const conn = try server.getOrCreateHttp3Connection(addr, allocator);
    try conn.handleUdpData(data);
}
