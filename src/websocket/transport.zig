// src/websocket/transport.zig
const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const AsyncIo = @import("../async/async.zig").AsyncIo;
const AsyncContext = @import("../async/async.zig").AsyncContext;

const log = std.log.scoped(.websocket_transport);

/// Low-level transport for WebSocket communication.
/// Handles async I/O operations over a socket.
pub const WebSocketTransport = struct {
    fd: posix.fd_t,
    allocator: Allocator,
    async_io: *AsyncIo,

    /// Initializes a WebSocketTransport over the given socket.
    pub fn init(socket: posix.fd_t, allocator: Allocator, async_io: *AsyncIo) !*WebSocketTransport {
        const transport = try allocator.create(WebSocketTransport);
        errdefer allocator.destroy(transport);
        transport.* = .{
            .fd = socket,
            .allocator = allocator,
            .async_io = async_io,
        };
        return transport;
    }

    /// Deinitializes the transport, freeing resources.
    pub fn deinit(self: *WebSocketTransport) void {
        self.allocator.destroy(self);
    }

    /// Schedules an async read into the buffer.
    pub fn readAsync(self: *WebSocketTransport, buffer: []u8, ctx: AsyncContext) !void {
        if (self.fd <= 0) {
            log.err("Invalid socket FD: {d}", .{self.fd});
            return error.InvalidSocket;
        }
        _ = try self.async_io.recv(self.fd, buffer, ctx);
    }

    /// Schedules an async write of the buffer.
    pub fn writeAsync(self: *WebSocketTransport, buffer: []const u8, ctx: AsyncContext) !void {
        if (self.fd <= 0) {
            log.err("Invalid socket FD: {d}", .{self.fd});
            return error.InvalidSocket;
        }
        _ = try self.async_io.write(self.fd, buffer, ctx);
    }

    /// Closes the socket asynchronously.
    pub fn close(self: *WebSocketTransport, ctx: AsyncContext) void {
        if (self.fd > 0) {
            _ = self.async_io.close(self.fd, ctx) catch |err| {
                log.err("Failed to submit async close for FD: {d}: {any}", .{ self.fd, err });
            };
        }
    }
};
