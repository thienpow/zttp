// src/db/resp/client.zig
const std = @import("std");

const types = @import("types.zig");
const errors = @import("errors.zig");
pub const buffer_pool = @import("buffer_pool.zig");

pub const RedisError = errors.RedisError;
pub const RedisClientConfig = types.RedisClientConfig;
pub const BufferPool = buffer_pool.BufferPool;

pub const RedisClient = struct {
    allocator: std.mem.Allocator,
    socket: std.net.Stream,
    connected: bool,
    last_used_timestamp: i64,
    config: RedisClientConfig,
    reconnect_attempts: u8 = 0,
    max_reconnect_attempts: u8 = 3,

    const Self = @This();

    /// Establishes a new connection to Redis
    pub fn connect(allocator: std.mem.Allocator, config: RedisClientConfig) RedisError!Self {
        // Initialize buffer pool if not already initialized
        buffer_pool.initGlobalPool(allocator, 16, 4096) catch |err| switch (err) {
            error.AlreadyInitialized => {}, // Ignore if already initialized
            error.OutOfMemory => return RedisError.OutOfMemory,
            else => return RedisError.ConnectionFailed,
        };

        const address = std.net.Address.parseIp(config.host, config.port) catch {
            return RedisError.ConnectionFailed;
        };

        const socket = std.net.tcpConnectToAddress(address) catch |err| {
            return switch (err) {
                error.ConnectionRefused => RedisError.ConnectionRefused,
                error.NetworkUnreachable, error.ConnectionTimedOut => RedisError.NetworkError,
                else => RedisError.ConnectionFailed,
            };
        };

        var client = Self{
            .allocator = allocator,
            .socket = socket,
            .connected = true,
            .last_used_timestamp = std.time.milliTimestamp(),
            .config = config,
        };

        // Verify connection with initial ping
        const ping_response = client.ping() catch |err| {
            client.disconnect();
            return err;
        };
        defer client.allocator.free(ping_response);

        if (!std.mem.eql(u8, ping_response, "PONG")) {
            client.disconnect();
            return RedisError.ConnectionFailed;
        }

        return client;
    }

    /// Disconnects the client and cleans up resources
    pub fn disconnect(self: *Self) void {
        if (!self.connected) return;
        self.socket.close();
        self.connected = false;
        self.last_used_timestamp = 0;
    }

    /// Checks if the client connection is healthy
    pub fn isHealthy(self: *Self) bool {
        if (!self.connected) return false;

        const idle_time = std.time.milliTimestamp() - self.last_used_timestamp;
        if (idle_time > self.config.idle_timeout_ms) return false;

        const ping_response = self.ping() catch {
            return false;
        };
        defer self.allocator.free(ping_response);

        return std.mem.eql(u8, ping_response, "PONG");
    }

    /// Attempts to reconnect to Redis
    pub fn reconnect(self: *Self) RedisError!void {
        if (self.connected) self.disconnect();

        while (self.reconnect_attempts < self.max_reconnect_attempts) : (self.reconnect_attempts += 1) {
            const address = std.net.Address.parseIp(self.config.host, self.config.port) catch {
                continue;
            };

            self.socket = std.net.tcpConnectToAddress(address) catch |err| {
                if (self.reconnect_attempts + 1 == self.max_reconnect_attempts) {
                    return switch (err) {
                        error.ConnectionRefused => RedisError.ConnectionRefused,
                        error.NetworkUnreachable => RedisError.NetworkError,
                        error.OutOfMemory => RedisError.OutOfMemory,
                        else => RedisError.ReconnectFailed,
                    };
                }
                std.time.sleep(std.time.ns_per_s);
                continue;
            };

            self.connected = true;
            self.last_used_timestamp = std.time.milliTimestamp();
            self.reconnect_attempts = 0;
            return;
        }

        self.connected = false;
        return RedisError.ReconnectFailed;
    }

    /// Format a Redis command with proper RESP protocol formatting
    pub fn formatCommand(self: *Self, comptime fmt: []const u8, args: anytype) ![]u8 {
        if (buffer_pool.getGlobalPool()) |bpool| {
            const buf = try bpool.acquire();
            errdefer bpool.release(buf);
            const result = std.fmt.bufPrint(buf, fmt, args) catch {
                bpool.release(buf);
                return RedisError.OutOfMemory;
            };
            const owned = try self.allocator.dupe(u8, result);
            bpool.release(buf);
            return owned;
        } else {
            return std.fmt.allocPrint(self.allocator, fmt, args) catch return RedisError.OutOfMemory;
        }
    }

    /// Send a command to the Redis server
    pub fn sendCommand(self: *Self, cmd: []const u8) !void {
        if (!self.connected) return RedisError.DisconnectedClient;
        self.last_used_timestamp = std.time.milliTimestamp();
        self.socket.writer().writeAll(cmd) catch |err| switch (err) {
            error.ConnectionResetByPeer, error.BrokenPipe => return RedisError.NetworkError,
            error.WouldBlock => return RedisError.WouldBlock,
            error.SystemResources, error.NoSpaceLeft, error.DiskQuota, error.FileTooBig, error.InputOutput, error.DeviceBusy => return RedisError.SystemResources,
            error.NotOpenForWriting, error.AccessDenied => return RedisError.DisconnectedClient,
            else => return RedisError.NetworkError,
        };
    }

    // Import commands and response handling
    pub usingnamespace @import("commands.zig");
    pub usingnamespace @import("response.zig");
};
