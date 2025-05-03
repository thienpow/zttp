const std = @import("std");
const types = @import("types.zig");
const errors = @import("errors.zig");

const RedisError = errors.RedisError;
const ResponseType = types.ResponseType;

pub fn ResponseHandling(comptime T: type) type {
    return struct {
        /// Execute a Redis command and return the raw response
        pub fn executeCommand(self: *T, cmd: []const u8) RedisError![]const u8 {
            if (!self.connected) try self.reconnect();

            const start_time = std.time.milliTimestamp();
            var retry_count: u8 = 0;
            const max_retries: u8 = 3;

            while (retry_count < max_retries) : (retry_count += 1) {
                const elapsed = std.time.milliTimestamp() - start_time;
                if (elapsed > self.config.read_timeout_ms) return RedisError.Timeout;

                try self.sendCommand(cmd);
                var buffer = std.ArrayList(u8).initCapacity(self.allocator, 1024) catch return RedisError.OutOfMemory;
                errdefer buffer.deinit();

                const response_type = try self.readResponseType(&buffer, self.socket.reader());
                try self.parseResponse(&buffer, self.socket.reader(), response_type);

                const response = try buffer.toOwnedSlice();
                // Special handling for TTL command to handle intermittent issues
                if (cmd.len >= 7 and std.mem.startsWith(u8, cmd, "*2\r\n$3\r\nTTL\r\n") and response.len > 0 and response[0] != ':') {
                    self.allocator.free(response);
                    try self.reconnect();
                    continue;
                }
                return response;
            }
            return RedisError.CommandFailed;
        }

        fn readResponseType(_: *T, buffer: *std.ArrayList(u8), reader: anytype) RedisError!ResponseType {
            const first_byte = reader.readByte() catch |err| switch (err) {
                error.WouldBlock => return RedisError.WouldBlock,
                error.ConnectionTimedOut => return RedisError.Timeout,
                error.ConnectionResetByPeer, error.BrokenPipe => return RedisError.NetworkError,
                error.InputOutput, error.SystemResources => return RedisError.SystemResources,
                error.EndOfStream => return RedisError.EndOfStream,
                error.SocketNotConnected => return RedisError.SocketNotConnected,
                else => return RedisError.InvalidResponse,
            };
            try buffer.append(first_byte);

            return switch (first_byte) {
                '+' => .SimpleString,
                '-' => .Error,
                ':' => .Integer,
                '$' => .BulkString,
                '*' => .Array,
                else => return RedisError.InvalidResponse,
            };
        }

        fn parseResponse(self: *T, buffer: *std.ArrayList(u8), reader: anytype, response_type: ResponseType) RedisError!void {
            switch (response_type) {
                .SimpleString, .Error, .Integer => try self.readLine(buffer, reader),
                .BulkString => try self.readBulkString(buffer, reader),
                .Array => try self.readArray(buffer, reader),
            }
        }

        fn readLine(self: *T, buffer: *std.ArrayList(u8), reader: anytype) RedisError!void {
            const start_time = std.time.milliTimestamp();
            while (true) {
                if (std.time.milliTimestamp() - start_time > self.config.read_timeout_ms) {
                    return RedisError.Timeout;
                }
                const byte = reader.readByte() catch |err| switch (err) {
                    error.WouldBlock => return RedisError.WouldBlock,
                    error.ConnectionTimedOut => return RedisError.Timeout,
                    error.ConnectionResetByPeer, error.BrokenPipe => return RedisError.NetworkError,
                    error.InputOutput, error.SystemResources => return RedisError.SystemResources,
                    error.EndOfStream => return RedisError.EndOfStream,
                    error.SocketNotConnected => return RedisError.SocketNotConnected,
                    else => return RedisError.InvalidResponse,
                };
                try buffer.append(byte);
                if (byte == '\n' and buffer.items.len >= 2 and buffer.items[buffer.items.len - 2] == '\r') {
                    break;
                }
            }
        }

        fn readBulkString(self: *T, buffer: *std.ArrayList(u8), reader: anytype) !void {
            try self.readLine(buffer, reader);

            const dollar_pos = std.mem.lastIndexOfScalar(u8, buffer.items, '$') orelse return RedisError.InvalidResponse;
            const line = buffer.items[dollar_pos + 1 ..];
            const len_end = std.mem.indexOf(u8, line, "\r") orelse return RedisError.InvalidResponse;

            const length = std.fmt.parseInt(i64, line[0..len_end], 10) catch |err| switch (err) {
                error.InvalidCharacter => return RedisError.InvalidFormat,
                error.Overflow => return RedisError.Overflow,
            };
            if (length == -1) return;
            if (length < 0) return RedisError.InvalidResponse;
            if (length > std.math.maxInt(usize)) return RedisError.Overflow;

            const length_usize: usize = @intCast(length);
            const total_len: usize = length_usize + 2;
            const data = try self.allocator.alloc(u8, total_len);
            defer self.allocator.free(data);

            const bytes_read = reader.readAll(data) catch |err| switch (err) {
                error.WouldBlock => return RedisError.WouldBlock,
                error.ConnectionTimedOut => return RedisError.Timeout,
                error.ConnectionResetByPeer, error.BrokenPipe => return RedisError.NetworkError,
                error.InputOutput, error.SystemResources, error.AccessDenied, error.LockViolation => return RedisError.SystemResources,
                error.SocketNotConnected => return RedisError.SocketNotConnected,
                error.NotOpenForReading => return RedisError.DisconnectedClient,
                else => return RedisError.NetworkError,
            };
            if (bytes_read != total_len) return RedisError.InvalidResponse;
            if (data[length_usize] != '\r' or data[length_usize + 1] != '\n') return RedisError.InvalidResponse;

            try buffer.appendSlice(data);
        }

        fn readArray(self: *T, buffer: *std.ArrayList(u8), reader: anytype) RedisError!void {
            try self.readLine(buffer, reader);

            const line = buffer.items[1..];
            const len_end = std.mem.indexOf(u8, line, "\r") orelse return RedisError.InvalidResponse;
            const num_elements = std.fmt.parseInt(i64, line[0..len_end], 10) catch |err| switch (err) {
                error.InvalidCharacter => return RedisError.InvalidFormat,
                error.Overflow => return RedisError.Overflow,
            };

            if (num_elements == -1) return;

            var i: i64 = 0;
            while (i < num_elements) : (i += 1) {
                const element_type = try self.readResponseType(buffer, reader);
                try self.parseResponse(buffer, reader, element_type);
            }
        }
    };
}
