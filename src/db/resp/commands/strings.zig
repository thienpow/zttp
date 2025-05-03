const std = @import("std");
const errors = @import("../errors.zig");

const RedisError = errors.RedisError;

pub fn Commands(comptime T: type) type {
    return struct {
        /// Sets a key-value pair
        pub fn set(self: *T, key: []const u8, value: []const u8) !void {
            if (key.len == 0 or value.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*3\r\n$3\r\nSET\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, value.len, value });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.eql(u8, response, "+OK\r\n")) return RedisError.SetFailed;
        }

        /// Sets a key-value pair with expiration
        pub fn setex(self: *T, key: []const u8, value: []const u8, ttl_seconds: i64) !void {
            if (key.len == 0 or value.len == 0 or ttl_seconds <= 0) return RedisError.InvalidArgument;

            const ttl_str = try std.fmt.allocPrint(self.allocator, "{d}", .{ttl_seconds});
            defer self.allocator.free(ttl_str);

            const cmd = try self.formatCommand("*4\r\n$5\r\nSETEX\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, ttl_str.len, ttl_str, value.len, value });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.eql(u8, response, "+OK\r\n")) return RedisError.SetFailed;
        }

        /// Gets a value by key
        pub fn get(self: *T, key: []const u8) !?[]const u8 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$3\r\nGET\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (response[0] == '$') {
                if (std.mem.eql(u8, response[0..4], "$-1\r")) return null;

                const len_end = std.mem.indexOf(u8, response, "\r\n") orelse return RedisError.InvalidResponse;
                const len = try std.fmt.parseInt(usize, response[1..len_end], 10);
                const value_start = len_end + 2;
                const value_end = value_start + len;

                if (value_end > response.len - 2) return RedisError.InvalidResponse;
                return try self.allocator.dupe(u8, response[value_start..value_end]);
            }
            return RedisError.InvalidResponse;
        }

        /// Gets multiple values by keys
        pub fn mget(self: *T, keys_list: [][]const u8) !?[][]const u8 {
            if (keys_list.len == 0) return RedisError.InvalidArgument;

            const cmd_len: usize = 2 + keys_list.len;
            var cmd_buf = std.ArrayList(u8).init(self.allocator);
            defer cmd_buf.deinit();

            try cmd_buf.writer().print("*{d}\r\n$4\r\nMGET\r\n", .{cmd_len});
            for (keys_list) |key| {
                if (key.len == 0) return RedisError.InvalidArgument;
                try cmd_buf.writer().print("${d}\r\n{s}\r\n", .{ key.len, key });
            }

            const cmd = try cmd_buf.toOwnedSlice();
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (response[0] == '*') {
                var strings = std.ArrayList([]const u8).init(self.allocator);
                errdefer {
                    for (strings.items) |item| self.allocator.free(item);
                    strings.deinit();
                }

                const len_end = std.mem.indexOf(u8, response[1..], "\r\n") orelse return RedisError.InvalidResponse;
                const num_elements = try std.fmt.parseInt(i64, response[1 .. 1 + len_end], 10);
                if (num_elements != keys_list.len) return RedisError.InvalidResponse;

                var current_pos: usize = len_end + 3;
                var i: i64 = 0;
                while (i < num_elements) : (i += 1) {
                    if (response[current_pos] != '$') return RedisError.InvalidResponse;
                    if (std.mem.startsWith(u8, response[current_pos..], "$-1\r\n")) {
                        try strings.append(try self.allocator.dupe(u8, ""));
                        current_pos += 5;
                        continue;
                    }
                    const str_len_end = std.mem.indexOf(u8, response[current_pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
                    const str_len = try std.fmt.parseInt(usize, response[current_pos + 1 .. current_pos + 1 + str_len_end], 10);
                    current_pos += str_len_end + 3;
                    const string = response[current_pos .. current_pos + str_len];
                    try strings.append(try self.allocator.dupe(u8, string));
                    current_pos += str_len + 2;
                }
                return try strings.toOwnedSlice();
            }
            return RedisError.InvalidResponse;
        }

        /// Sets multiple key-value pairs
        pub fn mset(self: *T, pairs: []const struct { key: []const u8, value: []const u8 }) !void {
            if (pairs.len == 0) return RedisError.InvalidArgument;

            const cmd_len: usize = 2 + 2 * pairs.len;
            var cmd_buf = std.ArrayList(u8).init(self.allocator);
            defer cmd_buf.deinit();

            try cmd_buf.writer().print("*{d}\r\n$4\r\nMSET\r\n", .{cmd_len});
            for (pairs) |pair| {
                if (pair.key.len == 0 or pair.value.len == 0) return RedisError.InvalidArgument;
                try cmd_buf.writer().print("${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ pair.key.len, pair.key, pair.value.len, pair.value });
            }

            const cmd = try cmd_buf.toOwnedSlice();
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.eql(u8, response, "+OK\r\n")) return RedisError.SetFailed;
        }

        /// Increments a key by 1
        pub fn incr(self: *T, key: []const u8) !u64 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$4\r\nINCR\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Increments a key by a specified amount
        pub fn incrby(self: *T, key: []const u8, increment: i64) !u64 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const incr_str = try std.fmt.allocPrint(self.allocator, "{d}", .{increment});
            defer self.allocator.free(incr_str);

            const cmd = try self.formatCommand("*3\r\n$6\r\nINCRBY\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, incr_str.len, incr_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Decrements a key by 1
        pub fn decr(self: *T, key: []const u8) !u64 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$4\r\nDECR\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Decrements a key by a specified amount
        pub fn decrby(self: *T, key: []const u8, decrement: i64) !u64 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const decr_str = try std.fmt.allocPrint(self.allocator, "{d}", .{decrement});
            defer self.allocator.free(decr_str);

            const cmd = try self.formatCommand("*3\r\n$6\r\nDECRBY\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, decr_str.len, decr_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }
    };
}
