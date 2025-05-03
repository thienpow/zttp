const std = @import("std");
const types = @import("../types.zig");
const errors = @import("../errors.zig");

const RedisError = errors.RedisError;
const ScanResult = types.ScanResult;

pub fn Commands(comptime T: type) type {
    return struct {
        /// Deletes a key
        pub fn del(self: *T, key: []const u8) !u64 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$3\r\nDEL\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Checks if a key exists in Redis
        pub fn exists(self: *T, key: []const u8) !u64 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$6\r\nEXISTS\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Sets expiration for a key
        pub fn expire(self: *T, key: []const u8, ttl_seconds: i64) !bool {
            if (key.len == 0 or ttl_seconds < 0) return RedisError.InvalidArgument;

            const ttl_str = try std.fmt.allocPrint(self.allocator, "{d}", .{ttl_seconds});
            defer self.allocator.free(ttl_str);

            const cmd = try self.formatCommand("*3\r\n$6\r\nEXPIRE\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, ttl_str.len, ttl_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            const result = try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
            return result == 1;
        }

        /// Sets expiration at a specific timestamp
        pub fn expireat(self: *T, key: []const u8, timestamp_seconds: i64) !bool {
            if (key.len == 0 or timestamp_seconds < 0) return RedisError.InvalidArgument;

            const ts_str = try std.fmt.allocPrint(self.allocator, "{d}", .{timestamp_seconds});
            defer self.allocator.free(ts_str);

            const cmd = try self.formatCommand("*3\r\n$8\r\nEXPIREAT\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, ts_str.len, ts_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            const result = try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
            return result == 1;
        }

        /// Sets expiration for a key in milliseconds
        pub fn pexpire(self: *T, key: []const u8, ttl_milliseconds: i64) !bool {
            if (key.len == 0 or ttl_milliseconds < 0) return RedisError.InvalidArgument;

            const ttl_str = try std.fmt.allocPrint(self.allocator, "{d}", .{ttl_milliseconds});
            defer self.allocator.free(ttl_str);

            const cmd = try self.formatCommand("*3\r\n$8\r\nPEXPIRE\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, ttl_str.len, ttl_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            const result = try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
            return result == 1;
        }

        /// Sets expiration at a specific timestamp in milliseconds
        pub fn pexpireat(self: *T, key: []const u8, timestamp_milliseconds: i64) !bool {
            if (key.len == 0 or timestamp_milliseconds < 0) return RedisError.InvalidArgument;

            const ts_str = try std.fmt.allocPrint(self.allocator, "{d}", .{timestamp_milliseconds});
            defer self.allocator.free(ts_str);

            const cmd = try self.formatCommand("*3\r\n$9\r\nPEXPIREAT\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, ts_str.len, ts_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            const result = try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
            return result == 1;
        }

        /// Removes expiration from a key
        pub fn persist(self: *T, key: []const u8) !bool {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$7\r\nPERSIST\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            const result = try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
            return result == 1;
        }

        /// Gets the type of a key
        pub fn getType(self: *T, key: []const u8) ![]const u8 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$4\r\nTYPE\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, "+")) return RedisError.InvalidResponse;
            return try self.allocator.dupe(u8, response[1 .. response.len - 2]);
        }

        /// Renames a key
        pub fn rename(self: *T, key: []const u8, new_key: []const u8) !void {
            if (key.len == 0 or new_key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*3\r\n$6\r\nRENAME\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, new_key.len, new_key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.eql(u8, response, "+OK\r\n")) return RedisError.CommandFailed;
        }

        /// Gets keys matching a pattern
        pub fn keys(self: *T, pattern: []const u8) !?[][]const u8 {
            if (pattern.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$4\r\nKEYS\r\n${d}\r\n{s}\r\n", .{ pattern.len, pattern });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (std.mem.eql(u8, response, "*0\r\n")) return null;

            if (response[0] == '*') {
                var strings = std.ArrayList([]const u8).init(self.allocator);
                errdefer {
                    for (strings.items) |item| self.allocator.free(item);
                    strings.deinit();
                }

                const len_end = std.mem.indexOf(u8, response[1..], "\r\n") orelse return RedisError.InvalidResponse;
                const num_elements = try std.fmt.parseInt(i64, response[1 .. 1 + len_end], 10);
                if (num_elements <= 0) return null;

                var current_pos: usize = len_end + 3;
                var i: i64 = 0;
                while (i < num_elements) : (i += 1) {
                    if (response[current_pos] != '$') return RedisError.InvalidResponse;
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

        /// Scans keys matching a pattern
        pub fn scan(self: *T, cursor: []const u8, match_pattern: ?[]const u8, count: ?u32) !ScanResult {
            if (cursor.len == 0) return RedisError.InvalidArgument;

            const arg_count = 2 + @as(usize, if (match_pattern != null) 2 else 0) + @as(usize, if (count != null) 2 else 0);
            var cmd: []u8 = undefined;

            if (count) |c| {
                const count_str = try std.fmt.allocPrint(self.allocator, "{d}", .{c});
                defer self.allocator.free(count_str);

                if (match_pattern) |pattern| {
                    cmd = try self.formatCommand("*{d}\r\n$4\r\nSCAN\r\n${d}\r\n{s}\r\n$5\r\nMATCH\r\n${d}\r\n{s}\r\n$5\r\nCOUNT\r\n${d}\r\n{s}\r\n", .{ arg_count, cursor.len, cursor, pattern.len, pattern, count_str.len, count_str });
                } else {
                    cmd = try self.formatCommand("*{d}\r\n$4\r\nSCAN\r\n${d}\r\n{s}\r\n$5\r\nCOUNT\r\n${d}\r\n{s}\r\n", .{ arg_count, cursor.len, cursor, count_str.len, count_str });
                }
            } else if (match_pattern) |pattern| {
                cmd = try self.formatCommand("*{d}\r\n$4\r\nSCAN\r\n${d}\r\n{s}\r\n$5\r\nMATCH\r\n${d}\r\n{s}\r\n", .{ arg_count, cursor.len, cursor, pattern.len, pattern });
            } else {
                cmd = try self.formatCommand("*{d}\r\n$4\r\nSCAN\r\n${d}\r\n{s}\r\n", .{ arg_count, cursor.len, cursor });
            }
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (response.len < 5 or response[0] != '*') return RedisError.InvalidResponse;

            const array_size_end = std.mem.indexOf(u8, response[1..], "\r\n") orelse return RedisError.InvalidResponse;
            const array_size = try std.fmt.parseInt(usize, response[1 .. 1 + array_size_end], 10);
            if (array_size != 2) return RedisError.InvalidResponse;

            var pos = 1 + array_size_end + 2;
            if (pos >= response.len or response[pos] != '$') return RedisError.InvalidResponse;

            const cursor_len_end = std.mem.indexOf(u8, response[pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
            const cursor_len = try std.fmt.parseInt(usize, response[pos + 1 .. pos + 1 + cursor_len_end], 10);
            const new_cursor = try self.allocator.dupe(u8, response[pos + 1 + cursor_len_end + 2 .. pos + 1 + cursor_len_end + 2 + cursor_len]);
            errdefer self.allocator.free(new_cursor);
            pos += 1 + cursor_len_end + 2 + cursor_len;

            if (pos >= response.len or response[pos] != '*') return RedisError.InvalidResponse;
            const keys_count_end = std.mem.indexOf(u8, response[pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
            const keys_count = try std.fmt.parseInt(usize, response[pos + 1 .. pos + 1 + keys_count_end], 10);
            pos += 1 + keys_count_end + 2;

            var keys_list = std.ArrayList([]const u8).init(self.allocator);
            errdefer {
                for (keys_list.items) |key| self.allocator.free(key);
                keys_list.deinit();
            }

            var i: usize = 0;
            while (i < keys_count and pos < response.len) : (i += 1) {
                if (response[pos] != '$') return RedisError.InvalidResponse;
                const key_len_end = std.mem.indexOf(u8, response[pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
                const key_len = try std.fmt.parseInt(usize, response[pos + 1 .. pos + 1 + key_len_end], 10);
                const key = try self.allocator.dupe(u8, response[pos + 1 + key_len_end + 2 .. pos + 1 + key_len_end + 2 + key_len]);
                try keys_list.append(key);
                pos += 1 + key_len_end + 2 + key_len;
            }
            if (i != keys_count) return RedisError.InvalidResponse;

            return ScanResult{
                .cursor = new_cursor,
                .keys = try keys_list.toOwnedSlice(),
            };
        }

        /// Moves a key to another database
        pub fn move(self: *T, key: []const u8, db: u32) !bool {
            if (key.len == 0) return RedisError.InvalidArgument;

            const db_str = try std.fmt.allocPrint(self.allocator, "{d}", .{db});
            defer self.allocator.free(db_str);

            const cmd = try self.formatCommand("*3\r\n$4\r\nMOVE\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, db_str.len, db_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            const result = try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
            return result == 1;
        }
    };
}
