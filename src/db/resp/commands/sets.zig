const std = @import("std");
const errors = @import("../errors.zig");

const RedisError = errors.RedisError;

pub fn Commands(comptime T: type) type {
    return struct {
        /// Adds a member to a set
        pub fn sadd(self: *T, key: []const u8, member: []const u8) !u64 {
            if (key.len == 0 or member.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*3\r\n$4\r\nSADD\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, member.len, member });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Removes a member from a set
        pub fn srem(self: *T, key: []const u8, member: []const u8) !u64 {
            if (key.len == 0 or member.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*3\r\n$4\r\nSREM\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ key.len, key, member.len, member });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Gets all members of a set
        pub fn smembers(self: *T, key: []const u8) !?[][]const u8 {
            if (key.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$8\r\nSMEMBERS\r\n${d}\r\n{s}\r\n", .{ key.len, key });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (std.mem.eql(u8, response, "*0")) return null;

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
            return null;
        }
    };
}
