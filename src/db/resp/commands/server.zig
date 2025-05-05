const std = @import("std");
const errors = @import("../errors.zig");

const RedisError = errors.RedisError;

pub fn Commands(comptime T: type) type {
    return struct {
        /// Flushes the current database
        pub fn flushdb(self: *T) !void {
            const cmd = try self.formatCommand("*1\r\n$7\r\nFLUSHDB\r\n", .{});
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.eql(u8, response, "+OK\r\n")) return RedisError.CommandFailed;
        }

        /// Flushes all databases
        pub fn flushall(self: *T) !void {
            const cmd = try self.formatCommand("*1\r\n$8\r\nFLUSHALL\r\n", .{});
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.eql(u8, response, "+OK\r\n")) return RedisError.CommandFailed;
        }

        /// Gets the number of keys in the current database
        pub fn dbsize(self: *T) !u64 {
            const cmd = try self.formatCommand("*1\r\n$6\r\nDBSIZE\r\n", .{});
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }

        /// Gets server information
        pub fn info(self: *T, section: ?[]const u8) ![]const u8 {
            const cmd = if (section) |sec| try self.formatCommand("*2\r\n$4\r\nINFO\r\n${d}\r\n{s}\r\n", .{ sec.len, sec }) else try self.formatCommand("*1\r\n$4\r\nINFO\r\n", .{});
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (response[0] != '$') return RedisError.InvalidResponse;
            const len_end = std.mem.indexOf(u8, response, "\r\n") orelse return RedisError.InvalidResponse;
            const len = try std.fmt.parseInt(usize, response[1..len_end], 10);
            const value_start = len_end + 2;
            const value_end = value_start + len;

            if (value_end > response.len - 2) return RedisError.InvalidResponse;
            return try self.allocator.dupe(u8, response[value_start..value_end]);
        }

        /// Executes a CONFIG command
        pub fn config(self: *T, command: []const u8, parameters: [][]const u8) ![]const u8 {
            if (command.len == 0) return RedisError.InvalidArgument;

            const cmd_len: usize = 2 + parameters.len;
            var cmd_buf = std.ArrayList(u8).init(self.allocator);
            defer cmd_buf.deinit();

            try cmd_buf.writer().print("*{d}\r\n$6\r\nCONFIG\r\n${d}\r\n{s}\r\n", .{ cmd_len, command.len, command });
            for (parameters) |param| {
                if (param.len == 0) return RedisError.InvalidArgument;
                try cmd_buf.writer().print("${d}\r\n{s}\r\n", .{ param.len, param });
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
                if (num_elements <= 0) return try self.allocator.dupe(u8, "");

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
                const result = try std.mem.join(self.allocator, " ", strings.items);
                for (strings.items) |item| self.allocator.free(item);
                strings.deinit();
                return result;
            } else if (response[0] == '+') {
                return try self.allocator.dupe(u8, response[1 .. response.len - 2]);
            } else if (response[0] == '$') {
                const len_end = std.mem.indexOf(u8, response, "\r\n") orelse return RedisError.InvalidResponse;
                const len = try std.fmt.parseInt(usize, response[1..len_end], 10);
                const value_start = len_end + 2;
                const value_end = value_start + len;

                if (value_end > response.len - 2) return RedisError.InvalidResponse;
                return try self.allocator.dupe(u8, response[value_start..value_end]);
            }
            return RedisError.InvalidResponse;
        }
    };
}
