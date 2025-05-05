const std = @import("std");
const errors = @import("../errors.zig");

const RedisError = errors.RedisError;

pub fn Commands(comptime T: type) type {
    return struct {
        /// Subscribes to channels
        pub fn subscribe(self: *T, channels: [][]const u8) ![][]const u8 {
            if (channels.len == 0) return RedisError.InvalidArgument;

            const cmd_len: usize = 2 + channels.len;
            var cmd_buf = std.ArrayList(u8).init(self.allocator);
            defer cmd_buf.deinit();

            try cmd_buf.writer().print("*{d}\r\n$9\r\nSUBSCRIBE\r\n", .{cmd_len});
            for (channels) |channel| {
                if (channel.len == 0) return RedisError.InvalidArgument;
                try cmd_buf.writer().print("${d}\r\n{s}\r\n", .{ channel.len, channel });
            }

            const cmd = try cmd_buf.toOwnedSlice();
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (response[0] != '*') return RedisError.InvalidResponse;

            var messages = std.ArrayList([]const u8).init(self.allocator);
            errdefer {
                for (messages.items) |item| self.allocator.free(item);
                messages.deinit();
            }

            var current_pos: usize = 0;
            for (channels) |_| {
                if (response[current_pos] != '*') return RedisError.InvalidResponse;
                const len_end = std.mem.indexOf(u8, response[current_pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
                const num_elements = try std.fmt.parseInt(i64, response[current_pos + 1 .. current_pos + 1 + len_end], 10);
                if (num_elements != 3) return RedisError.InvalidResponse;

                current_pos += len_end + 3;

                if (response[current_pos] != '$') return RedisError.InvalidResponse;
                var str_len_end = std.mem.indexOf(u8, response[current_pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
                var str_len = try std.fmt.parseInt(usize, response[current_pos + 1 .. current_pos + 1 + str_len_end], 10);
                current_pos += str_len_end + 3;
                const message_type = response[current_pos .. current_pos + str_len];
                if (!std.mem.eql(u8, message_type, "subscribe")) return RedisError.InvalidResponse;
                current_pos += str_len + 2;

                if (response[current_pos] != '$') return RedisError.InvalidResponse;
                str_len_end = std.mem.indexOf(u8, response[current_pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
                str_len = try std.fmt.parseInt(usize, response[current_pos + 1 .. current_pos + 1 + str_len_end], 10);
                current_pos += str_len_end + 3;
                const channel = response[current_pos .. current_pos + str_len];
                try messages.append(try self.allocator.dupe(u8, channel));
                current_pos += str_len + 2;

                if (response[current_pos] != ':') return RedisError.InvalidResponse;
                str_len_end = std.mem.indexOf(u8, response[current_pos + 1 ..], "\r\n") orelse return RedisError.InvalidResponse;
                current_pos += str_len_end + 3;
            }

            return try messages.toOwnedSlice();
        }

        /// Publishes a message to a channel
        pub fn publish(self: *T, channel: []const u8, message: []const u8) !u64 {
            if (channel.len == 0 or message.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*3\r\n$7\r\nPUBLISH\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ channel.len, channel, message.len, message });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.startsWith(u8, response, ":")) return RedisError.InvalidResponse;
            return try std.fmt.parseInt(u64, response[1 .. response.len - 2], 10);
        }
    };
}
