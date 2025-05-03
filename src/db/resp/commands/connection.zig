const std = @import("std");
const types = @import("../types.zig");
const errors = @import("../errors.zig");

const RedisError = errors.RedisError;

pub fn Commands(comptime T: type) type {
    return struct {
        /// Authenticates with the Redis server
        pub fn auth(self: *T, password: []const u8) RedisError!void {
            if (password.len == 0) return RedisError.InvalidArgument;

            const cmd = try self.formatCommand("*2\r\n$4\r\nAUTH\r\n${d}\r\n{s}\r\n", .{ password.len, password });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (response.len == 0 or response[0] != '+') {
                return RedisError.AuthenticationFailed;
            }
        }

        /// Selects a Redis database
        pub fn select(self: *T, db: u32) RedisError!void {
            const db_str = try std.fmt.allocPrint(self.allocator, "{d}", .{db});
            defer self.allocator.free(db_str);

            const cmd = try self.formatCommand("*2\r\n$6\r\nSELECT\r\n${d}\r\n{s}\r\n", .{ db_str.len, db_str });
            defer self.allocator.free(cmd);

            const response = try self.executeCommand(cmd);
            defer self.allocator.free(response);

            if (!std.mem.eql(u8, response, "+OK\r\n")) return RedisError.CommandFailed;
        }

        /// Sends a PING command and returns the response
        pub fn ping(self: *T) ![]const u8 {
            const cmd = "PING\r\n";
            const response = try self.executeCommand(cmd);
            if (!std.mem.startsWith(u8, response, "+")) {
                self.allocator.free(response);
                return RedisError.InvalidResponse;
            }
            const result = try self.allocator.dupe(u8, response[1 .. response.len - 2]);
            self.allocator.free(response);
            return result;
        }
    };
}
