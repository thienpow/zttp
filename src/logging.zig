const std = @import("std");

pub fn log(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("[zttp] " ++ fmt ++ "\n", args);
}
