const std = @import("std");

test {
    std.testing.refAllDecls(@import("pool.zig"));
}
