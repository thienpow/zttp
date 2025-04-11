const std = @import("std");

test {
    //std.testing.refAllDecls(@import("pool.zig"));
    //std.testing.refAllDecls(@import("heavy.zig"));
    std.testing.refAllDecls(@import("crash.zig"));
}
