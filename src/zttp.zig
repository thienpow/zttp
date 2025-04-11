const std = @import("std");
pub const Server = @import("server.zig").Server;
pub const ThreadPool = @import("pool.zig").ThreadPool;

/// Initializes a simple zttp Server
pub fn initServer(allocator: std.mem.Allocator, port: u16) Server {
    return Server.init(allocator, port);
}
