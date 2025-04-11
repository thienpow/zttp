const std = @import("std");
pub const Server = @import("server.zig").Server;
pub const ThreadPool = @import("pool.zig").ThreadPool;
pub const Request = @import("http/request.zig").Request;
pub const Response = @import("http/response.zig").Response;

/// Initializes a simple zttp Server
pub fn initServer(allocator: std.mem.Allocator, port: u16) Server {
    return Server.init(allocator, port);
}
