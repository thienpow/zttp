// app_context.zig
const std = @import("std");
const zttp = @import("zttp");
pub const redis = zttp.db.resp;

const redis_config = redis.RedisClientConfig{
    .host = "127.0.0.1",
    .port = 6379,
    .max_connections = 6,
    .timeout_ms = 2000, // Timeout for acquiring a connection
    .idle_timeout_ms = 60000, // Disconnect idle connections after 60s
    .read_timeout_ms = 2000, // Timeout for reading a response
    // .password = "yourpassword", // Uncomment and set if needed
    // .database = 0, // Uncomment and set if needed
};

pub const AppContext = struct {
    allocator: std.mem.Allocator,
    redis_pool: redis.PooledRedisClient,
    // Add other global resources here (e.g., database connection pool, config)

    pub fn init(allocator: std.mem.Allocator) !*AppContext {
        const self = try allocator.create(AppContext);
        self.* = .{
            .allocator = allocator,
            .redis_pool = try redis.PooledRedisClient.init(allocator, redis_config),
            // TODO: Initialize other resources
        };
        return self;
    }

    pub fn deinit(self: *AppContext) void {
        self.redis_pool.deinit();
        // TODO: Deinitialize other resources
        self.allocator.destroy(self);
    }
};
