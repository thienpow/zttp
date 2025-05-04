const buffer_pool_mod = @import("buffer_pool.zig");
const client_mod = @import("client.zig");
const errors_mod = @import("errors.zig");
const pipeline_mod = @import("pipeline.zig");
const pool_mod = @import("pool.zig");
const types_mod = @import("types.zig");

// Re-export the main types and errors
pub const RedisError = errors_mod.RedisError;
pub const RedisClientConfig = types_mod.RedisClientConfig;
pub const RedisClient = client_mod.RedisClient;
pub const PooledRedisClient = pool_mod.PooledRedisClient;
pub const RedisPipeline = pipeline_mod.RedisPipeline;
pub const ScanResult = types_mod.ScanResult;

// Re-export the buffer pool type and global functions
pub const BufferPool = buffer_pool_mod.BufferPool;
pub const initGlobalPool = buffer_pool_mod.initGlobalPool;
pub const deinitGlobalPool = buffer_pool_mod.deinitGlobalPool;
pub const getGlobalPool = buffer_pool_mod.getGlobalPool;
