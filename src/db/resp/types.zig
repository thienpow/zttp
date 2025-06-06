const std = @import("std");

pub const REDIS_PROTOCOL = struct {
    pub const CRLF = "\r\n";
    pub const SIMPLE_STRING = '+';
    pub const ERROR = '-';
    pub const INTEGER = ':';
    pub const BULK_STRING = '$';
    pub const ARRAY = '*';
};

pub const RedisClientConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 6379,
    min_connections: usize = 3,
    max_connections: usize = 50,
    timeout_ms: u64 = 5000,
    idle_timeout_ms: i64 = 30000,
    read_timeout_ms: i64 = 5000,
    password: ?[]const u8 = null,
    database: ?u32 = null,
    max_pipeline_commands: usize = 1000,
    cleanup_interval_ms: i64 = 60000,
};

pub const ResponseType = enum {
    SimpleString,
    Error,
    Integer,
    BulkString,
    Array,
};

pub const ScanResult = struct {
    cursor: []const u8,
    keys: [][]const u8,

    pub fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        allocator.free(self.cursor);
        for (self.keys) |key| allocator.free(key);
        allocator.free(self.keys);
    }
};
