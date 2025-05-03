const std = @import("std");

const connection = @import("commands/connection.zig");
const keysz = @import("commands/keys.zig");
const strings = @import("commands/strings.zig");
const sets = @import("commands/sets.zig");
const hashes = @import("commands/hashes.zig");
const lists = @import("commands/lists.zig");
const sorted_sets = @import("commands/sorted_sets.zig");
const pubsub = @import("commands/pubsub.zig");
const server = @import("commands/server.zig");

pub fn Commands(comptime T: type) type {
    return struct {
        const Connection = connection.Commands(T);
        const Keys = keysz.Commands(T);
        const Strings = strings.Commands(T);
        const Sets = sets.Commands(T);
        const Hashes = hashes.Commands(T);
        const Lists = lists.Commands(T);
        const SortedSets = sorted_sets.Commands(T);
        const PubSub = pubsub.Commands(T);
        const Server = server.Commands(T);

        // Connection commands
        pub const auth = Connection.auth;
        pub const select = Connection.select;
        pub const ping = Connection.ping;

        // Key commands
        pub const del = Keys.del;
        pub const exists = Keys.exists;
        pub const expire = Keys.expire;
        pub const expireat = Keys.expireat;
        pub const pexpire = Keys.pexpire;
        pub const pexpireat = Keys.pexpireat;
        pub const persist = Keys.persist;
        pub const getType = Keys.getType;
        pub const rename = Keys.rename;
        pub const keys = Keys.keys;
        pub const scan = Keys.scan;
        pub const move = Keys.move;

        // String commands
        pub const set = Strings.set;
        pub const setex = Strings.setex;
        pub const get = Strings.get;
        pub const mget = Strings.mget;
        pub const mset = Strings.mset;
        pub const incr = Strings.incr;
        pub const incrby = Strings.incrby;
        pub const decr = Strings.decr;
        pub const decrby = Strings.decrby;

        // Set commands
        pub const sadd = Sets.sadd;
        pub const srem = Sets.srem;
        pub const smembers = Sets.smembers;

        // Hash commands
        pub const hset = Hashes.hset;
        pub const hget = Hashes.hget;
        pub const hdel = Hashes.hdel;
        pub const hgetall = Hashes.hgetall;

        // List commands
        pub const lpush = Lists.lpush;
        pub const lpop = Lists.lpop;
        pub const rpush = Lists.rpush;
        pub const rpop = Lists.rpop;
        pub const lrange = Lists.lrange;

        // Sorted set commands
        pub const zadd = SortedSets.zadd;
        pub const zrange = SortedSets.zrange;
        pub const zrem = SortedSets.zrem;

        // Pub/sub commands
        pub const subscribe = PubSub.subscribe;
        pub const publish = PubSub.publish;

        // Server commands
        pub const flushdb = Server.flushdb;
        pub const flushall = Server.flushall;
        pub const dbsize = Server.dbsize;
        pub const info = Server.info;
        pub const config = Server.config;
    };
}
