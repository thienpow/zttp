const std = @import("std");
const Allocator = std.mem.Allocator;

// Import HTTP types
const http = @import("../http/mod.zig");
const Request = http.Request;
const Response = http.Response;

// HTTP/2 Stream States
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    reserved_local,
    reserved_remote,
    closed,
};

// Priority information for HTTP/2 streams
pub const Priority = struct {
    exclusive: bool,
    dependency_stream_id: u31,
    weight: u8,
};

// HTTP/2 Stream
pub const Stream = struct {
    id: u31,
    state: StreamState,
    request: ?*Request,
    response: ?*Response,
    window_size: i32,
    priority: ?Priority,

    pub fn init(allocator: Allocator, id: u31) !*Stream {
        const stream = try allocator.create(Stream);
        stream.* = .{
            .id = id,
            .state = .idle,
            .request = null,
            .response = null,
            .window_size = 65535,
            .priority = null,
        };
        return stream;
    }

    pub fn deinit(self: *Stream, allocator: Allocator) void {
        if (self.request) |req| {
            req.deinit();
            allocator.destroy(req);
        }
        if (self.response) |res| {
            res.deinit();
            allocator.destroy(res);
        }
        allocator.destroy(self);
    }

    pub fn setRequest(self: *Stream, request: *Request) void {
        self.request = request;
    }

    pub fn setResponse(self: *Stream, response: *Response) void {
        self.response = response;
    }

    pub fn updateState(self: *Stream, new_state: StreamState) void {
        self.state = new_state;
    }

    pub fn updateWindowSize(self: *Stream, increment: i32) void {
        self.window_size += increment;
    }
};

// Stream collection to manage multiple streams
pub const StreamCollection = struct {
    streams: std.AutoHashMap(u31, *Stream),
    next_stream_id: u31,
    allocator: Allocator,

    pub fn init(allocator: Allocator) StreamCollection {
        return .{
            .streams = std.AutoHashMap(u31, *Stream).init(allocator),
            .next_stream_id = 1, // Client uses odd IDs
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StreamCollection) void {
        var it = self.streams.valueIterator();
        while (it.next()) |stream| {
            stream.*.deinit(self.allocator);
        }
        self.streams.deinit();
    }

    pub fn createStream(self: *StreamCollection) !*Stream {
        const id = self.next_stream_id;
        self.next_stream_id += 2; // Increment by 2 to maintain odd IDs for client-initiated streams

        const stream = try Stream.init(self.allocator, id);
        try self.streams.put(id, stream);
        return stream;
    }

    pub fn getStream(self: *StreamCollection, id: u31) ?*Stream {
        return self.streams.get(id);
    }

    pub fn removeStream(self: *StreamCollection, id: u31) void {
        if (self.streams.fetchRemove(id)) |kv| {
            kv.value.deinit(self.allocator);
        }
    }
};
