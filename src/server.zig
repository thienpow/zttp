const std = @import("std");
const logging = @import("logging.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    server: ?std.net.Server,
    port: u16,
    running: bool,
    routes: RouteMap,

    /// Route storage that doesn't use hash map of function pointers
    const RouteMap = struct {
        const Route = struct {
            path: []const u8,
            handler: Handler,
        };

        routes: std.ArrayList(Route),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) RouteMap {
            return RouteMap{
                .routes = std.ArrayList(Route).init(allocator),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *RouteMap) void {
            for (self.routes.items) |route| {
                self.allocator.free(route.path);
            }
            self.routes.deinit();
        }

        pub fn add(self: *RouteMap, path: []const u8, handler: Handler) !void {
            const path_dup = try self.allocator.dupe(u8, path);
            try self.routes.append(Route{
                .path = path_dup,
                .handler = handler,
            });
        }

        pub fn find(self: *RouteMap, path: []const u8) ?Handler {
            for (self.routes.items) |route| {
                if (std.mem.eql(u8, route.path, path)) {
                    return route.handler;
                }
            }
            return null;
        }
    };

    /// Handler function type
    pub const Handler = *const fn (*Request, *Response) void;

    /// HTTP Request structure
    pub const Request = struct {
        method: []const u8,
        path: []const u8,
        headers: std.StringHashMap([]const u8),
        body: ?[]const u8,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) !Request {
            return Request{
                .method = "",
                .path = "",
                .headers = std.StringHashMap([]const u8).init(allocator),
                .body = null,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Request) void {
            var header_it = self.headers.iterator();
            while (header_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            self.headers.deinit();

            if (self.method.len > 0) self.allocator.free(self.method);
            if (self.path.len > 0) self.allocator.free(self.path);
            if (self.body) |body| self.allocator.free(body);
        }
    };

    /// HTTP Response structure
    pub const Response = struct {
        status: u16,
        headers: std.StringHashMap([]const u8),
        body: ?[]const u8,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Response {
            return Response{
                .status = 200,
                .headers = std.StringHashMap([]const u8).init(allocator),
                .body = null,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Response) void {
            var header_it = self.headers.iterator();
            while (header_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            self.headers.deinit();

            if (self.body) |body| self.allocator.free(body);
        }

        pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
            const name_dup = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(name_dup);

            const value_dup = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(value_dup);

            if (self.headers.get(name_dup)) |old_value| {
                self.allocator.free(old_value);
            }

            try self.headers.put(name_dup, value_dup);
        }

        pub fn setBody(self: *Response, body: []const u8) !void {
            if (self.body) |old_body| {
                self.allocator.free(old_body);
            }
            self.body = try self.allocator.dupe(u8, body);
        }

        pub fn writeToStream(self: *Response, stream: std.net.Stream) !void {
            var buffer = std.ArrayList(u8).init(self.allocator);
            defer buffer.deinit();

            // Status line
            try buffer.writer().print("HTTP/1.1 {} OK\r\n", .{self.status});

            // Headers
            var content_type_set = false;
            var content_length_set = false;

            var header_it = self.headers.iterator();
            while (header_it.next()) |entry| {
                try buffer.writer().print("{s}: {s}\r\n", .{
                    entry.key_ptr.*,
                    entry.value_ptr.*,
                });

                if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "Content-Type")) {
                    content_type_set = true;
                } else if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "Content-Length")) {
                    content_length_set = true;
                }
            }

            // Add default headers if not set
            if (!content_type_set) {
                try buffer.writer().writeAll("Content-Type: text/plain\r\n");
            }

            if (!content_length_set and self.body != null) {
                try buffer.writer().print("Content-Length: {d}\r\n", .{self.body.?.len});
            } else if (!content_length_set) {
                try buffer.writer().writeAll("Content-Length: 0\r\n");
            }

            // End of headers
            try buffer.writer().writeAll("\r\n");

            // Body
            if (self.body) |body| {
                try buffer.writer().writeAll(body);
            }

            // Send everything to the stream
            try stream.writer().writeAll(buffer.items);
        }
    };

    /// Parse a raw HTTP request
    fn parseHttpRequest(allocator: std.mem.Allocator, buffer: []const u8) !Request {
        var request = try Request.init(allocator);
        errdefer request.deinit();

        // Split the request into lines
        var lines = std.mem.splitSequence(u8, buffer, "\r\n");

        // Parse request line (first line)
        const request_line = lines.next() orelse return error.InvalidRequest;
        var parts = std.mem.splitScalar(u8, request_line, ' ');

        const method = parts.next() orelse return error.InvalidRequest;
        request.method = try allocator.dupe(u8, method);

        const path = parts.next() orelse return error.InvalidRequest;
        request.path = try allocator.dupe(u8, path);

        // Skip protocol version for simplicity

        // Parse headers
        while (lines.next()) |line| {
            if (line.len == 0) break; // Empty line separates headers from body

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const name = std.mem.trim(u8, line[0..colon_pos], " ");
            const value = std.mem.trim(u8, line[colon_pos + 1 ..], " ");

            const name_dup = try allocator.dupe(u8, name);
            errdefer allocator.free(name_dup);

            const value_dup = try allocator.dupe(u8, value);
            errdefer allocator.free(value_dup);

            try request.headers.put(name_dup, value_dup);
        }

        // Simple body handling (will be incomplete for some requests)
        const body_start = std.mem.indexOf(u8, buffer, "\r\n\r\n");
        if (body_start) |pos| {
            if (pos + 4 < buffer.len) {
                request.body = try allocator.dupe(u8, buffer[pos + 4 ..]);
            }
        }

        return request;
    }

    /// Initialize a new server with the given port
    pub fn init(allocator: std.mem.Allocator, port: u16) Server {
        return Server{
            .allocator = allocator,
            .server = null,
            .port = port,
            .running = false,
            .routes = RouteMap.init(allocator),
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Server) void {
        if (self.server) |*server| {
            server.deinit();
        }
        self.routes.deinit();
    }

    /// Add a route to the server
    pub fn addRoute(self: *Server, path: []const u8, handler: Handler) !void {
        try self.routes.add(path, handler);
    }

    /// Default handler for routes that aren't found
    fn notFoundHandler(_: *Request, res: *Response) void {
        res.status = 404;
        res.setBody("Not Found") catch {};
    }

    /// Find a handler for the given path
    fn findHandler(self: *Server, path: []const u8) Handler {
        return self.routes.find(path) orelse &notFoundHandler;
    }

    /// Start the server
    pub fn start(self: *Server) !void {
        if (self.running) return error.AlreadyRunning;

        // Create address
        const address = try std.net.Address.parseIp("0.0.0.0", self.port);

        // In your version of Zig, the listen function is on Address, not Server
        const server = try address.listen(.{
            .reuse_address = true,
        });

        self.server = server;
        self.running = true;

        std.debug.print("Server listening on 0.0.0.0:{d}\n", .{self.port});

        // Accept and handle connections
        while (self.running) {
            const connection = self.server.?.accept() catch |err| {
                std.debug.print("Error accepting connection: {}\n", .{err});
                continue;
            };

            // Handle the connection
            self.handleConnection(connection) catch |err| {
                std.debug.print("Error handling connection: {}\n", .{err});
                connection.stream.close();
            };
        }
    }

    /// Handle a client connection
    fn handleConnection(self: *Server, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        // Read the request
        var buffer: [4096]u8 = undefined;
        const bytes_read = try connection.stream.read(&buffer);

        if (bytes_read == 0) return; // Client closed connection

        // Parse the request
        var request = parseHttpRequest(self.allocator, buffer[0..bytes_read]) catch |err| {
            std.debug.print("Error parsing request: {}\n", .{err});

            // Send error response
            var response = Response.init(self.allocator);
            defer response.deinit();

            response.status = 400;
            try response.setBody("Bad Request");
            try response.writeToStream(connection.stream);
            return;
        };
        defer request.deinit();

        // Create response object
        var response = Response.init(self.allocator);
        defer response.deinit();

        // Set basic headers
        try response.setHeader("Server", "zttp/0.1.0");
        try response.setHeader("Connection", "close");

        // Find and call the appropriate handler
        const handler = self.findHandler(request.path);
        handler(&request, &response);

        // Send the response
        try response.writeToStream(connection.stream);
    }
};

/// Initialize a server with the given port
pub fn initServer(allocator: std.mem.Allocator, port: u16) Server {
    return Server.init(allocator, port);
}
