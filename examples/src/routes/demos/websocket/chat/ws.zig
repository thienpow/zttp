const std = @import("std");
const zttp = @import("zttp");

const Allocator = std.mem.Allocator;

/// Client represents a connected WebSocket client
const Client = struct {
    wsk: *zttp.WebSocket,
    id: u64, // Unique identifier for the client
    username: []const u8, // User-provided username
};

/// Thread-safe map to store all connected clients
const ServerState = struct {
    clients: std.AutoHashMap(u64, Client),
    mutex: std.Thread.Mutex,
    allocator: Allocator,
    initialized: bool,

    // Singleton instance for global access
    var instance: ServerState = undefined;

    /// Initialize the global singleton instance
    pub fn init(allocator: Allocator) !void {
        instance = .{
            .clients = std.AutoHashMap(u64, Client).init(allocator),
            .mutex = .{},
            .allocator = allocator,
            .initialized = true,
        };
    }

    /// Clean up resources
    pub fn deinit() void {
        if (!instance.initialized) return;

        instance.mutex.lock();
        defer instance.mutex.unlock();

        var iter = instance.clients.iterator();
        while (iter.next()) |entry| {
            instance.allocator.free(entry.value_ptr.username);
        }
        instance.clients.deinit();
        instance.initialized = false;
    }

    /// Add a client to the global map
    pub fn addClient(wsk: *zttp.WebSocket, username: []const u8) !u64 {
        const client_id = @intFromPtr(wsk);

        instance.mutex.lock();
        defer instance.mutex.unlock();

        if (instance.clients.contains(client_id)) {
            // If client already exists, free the passed username since we already have one stored
            std.log.debug("Client {d} already exists, freeing dupe username.", .{client_id});
            instance.allocator.free(username);
            return client_id; // Client already exists
        }

        // Store username as provided - we assume the caller has already made a persistent copy
        try instance.clients.put(client_id, .{ .wsk = wsk, .id = client_id, .username = username });
        std.log.info("Client {d} ({s}) connected. Total clients: {d}", .{ client_id, username, instance.clients.count() });

        return client_id;
    }

    /// Remove a client from the global map
    pub fn removeClient(client_id: u64) bool {
        instance.mutex.lock();
        defer instance.mutex.unlock();

        if (instance.clients.fetchRemove(client_id)) |kv| {
            instance.allocator.free(kv.value.username);
            std.log.info("Client {d} ({s}) disconnected. Total clients: {d}", .{ client_id, kv.value.username, instance.clients.count() });
            return true;
        }

        return false;
    }

    /// Broadcast a message to all clients except the sender
    pub fn broadcast(message: []const u8, sender_id: u64) void {
        instance.mutex.lock();
        defer instance.mutex.unlock();

        // Create a persistent copy of the message
        const persistent_message = instance.allocator.dupe(u8, message) catch |err| {
            std.log.err("Failed to duplicate message for broadcast: {any}", .{err});
            return;
        };
        defer instance.allocator.free(persistent_message);

        std.log.debug("Broadcasting to {d} clients (excluding sender {d}): {s}", .{ instance.clients.count(), sender_id, persistent_message });

        var sent_count: usize = 0;
        var iter = instance.clients.iterator();
        while (iter.next()) |entry| {
            const client = entry.value_ptr;

            // Skip the sender
            if (client.id == sender_id) continue;

            std.log.debug("Sending to client {d} ({s})", .{ client.id, client.username });
            client.wsk.sendMessage(persistent_message) catch |err| {
                std.log.err("Failed to send to client {d} ({s}): {any}", .{ client.id, client.username, err });
                // Clients that fail to send will remain in the map until
                // they explicitly disconnect or their own message handler
                // is called and fails.
            };
            sent_count += 1;
        }

        std.log.debug("Message sent to {d} clients", .{sent_count});
    }

    /// Get current client count (for diagnostics)
    pub fn getClientCount() usize {
        instance.mutex.lock();
        defer instance.mutex.unlock();
        return instance.clients.count();
    }
};

/// Initialize the chat WebSocket module
pub fn init(allocator: Allocator) !void {
    try ServerState.init(allocator);
    std.log.info("Chat WebSocket module initialized with global state.", .{});
}

/// Clean up resources
pub fn deinit() void {
    ServerState.deinit();
    std.log.info("Chat WebSocket module deinitialized.", .{});
}

/// Helper function to manually parse URL for query parameters
fn parseQueryParameter(url: []const u8, param_name: []const u8) ?[]const u8 {
    // Find the query part (after ?)
    const query_start_idx = std.mem.indexOfScalar(u8, url, '?') orelse return null;
    if (query_start_idx + 1 >= url.len) return null;

    const query = url[query_start_idx + 1 ..];

    // Split query by & to get key=value pairs
    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        // Split pair by = to get key and value
        var kv_iter = std.mem.splitScalar(u8, pair, '=');
        if (kv_iter.next()) |key| {
            if (std.mem.eql(u8, key, param_name)) {
                return kv_iter.next(); // Return the value if key matches
            }
        }
    }

    return null;
}

/// WebSocket message handler function
pub fn ws(wsk: *zttp.WebSocket, message: []const u8, _: *zttp.Context) void {
    if (!ServerState.instance.initialized) {
        std.log.err("WebSocket module not initialized!", .{});
        wsk.close();
        return;
    }

    // Extract client ID from WebSocket pointer
    const client_id = @intFromPtr(wsk);

    // Log raw message for debugging
    std.log.debug("WS handler: Received raw message from {d}: {s}", .{ client_id, message });

    // Handle client connection (triggered by the first message received from a new client)
    if (!ServerState.instance.clients.contains(client_id)) {
        // Extract username from message if possible
        var extracted_username: ?[]const u8 = null;

        // Parse the JSON message to extract username from HX-Current-URL if available
        var arena = std.heap.ArenaAllocator.init(ServerState.instance.allocator);
        defer arena.deinit();

        const allocator = arena.allocator();

        // Try to parse the message as JSON
        const MessageWithHeaders = struct {
            chat_message: []const u8,
            HEADERS: std.json.Value,
        };

        const parsed = std.json.parseFromSlice(MessageWithHeaders, allocator, message, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch null;

        defer if (parsed) |*p| p.deinit();

        // Extract username from HX-Current-URL if present
        if (parsed) |p| {
            // Check if HEADERS is an object type
            if (p.value.HEADERS == .object) {
                const headers_obj = p.value.HEADERS.object;

                // Look for HX-Current-URL in the headers
                if (headers_obj.get("HX-Current-URL")) |url_value| {
                    // Check if the value is a string
                    if (url_value == .string) {
                        const url_str = url_value.string;
                        std.log.debug("WS handler: Found HX-Current-URL: {s}", .{url_str});

                        // Instead of using std.Uri parsing, manually parse the URL
                        if (parseQueryParameter(url_str, "user")) |user_value| {
                            // Make a copy of the username for persistent storage
                            extracted_username = ServerState.instance.allocator.dupe(u8, user_value) catch null;
                            if (extracted_username) |username| {
                                std.log.debug("WS handler: Extracted username: {s}", .{username});
                            }
                        }
                    }
                }
            }
        }

        // Create persistent username
        var default_buffer: [32]u8 = undefined;
        const username_slice = if (extracted_username) |name|
            name
        else blk: {
            const guest_name = std.fmt.bufPrint(&default_buffer, "Guest_{d}", .{client_id}) catch "Guest";
            break :blk guest_name;
        };

        // Create persistent copy of the username if we don't already have one from the URL
        const persistent_username = if (extracted_username) |name|
            name // Already allocated above
        else
            ServerState.instance.allocator.dupe(u8, username_slice) catch |err| {
                std.log.err("WS handler: Failed to duplicate username: {any}", .{err});
                wsk.close();
                return;
            };

        // Add client to the global map
        _ = ServerState.addClient(wsk, persistent_username) catch |err| {
            std.log.err("WS handler: Failed to register client: {any}", .{err});
            ServerState.instance.allocator.free(persistent_username);
            wsk.close();
            return;
        };

        // Send join notification to all clients
        var join_buffer: [256]u8 = undefined;
        if (std.fmt.bufPrint(&join_buffer, "<div hx-swap-oob=\"beforeend:#chat-messages\" class=\"message-wrapper\"><div class=\"chat-message system\">{s} joined the chat</div></div>", .{persistent_username})) |join_msg| {
            ServerState.broadcast(join_msg, client_id);
        } else |err| {
            std.log.err("WS handler: Failed to format join message: {any}", .{err});
        }

        // If this was just an initial empty message on connection, we're done
        if (message.len == 0) {
            std.log.debug("WS handler: Processed initial empty message for client {d}", .{client_id});
            return;
        }
    }

    // Handle client disconnect
    if (std.mem.eql(u8, message, "__disconnect__")) {
        if (ServerState.instance.clients.get(client_id)) |client| {
            var leave_buffer: [256]u8 = undefined;
            if (std.fmt.bufPrint(&leave_buffer, "<div hx-swap-oob=\"beforeend:#chat-messages\" class=\"message-wrapper\"><div class=\"chat-message system\">{s} left the chat</div></div>", .{client.username})) |leave_msg| {
                // Broadcast before removing to ensure we can access the username
                ServerState.broadcast(leave_msg, client_id);
            } else |err| {
                std.log.err("WS handler: Failed to format leave message: {any}", .{err});
            }
            _ = ServerState.removeClient(client_id);
        } else {
            std.log.warn("WS handler: Received disconnect message but client {d} not found", .{client_id});
        }
        return;
    }

    // Process normal chat messages
    if (message.len > 0) {
        // Parse JSON to get chat_message content
        var arena = std.heap.ArenaAllocator.init(ServerState.instance.allocator);
        defer arena.deinit();

        const ChatMessage = struct {
            chat_message: []const u8,
            HEADERS: ?std.json.Value = null,
        };

        const parsed = std.json.parseFromSlice(ChatMessage, arena.allocator(), message, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |err| {
            std.log.debug("WS handler: Failed to parse chat message JSON: {any}", .{err});
            return;
        };
        defer parsed.deinit();

        const actual_message = parsed.value.chat_message;

        // Get username for the client
        const username = if (ServerState.instance.clients.get(client_id)) |client|
            client.username
        else
            "Unknown";

        // Format and broadcast message
        var response_buffer: [600]u8 = undefined;
        if (std.fmt.bufPrint(&response_buffer, "<div hx-swap-oob=\"beforeend:#chat-messages\" class=\"message-wrapper\"><div class=\"chat-message other\">{s}: {s}</div></div>", .{ username, actual_message })) |formatted_msg| {
            ServerState.broadcast(formatted_msg, client_id);
        } else |err| {
            std.log.err("WS handler: Failed to format chat message: {any}", .{err});
        }
    }
}

/// Get diagnostic information about the server state
pub fn getDebugInfo() struct { clients: usize } {
    return .{ .clients = ServerState.getClientCount() };
}
