// examples/src/routes/demos/websocket/chat/ws.zig
const std = @import("std");
const zttp = @import("zttp");

const Allocator = std.mem.Allocator;

/// Client represents a connected WebSocket client
const Client = struct {
    wsk: *zttp.WebSocket,
    id: u64,
    username: []const u8,
};

/// Thread-safe map to store all connected clients
const ServerState = struct {
    clients: std.AutoHashMap(u64, Client),
    mutex: std.Thread.Mutex,
    allocator: Allocator,

    // Singleton instance
    var instance: ?ServerState = null;

    pub fn init(allocator: Allocator) !void {
        std.log.debug("ServerState.init: Initializing", .{});
        instance = ServerState{
            .clients = std.AutoHashMap(u64, Client).init(allocator),
            .mutex = .{},
            .allocator = allocator,
        };
        std.log.debug("ServerState.init: Initialized", .{});
    }

    pub fn deinit() void {
        std.log.debug("ServerState.deinit: Starting", .{});
        if (instance == null) return;

        instance.?.mutex.lock();
        defer instance.?.mutex.unlock();

        var iter = instance.?.clients.iterator();
        while (iter.next()) |entry| {
            instance.?.allocator.free(entry.value_ptr.username);
        }
        instance.?.clients.deinit();
        instance = null;
        std.log.debug("ServerState.deinit: Completed", .{});
    }

    pub fn addClient(wsk: *zttp.WebSocket, username: []const u8) !u64 {
        std.log.debug("ServerState.addClient: Adding client for wsk={*}", .{wsk});
        if (instance == null) return error.NotInitialized;

        const client_id = @intFromPtr(wsk);
        instance.?.mutex.lock();
        defer instance.?.mutex.unlock();

        if (instance.?.clients.contains(client_id)) {
            instance.?.allocator.free(username);
            std.log.debug("ServerState.addClient: Client {d} already exists", .{client_id});
            return client_id;
        }

        try instance.?.clients.put(client_id, .{
            .wsk = wsk,
            .id = client_id,
            .username = username,
        });
        std.log.info("Client {d} ({s}) connected. Total: {d}", .{ client_id, username, instance.?.clients.count() });
        std.log.debug("ServerState.addClient: Added client {d}", .{client_id});
        return client_id;
    }

    pub fn removeClient(client_id: u64) bool {
        std.log.debug("ServerState.removeClient: Removing client {d}", .{client_id});
        if (instance == null) return false;

        instance.?.mutex.lock();
        defer instance.?.mutex.unlock();

        if (instance.?.clients.fetchRemove(client_id)) |kv| {
            instance.?.allocator.free(kv.value.username);
            std.log.info("Client {d} disconnected. Total: {d}", .{ client_id, instance.?.clients.count() });
            std.log.debug("ServerState.removeClient: Removed client {d}", .{client_id});
            return true;
        }
        std.log.debug("ServerState.removeClient: Client {d} not found", .{client_id});
        return false;
    }

    pub fn broadcast(message: []const u8, sender_id: u64, async_ctx: zttp.AsyncContext) !void {
        std.log.debug("ServerState.broadcast: Broadcasting message '{s}' from sender {d}", .{ message, sender_id });
        if (instance == null) return error.NotInitialized;

        const message_copy = try instance.?.allocator.dupe(u8, message);
        defer instance.?.allocator.free(message_copy);

        var recipients = std.ArrayList(struct { wsk: *zttp.WebSocket, id: u64 }).init(instance.?.allocator);
        defer recipients.deinit();

        // Collect recipients under mutex
        {
            instance.?.mutex.lock();
            defer instance.?.mutex.unlock();

            std.log.debug("ServerState.broadcast: Collecting recipients", .{});
            var iter = instance.?.clients.iterator();
            while (iter.next()) |entry| {
                const client = entry.value_ptr;
                if (client.id == sender_id) continue;
                try recipients.append(.{ .wsk = client.wsk, .id = client.id });
            }
            std.log.debug("ServerState.broadcast: Collected {d} recipients", .{recipients.items.len});
        }

        // Send messages to all recipients asynchronously
        for (recipients.items) |recipient| {
            std.log.debug("ServerState.broadcast: Sending to client {d}", .{recipient.id});
            recipient.wsk.sendMessageAsync(message_copy, async_ctx) catch |err| {
                std.log.err("ServerState.broadcast: Failed to send to client {d}: {any}", .{ recipient.id, err });
                continue;
            };
            std.log.debug("ServerState.broadcast: Successfully sent to client {d}", .{recipient.id});
        }

        // Retry for newly added clients
        {
            instance.?.mutex.lock();
            defer instance.?.mutex.unlock();

            var retry_recipients = std.ArrayList(struct { wsk: *zttp.WebSocket, id: u64 }).init(instance.?.allocator);
            defer retry_recipients.deinit();

            std.log.debug("ServerState.broadcast: Checking for new recipients", .{});
            var iter = instance.?.clients.iterator();
            while (iter.next()) |entry| {
                const client = entry.value_ptr;
                if (client.id == sender_id) continue;
                var was_sent = false;
                for (recipients.items) |r| {
                    if (r.id == client.id) {
                        was_sent = true;
                        break;
                    }
                }
                if (!was_sent) {
                    try retry_recipients.append(.{ .wsk = client.wsk, .id = client.id });
                }
            }

            if (retry_recipients.items.len > 0) {
                std.log.debug("ServerState.broadcast: Retrying for {d} new recipients", .{retry_recipients.items.len});
                for (retry_recipients.items) |recipient| {
                    std.log.debug("ServerState.broadcast: Retry sending to client {d}", .{recipient.id});
                    recipient.wsk.sendMessageAsync(message_copy, async_ctx) catch |err| {
                        std.log.err("ServerState.broadcast: Retry failed for client {d}: {any}", .{ recipient.id, err });
                        continue;
                    };
                    std.log.debug("ServerState.broadcast: Retry succeeded for client {d}", .{recipient.id});
                }
            }
        }
    }

    pub fn getClientCount() usize {
        std.log.debug("ServerState.getClientCount: Checking client count", .{});
        if (instance == null) return 0;
        instance.?.mutex.lock();
        defer instance.?.mutex.unlock();
        const count = instance.?.clients.count();
        std.log.debug("ServerState.getClientCount: Count = {d}", .{count});
        return count;
    }
};

pub fn init(allocator: Allocator) !void {
    std.log.debug("ws.init: Initializing", .{});
    try ServerState.init(allocator);
    std.log.info("Chat WebSocket module initialized", .{});
}

pub fn deinit() void {
    std.log.debug("ws.deinit: Deinitializing", .{});
    ServerState.deinit();
    std.log.info("Chat WebSocket module deinitialized", .{});
}

fn parseQueryParameter(allocator: Allocator, url: []const u8, param_name: []const u8) !?[]const u8 {
    std.log.debug("parseQueryParameter: Parsing URL '{s}' for param '{s}'", .{ url, param_name });
    const query_start = std.mem.indexOfScalar(u8, url, '?') orelse return null;
    if (query_start + 1 >= url.len) return null;

    const query = url[query_start + 1 ..];
    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        var kv_iter = std.mem.splitScalar(u8, pair, '=');
        if (kv_iter.next()) |key| {
            if (std.mem.eql(u8, key, param_name)) {
                if (kv_iter.next()) |value| {
                    const result = try allocator.dupe(u8, value);
                    std.log.debug("parseQueryParameter: Found param '{s}' = '{s}'", .{ param_name, result });
                    return result;
                }
            }
        }
    }
    std.log.debug("parseQueryParameter: Param '{s}' not found", .{param_name});
    return null;
}

pub fn ws(wsk: *zttp.WebSocket, message: []const u8, ctx: *zttp.Context, async_ctx: zttp.AsyncContext) void {
    _ = ctx;
    std.log.debug("ws: Entering for wsk={*}, message_len={d}", .{ wsk, message.len });
    if (ServerState.instance == null) {
        std.log.err("ws: WebSocket module not initialized", .{});
        wsk.close(async_ctx);
        std.log.debug("ws: Closed wsk={*} due to uninitialized state", .{wsk});
        return;
    }

    const client_id = @intFromPtr(wsk);
    const allocator = ServerState.instance.?.allocator;

    // Limit to 8 clients to prevent thread exhaustion
    if (ServerState.getClientCount() >= 8 and !ServerState.instance.?.clients.contains(client_id)) {
        std.log.debug("ws: Rejecting client {d} due to client limit (8)", .{client_id});
        wsk.close(async_ctx);
        std.log.debug("ws: Closed wsk={*} due to client limit", .{wsk});
        return;
    }

    // Handle new client connection
    if (!ServerState.instance.?.clients.contains(client_id)) {
        std.log.debug("ws: Handling new client connection: {d}", .{client_id});
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        var username: []const u8 = undefined;
        var username_owned = false;

        // Try to extract username from URL in headers
        const MessageWithHeaders = struct {
            chat_message: []const u8,
            HEADERS: ?struct { @"HX-Current-URL": ?[]const u8 = null },
        };

        std.log.debug("ws: Parsing JSON for client {d}", .{client_id});
        const parsed: ?std.json.Parsed(MessageWithHeaders) = blk: {
            const result = std.json.parseFromSlice(MessageWithHeaders, arena_alloc, message, .{ .ignore_unknown_fields = true }) catch |err| {
                std.log.debug("ws: Failed to parse message as JSON: {any}", .{err});
                break :blk null;
            };
            break :blk result;
        };

        if (parsed) |p| {
            defer p.deinit();
            std.log.debug("ws: JSON parsed successfully for client {d}", .{client_id});
            if (p.value.HEADERS) |headers| {
                if (headers.@"HX-Current-URL") |url| {
                    std.log.debug("ws: Found HX-Current-URL: '{s}'", .{url});
                    if (parseQueryParameter(allocator, url, "user")) |user| {
                        username = user.?;
                        username_owned = true;
                        std.log.debug("ws: Extracted username '{s}' for client {d}", .{ username, client_id });
                    } else |err| {
                        std.log.debug("ws: Failed to parse query parameter: {any}", .{err});
                    }
                }
            }
        }

        if (!username_owned) {
            var buf: [32]u8 = undefined;
            username = std.fmt.bufPrint(&buf, "Guest_{d}", .{client_id}) catch "Guest";
            username = allocator.dupe(u8, username) catch {
                std.log.err("ws: Failed to allocate username for client {d}", .{client_id});
                wsk.close(async_ctx);
                std.log.debug("ws: Closed wsk={*} due to allocation failure", .{wsk});
                return;
            };
            username_owned = true;
            std.log.debug("ws: Assigned default username '{s}' for client {d}", .{ username, client_id });
        }

        std.log.debug("ws: Adding client {d} with username '{s}'", .{ client_id, username });
        _ = ServerState.addClient(wsk, username) catch |err| {
            std.log.err("ws: Failed to add client {d}: {any}", .{ client_id, err });
            if (username_owned) allocator.free(username);
            wsk.close(async_ctx);
            std.log.debug("ws: Closed wsk={*} due to addClient error", .{wsk});
            return;
        };
        std.log.debug("ws: Client {d} join process completed", .{client_id});

        var join_buf: [256]u8 = undefined;
        if (std.fmt.bufPrint(&join_buf, "<div hx-swap-oob=\"beforeend:#chat-messages\" class=\"message-wrapper\"><div class=\"chat-message system\">{s} joined the chat</div></div>", .{username})) |join_msg| {
            std.log.debug("ws: Broadcasting join message for client {d}", .{client_id});
            ServerState.broadcast(join_msg, client_id, async_ctx) catch |err| {
                std.log.err("ws: Failed to broadcast join message: {any}", .{err});
            };
        } else |err| {
            std.log.err("ws: Failed to format join message: {any}", .{err});
        }

        if (message.len == 0) {
            std.log.debug("ws: Empty message for new client {d}, returning", .{client_id});
            return;
        }
    }

    // Handle disconnect
    if (std.mem.eql(u8, message, "__disconnect__")) {
        std.log.debug("ws: Handling disconnect for client {d}", .{client_id});
        if (ServerState.instance.?.clients.get(client_id)) |client| {
            var leave_buf: [256]u8 = undefined;
            if (std.fmt.bufPrint(&leave_buf, "<div hx-swap-oob=\"beforeend:#chat-messages\" class=\"message-wrapper\"><div class=\"chat-message system\">{s} left the chat</div></div>", .{client.username})) |leave_msg| {
                std.log.debug("ws: Broadcasting leave message for client {d}", .{client_id});
                ServerState.broadcast(leave_msg, client_id, async_ctx) catch |err| {
                    std.log.err("ws: Failed to broadcast leave message: {any}", .{err});
                };
            } else |err| {
                std.log.err("ws: Failed to format leave message: {any}", .{err});
            }
            _ = ServerState.removeClient(client_id);
        }
        std.log.debug("ws: Disconnect process completed for client {d}", .{client_id});
        return;
    }

    // Handle chat messages
    if (message.len > 0) {
        std.log.debug("ws: Handling chat message from client {d}", .{client_id});
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const ChatMessage = struct {
            chat_message: []const u8,
        };

        std.log.debug("ws: Parsing chat message JSON for client {d}", .{client_id});
        const parsed: ?std.json.Parsed(ChatMessage) = blk: {
            const result = std.json.parseFromSlice(ChatMessage, arena.allocator(), message, .{ .ignore_unknown_fields = true }) catch |err| {
                std.log.debug("ws: Failed to parse chat message: {any}", .{err});
                break :blk null;
            };
            break :blk result;
        };

        if (parsed) |p| {
            defer p.deinit();
            std.log.debug("ws: Chat message parsed successfully for client {d}", .{client_id});

            const username = if (ServerState.instance.?.clients.get(client_id)) |client|
                client.username
            else
                "Unknown";

            var msg_buf: [600]u8 = undefined;
            if (std.fmt.bufPrint(&msg_buf, "<div hx-swap-oob=\"beforeend:#chat-messages\" class=\"message-wrapper\"><div class=\"chat-message other\">{s}: {s}</div></div>", .{ username, p.value.chat_message })) |formatted| {
                std.log.debug("ws: Broadcasting chat message from client {d}", .{client_id});
                ServerState.broadcast(formatted, client_id, async_ctx) catch |err| {
                    std.log.err("ws: Failed to broadcast chat message: {any}", .{err});
                };
            } else |err| {
                std.log.err("ws: Failed to format chat message: {any}", .{err});
            }
        }
        std.log.debug("ws: Chat message handling completed for client {d}", .{client_id});
    }
    std.log.debug("ws: Exiting for client {d}", .{client_id});
}

pub fn getDebugInfo() struct { clients: usize } {
    std.log.debug("ws.getDebugInfo: Retrieving client count", .{});
    return .{ .clients = ServerState.getClientCount() };
}
