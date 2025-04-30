const std = @import("std");
const zttp = @import("zttp");
const WebSocket = zttp.WebSocket;
const Context = zttp.Context;
const AsyncContext = zttp.AsyncContext;

const Allocator = std.mem.Allocator;

// Message types for better code organization
const MessageType = enum {
    chat,
    system,
    register,
    ping,

    fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .chat => "chat",
            .system => "system",
            .register => "register",
            .ping => "ping",
        };
    }
};

// Define a message structure for serialization
const ChatMessage = struct {
    username: []const u8,
    message: []const u8,
    type: []const u8,
    room: ?[]const u8 = null,

    fn init(username: []const u8, message: []const u8, msg_type: MessageType, room: ?[]const u8) ChatMessage {
        return .{
            .username = username,
            .message = message,
            .type = msg_type.toString(),
            .room = room,
        };
    }
};

// Client management structure
const Client = struct {
    wsk: *WebSocket,
    username: []u8,
    room: []u8,
    async_ctx: AsyncContext,

    fn deinit(self: *Client, allocator: Allocator) void {
        allocator.free(self.username);
        allocator.free(self.room);
    }
};

// Server state to manage clients
pub const ChatServer = struct {
    clients: std.AutoArrayHashMap(*WebSocket, Client),
    allocator: Allocator,
    mutex: std.Thread.Mutex,

    fn init(allocator: Allocator) ChatServer {
        std.log.debug("ChatServer.init: Initializing with allocator", .{});
        return .{
            .clients = std.AutoArrayHashMap(*WebSocket, Client).init(allocator),
            .allocator = allocator,
            .mutex = std.Thread.Mutex{},
        };
    }

    fn deinit(self: *ChatServer) void {
        std.log.debug("ChatServer.deinit: Deinitializing, client count={}", .{self.clients.count()});
        var it = self.clients.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.clients.deinit();
    }

    fn addClient(self: *ChatServer, wsk: *WebSocket, username: []const u8, room: []const u8, async_ctx: AsyncContext) !void {
        const owned_username = try self.allocator.dupe(u8, username);
        errdefer self.allocator.free(owned_username);

        const owned_room = try self.allocator.dupe(u8, room);
        errdefer self.allocator.free(owned_room);

        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if client already exists
        if (self.clients.contains(wsk)) {
            self.allocator.free(owned_username);
            self.allocator.free(owned_room);
            return error.ClientAlreadyExists;
        }

        try self.clients.put(wsk, .{
            .wsk = wsk,
            .username = owned_username,
            .room = owned_room,
            .async_ctx = async_ctx,
        });
        std.log.debug("ChatServer.addClient: Added client, username={s}, room={s}, wsk={*}, total clients={}", .{ username, room, wsk, self.clients.count() });
    }

    fn removeClient(self: *ChatServer, wsk: *WebSocket) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.clients.getEntry(wsk)) |entry| {
            const client = entry.value_ptr;
            std.log.debug("ChatServer.removeClient: Removing client, username={s}, room={s}, wsk={*}, remaining clients={}", .{ client.username, client.room, wsk, self.clients.count() - 1 });
            client.deinit(self.allocator);
            _ = self.clients.orderedRemove(wsk);
        } else {
            std.log.debug("ChatServer.removeClient: Client not found, wsk={*}", .{wsk});
        }
    }

    fn getClientInfo(self: *ChatServer, wsk: *WebSocket) ?struct { username: []const u8, room: []const u8 } {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.clients.getPtr(wsk)) |client| {
            return .{ .username = client.username, .room = client.room };
        }
        return null;
    }

    fn hasClient(self: *ChatServer, wsk: *WebSocket) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.clients.contains(wsk);
    }

    fn getClientCount(self: *ChatServer) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.clients.count();
    }

    fn getClientCountInRoom(self: *ChatServer, room: []const u8) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        var it = self.clients.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.room, room)) {
                count += 1;
            }
        }
        return count;
    }

    fn broadcast(self: *ChatServer, message: ChatMessage) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        const json = try std.json.stringifyAlloc(arena_allocator, message, .{});
        const target_room = message.room orelse "";

        std.log.debug("ChatServer.broadcast: Broadcasting message, type={s}, username={s}, room={s}, json={s}", .{ message.type, message.username, target_room, json });

        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.clients.iterator();
        var client_count: usize = 0;
        var failed_clients = std.ArrayList(*WebSocket).init(arena_allocator);

        while (it.next()) |entry| {
            // Only broadcast to clients in the target room if specified
            if (message.room != null and !std.mem.eql(u8, entry.value_ptr.room, target_room)) {
                std.log.debug("ChatServer.broadcast: Skipping client in different room, username={s}, client_room={s}, target_room={s}", .{ entry.value_ptr.username, entry.value_ptr.room, target_room });
                continue;
            }

            client_count += 1;
            std.log.debug("ChatServer.broadcast: Sending to client, username={s}, room={s}, wsk={*}", .{ entry.value_ptr.username, entry.value_ptr.room, entry.value_ptr.wsk });

            entry.value_ptr.wsk.sendMessageAsync(json, entry.value_ptr.async_ctx) catch |err| {
                std.log.err("ChatServer.broadcast: Failed to send message to client, username={s}, room={s}, wsk={*}, error={}", .{ entry.value_ptr.username, entry.value_ptr.room, entry.value_ptr.wsk, err });
                try failed_clients.append(entry.value_ptr.wsk);
                continue;
            };
        }

        // Close and remove failed clients
        for (failed_clients.items) |failed_wsk| {
            failed_wsk.close(self.clients.get(failed_wsk).?.async_ctx);
        }

        std.log.debug("ChatServer.broadcast: Sent to {} clients", .{client_count - failed_clients.items.len});
    }

    fn broadcastToRoom(self: *ChatServer, sender_wsk: *WebSocket, html_message: []const u8, room: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.clients.iterator();
        var client_count: usize = 0;
        var failed_clients = std.ArrayList(*WebSocket).init(self.allocator);
        defer failed_clients.deinit();

        while (it.next()) |entry| {
            // Skip if not in the same room
            if (!std.mem.eql(u8, entry.value_ptr.room, room)) {
                continue;
            }

            // Skip the sender
            if (entry.key_ptr.* == sender_wsk) {
                std.log.debug("ChatServer.broadcastToRoom: Skipping sender, username={s}, room={s}, wsk={*}", .{ entry.value_ptr.username, entry.value_ptr.room, entry.value_ptr.wsk });
                continue;
            }

            client_count += 1;
            std.log.debug("ChatServer.broadcastToRoom: Sending to client, username={s}, room={s}, wsk={*}", .{ entry.value_ptr.username, entry.value_ptr.room, entry.value_ptr.wsk });

            entry.value_ptr.wsk.sendMessageAsync(html_message, entry.value_ptr.async_ctx) catch |err| {
                std.log.err("ChatServer.broadcastToRoom: Failed to send message to client, username={s}, room={s}, wsk={*}, error={}", .{ entry.value_ptr.username, entry.value_ptr.room, entry.value_ptr.wsk, err });
                try failed_clients.append(entry.value_ptr.wsk);
                continue;
            };
        }

        // Close and remove failed clients outside the iterator
        for (failed_clients.items) |failed_wsk| {
            if (self.clients.getPtr(failed_wsk)) |client| {
                client.wsk.close(client.async_ctx);
                client.deinit(self.allocator);
                _ = self.clients.orderedRemove(failed_wsk);
            }
        }

        std.log.debug("ChatServer.broadcastToRoom: Sent to {} clients in room {s}", .{ client_count - failed_clients.items.len, room });
        if (client_count == 0) {
            std.log.warn("ChatServer.broadcastToRoom: No other clients found in room {s} for sender_wsk={*}", .{ room, sender_wsk });
        }
    }

    fn broadcastSystemMessage(self: *ChatServer, ctx: *Context, room: []const u8, comptime format_string: []const u8, args: anytype) !void {
        const html = try std.fmt.allocPrint(ctx.allocator, "<div id=\"chat-messages\" hx-swap-oob=\"beforeend\"><div class=\"chat-message system\">System: " ++ format_string ++ "</div></div>", args);
        defer ctx.allocator.free(html);

        try self.broadcast(ChatMessage.init("System", html, .system, room));
    }
};

// Server state singleton
const ServerState = struct {
    server: ?*ChatServer,
    allocator: ?Allocator,
};
var server_state: ServerState = .{ .server = null, .allocator = null };
var init_mutex: std.Thread.Mutex = .{};

// Helper to get or initialize ChatServer
fn getChatServer(ctx: *Context) !*ChatServer {
    init_mutex.lock();
    defer init_mutex.unlock();

    std.log.debug("getChatServer: Attempting to get or initialize ChatServer", .{});
    if (server_state.server) |server| {
        std.log.debug("getChatServer: Returning existing ChatServer, ptr={*}", .{server});
        const server_ptr_str = try std.fmt.allocPrint(ctx.allocator, "{}", .{@intFromPtr(server)});
        errdefer ctx.allocator.free(server_ptr_str);
        try ctx.set("chat_server", server_ptr_str);
        std.log.debug("getChatServer: Set chat_server in ctx, server_ptr_str={s}", .{server_ptr_str});
        return server;
    }

    const allocator = ctx.allocator;
    std.log.debug("getChatServer: Creating new ChatServer", .{});
    const server = try allocator.create(ChatServer);
    errdefer allocator.destroy(server);
    server.* = ChatServer.init(allocator);

    server_state.server = server;
    server_state.allocator = allocator;

    const server_ptr_str = try std.fmt.allocPrint(allocator, "{}", .{@intFromPtr(server)});
    errdefer allocator.free(server_ptr_str);
    try ctx.set("chat_server", server_ptr_str);
    std.log.debug("getChatServer: Initialized new ChatServer, ptr={*}, stored in ctx, server_ptr_str={s}", .{ server, server_ptr_str });

    return server;
}

// Get ChatServer from pointer string
fn getServerFromPtrStr(server_ptr_str: []const u8) ?*ChatServer {
    const server_ptr_int = std.fmt.parseInt(usize, server_ptr_str, 10) catch |err| {
        std.log.err("Failed to parse chat_server pointer: {}", .{err});
        return null;
    };
    return @as(*ChatServer, @ptrFromInt(server_ptr_int));
}

// Cleanup function for ChatServer
pub fn deinitChatServer() void {
    init_mutex.lock();
    defer init_mutex.unlock();

    std.log.debug("deinitChatServer: Attempting to deinitialize ChatServer", .{});
    if (server_state.server) |server| {
        if (server_state.allocator) |allocator| {
            std.log.debug("deinitChatServer: Deinitializing ChatServer, ptr={*}", .{server});
            server.deinit();
            allocator.destroy(server);
        }
        server_state.server = null;
        server_state.allocator = null;
        std.log.debug("deinitChatServer: ChatServer deinitialized", .{});
    }
}

// Handle register message
fn handleRegisterMessage(server: *ChatServer, wsk: *WebSocket, username: []const u8, room: []const u8, async_ctx: AsyncContext, ctx: *Context) !void {
    if (!server.hasClient(wsk)) {
        std.log.debug("handleRegisterMessage: Registering new client, username={s}, room={s}, wsk={*}", .{ username, room, wsk });
        try server.addClient(wsk, username, room, async_ctx);

        const room_count = server.getClientCountInRoom(room);
        std.log.debug("handleRegisterMessage: Room {s} now has {} clients", .{ room, room_count });

        try server.broadcastSystemMessage(ctx, room, "{s} joined the chat in room {s}", .{ username, room });
    }
}

// Handle chat message
fn handleChatMessage(server: *ChatServer, wsk: *WebSocket, msg_content: []const u8, ctx: *Context) !void {
    const client_info = server.getClientInfo(wsk) orelse {
        std.log.warn("handleChatMessage: Client not found for wsk={*}", .{wsk});
        return;
    };

    const username = client_info.username;
    const room = client_info.room;

    const room_count = server.getClientCountInRoom(room);
    std.log.debug("handleChatMessage: Broadcasting to room {s}, total clients in room={}", .{ room, room_count });

    const chat_html = try std.fmt.allocPrint(ctx.allocator, "<div id=\"chat-messages\" hx-swap-oob=\"beforeend\"><div class=\"chat-message other\">{s}: {s}</div></div>", .{ username, msg_content });
    defer ctx.allocator.free(chat_html);

    std.log.debug("handleChatMessage: Broadcasting chat message from {s} in room {s}", .{ username, room });
    try server.broadcastToRoom(wsk, chat_html, room);
}

// WebSocket message handler
pub fn ws(wsk: *WebSocket, message: []const u8, ctx: *Context, async_ctx: AsyncContext) anyerror!void {
    std.log.debug("ws: Received message, wsk={*}, message={s}", .{ wsk, message });

    const server = try getChatServer(ctx);
    std.log.debug("ws: Retrieved ChatServer, ptr={*}", .{server});

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    // Handle ping
    if (std.mem.eql(u8, message, "ping")) {
        std.log.debug("ws: Handling ping, sending pong", .{});
        try wsk.sendMessageAsync("pong", async_ctx);
        return;
    }

    // Check for register message
    const RegisterPayload = struct {
        type: []const u8,
        username: []const u8,
        room: []const u8,
    };

    if (std.json.parseFromSliceLeaky(RegisterPayload, arena_allocator, message, .{ .ignore_unknown_fields = true })) |payload| {
        if (std.mem.eql(u8, payload.type, "register")) {
            std.log.debug("ws: Handling register message, wsk={*}, username={s}, room={s}", .{ wsk, payload.username, payload.room });
            try handleRegisterMessage(server, wsk, payload.username, payload.room, async_ctx, ctx);
            return;
        }
    } else |err| {
        std.log.debug("ws: Not a register message: {s}, error={}", .{ message, err });
    }

    // Handle chat message
    const JsonPayload = struct {
        chat_message: []const u8,
        HEADERS: ?struct {
            @"HX-Request": ?[]const u8 = null,
            @"HX-Trigger": ?[]const u8 = null,
            @"HX-Trigger-Name": ?[]const u8 = null,
            @"HX-Target": ?[]const u8 = null,
            @"HX-Current-URL": ?[]const u8 = null,
        } = null,
    };

    const parsed = std.json.parseFromSliceLeaky(JsonPayload, arena_allocator, message, .{ .ignore_unknown_fields = true }) catch |err| {
        std.log.warn("ws: Failed to parse JSON message: {s}, error={}", .{ message, err });

        const error_html = "<div id=\"chat-messages\" hx-swap-oob=\"beforeend\"><div class=\"chat-message system\">System: Invalid message format</div></div>";
        try wsk.sendMessageAsync(error_html, async_ctx);
        return;
    };

    const msg_content = parsed.chat_message;

    try handleChatMessage(server, wsk, msg_content, ctx);
}

// Handle WebSocket close
pub fn wsClose(wsk: *WebSocket, ctx: *Context, _: AsyncContext) void {
    std.log.debug("wsClose: WebSocket closing, wsk={*}", .{wsk});

    const server = if (ctx.get("chat_server")) |server_ptr_str|
        getServerFromPtrStr(server_ptr_str) orelse {
            std.log.err("Invalid chat_server pointer in wsClose", .{});
            return;
        }
    else {
        std.log.err("No chat_server in ctx for wsClose", .{});
        return;
    };

    const client_info = server.getClientInfo(wsk) orelse {
        std.log.warn("wsClose: Client not found for wsk={*}", .{wsk});
        return;
    };

    const username = client_info.username;
    const room = client_info.room;

    std.log.debug("wsClose: Removing client, username={s}, room={s}, wsk={*}", .{ username, room, wsk });

    server.removeClient(wsk);

    std.log.debug("wsClose: Broadcasting leave message for {s} in room {s}", .{ username, room });
    server.broadcastSystemMessage(ctx, room, "{s} left the chat in room {s}", .{ username, room }) catch |err| {
        std.log.err("wsClose: Failed to broadcast leave message for {s} in room {s}: {}", .{ username, room, err });
    };
}
