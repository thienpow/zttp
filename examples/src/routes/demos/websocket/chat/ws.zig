const std = @import("std");
const zttp = @import("zttp");

const Allocator = std.mem.Allocator;

// Define a structure to hold client information
const Client = struct {
    ws: *zttp.WebSocket,
    id: u64, // Unique identifier for the client
};

// Define a map to store connected clients
const ClientMap = std.AutoHashMap(u64, Client);

// Server-wide client map with mutex for thread safety
const ServerClients = struct {
    clients: ClientMap,
    mutex: std.Thread.Mutex,

    fn init(allocator: Allocator) ServerClients {
        return .{
            .clients = ClientMap.init(allocator),
            .mutex = .{},
        };
    }

    fn deinit(self: *ServerClients) void {
        self.clients.deinit();
        std.log.debug("ServerClients deinitialized", .{});
    }
};

// Global server clients, initialized once
var server_clients: ?ServerClients = null;

pub fn init(allocator: std.mem.Allocator) !void {
    if (server_clients != null) {
        std.log.warn("Server clients already initialized", .{});
        return;
    }
    server_clients = ServerClients.init(allocator);
}

pub fn deinit() void {
    std.log.debug("Entering chat_ws.deinit", .{});
    if (server_clients) |*sc| {
        sc.deinit();
        server_clients = null;
        std.log.info("Chat WebSocket module deinitialized", .{});
    }
}

pub fn ws(wsk: *zttp.WebSocket, message: []const u8, ctx: *zttp.Context) void {
    std.log.debug("WebSocket handler called for client {*}, message: {s}, ctx.allocator: {*}", .{ wsk, message, ctx.allocator.ptr });

    // Use ctx.allocator for temporary allocations
    const allocator = ctx.allocator;

    // Access server clients
    const clients = if (server_clients) |*sc| &sc.clients else {
        std.log.err("Server clients not initialized", .{});
        return;
    };

    // Lock the client map for thread safety
    var mutex = if (server_clients) |*sc| &sc.mutex else return;
    mutex.lock();
    defer mutex.unlock();

    // Generate a unique client ID (using pointer address for simplicity)
    const client_id = @intFromPtr(wsk);

    // Check if client is already registered
    const is_new_client = !clients.contains(client_id);

    // Register new client
    if (is_new_client) {
        std.log.debug("Adding client {d} with clients.allocator: {*}", .{ client_id, clients.allocator.ptr });
        const client = Client{ .ws = wsk, .id = client_id };
        clients.put(client_id, client) catch |err| {
            std.log.err("Failed to add client {d}: {}", .{ client_id, err });
            return;
        };
        std.log.info("Client {d} connected. Total clients: {d}", .{ client_id, clients.count() });

        // Notify all clients about the new connection
        var connect_buffer: [256]u8 = undefined;
        const connect_msg = std.fmt.bufPrint(&connect_buffer, "<div class='chat-message system'>User {d} joined the chat</div>", .{client_id}) catch {
            std.log.err("Failed to format connect message", .{});
            return;
        };

        broadcast(clients, connect_msg, client_id, allocator);
    }

    // Handle WebSocket events
    if (std.mem.eql(u8, message, "__disconnect__")) {
        // Client disconnected
        _ = clients.remove(client_id);
        std.log.info("Client {d} disconnected. Total clients: {d}", .{ client_id, clients.count() });

        // Notify all clients about the disconnection
        var disconnect_buffer: [256]u8 = undefined;
        const disconnect_msg = std.fmt.bufPrint(&disconnect_buffer, "<div class='chat-message system'>User {d} left the chat</div>", .{client_id}) catch {
            std.log.err("Failed to format disconnect message", .{});
            return;
        };

        broadcast(clients, disconnect_msg, client_id, allocator);
    } else {
        // Handle regular chat message
        std.log.info("Received message from {d}: {s}", .{ client_id, message });

        // Parse the message (assuming it's in the format sent by HTMX form: "chat_message=message")
        const msg_prefix = "chat_message=";
        const actual_message = if (std.mem.startsWith(u8, message, msg_prefix))
            message[msg_prefix.len..]
        else
            message;

        // Format the message as HTML for broadcasting
        var response_buffer: [512]u8 = undefined;
        const formatted_message = std.fmt.bufPrint(
            &response_buffer,
            "<div class='chat-message other'>User {d}: {s}</div>",
            .{ client_id, actual_message },
        ) catch |err| {
            std.log.err("Failed to format message: {}", .{err});
            wsk.sendMessage("Error formatting message") catch {};
            return;
        };

        // Broadcast the message to all clients
        broadcast(clients, formatted_message, client_id, allocator);
    }
}

// Helper function to broadcast messages to all clients except the sender
fn broadcast(clients: *ClientMap, message: []const u8, sender_id: u64, allocator: Allocator) void {
    // Create a copy of the message to ensure it persists
    const persistent_message = allocator.dupe(u8, message) catch {
        std.log.err("Failed to duplicate message for broadcast", .{});
        return;
    };
    defer allocator.free(persistent_message);

    std.log.debug("Broadcasting message: {s}", .{persistent_message});

    var iterator = clients.iterator();
    while (iterator.next()) |entry| {
        const client = entry.value_ptr;
        // Don't send to the sender (they already appended their message client-side)
        if (client.id != sender_id) {
            client.ws.sendMessage(persistent_message) catch |err| {
                std.log.err("Failed to send message to client {d}: {}", .{ client.id, err });
            };
        }
    }
}
