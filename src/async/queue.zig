// zttp/src/async/queue.zig
const std = @import("std");
const assert = std.debug.assert;

const log = std.log.scoped(.queue);

/// Intrusive doubly-linked list for managing tasks.
/// Thread-safe: all operations are protected by a mutex.
/// `T` is the type of the node (e.g., Task).
/// `field` is the name of the field in `T` that contains the queue pointers (next, prev).
pub fn Intrusive(comptime T: type, comptime field: std.meta.FieldEnum(T)) type {
    return struct {
        const Self = @This();
        const Node = T;

        head: ?*Node = null,
        tail: ?*Node = null,
        len: usize = 0,
        mutex: std.Thread.Mutex = .{},
        _field: std.meta.FieldEnum(T) = field,

        /// Initializes an empty queue.
        pub fn init() Self {
            return .{};
        }

        /// Returns true if the queue is empty.
        pub fn empty(self: *const Self) bool {
            return self.head == null;
        }

        /// Checks if a node is in the queue.
        pub fn hasItem(self: *const Self, node: *const Node) bool {
            var current = self.head;
            while (current) |n| {
                if (n == node) return true;
                current = @field(n, @tagName(field)).next;
            }
            return false;
        }

        /// Pushes a node to the end of the queue.
        /// Thread-safe: locks the mutex during operation.
        pub fn push(self: *Self, node: *Node) void {
            assert(@field(node, @tagName(field)).next == null);
            assert(@field(node, @tagName(field)).prev == null);

            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.tail) |tail| {
                @field(tail, @tagName(field)).next = node;
                @field(node, @tagName(field)).prev = tail;
                self.tail = node;
            } else {
                self.head = node;
                self.tail = node;
            }
            self.len += 1;
        }

        /// Pops a node from the front of the queue.
        /// Thread-safe: locks the mutex during operation.
        /// Returns null if the queue is empty.
        pub fn pop(self: *Self) ?*Node {
            self.mutex.lock();
            defer self.mutex.unlock();

            const node = self.head orelse return null;
            self.head = @field(node, @tagName(field)).next;

            if (self.head) |new_head| {
                @field(new_head, @tagName(field)).prev = null;
            } else {
                self.tail = null;
            }

            @field(node, @tagName(field)).next = null;
            @field(node, @tagName(field)).prev = null;
            self.len -= 1;

            return node;
        }

        /// Pushes a node to the front of the queue.
        /// Thread-safe: locks the mutex during operation.
        pub fn pushFront(self: *Self, node: *Node) void {
            assert(@field(node, @tagName(field)).next == null);
            assert(@field(node, @tagName(field)).prev == null);

            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.head) |head| {
                @field(node, @tagName(field)).next = head;
                @field(head, @tagName(field)).prev = node;
                self.head = node;
            } else {
                self.head = node;
                self.tail = node;
            }
            self.len += 1;
        }

        /// Removes a specific node from the queue.
        /// Thread-safe: locks the mutex during operation.
        pub fn remove(self: *Self, node: *Node) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (!self.hasItem(node)) {
                log.warn("Attempt to remove node {*} not in queue", .{node});
                return;
            }

            const prev = @field(node, @tagName(field)).prev;
            const next = @field(node, @tagName(field)).next;

            if (prev) |p| {
                @field(p, @tagName(field)).next = next;
            } else {
                self.head = next;
            }

            if (next) |n| {
                @field(n, @tagName(field)).prev = prev;
            } else {
                self.tail = prev;
            }

            @field(node, @tagName(field)).next = null;
            @field(node, @tagName(field)).prev = null;
            self.len -= 1;
        }
    };
}
