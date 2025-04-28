// zttp/src/async/queue.zig
const std = @import("std");
const assert = std.debug.assert;

pub fn Intrusive(comptime T: type, comptime state: @Type(.enum_literal)) type {
    return struct {
        const Self = @This();

        const set_state = state;

        /// Head is the front of the queue and tail is the back of the queue.
        head: ?*T = null,
        tail: ?*T = null,

        /// Enqueue a new element to the back of the queue.
        pub fn push(self: *Self, v: *T) void {
            assert(v.next == null);
            v.state = set_state;

            if (self.tail) |tail| {
                // If we have elements in the queue, then we add a new tail.
                tail.next = v;
                v.prev = tail;
                self.tail = v;
            } else {
                // No elements in the queue we setup the initial state.
                self.head = v;
                self.tail = v;
            }
        }

        /// Enqueue a new element to the front of the queue.
        // pub fn pushFront(self: *Self, v: *T) void {
        //     assert(v.next == null);
        //     v.state = set_state; // Ensure state is set correctly

        //     if (self.head) |head| {
        //         // If we have elements, the new element becomes the head
        //         v.next = head;
        //         head.prev = v;
        //         self.head = v;
        //     } else {
        //         // If empty, this is the first and only element
        //         self.head = v;
        //         self.tail = v;
        //     }
        // }

        /// Dequeue the next element from the queue.
        pub fn pop(self: *Self) ?*T {
            // The next element is in "head".
            const next = self.head orelse return null;

            // If the head and tail are equal this is the last element
            // so we also set tail to null so we can now be empty.
            if (self.head == self.tail) self.tail = null;

            // Head is whatever is next (if we're the last element,
            // this will be null);
            self.head = next.next;
            if (self.head) |head| head.prev = null;

            // We set the "next" field to null so that this element
            // can be inserted again.
            next.next = null;
            next.prev = null;
            return next;
        }

        /// Returns true if the queue is empty.
        pub fn empty(self: Self) bool {
            return self.head == null;
        }

        /// Removes the item from the queue. Checks if item is in the queue first.
        pub fn remove(self: *Self, item: *T) void {
            assert(self.hasItem(item));
            if (item.prev) |prev| prev.next = item.next else self.head = item.next;

            if (item.next) |next| next.prev = item.prev else self.tail = item.prev;

            item.prev = null;
            item.next = null;
        }

        pub fn hasItem(self: Self, item: *T) bool {
            var maybe_node = self.head;
            while (maybe_node) |node| {
                if (node == item) return true;
                maybe_node = node.next;
            }
            return false; // Changed from else return false;
        }

        pub fn len(self: Self) usize {
            var count: usize = 0;
            var maybe_node = self.head;
            while (maybe_node) |node| {
                count += 1;
                maybe_node = node.next;
            }
            return count;
        }
    };
}
