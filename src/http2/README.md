# HTTP/2 Implementation Refactoring

This refactoring splits the original monolithic HTTP/2 implementation into several logically organized files and modules. Here's an explanation of the changes and their benefits:

## Project Structure

```
src/http2/
├── mod.zig                # Main entry point, exports all public components
├── frame.zig             # Frame types and frame header implementation
├── settings.zig          # HTTP/2 settings implementation
├── error.zig             # Error codes and error handling
├── client.zig            # Client connection implementation
├── hpack/
│   ├── mod.zig           # HPACK module entry point
│   ├── static_table.zig  # Static table definitions
│   ├── dynamic_table.zig # Dynamic table implementation
│   └── encoding.zig      # Integer and string encoding/decoding
└── stream.zig            # Stream state and management
```


## How to Use

The refactored code maintains the same API for basic operations but provides a clearer structure. Top-level imports should come from `mod.zig`, which exports all the public interfaces:

```zig
const http2 = @import("http2/mod.zig");
const Client = http2.Client;
const HPACK = http2.HPACK;
const Stream = http2.Stream;
```
