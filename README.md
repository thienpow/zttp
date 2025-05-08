ZTTP, async (io_uring only) http server for zig. WebSocket Ready. Multi-threaded Ready, streaming (soon)...

Credits:
*   The inspiration for building a comprehensive web framework in Zig, particularly the concept of integrating with modern frontend approaches like HTMX, is attributed to the Jetzig framework ([https://github.com/jetzig-framework/jetzig](https://github.com/jetzig-framework/jetzig)) and the pioneering work of its core contributor, @bobf. While no code was directly copied, this project's broader goal was shaped by Jetzig's innovative approach to building web applications in Zig.
*   Async I/O backend inspired by the `ourio` project ([https://github.com/rockorager/ourio](https://github.com/rockorager/ourio)) by Tim Culverhouse (@rockorager). Please see `LICENSE.md` for full license details.

# TODO:
*   Implement support for HTTP/3.(drafting...)

*   Implement more sophisticated router matching (e.g., regex routes, route priorities).
*   Add nested router capability.
*   Review and refine parameter/wildcard value lifetime and allocation in the Context during route matching.

*   Add health checks or monitoring capabilities.
*   Implement robust graceful shutdown, waiting for active connections and tasks to complete.
*   Add comprehensive unit and integration tests.
