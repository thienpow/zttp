ZTTP, async (io_uring only) http server for zig. WebSocket Ready. Multi-threaded Ready, streaming (soon)...

# TODO:
*   Implement support for HTTP/2, or HTTP/3.
*   Add handling for HTTP request body streaming instead of full buffer.
*   Implement support for chunked transfer encoding for responses.
*   Provide convenience functions for serving static files or templated responses directly from the Response struct.

*   Implement more sophisticated router matching (e.g., regex routes, route priorities).
*   Add nested router capability.
*   Review and refine parameter/wildcard value lifetime and allocation in the Context during route matching.

*   Add health checks or monitoring capabilities.
*   Implement robust graceful shutdown, waiting for active connections and tasks to complete.
*   Add comprehensive unit and integration tests.
