ZTTP, async (io_uring only) http server for zig. WebSocket Ready. Multi-threaded Ready, streaming (soon)...

# TODO:
*   Implement support for HTTP/2, or HTTP/3.
*   Add handling for HTTP request body streaming instead of full buffer.
*   Enhance HTTP header parsing (e.g., folded headers, multiple headers with same name).
*   Implement support for chunked transfer encoding for responses.
*   Add more granular control over response headers, allowing duplicate headers (e.g., Set-Cookie).
*   Implement support for server-side WebSocket ping/pong initiation.
*   Add support for WebSocket extensions (e.g., permessage-deflate).
*   Implement a proper WebSocket close handshake sequence.
*   Refine WebSocket frame processing for fragmented messages.
*   Improve handling of WebSocket control frames (e.g., validating close codes).
*   Implement more sophisticated router matching (e.g., regex routes, route priorities).
*   Add nested router capability.
*   Review and refine parameter/wildcard value lifetime and allocation in the Context during route matching.
*   Provide a more flexible middleware mechanism (e.g., explicit halt of the chain, dedicated error handling middleware).
*   Implement more structured and consistent error handling across the application layers.
*   Improve logging granularity and configuration options.
*   Review ThreadPool concurrency logic for potential deadlocks, especially with dependency handling and task status updates.
*   Consider dynamic scaling of ThreadPool workers based on load.
*   Add health checks or monitoring capabilities.
*   Provide convenience functions for serving static files or templated responses directly from the Response struct.
*   Implement robust graceful shutdown, waiting for active connections and tasks to complete.
*   Review memory management practices for long-lived data stored in Context or TaskData to prevent leaks.
*   Add comprehensive unit and integration tests.
*   Implement basic security features like protection against Slowloris or other resource exhaustion attacks.
