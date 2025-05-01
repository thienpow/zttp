pub const log = @import("logger.zig").log;
pub const htmx = @import("htmx.zig").htmx;
pub const static = @import("static.zig").static;

const middleware = @import("middleware.zig");
pub const MiddlewareContext = middleware.MiddlewareContext;
pub const executeChain = middleware.executeChain;
pub const callNextMiddleware = middleware.callNextMiddleware;
