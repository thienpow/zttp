// src/server.zig
const std = @import("std");
const Context = @import("context.zig").Context;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const StatusCode = @import("response.zig").StatusCode;
const ThreadPool = @import("pool.zig").ThreadPool;
const HandlerFn = @import("router.zig").HandlerFn;
const MiddlewareFn = @import("router.zig").MiddlewareFn;
const NextFn = @import("router.zig").NextFn;
const Router = @import("router.zig").Router;
const HttpMethod = @import("zttp.zig").HttpMethod;
const Template = @import("template/main.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    listener: ?std.net.Server,
    port: u16,
    running: bool,
    router: Router,
    pool: *ThreadPool,

    pub fn init(allocator: std.mem.Allocator, port: u16, pool: *ThreadPool) Server {
        Template.initTemplateCache(allocator) catch |err| {
            std.log.err("Failed to initialize template cache: {}", .{err});
            @panic("Template cache initialization failed");
        };
        return .{
            .allocator = allocator,
            .listener = null,
            .port = port,
            .running = false,
            .router = Router.init(allocator),
            .pool = pool,
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.listener) |*listener| {
            listener.deinit();
        }
        self.router.deinit();
        Template.deinitTemplateCache();
    }

    pub fn route(self: *Server, module_name: []const u8, method: HttpMethod, path: []const u8, handler: HandlerFn, template_path: []const u8) !void {
        try self.router.add(module_name, method, path, handler, template_path);
    }

    pub fn use(self: *Server, middleware: MiddlewareFn) !void {
        try self.router.use(middleware);
    }

    pub fn start(self: *Server) !void {
        if (self.running) return error.AlreadyRunning;

        const address = try std.net.Address.parseIp("0.0.0.0", self.port);
        self.listener = try address.listen(.{ .reuse_address = true });
        self.running = true;

        std.log.info("Server listening on 0.0.0.0:{d}", .{self.port});

        while (self.running) {
            const conn = self.listener.?.accept() catch |err| {
                std.log.err("Failed to accept connection: {}", .{err});
                continue;
            };
            const task_id = try self.pool.schedule(
                handleConnection,
                ConnectionTask{ .server = self, .conn = conn },
                null,
                5,
                null,
                0,
                0,
                null,
                null,
            );
            _ = task_id;
            //std.log.debug("Scheduled connection handling task: {d}", .{task_id});
        }
    }

    const ConnectionTask = struct {
        server: *Server,
        conn: std.net.Server.Connection,
    };

    fn handleConnection(task: ConnectionTask, result: *ThreadPool.TaskResult) void {
        defer task.conn.stream.close();
        var arena = std.heap.ArenaAllocator.init(task.server.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        var buffer: [65536]u8 = undefined;
        const bytes_read = task.conn.stream.read(&buffer) catch |err| {
            std.log.err("Failed to read request: {}", .{err});
            result.success = false;
            return;
        };
        if (bytes_read == 0) {
            result.success = true;
            return;
        }

        var req = Request.parse(alloc, buffer[0..bytes_read]) catch |err| {
            std.log.err("Failed to parse request: {}", .{err});
            sendError(task.conn.stream, alloc, .bad_request, "Invalid Request");
            result.success = false;
            return;
        };
        var res = Response.init(alloc);
        var ctx = Context.init(alloc);

        res.setHeader("Server", "zig-http/0.1") catch {
            sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
            result.success = false;
            return;
        };

        const keep_alive = req.isKeepAlive();
        if (keep_alive) {
            res.setHeader("Connection", "keep-alive") catch {};
        } else {
            res.setHeader("Connection", "close") catch {};
        }

        const middlewares = task.server.router.getMiddlewares();
        if (middlewares.len > 0) {
            // Store MiddlewareContext in ctx
            const middleware_context = MiddlewareContext{
                .middlewares = middlewares,
                .index = 0,
                .server = task.server,
            };
            const context_ptr = alloc.create(MiddlewareContext) catch |err| {
                std.log.err("Failed to allocate MiddlewareContext: {}", .{err});
                sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
                result.success = false;
                return;
            };
            context_ptr.* = middleware_context;
            const context_addr = std.fmt.allocPrint(alloc, "{x}", .{@intFromPtr(context_ptr)}) catch |err| {
                std.log.err("Failed to format MiddlewareContext address: {}", .{err});
                sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
                result.success = false;
                return;
            };
            ctx.set("middleware_context", context_addr) catch |err| {
                std.log.err("Failed to set middleware_context in ctx: {}", .{err});
                sendError(task.conn.stream, alloc, .internal_server_error, "Server Error");
                alloc.free(context_addr);
                result.success = false;
                return;
            };
            callNext(&req, &res, &ctx);
        } else {
            const handler = task.server.router.getHandler(req.method, req.path, &ctx) orelse notFound;
            handler(&req, &res, &ctx);
        }

        const template = task.server.router.getTemplate(req.method, req.path);

        if (template) |t| {
            const rendered = Template.renderTemplate(res.allocator, t, &ctx) catch |err| {
                std.log.err("Template error: {}", .{err});
                res.setBody("Internal Server Error") catch return;
                res.status = .internal_server_error;
                return;
            };

            res.setBody(rendered) catch return;
            res.setHeader("Content-Type", "text/html") catch return;
        }

        res.send(task.conn.stream) catch |err| {
            std.log.err("Failed to send response: {}", .{err});
            result.success = false;
            return;
        };

        result.success = true;
    }

    const MiddlewareContext = struct {
        middlewares: []const MiddlewareFn,
        index: usize,
        server: *Server,
    };

    fn callNext(req: *Request, res: *Response, ctx: *Context) void {
        const context_addr = ctx.get("middleware_context") orelse {
            std.log.err("Middleware context not found", .{});
            return;
        };
        const context_ptr = @as(*MiddlewareContext, @ptrFromInt(
            std.fmt.parseInt(usize, context_addr, 16) catch {
                std.log.err("Invalid middleware context address", .{});
                return;
            },
        ));
        if (context_ptr.index < context_ptr.middlewares.len) {
            const mw = context_ptr.middlewares[context_ptr.index];
            context_ptr.index += 1;
            mw(req, res, ctx, &callNext);
        } else {
            const handler = context_ptr.server.router.getHandler(req.method, req.path, ctx) orelse notFound;
            handler(req, res, ctx);
        }
    }

    fn sendError(stream: std.net.Stream, alloc: std.mem.Allocator, status: StatusCode, msg: []const u8) void {
        var res = Response.init(alloc);
        defer res.deinit();
        res.status = status;
        res.setBody(msg) catch return;
        res.setHeader("Content-Type", "text/plain") catch return;
        res.send(stream) catch return;
    }

    fn notFound(_: *Request, res: *Response, _: *Context) void {
        res.status = .not_found;
        res.setBody("Not Found") catch return;
        res.setHeader("Content-Type", "text/plain") catch return;
    }
};

pub fn initServer(allocator: std.mem.Allocator, port: u16, pool: *ThreadPool) Server {
    return Server.init(allocator, port, pool);
}
