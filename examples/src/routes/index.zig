const std = @import("std");
const zttp = @import("zttp");
const Request = zttp.Request;
const Response = zttp.Response;
const Context = zttp.Context;

pub fn get(req: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;

    const request_id = ctx.get("request_id");
    const logged_in = request_id != null;
    std.log.info("GET: request_id={?s}, logged_in={}", .{ request_id, logged_in });
    ctx.set("logged_in", if (logged_in) "true" else "false") catch {
        std.log.err("Failed to set logged_in context", .{});
        return;
    };

    var username: []const u8 = "Alice";
    if (req.query.get("username")) |query_username| {
        blk: {
            const decoded = res.allocator.alloc(u8, query_username.len) catch break :blk;
            std.mem.copyForwards(u8, decoded, query_username);
            const decoded_result = std.Uri.percentDecodeInPlace(decoded);
            if (decoded_result.len == 0) {
                res.allocator.free(decoded);
                break :blk;
            }
            username = decoded_result;
            res.allocator.free(decoded);
        }
    }
    std.log.info("GET: username={s}", .{username});
    ctx.set("username", username) catch {
        std.log.err("Failed to set username context", .{});
        return;
    };

    ctx.set("items", "[\"apple\", \"banana\"]") catch {
        std.log.err("Failed to set items context", .{});
        return;
    };
    const role = if (logged_in) "user" else "guest";
    std.log.info("GET: role={s}", .{role});
    ctx.set("role", role) catch {
        std.log.err("Failed to set role context", .{});
        return;
    };
    const show = if (req.query.get("show")) |v| v else "false";
    std.log.info("GET: show={s}", .{show});
    ctx.set("show", show) catch {
        std.log.err("Failed to set show context", .{});
        return;
    };
    const cond1 = if (req.query.get("cond1")) |v| v else "true";
    std.log.info("GET: cond1={s}", .{cond1});
    ctx.set("cond1", cond1) catch {
        std.log.err("Failed to set cond1 context", .{});
        return;
    };
    const cond2 = if (req.query.get("cond2")) |v| v else "false";
    std.log.info("GET: cond2={s}", .{cond2});
    ctx.set("cond2", cond2) catch {
        std.log.err("Failed to set cond2 context", .{});
        return;
    };
    const theme = if (req.query.get("theme")) |v| v else "default";
    std.log.info("GET: theme={s}", .{theme});
    ctx.set("theme", theme) catch {
        std.log.err("Failed to set theme context", .{});
        return;
    };

    const rendered = zttp.Template.renderTemplate(res.allocator, "src/routes/index.zmx", ctx) catch |err| {
        std.log.err("Template error: {}", .{err});
        res.setBody("Internal Server Error") catch return;
        res.status = .internal_server_error;
        return;
    };

    res.setBody(rendered) catch return;
    res.setHeader("Content-Type", "text/html") catch return;
    std.log.info("Served GET index endpoint", .{});

    std.log.info("{s}", .{@src().file});
    std.log.info("{s}", .{req.path});
}

pub fn post(req: *Request, res: *Response, ctx: *Context) void {
    res.status = .ok;

    var logged_in = false;
    var username: []const u8 = "";
    if (req.form) |form| {
        if (form.get("username")) |form_username| {
            username = form_username;
            logged_in = username.len > 0;
        }
    }
    std.log.info("POST: username={s}, logged_in={}", .{ username, logged_in });
    ctx.set("logged_in", if (logged_in) "true" else "false") catch {
        std.log.err("Failed to set logged_in context", .{});
        return;
    };

    ctx.set("username", username) catch return;
    ctx.set("items", "[\"apple\", \"banana\"]") catch return;
    ctx.set("role", if (logged_in) "user" else "guest") catch return;
    ctx.set("show", if (req.query.get("show")) |v| v else "false") catch return;
    ctx.set("cond1", if (req.query.get("cond1")) |v| v else "true") catch return;
    ctx.set("cond2", if (req.query.get("cond2")) |v| v else "false") catch return;
    ctx.set("theme", if (req.query.get("theme")) |v| v else "default") catch return;

    const rendered = zttp.Template.renderTemplate(res.allocator, "src/routes/index.zmx", ctx) catch |err| {
        std.log.err("Template error: {}", .{err});
        res.setBody("Internal Server Error") catch return;
        res.status = .internal_server_error;
        return;
    };

    res.setBody(rendered) catch return;
    res.setHeader("Content-Type", "text/html") catch return;
    std.log.info("Served POST index endpoint", .{});
}
