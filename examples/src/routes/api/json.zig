const zttp = @import("zttp");

pub const method = "GET";
pub const path = "/api/json";

pub fn handler(req: *zttp.Request, res: *zttp.Response, ctx: *zttp.Context) void {
    _ = req;
    _ = ctx;
    res.status = .ok;
    res.setJson(.{ .message = "JSON API endpoint" }) catch return;
}
