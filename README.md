const zttp = @import("zttp");
var server = try zttp.initServer(allocator, 8080);
try server.router.addRoute("GET", "/", myHandler);
try server.start();
