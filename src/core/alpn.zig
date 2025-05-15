// src/core/alpn.zig
const std = @import("std");
const tls = @import("tls.zig");
const Protocol = tls.Protocol;

const Connection = @import("connection.zig").Connection;
const http2 = @import("../http2/mod.zig");
const http3 = @import("../http3/mod.zig");

const log = std.log.scoped(.alpn);

/// Result of protocol negotiation
pub const NegotiationResult = struct {
    protocol: Protocol,
    connection: ?*Connection, // New connection if protocol requires it
    upgrade_required: bool, // Whether protocol upgrade handling is needed
};

/// Handler settings
pub const Settings = struct {
    http2_settings: http2.Settings = .{},
    http3_settings: http3.Settings = .{},
    enable_http2: bool = true,
    enable_http3: bool = false,
};

/// ALPN handler that manages protocol selection and upgrade
pub const AlpnHandler = struct {
    allocator: std.mem.Allocator,
    settings: Settings,

    /// Initialize ALPN handler with settings
    pub fn init(allocator: std.mem.Allocator, settings: Settings) AlpnHandler {
        return AlpnHandler{
            .allocator = allocator,
            .settings = settings,
        };
    }

    /// Deinitialize ALPN handler
    pub fn deinit(self: *AlpnHandler) void {
        _ = self;
        // Nothing to clean up currently
    }

    /// Get supported protocols based on settings
    pub fn getSupportedProtocols(self: *const AlpnHandler) []const Protocol {
        const protocols = self.allocator.alloc(Protocol, @intFromBool(true) + // HTTP/1.1 always supported
            @intFromBool(self.settings.enable_http2) +
            @intFromBool(self.settings.enable_http3)) catch |err| {
            log.err("Failed to allocate protocol list: {}", .{err});
            @panic("Out of memory");
        };

        var index: usize = 0;
        protocols[index] = .http1;
        index += 1;

        if (self.settings.enable_http2) {
            protocols[index] = .h2;
            index += 1;
        }

        if (self.settings.enable_http3) {
            protocols[index] = .h3;
            index += 1;
        }

        return protocols;
    }

    /// Handle protocol negotiation result for a TLS connection
    pub fn handleNegotiation(self: *AlpnHandler, tls_conn: *tls.TlsConnection) !NegotiationResult {
        // Get negotiated protocol from TLS connection
        const protocol = tls_conn.getNegotiatedProtocol() catch {
            log.warn("Protocol negotiation failed, defaulting to HTTP/1.1", .{});
            return NegotiationResult{
                .protocol = .http1,
                .connection = null,
                .upgrade_required = false,
            };
        };

        log.info("Negotiated protocol: {s}", .{@tagName(protocol)});

        switch (protocol) {
            .http1 => {
                // HTTP/1.1 doesn't need special handling
                return NegotiationResult{
                    .protocol = .http1,
                    .connection = null,
                    .upgrade_required = false,
                };
            },
            .h2 => {
                if (self.settings.enable_http2) {
                    // Mark for HTTP/2 upgrade
                    return NegotiationResult{
                        .protocol = .h2,
                        .connection = null,
                        .upgrade_required = true,
                    };
                } else {
                    log.warn("HTTP/2 negotiated but disabled in settings", .{});
                    return NegotiationResult{
                        .protocol = .http1,
                        .connection = null,
                        .upgrade_required = false,
                    };
                }
            },
            .h3 => {
                if (self.settings.enable_http3) {
                    // HTTP/3 needs a new connection type
                    log.debug("Creating HTTP/3 connection", .{});
                    // This would be implemented in your HTTP/3 module
                    return NegotiationResult{
                        .protocol = .h3,
                        .connection = null, // HTTP/3 uses the existing QUIC connection
                        .upgrade_required = true,
                    };
                } else {
                    log.warn("HTTP/3 negotiated but disabled in settings", .{});
                    return NegotiationResult{
                        .protocol = .http1,
                        .connection = null,
                        .upgrade_required = false,
                    };
                }
            },
        }
    }

    /// Handle HTTP/1.1 Connection header with Upgrade for HTTP/2
    pub fn handleConnectionUpgrade(self: *AlpnHandler, upgrade_protocol: []const u8) !NegotiationResult {
        if (std.mem.eql(u8, upgrade_protocol, "h2c")) {
            // HTTP/2 cleartext upgrade
            if (self.settings.enable_http2) {
                log.info("Handling HTTP/2 upgrade via Connection header", .{});
                return NegotiationResult{
                    .protocol = .h2,
                    .connection = null,
                    .upgrade_required = true,
                };
            } else {
                log.warn("HTTP/2 upgrade requested but disabled in settings", .{});
            }
        }

        // Default to HTTP/1.1 if no supported upgrade
        return NegotiationResult{
            .protocol = .http1,
            .connection = null,
            .upgrade_required = false,
        };
    }

    /// Process Alt-Svc header for advertising HTTP/3
    pub fn processAltSvcHeader(self: *AlpnHandler, headers: *std.StringHashMap([]const u8)) !void {
        if (self.settings.enable_http3) {
            try headers.put("Alt-Svc", "h3=\":443\"; ma=3600");
        }
    }

    /// Upgrade a connection to HTTP/2
    pub fn upgradeToHttp2(self: *AlpnHandler, server_conn: *Connection, settings_header: ?[]const u8) !void {
        // Example implementation - actual implementation would initialize HTTP/2 state
        log.info("Upgrading connection to HTTP/2", .{});

        // Parse HTTP/2 settings from header if present
        const http2_settings = self.settings.http2_settings;
        if (settings_header) |settings| {
            log.debug("HTTP/2 settings header present, length: {d}", .{settings.len});
            // Parse settings header (implementation depends on your HTTP/2 module)
        }

        // Initialize HTTP/2 connection state
        try server_conn.initHttp2(http2_settings);
    }

    /// Upgrade a connection to HTTP/3
    pub fn upgradeToHttp3(
        self: *AlpnHandler,
        quic_conn: *Connection,
    ) !void {
        // Example implementation - actual implementation would initialize HTTP/3 state
        log.info("Upgrading connection to HTTP/3", .{});

        // Initialize HTTP/3 connection state using QUIC
        try quic_conn.initHttp3(self.settings.http3_settings);
    }
};
