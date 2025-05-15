// src/core/tls.zig
const std = @import("std");
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

const Connection = @import("connection.zig").Connection;

const log = std.log.scoped(.tls);

/// TLS Certificate Configuration
pub const CertConfig = struct {
    cert_file: []const u8,
    key_file: []const u8,
};

/// Supported ALPN protocols
pub const Protocol = enum {
    http1, // HTTP/1.1
    h2, // HTTP/2
    h3, // HTTP/3 (QUIC)

    /// Convert protocol enum to ALPN string representation
    pub fn toAlpnString(self: Protocol) []const u8 {
        return switch (self) {
            .http1 => "http/1.1",
            .h2 => "h2",
            .h3 => "h3",
        };
    }

    /// Convert ALPN string to protocol enum
    pub fn fromAlpnString(alpn_str: []const u8) ?Protocol {
        if (std.mem.eql(u8, alpn_str, "http/1.1")) return .http1;
        if (std.mem.eql(u8, alpn_str, "h2")) return .h2;
        if (std.mem.eql(u8, alpn_str, "h3")) return .h3;
        return null;
    }
};

/// TLS context that wraps OpenSSL functionality
pub const TlsContext = struct {
    allocator: std.mem.Allocator,
    ctx: *c.SSL_CTX,
    protocols: []const Protocol,
    error_buffer: [256]u8,

    const Error = error{
        TlsInitFailed,
        CertificateLoadFailed,
        AlpnSetupFailed,
    };

    const SSL_OP_NO_SSLv2 = 1 << 24;
    const SSL_OP_NO_SSLv3 = 1 << 25;
    const SSL_OP_NO_COMPRESSION = 1 << 17;

    /// Initialize TLS context with ALPN protocols
    pub fn init(allocator: std.mem.Allocator, cert_config: CertConfig, protocols: []const Protocol) !TlsContext {
        // Initialize OpenSSL
        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_SSL_DEFAULT, null);

        // Create SSL context for TLS v1.3
        const ctx = c.SSL_CTX_new(c.TLS_method()) orelse {
            log.err("Failed to create SSL context", .{});
            return Error.TlsInitFailed;
        };

        // Set minimum TLS version (TLS 1.2)
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);

        // Set security options
        _ = c.SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

        // Load certificate and key
        if (c.SSL_CTX_use_certificate_file(ctx, cert_config.cert_file.ptr, c.SSL_FILETYPE_PEM) != 1) {
            log.err("Failed to load certificate from {s}", .{cert_config.cert_file});
            c.SSL_CTX_free(ctx);
            return Error.CertificateLoadFailed;
        }

        if (c.SSL_CTX_use_PrivateKey_file(ctx, cert_config.key_file.ptr, c.SSL_FILETYPE_PEM) != 1) {
            log.err("Failed to load private key from {s}", .{cert_config.key_file});
            c.SSL_CTX_free(ctx);
            return Error.CertificateLoadFailed;
        }

        // Setup ALPN callback and protocol list
        var tls = TlsContext{
            .allocator = allocator,
            .ctx = ctx,
            .protocols = try allocator.dupe(Protocol, protocols),
            .error_buffer = undefined,
        };

        if (protocols.len > 0) try tls.setupAlpn();

        return tls;
    }

    /// Setup ALPN (Application Layer Protocol Negotiation)
    fn setupAlpn(self: *TlsContext) !void {
        // Create protocol list for ALPN
        var alpn_list = std.ArrayList(u8).init(self.allocator);
        defer alpn_list.deinit();

        for (self.protocols) |protocol| {
            const proto_str = protocol.toAlpnString();
            try alpn_list.append(@intCast(proto_str.len));
            try alpn_list.appendSlice(proto_str);
        }

        // Set ALPN protocols
        if (c.SSL_CTX_set_alpn_protos(self.ctx, alpn_list.items.ptr, @intCast(alpn_list.items.len)) != 0) {
            log.err("Failed to set ALPN protocols", .{});
            return Error.AlpnSetupFailed;
        }

        // Set ALPN select callback
        const userDataPtr: ?*anyopaque = @ptrCast(self);
        c.SSL_CTX_set_alpn_select_cb(self.ctx, alpnSelectCallback, userDataPtr);

        log.info("ALPN setup complete with {d} protocols", .{self.protocols.len});
    }

    /// Callback for ALPN protocol selection
    fn alpnSelectCallback(
        ssl: ?*c.SSL,
        out: [*c][*c]const u8,
        outlen: [*c]u8,
        in: [*c]const u8,
        inlen: c_uint,
        arg: ?*anyopaque,
    ) callconv(.C) c_int {
        _ = ssl;
        const self: *TlsContext = @ptrCast(@alignCast(arg.?));

        var i: usize = 0;
        while (i < inlen) {
            const proto_len = @as(usize, @intCast(in[i]));
            i += 1;

            if (i + proto_len > inlen) break;

            const client_proto = in[i .. i + proto_len];

            // Check if client-offered protocol is one we support
            for (self.protocols) |our_proto| {
                const our_proto_str = our_proto.toAlpnString();
                if (proto_len == our_proto_str.len and
                    std.mem.eql(u8, client_proto[0..proto_len], our_proto_str))
                {
                    out.* = client_proto.ptr;
                    outlen.* = @intCast(proto_len);
                    return c.SSL_TLSEXT_ERR_OK;
                }
            }

            i += proto_len;
        }

        // No match found, select our first protocol
        if (self.protocols.len > 0) {
            i = 0;
            while (i < inlen) {
                const proto_len = @as(usize, @intCast(in[i]));
                i += 1;

                if (i + proto_len > inlen) break;
                const client_proto = in[i .. i + proto_len];

                log.debug("Client offered ALPN: {s}", .{client_proto[0..proto_len]});
                i += proto_len;
            }

            // Just use our first protocol
            const first_proto = self.protocols[0].toAlpnString();
            out.* = first_proto.ptr;
            outlen.* = @intCast(first_proto.len);
            return c.SSL_TLSEXT_ERR_OK;
        }

        return c.SSL_TLSEXT_ERR_NOACK;
    }

    /// Create an SSL connection from a raw socket
    pub fn createConnection(self: *const TlsContext, socket_fd: std.posix.fd_t) !*TlsConnection {
        const ssl = c.SSL_new(self.ctx) orelse {
            log.err("Failed to create SSL object", .{});
            return Error.TlsInitFailed;
        };

        // Set SSL to use socket file descriptor
        if (c.SSL_set_fd(ssl, @intCast(socket_fd)) != 1) {
            c.SSL_free(ssl);
            log.err("Failed to set SSL fd", .{});
            return Error.TlsInitFailed;
        }

        // Create connection wrapper
        const conn = try self.allocator.create(TlsConnection);
        conn.* = TlsConnection{
            .allocator = self.allocator,
            .ssl = ssl,
            .socket_fd = socket_fd,
        };

        return conn;
    }

    /// Free TLS context resources
    pub fn deinit(self: *TlsContext) void {
        c.SSL_CTX_free(self.ctx);
        self.allocator.free(self.protocols);
    }

    /// Get the last OpenSSL error as a string
    pub fn getLastErrorString(self: *TlsContext) []const u8 {
        const err = c.ERR_get_error();
        c.ERR_error_string_n(err, &self.error_buffer, self.error_buffer.len);

        const len = std.mem.len(@as([*:0]const u8, @ptrCast(&self.error_buffer)));
        return self.error_buffer[0..len];
    }
};

/// TLS Connection that wraps OpenSSL SSL object
pub const TlsConnection = struct {
    allocator: std.mem.Allocator,
    ssl: *c.SSL,
    socket_fd: std.posix.fd_t,

    const Error = error{
        HandshakeFailed,
        ReadFailed,
        WriteFailed,
        ProtocolNegotiationFailed,
    };

    /// Performs TLS handshake
    pub fn handshake(self: *TlsConnection) !void {
        const result = c.SSL_accept(self.ssl);
        if (result <= 0) {
            const err = c.SSL_get_error(self.ssl, result);
            if (err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE) {
                // Would block, caller should retry
                return error.WouldBlock;
            }

            log.err("SSL handshake failed with error: {d}", .{err});
            return Error.HandshakeFailed;
        }
    }

    /// Read encrypted data from TLS connection
    pub fn read(self: *TlsConnection, buffer: []u8) !usize {
        const result = c.SSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));
        if (result <= 0) {
            const err = c.SSL_get_error(self.ssl, result);
            if (err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE) {
                return error.WouldBlock;
            } else if (err == c.SSL_ERROR_ZERO_RETURN) {
                // Connection closed
                return 0;
            }

            log.err("SSL read failed with error: {d}", .{err});
            return Error.ReadFailed;
        }

        return @intCast(result);
    }

    /// Write encrypted data to TLS connection
    pub fn write(self: *TlsConnection, data: []const u8) !usize {
        const result = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (result <= 0) {
            const err = c.SSL_get_error(self.ssl, result);
            if (err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE) {
                return error.WouldBlock;
            }

            log.err("SSL write failed with error: {d}", .{err});
            return Error.WriteFailed;
        }

        return @intCast(result);
    }

    /// Get the negotiated ALPN protocol
    pub fn getNegotiatedProtocol(self: *TlsConnection) !Connection.Protocol {
        var data: [*c]const u8 = undefined;
        var len: c_uint = 0;

        c.SSL_get0_alpn_selected(self.ssl, &data, &len);

        if (len == 0) {
            log.warn("No ALPN protocol was negotiated", .{});
            return Connection.Protocol.http1; // Default to HTTP/1.1
        }

        const proto_str = data[0..len];
        const tls_proto = Protocol.fromAlpnString(proto_str) orelse {
            log.err("Unknown ALPN protocol: {s}", .{proto_str});
            return Error.ProtocolNegotiationFailed;
        };

        return switch (tls_proto) {
            .http1 => Connection.Protocol.http1,
            .h2 => Connection.Protocol.http2,
            .h3 => Connection.Protocol.http3,
        };
    }

    /// Close the TLS connection and free resources
    pub fn close(self: *TlsConnection) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
    }

    /// Free TLS connection resources
    pub fn deinit(self: *TlsConnection) void {
        const fd = self.socket_fd;
        self.close();
        std.posix.close(fd);
        self.allocator.destroy(self);
    }

    /// Provide a reader interface for the TLS connection
    pub fn reader(self: *TlsConnection) std.io.AnyReader {
        return std.io.AnyReader{
            .context = self,
            .readFn = readerRead,
        };
    }

    fn readerRead(context: *const anyopaque, buffer: []u8) !usize {
        const self: *TlsConnection = @ptrCast(@constCast(@alignCast(context)));
        return try self.read(buffer);
    }

    /// Provide a writer interface for the TLS connection
    pub fn writer(self: *TlsConnection) std.io.AnyWriter {
        return std.io.AnyWriter{
            .context = self,
            .writeFn = writerWrite,
        };
    }

    fn writerWrite(context: *const anyopaque, bytes: []const u8) !usize {
        const self: *TlsConnection = @ptrCast(@constCast(@alignCast(context)));
        return try self.write(bytes);
    }
};
