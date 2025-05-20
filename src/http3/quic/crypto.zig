// src/http3/quic/crypto.zig
// Cryptographic operations for QUIC protocol per RFC 9001

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.quic_crypto);

const PacketType = @import("packet.zig").PacketType;

/// Key material for a specific QUIC packet type
const KeySet = struct {
    hp_key: [16]u8, // Header protection key (AES-128-ECB)
    pp_key: [16]u8, // Packet protection key (AES-128-GCM)
    pp_iv: [12]u8, // Packet protection IV
};

/// TLS context for QUIC connection per RFC 9001, Section 5
pub const TlsContext = struct {
    allocator: Allocator,
    is_server: bool,
    handshake_complete: bool,
    initial_secret: [32]u8,
    client_secrets: struct {
        initial: [32]u8,
        handshake: [32]u8,
        zero_rtt: [32]u8,
        application: [32]u8,
    },
    server_secrets: struct {
        initial: [32]u8,
        handshake: [32]u8,
        zero_rtt: [32]u8,
        application: [32]u8,
    },
    client_keys: struct {
        initial: KeySet,
        handshake: KeySet,
        zero_rtt: KeySet,
        application: KeySet,
    },
    server_keys: struct {
        initial: KeySet,
        handshake: KeySet,
        zero_rtt: KeySet,
        application: KeySet,
    },
    handshake_state: enum { none, client_hello, server_hello, finished },

    /// Initializes a TLS context for QUIC
    pub fn init(allocator: Allocator, is_server: bool) !*TlsContext {
        const ctx = try allocator.create(TlsContext);
        errdefer allocator.destroy(ctx);

        // Derive initial secret from a fixed salt per RFC 9001, Section 5.2
        const initial_salt = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0x3b, 0xd5, 0x4b, 0x87, 0x2f, 0xe3, 0x7e, 0xf9, 0x48, 0x0b, 0x91, 0xd2, 0x60 };
        var initial_secret: [32]u8 = undefined;
        var conn_id: [8]u8 = undefined;
        std.crypto.random.bytes(&conn_id);
        try hkdfExtract(&initial_secret, &initial_salt, &conn_id);
        log.debug("Derived initial secret for conn_id", .{});

        // Create structures with runtime-mutable fields
        ctx.* = .{
            .allocator = allocator,
            .is_server = is_server,
            .handshake_complete = false,
            .initial_secret = initial_secret,
            .client_secrets = .{
                .initial = [_]u8{0} ** 32,
                .handshake = [_]u8{0} ** 32,
                .zero_rtt = [_]u8{0} ** 32,
                .application = [_]u8{0} ** 32,
            },
            .server_secrets = .{
                .initial = [_]u8{0} ** 32,
                .handshake = [_]u8{0} ** 32,
                .zero_rtt = [_]u8{0} ** 32,
                .application = [_]u8{0} ** 32,
            },
            .client_keys = .{
                .initial = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
                .handshake = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
                .zero_rtt = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
                .application = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
            },
            .server_keys = .{
                .initial = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
                .handshake = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
                .zero_rtt = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
                .application = KeySet{ .hp_key = [_]u8{0} ** 16, .pp_key = [_]u8{0} ** 16, .pp_iv = [_]u8{0} ** 12 },
            },
            .handshake_state = if (is_server) .none else .client_hello,
        };

        // Derive client and server secrets after initialization
        try deriveSecret(&ctx.client_secrets.initial, &ctx.initial_secret, "client in");
        try deriveSecret(&ctx.server_secrets.initial, &ctx.initial_secret, "server in");
        try deriveSecret(&ctx.client_secrets.handshake, &ctx.client_secrets.initial, "client hs traffic");
        try deriveSecret(&ctx.server_secrets.handshake, &ctx.server_secrets.initial, "server hs traffic");
        try deriveSecret(&ctx.client_secrets.zero_rtt, &ctx.client_secrets.initial, "client 0rtt traffic");
        try deriveSecret(&ctx.server_secrets.zero_rtt, &ctx.server_secrets.initial, "server 0rtt traffic");
        try deriveSecret(&ctx.client_secrets.application, &ctx.client_secrets.handshake, "client app traffic");
        try deriveSecret(&ctx.server_secrets.application, &ctx.server_secrets.handshake, "server app traffic");

        // Derive key sets
        try deriveKeySet(&ctx.client_keys.initial, &ctx.client_secrets.initial);
        try deriveKeySet(&ctx.server_keys.initial, &ctx.server_secrets.initial);
        try deriveKeySet(&ctx.client_keys.handshake, &ctx.client_secrets.handshake);
        try deriveKeySet(&ctx.server_keys.handshake, &ctx.server_secrets.handshake);
        try deriveKeySet(&ctx.client_keys.zero_rtt, &ctx.client_secrets.zero_rtt);
        try deriveKeySet(&ctx.server_keys.zero_rtt, &ctx.server_secrets.zero_rtt);
        try deriveKeySet(&ctx.client_keys.application, &ctx.client_secrets.application);
        try deriveKeySet(&ctx.server_keys.application, &ctx.server_secrets.application);

        log.debug("Initialized TLS context (server={})", .{is_server});
        return ctx;
    }

    /// Deinitializes TLS context and zeros sensitive data
    pub fn deinit(self: *TlsContext) void {
        std.crypto.utils.secureZero(u8, &self.initial_secret);
        inline for (.{ "initial", "handshake", "zero_rtt", "application" }) |label| {
            std.crypto.utils.secureZero(u8, &@field(self.client_secrets, label));
            std.crypto.utils.secureZero(u8, &@field(self.server_secrets, label));
            std.crypto.utils.secureZero(u8, &@field(self.client_keys, label).hp_key);
            std.crypto.utils.secureZero(u8, &@field(self.client_keys, label).pp_key);
            std.crypto.utils.secureZero(u8, &@field(self.client_keys, label).pp_iv);
            std.crypto.utils.secureZero(u8, &@field(self.server_keys, label).hp_key);
            std.crypto.utils.secureZero(u8, &@field(self.server_keys, label).pp_key);
            std.crypto.utils.secureZero(u8, &@field(self.server_keys, label).pp_iv);
        }
        self.allocator.destroy(self);
        log.debug("Deinitialized TLS context", .{});
    }
};

/// Creates a new TLS context
pub fn createTlsContext(allocator: Allocator, is_server: bool) !*TlsContext {
    return try TlsContext.init(allocator, is_server);
}

/// Destroys a TLS context
pub fn destroyTlsContext(ctx: *TlsContext) void {
    ctx.deinit();
}

/// Performs HKDF-Extract per RFC 9001, Section 5.1
fn hkdfExtract(output: []u8, salt: []const u8, input_key_material: []const u8) !void {
    if (output.len != 32) return error.InvalidOutputLength;
    if (input_key_material.len < 8 or input_key_material.len > 20) return error.InvalidConnectionId;
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(salt);
    hmac.update(input_key_material);
    hmac.final(output[0..32]);
    log.debug("Performed HKDF-Extract (input_len={d})", .{input_key_material.len});
}

/// Derives a secret using HKDF-Expand-Label per RFC 9001, Section 5.1
fn deriveSecret(output: []u8, input_secret: []const u8, label: []const u8) !void {
    if (output.len != 32 and output.len != 16 and output.len != 12) return error.InvalidOutputLength;

    // Create a temporary buffer for the "quic " prefix + label
    var quic_label_buf: [30]u8 = undefined; // Buffer for "quic " + label
    @memcpy(quic_label_buf[0..5], "quic ");
    @memcpy(quic_label_buf[5 .. 5 + label.len], label);
    const quic_label = quic_label_buf[0 .. 5 + label.len];

    var info: [32]u8 = undefined; // Max: 2 + 1 + 25 + 1 = 29 bytes
    info[0] = 0x00; // Output length
    info[1] = @as(u8, @intCast(output.len));
    info[2] = @as(u8, @intCast(quic_label.len));
    @memcpy(info[3 .. 3 + quic_label.len], quic_label);
    info[3 + quic_label.len] = 0x00; // Empty context
    const info_len = 3 + quic_label.len + 1;

    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(input_secret);
    hmac.update(info[0..info_len]);
    var full_output: [32]u8 = undefined;
    hmac.final(&full_output);
    @memcpy(output, full_output[0..output.len]);
    log.debug("Derived secret for label '{s}' (len={d})", .{ label, output.len });
}

/// Derives a key set (hp_key, pp_key, pp_iv) from a secret
fn deriveKeySet(key_set: *KeySet, secret: []const u8) !void {
    try deriveSecret(&key_set.hp_key, secret, "hp");
    try deriveSecret(&key_set.pp_key, secret, "key");
    try deriveSecret(&key_set.pp_iv, secret, "iv");
}

/// Helper struct for selecting keys based on packet type
const KeySelector = struct {
    client_keys: *const TlsContext.client_keys,
    server_keys: *const TlsContext.server_keys,
    is_server: bool,

    fn getHpKey(self: KeySelector, packet_type: PacketType) *const [16]u8 {
        const keys = if (self.is_server) self.server_keys else self.client_keys;
        return switch (packet_type) {
            .initial => &keys.initial.hp_key,
            .handshake => &keys.handshake.hp_key,
            .zero_rtt => &keys.zero_rtt.hp_key,
            .short_header => &keys.application.hp_key,
            else => &keys.application.hp_key,
        };
    }

    fn getPpKey(self: KeySelector, packet_type: PacketType) *const [16]u8 {
        const keys = if (self.is_server) self.server_keys else self.client_keys;
        return switch (packet_type) {
            .initial => &keys.initial.pp_key,
            .handshake => &keys.handshake.pp_key,
            .zero_rtt => &keys.zero_rtt.pp_key,
            .short_header => &keys.application.pp_key,
            else => &keys.application.pp_key,
        };
    }

    fn getPpIv(self: KeySelector, packet_type: PacketType) *const [12]u8 {
        const keys = if (self.is_server) self.server_keys else self.client_keys;
        return switch (packet_type) {
            .initial => &keys.initial.pp_iv,
            .handshake => &keys.handshake.pp_iv,
            .zero_rtt => &keys.zero_rtt.pp_iv,
            .short_header => &keys.application.pp_iv,
            else => &keys.application.pp_iv,
        };
    }
};

/// Derives header protection key per RFC 9001, Section 5.4
pub fn deriveHeaderProtectionKey(ctx: *TlsContext, packet_type: PacketType) *const [16]u8 {
    const selector = KeySelector{
        .client_keys = &ctx.client_keys,
        .server_keys = &ctx.server_keys,
        .is_server = ctx.is_server,
    };
    return selector.getHpKey(packet_type);
}

/// Generates header protection mask per RFC 9001, Section 5.4.1
pub fn generateHeaderProtectionMask(hp_key: []const u8, sample: []const u8, mask: []u8) !void {
    if (hp_key.len != 16 or sample.len != 16 or mask.len != 5) return error.InvalidInput;

    var key_array: [16]u8 = undefined;
    @memcpy(&key_array, hp_key);

    var sample_array: [16]u8 = undefined;
    @memcpy(&sample_array, sample);

    var aes = std.crypto.core.aes.Aes128.initEnc(key_array);
    var encrypted: [16]u8 = undefined;
    aes.encrypt(&encrypted, &sample_array);
    @memcpy(mask, encrypted[0..5]);
    log.debug("Generated header protection mask", .{});
}

/// Derives packet protection key per RFC 9001, Section 5.1
pub fn derivePacketProtectionKey(ctx: *TlsContext, packet_type: PacketType) *const [16]u8 {
    const selector = KeySelector{
        .client_keys = &ctx.client_keys,
        .server_keys = &ctx.server_keys,
        .is_server = ctx.is_server,
    };
    return selector.getPpKey(packet_type);
}

/// Derives packet protection IV per RFC 9001, Section 5.1
pub fn derivePacketProtectionIv(ctx: *TlsContext, packet_type: PacketType) *const [12]u8 {
    const selector = KeySelector{
        .client_keys = &ctx.client_keys,
        .server_keys = &ctx.server_keys,
        .is_server = ctx.is_server,
    };
    return selector.getPpIv(packet_type);
}

/// Decrypts AEAD-protected payload per RFC 9001, Section 5.3
pub fn decryptAead(
    allocator: Allocator,
    key: []const u8,
    nonce: []const u8,
    ciphertext: []const u8,
    associated_data: []const u8,
) ![]u8 {
    if (key.len != 16 or nonce.len != 12) return error.InvalidInput;
    if (ciphertext.len < 16) return error.BufferTooShort;

    const tag = ciphertext[ciphertext.len - 16 ..];
    const actual_ciphertext = ciphertext[0 .. ciphertext.len - 16];

    var gcm = try std.crypto.aead.aes_gcm.Aes128Gcm.init(key, nonce);
    const decrypted = try allocator.alloc(u8, actual_ciphertext.len);
    errdefer allocator.free(decrypted);

    try gcm.decryptAndVerify(decrypted, actual_ciphertext, tag, associated_data);
    log.debug("Decrypted payload (len={d})", .{decrypted.len});
    return decrypted;
}

/// Processes CRYPTO frame data for TLS handshake
pub fn processCryptoData(ctx: *TlsContext, data: []const u8, offset: u64) !void {
    if (offset != 0) return error.InvalidCryptoOffset;
    log.debug("Processing CRYPTO data: {} bytes at offset {}", .{ data.len, offset });

    switch (ctx.handshake_state) {
        .none => {
            if (!ctx.is_server) return error.InvalidState;
            if (data.len < 1 or data[0] != 0x01) return error.InvalidClientHello;
            ctx.handshake_state = .client_hello;
            log.debug("Processed ClientHello", .{});
        },
        .client_hello => {
            if (ctx.is_server) {
                if (data.len < 1 or data[0] != 0x02) return error.InvalidServerHello;
                ctx.handshake_state = .server_hello;
                log.debug("Processed ServerHello", .{});
            } else {
                if (data.len < 1 or data[0] != 0x0b) return error.InvalidEncryptedExtensions;
                ctx.handshake_state = .finished;
                ctx.handshake_complete = true;
                log.debug("Handshake completed (client)", .{});
            }
        },
        .server_hello => {
            if (!ctx.is_server) return error.InvalidState;
            if (data.len < 1 or data[0] != 0x14) return error.InvalidFinished;
            ctx.handshake_state = .finished;
            ctx.handshake_complete = true;
            log.debug("Handshake completed (server)", .{});
        },
        .finished => return error.HandshakeAlreadyComplete,
    }
}

/// Checks if TLS handshake is complete
pub fn isHandshakeComplete(ctx: *TlsContext) bool {
    return ctx.handshake_complete;
}

/// Generates TLS handshake data
pub fn generateTlsHandshakeData(ctx: *TlsContext, allocator: Allocator) ![]u8 {
    log.debug("Generating TLS handshake data (state={s})", .{@tagName(ctx.handshake_state)});
    const data = try allocator.alloc(u8, 128);
    errdefer allocator.free(data);

    switch (ctx.handshake_state) {
        .none => {
            if (ctx.is_server) return error.InvalidState;
            data[0] = 0x01;
            std.crypto.random.bytes(data[1..]);
            ctx.handshake_state = .client_hello;
            log.debug("Generated ClientHello", .{});
        },
        .client_hello => {
            if (ctx.is_server) {
                data[0] = 0x02;
                std.crypto.random.bytes(data[1..]);
                ctx.handshake_state = .server_hello;
                log.debug("Generated ServerHello", .{});
            } else {
                data[0] = 0x0b;
                std.crypto.random.bytes(data[1..]);
                ctx.handshake_state = .finished;
                ctx.handshake_complete = true;
                log.debug("Generated EncryptedExtensions", .{});
            }
        },
        .server_hello => {
            if (!ctx.is_server) return error.InvalidState;
            data[0] = 0x14;
            std.crypto.random.bytes(data[1..]);
            ctx.handshake_state = .finished;
            ctx.handshake_complete = true;
            log.debug("Generated Finished", .{});
        },
        .finished => return error.HandshakeAlreadyComplete,
    }

    return data;
}
