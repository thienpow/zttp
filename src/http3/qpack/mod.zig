// src/http3/qpack/mod.zig

const encoder = @import("encoder.zig");
const decoder = @import("decoder.zig");

pub const QpackEncoder = encoder.QpackEncoder;
pub const QpackDecoder = decoder.QpackDecoder;

// Optionally, re-export specific QPACK related types if they are defined
// within the encoder or decoder files and need to be publicly accessible.
// const types = @import("types.zig"); // Assuming a shared types file for QPACK
// pub const QpackError = types.QpackError;
