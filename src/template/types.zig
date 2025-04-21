// src/template/types.zig
const std = @import("std");
pub const TemplateError = error{
    InvalidSyntax,
    MissingEndif,
    MissingEndfor,
    MissingEndwhile,
    MissingEndblock,
    FileNotFound,
    LayoutNotFound,
    OutOfMemory,
    UnclosedTag,
    InvalidCollection,
    InvalidSetExpression,
    WhileLoopOverflow,
    ExtendsMustBeFirst,
    BlockNameMismatch,
    NestedExtendsNotSupported,
    PathResolutionError,
    ParseIntError,
    CircularInclude,
    NoContentBlock,
};

pub const CacheError = error{
    CacheNotInitialized,
    InvalidValue, // May not be needed anymore if accessCache is removed
    TokenizationFailed,
    OutOfMemory, // Often implicitly handled by allocator failures
};

// Define ComparisonData first so it can be used in Condition
pub const ComparisonData = struct {
    var_name: []const u8,
    value: []const u8,
    is_literal: bool,
};

pub const Condition = union(enum) {
    simple: []const u8,
    non_empty: []const u8,
    equals: ComparisonData,
    not_equals: ComparisonData,
    less_than: ComparisonData,
    less_than_or_equal: ComparisonData,
    greater_than: ComparisonData,
    greater_than_or_equal: ComparisonData,
    logical_and: struct { left: *const Condition, right: *const Condition },
    logical_or: struct { left: *const Condition, right: *const Condition },
};

pub const SetStmtPayload = struct {
    var_name: []const u8,
    value: []const u8,
};

pub const Token = union(enum) {
    include: []const u8,
    text: []const u8,
    variable: []const u8,
    if_start: Condition,
    elseif_stmt: Condition,
    else_stmt,
    endif_stmt,
    for_start: struct { var_name: []const u8, collection: []const u8 },
    endfor_stmt,
    while_start: Condition,
    endwhile_stmt,
    set_stmt: SetStmtPayload,
    extends: []const u8,
    block_start: []const u8,
    endblock_stmt,
    css: []const u8,
    js: []const u8,
};
