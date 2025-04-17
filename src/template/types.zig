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
};

pub const Condition = union(enum) {
    simple: []const u8,
    non_empty: []const u8,
    equals: struct { var_name: []const u8, value: []const u8 },
};

pub const SetStmtPayload = struct {
    var_name: []const u8,
    value: []const u8,
};

pub const Token = union(enum) {
    text: []const u8,
    variable: []const u8,
    if_start: Condition,
    elseif_stmt: Condition,
    else_stmt,
    endif_stmt,
    for_start: struct { var_name: []const u8, collection: []const u8 },
    endfor_stmt,
    while_start: []const u8,
    endwhile_stmt,
    set_stmt: SetStmtPayload,
    extends: []const u8,
    block_start: []const u8,
    endblock_stmt,
};
