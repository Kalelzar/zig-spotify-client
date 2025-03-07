const std = @import("std");

// Check if a given type is a struct.
pub fn isStruct(comptime Type: type) bool {
    return switch (@typeInfo(Type)) {
        .@"struct" => true,
        else => false,
    };
}

pub fn ensureStruct(comptime Type: type) void {
    if (!isStruct(Type)) {
        @compileError("Only structs are supported");
    }
}

// Merge two structs into a single type.
// NOTE: This discards any declarations they have (fn, var, etc...)
pub fn MergeStructs(comptime Base: type, comptime Child: type) type {
    const base_info = @typeInfo(Base);
    const child_info = @typeInfo(Child);

    ensureStruct(Base);
    ensureStruct(Child);

    var fields: []const std.builtin.Type.StructField = base_info.@"struct".fields;

    fields = fields ++ child_info.@"struct".fields;

    return @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .fields = fields,
            .decls = &.{},
            .is_tuple = false,
        },
    });
}
