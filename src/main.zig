const std = @import("std");
const spotify = @import("spotify");

const Settings = struct {
    id: []const u8,
    secret: []const u8,
    refresh_token: ?[]const u8 = null,
};

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    {
        const allocator = gpa.allocator();

        const file = try std.fs.cwd().openFile("token.json", .{ .mode = .read_write });
        defer file.close();
        const file_reader = file.reader();
        var json_reader = std.json.reader(allocator, file_reader);
        defer json_reader.deinit();
        var config = try std.json.parseFromTokenSource(Settings, allocator, &json_reader, .{});
        defer config.deinit();

        var client = try spotify.Client.init(
            allocator,
            config.value.id,
            config.value.secret,
            config.value.refresh_token,
        );

        defer {
            client.deinit(allocator);
            allocator.destroy(client);
        }

        try client.auth.auth(
            allocator,
            .{
                .scopes = "user-read-playback-state",
            },
        );

        const state = try client.getPlaybackState(allocator);
        if (state) |s| {
            defer s.deinit();

            const val = try std.json.stringifyAlloc(allocator, s.value, .{ .whitespace = .indent_2 });
            defer allocator.free(val);

            std.log.info("{s}", .{val});

            config.value.refresh_token = client.auth.info.?.refresh_token;
            try file.seekTo(0);
            const file_writer = file.writer();
            try std.json.stringify(
                config.value,
                .{ .whitespace = .indent_2 },
                file_writer,
            );
        } else {
            std.log.info("NO PLAYBACK DETECTED", .{});
        }
    }
    if (gpa.detectLeaks()) {
        @panic("MEMORY LEAK DETECTED");
    }
}
