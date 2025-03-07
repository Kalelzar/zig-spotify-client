const std = @import("std");
const playback = @import("playback.zig");

//FIXME: This should be configurable to allow for integration tests with a mock client eventually.
const spotify_base_uri = "https://api.spotify.com/v1";

pub const ErrorResponse = struct {
    @"error": struct {
        status: i32,
        message: []const u8,
    },
};

const Client = @This();

id: []const u8,
secret: []const u8,
auth: Auth,
http: std.http.Client,

pub fn init(allocator: std.mem.Allocator, id: []const u8, secret: []const u8, refresh_token: ?[]const u8) !*Client {
    const client = try allocator.create(Client);
    const auth = try Auth.init(
        client,
        allocator,
        refresh_token,
    );

    const http_client = std.http.Client{ .allocator = allocator };

    client.* = .{
        .auth = auth,
        .id = id,
        .secret = secret,
        .http = http_client,
    };

    return client;
}

pub fn deinit(self: *Client, allocator: std.mem.Allocator) void {
    self.http.deinit();
    self.auth.deinit(allocator);
}

pub fn getPlaybackState(self: *Client, allocator: std.mem.Allocator) !?std.json.Parsed(playback.State) {
    //FIXME: Validate scopes

    var server_headers: [4096]u8 = undefined;

    const token = try self.auth.token(allocator);
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
    defer allocator.free(auth_header);
    const api_uri = spotify_base_uri ++ "/me/player?additional_types=track,episode";
    const uri = try std.Uri.parse(api_uri);

    var request = try self.http.open(.GET, uri, .{
        .server_header_buffer = &server_headers,
        .headers = .{
            .authorization = .{ .override = auth_header },
        },
    });

    defer request.deinit();
    try request.send();
    try request.finish();
    try request.wait();

    const request_reader = request.reader();
    var json_reader = std.json.reader(allocator, request_reader);
    defer json_reader.deinit();

    if (request.response.status == .ok) {
        const out = try std.json.parseFromTokenSource(playback.State, allocator, &json_reader, .{ .ignore_unknown_fields = true });
        return out;
    } else if (request.response.status == .no_content) {
        return null;
    }

    const out = try std.json.parseFromTokenSource(ErrorResponse, allocator, &json_reader, .{});
    defer out.deinit();
    std.log.err("Failed to retrieve current player state: ({}) {s}", .{ out.value.@"error".status, out.value.@"error".message });
    return error.BadRequest;
}

const Auth = struct {
    clock_skew: i64 = 30,
    state: []const u8,
    base_uri: []const u8 = "127.0.0.1",
    route: []const u8 = "/callback",
    port: u16 = 9999,
    client: *Client,
    last_refresh: i64 = 0,

    info: ?Info = null,

    pub const Info = struct {
        access_token: ?[]const u8 = null,
        token_type: []const u8, // Always 'Bearer'.
        scope: ?[]const u8 = null,
        expires_in: i32,
        refresh_token: ?[]const u8 = null,

        pub fn dupe(self: *const Info, allocator: std.mem.Allocator) !Info {
            const at = if (self.access_token) |tk| try allocator.dupe(u8, tk) else null;
            errdefer if (at) |s| allocator.free(s);
            const tt = try allocator.dupe(u8, self.token_type);
            errdefer allocator.free(tt);
            const sc = if (self.scope) |scope| try allocator.dupe(u8, scope) else null;
            errdefer if (sc) |s| allocator.free(s);
            const rt = if (self.refresh_token) |tk| try allocator.dupe(u8, tk) else null;
            errdefer if (rt) |s| allocator.free(s);
            return .{
                .access_token = at,
                .token_type = tt,
                .scope = sc,
                .expires_in = self.expires_in,
                .refresh_token = rt,
            };
        }

        pub fn deinit(self: *Info, allocator: std.mem.Allocator) void {
            if (self.access_token) |access_token|
                allocator.free(access_token);
            allocator.free(self.token_type);
            if (self.scope) |scope|
                allocator.free(scope);
            if (self.refresh_token) |refresh_token|
                allocator.free(refresh_token);
        }
    };

    pub const AuthErrorResponse = struct {
        @"error": []const u8,
        error_description: ?[]const u8 = null,
    };

    pub fn init(parent: *Client, allocator: std.mem.Allocator, refresh_token: ?[]const u8) !Auth {
        const state = blk: {
            const bytes = try allocator.alloc(u8, 32);
            defer allocator.free(bytes);
            std.crypto.random.bytes(bytes);
            const size = std.base64.standard_no_pad.Encoder.calcSize(bytes.len);
            const out = try allocator.alloc(u8, size);
            defer allocator.free(out);
            const b64 = std.base64.standard_no_pad.Encoder.encode(out, bytes);
            const comp = std.Uri.Component{
                .raw = b64,
            };
            break :blk try std.fmt.allocPrint(allocator, "{%}", .{comp});
        };
        errdefer allocator.free(state);

        const token_type = try allocator.dupe(u8, "Bearer");
        errdefer allocator.free(token_type);
        const rt = if (refresh_token) |tk| try allocator.dupe(u8, tk) else null;
        errdefer if (rt) |t| allocator.free(t);
        const info = Info{
            .refresh_token = rt,
            .token_type = token_type,
            .expires_in = 0,
        };
        return .{
            .client = parent, // This assumes that an Auth is owned by a Client and will never outlive it. Don't lie to it.
            .info = info,
            .state = state,
        };
    }

    pub fn deinit(self: *Auth, allocator: std.mem.Allocator) void {
        if (self.info) |_|
            self.info.?.deinit(allocator);
        allocator.free(self.state);
    }

    pub fn token(self: *Auth, allocator: std.mem.Allocator) ![]const u8 {
        const info = blk: {
            if (self.info) |info| {
                break :blk info;
            } else {
                std.log.err("You need to call .auth() first!", .{});
                return error.NotAuthorized;
            }
        };

        _ = blk: {
            if (info.access_token) |tk| {
                break :blk tk;
            } else {
                if (info.refresh_token) |_| {
                    try self.refresh(allocator);
                } else {
                    std.log.err("Botched token refresh. You need to call .auth() first!", .{});
                    return error.RefreshFailure;
                }
            }
        };

        if (info.expires_in + self.last_refresh < std.time.timestamp() - self.clock_skew) {
            std.log.info("The token has 'expired'. We need to refresh it. {}", .{info.expires_in});
            try self.refresh(allocator);
        }

        return self.info.?.access_token orelse unreachable;
    }

    fn refresh(self: *Auth, allocator: std.mem.Allocator) !void {
        const refresh_token = blk: {
            if (self.info) |info| {
                if (info.refresh_token) |refresh_token| {
                    break :blk refresh_token;
                }
            }
            std.log.err("No refresh token available. Run .auth()!", .{});
            return error.NoRefreshToken;
        };

        const body = try std.fmt.allocPrint(
            allocator,
            "grant_type=refresh_token&refresh_token={?s}",
            .{refresh_token},
        );
        defer allocator.free(body);

        const info = try self.send_request(allocator, body);
        if (info.refresh_token) |_| {
            self.info.?.deinit(allocator);
            self.info.? = info;
        } else {
            var old_info = self.info.?;
            defer old_info.deinit(allocator);
            self.info.? = info;
            self.info.?.refresh_token = try allocator.dupe(u8, refresh_token);
        }
        self.last_refresh = std.time.timestamp();
    }

    fn basic_header(self: *const Auth, allocator: std.mem.Allocator) ![]const u8 {
        const source = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ self.client.id, self.client.secret });
        defer allocator.free(source);
        const size = std.base64.standard.Encoder.calcSize(source.len);
        const dest = try allocator.alloc(u8, size);
        defer allocator.free(dest);
        const cred = std.base64.standard.Encoder.encode(dest, source);
        return std.fmt.allocPrint(allocator, "Basic {s}", .{cred});
    }

    pub fn auth(self: *Auth, allocator: std.mem.Allocator, options: struct {
        scopes: []const u8 = "",
        show_dialog: bool = false,
    }) !void {
        if (self.info) |info| {
            if (info.access_token) |_| {
                return; // FIXME: We should probably check if new scopes are being requested since that would be a legitimate use case.
            } else if (info.refresh_token) |_| {
                try self.refresh(allocator);
                return;
            }
        }
        const uri = try std.fmt.allocPrint(allocator, "http://{s}:{}{s}", .{ self.base_uri, self.port, self.route });
        defer allocator.free(uri);

        const target = try std.fmt.allocPrint(
            allocator,
            "https://accounts.spotify.com/authorize?response_type=code&client_id={s}&scope={s}&redirect_uri={%}&state={s}&show_dialog={}",
            .{
                self.client.id,
                options.scopes,
                std.Uri.Component{ .raw = uri },
                self.state,
                options.show_dialog,
            },
        );
        defer allocator.free(target);

        std.log.info("You need to navigate to '{s}' in order to accept the auth request.", .{target});

        const code = try self.getAuthCode(allocator);
        defer allocator.free(code);
        const new_info = try self.codeExchange(allocator, code, uri);
        if (self.info) |_| {
            self.info.?.deinit(allocator);
        }
        self.info = new_info;
        self.last_refresh = std.time.timestamp();
    }

    fn codeExchange(self: *Auth, allocator: std.mem.Allocator, code: []const u8, redirect_uri: []const u8) !Info {
        const body = try std.fmt.allocPrint(
            allocator,
            "grant_type=authorization_code&code={s}&redirect_uri={s}",
            .{ code, redirect_uri },
        );
        defer allocator.free(body);

        return self.send_request(allocator, body);
    }

    fn send_request(self: *Auth, allocator: std.mem.Allocator, body: []const u8) !Info {
        const uri = try std.Uri.parse("https://accounts.spotify.com/api/token");
        const basic_auth_header = try self.basic_header(allocator);
        defer allocator.free(basic_auth_header);

        var server_headers: [4096]u8 = undefined;

        var request = try self.client.http.open(.POST, uri, .{
            .server_header_buffer = &server_headers,
            .headers = .{
                .authorization = .{ .override = basic_auth_header },
                .content_type = .{ .override = "application/x-www-form-urlencoded" },
            },
        });
        defer request.deinit();
        request.transfer_encoding = .{ .content_length = body.len };
        try request.send();
        try request.writeAll(body);
        try request.finish();
        try request.wait();

        const request_reader = request.reader();
        var json_reader = std.json.reader(allocator, request_reader);
        defer json_reader.deinit();

        if (request.response.status != .ok) {
            const out = try std.json.parseFromTokenSource(AuthErrorResponse, allocator, &json_reader, .{});
            defer out.deinit();
            std.log.err("Failed to exchange auth code for token: ({s}) {s}", .{ out.value.@"error", out.value.error_description orelse "Unknown" });
            return error.BadAuthRequest;
        }

        const out = try std.json.parseFromTokenSource(Info, allocator, &json_reader, .{});
        defer out.deinit();
        return out.value.dupe(allocator);
    }

    const AuthError = error{
        StateMismatch,
        MissingState,
        UserRefused,
        MissingExpectedParameters,
        MissingQueryParameters,
    };

    const AuthCodeError = std.net.Stream.ReadError ||
        std.net.Server.AcceptError ||
        std.net.IPv4ParseError ||
        std.net.Address.ListenError ||
        AuthError ||
        QueryParseError ||
        error{
            OutOfMemory,
            StreamTooLong,
        };

    fn getAuthCode(self: *Auth, allocator: std.mem.Allocator) AuthCodeError![]const u8 {
        const localhost = try std.net.Address.parseIp4(self.base_uri, self.port);
        var server = try localhost.listen(.{});
        defer server.deinit();

        var client = try server.accept();
        defer client.stream.close();
        const reader = client.stream.reader();
        const response = try reader.readAllAlloc(allocator, 4 * 1024 * 1024);
        defer allocator.free(response);

        const codeOrError = blk: {
            const has_query = std.mem.indexOf(u8, response, "?");
            if (has_query) |begin_query| {
                const end_query = std.mem.indexOfScalar(u8, response[begin_query..], ' ').? + begin_query;

                const query_string = response[begin_query + 1 .. end_query];
                var query = try yoinkQueryParams(allocator, query_string);
                defer query.deinit(allocator);
                if (query.get("state")) |res_state| {
                    if (!std.mem.eql(u8, res_state, self.state)) {
                        std.log.err("State didn't match what we send.", .{});
                        break :blk AuthError.StateMismatch;
                    }
                } else {
                    std.log.err("Callback didn't pass back state.", .{});
                    break :blk AuthError.MissingState;
                }
                if (query.get("code")) |code| {
                    break :blk allocator.dupe(u8, code);
                } else if (query.get("error")) |err| {
                    std.log.err("User refused to authorize: {s}", .{err});
                    break :blk AuthError.UserRefused;
                } else {
                    std.log.err("Could not find standard Authorization Code parameters (code/error). Try again.", .{});
                    break :blk AuthError.MissingExpectedParameters;
                }
            } else {
                std.log.err("Missing query paramaters. Try again.", .{});
                break :blk AuthError.MissingQueryParameters;
            }
        };

        return codeOrError;
    }

    const QueryParseError = error{
        MalformedQuery,
    };

    fn yoinkQueryParams(allocator: std.mem.Allocator, query: []const u8) (QueryParseError || error{OutOfMemory})!std.StringHashMapUnmanaged([]const u8) {
        var map = std.StringHashMapUnmanaged([]const u8){};
        errdefer map.deinit(allocator);
        var it =
            std.mem.splitScalar(u8, query, '&');
        while (it.next()) |param| {
            const sep = std.mem.indexOfScalar(u8, param, '=') orelse return QueryParseError.MalformedQuery;
            const key = param[0..sep];
            const value = param[sep + 1 ..];
            try map.put(allocator, key, value);
        }
        return map;
    }
};
