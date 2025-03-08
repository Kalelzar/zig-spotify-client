const std = @import("std");
const meta = @import("meta.zig");

pub const ContextType = enum {
    artist,
    playlist,
    album,
    show,
    collection,
};

pub const DeviceType = enum {
    Computer,
    Smartphone,
    Speaker,
};

pub const Device = struct {
    id: ?[]const u8 = null,
    is_active: bool,
    is_private_session: bool,
    is_restricted: bool,
    name: []const u8,
    type: DeviceType,
    volume_percent: ?i8 = null,
    supports_volume: bool,
};

pub const Context = struct {
    type: ContextType,
    href: []const u8,
    external_urls: ExternalUrl,
    uri: []const u8,
};

pub const RepeatState = enum {
    off,
    track,
    context,
};

pub const ItemType = enum {
    track,
    episode,
};

pub const ExternalUrl = struct {
    spotify: []const u8,
};

pub const RestrictReason = enum {
    market,
    product,
    explicit,
};

pub const Restrictions = struct {
    reason: RestrictReason,
};

pub const ItemBase = struct {
    type: ItemType,
    duration_ms: i32,
    explicit: bool,
    external_urls: ExternalUrl,
    href: []const u8,
    id: []const u8,
    name: []const u8,
    restrictions: ?Restrictions = null,
    uri: []const u8,
};

pub const AlbumType = enum {
    album,
    single,
    compilation,
};

pub const Image = struct {
    url: []const u8,
    height: i32,
    width: i32,
};

pub const SimplifiedArtist = struct {
    external_urls: ExternalUrl,
    href: []const u8,
    id: []const u8,
    name: []const u8,
    type: ContextType,
    uri: []const u8,
};

pub const Album = struct {
    album_type: AlbumType,
    total_tracks: i32,
    available_markets: []const []const u8,
    external_urls: ExternalUrl,
    href: []const u8,
    images: []const Image,
    name: []const u8,
    release_date: []const u8,
    release_date_precision: DatePrecision,
    type: ContextType,
    uri: []const u8,
    artists: []const SimplifiedArtist,
    id: []const u8,
};

pub const ExternalId = struct {
    isrc: ?[]const u8 = null,
    ean: ?[]const u8 = null,
    upc: ?[]const u8 = null,
};

pub const Track = meta.MergeStructs(ItemBase, struct {
    album: Album,
    artists: []const SimplifiedArtist,
    preview_url: ?[]const u8,
    available_markets: ?[]const []const u8 = null,
    disc_number: i8,
    external_ids: ExternalId,
    popularity: i8,
    track_number: i16,
    is_local: bool,
});

pub const DatePrecision = enum {
    year,
    month,
    day,
};

pub const CopyrightType = enum {
    C, // Copyright
    P, // Recording (Performance) Copyright
};

pub const Copyright = struct {
    text: []const u8,
    type: CopyrightType,
};

pub const Show = struct {
    available_markets: []const []const u8,
    copyrights: []const Copyright,
    description: []const u8,
    html_description: []const u8,
    explicit: bool,
    external_urls: ExternalUrl,
    href: []const u8,
    id: []const u8,
    images: []const Image,
    is_externally_hosted: bool,
    languages: []const []const u8,
    media_type: []const u8,
    name: []const u8,
    publisher: []const u8,
    uri: []const u8,
    type: ContextType,
    total_episodes: i32,
};

pub const ResumePoint = struct {
    fully_played: bool = true,
    resume_position_ms: i64,
};

pub const Episode = meta.MergeStructs(ItemBase, struct {
    audio_preview_url: ?[]const u8 = null,
    description: []const u8,
    html_description: []const u8,
    images: []const Image,
    is_externally_hosted: bool,
    language: []const u8,
    languages: []const []const u8,
    release_date: []const u8,
    release_date_precision: DatePrecision,
    show: Show,
    resume_point: ?ResumePoint = null,
});

pub const Item = union(ItemType) {
    track: Track,
    episode: Episode,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
        const parsed = try std.json.innerParse(std.json.Value, allocator, source, options);
        if (parsed != .object) {
            return error.UnexpectedToken;
        }

        return jsonParseFromValue(allocator, parsed, options);
    }

    pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, options: std.json.ParseOptions) !@This() {
        if (source.object.get("type")) |ty| {
            var opts = options;
            opts.ignore_unknown_fields = true;
            if (std.mem.eql(u8, ty.string, "episode")) {
                return .{ .episode = try std.json.parseFromValueLeaky(Episode, allocator, source, opts) };
            } else if (std.mem.eql(u8, ty.string, "track")) {
                const track = try std.json.parseFromValueLeaky(Track, allocator, source, opts);
                return .{ .track = track };
            }
        }
        return error.MissingField;
    }
};

pub const MediaType = enum {
    track,
    episode,
    ad,
    unknown,
};

pub const Actions = struct {
    disallows: struct {
        interrupting_playback: bool = false,
        pausing: bool = false,
        resuming: bool = false,
        seeking: bool = false,
        skipping_next: bool = false,
        skipping_prev: bool = false,
        toggling_repeat_context: bool = false,
        toggling_shuffle: bool = false,
        toggling_repeat_track: bool = false,
        transferring_playback: bool = false,
    } = .{},
};

pub const State = struct {
    device: Device,
    repeat_state: RepeatState,
    shuffle_state: bool,
    smart_shuffle: bool,
    context: ?Context = null,
    timestamp: i64, // milliseconds
    progress_ms: ?i64 = null,
    is_playing: bool,
    item: Item,
    currently_playing_type: MediaType,
    actions: Actions,
};
