//! Minimal Shadowsocks 2022 example.
//!
//! Server mode runs an SS2022 inbound that forwards directly. Client mode runs
//! a SOCKS5 inbound whose outbound is an SS2022 client.

const std = @import("std");
const marmo = @import("marmo");

const default_method = "2022-blake3-aes-128-gcm";
const demo_password = "MDEyMzQ1Njc4OWFiY2RlZg==";

const Mode = enum { client, server };

const Options = struct {
    mode: Mode = .server,
    listen: []const u8 = "127.0.0.1:8388",
    server: []const u8 = "127.0.0.1:8388",
    method: []const u8 = default_method,
    password: []const u8 = demo_password,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const options = parseOptions(args) catch {
        usage();
        return error.InvalidArguments;
    };

    const config = switch (options.mode) {
        .server => marmo.Config{
            .inbounds = &.{
                .{
                    .tag = "ss-in",
                    .protocol = .shadowsocks,
                    .listen = options.listen,
                    .method = options.method,
                    .password = options.password,
                },
            },
            .route = .{ .final = "direct" },
        },
        .client => marmo.Config{
            .inbounds = &.{
                .{ .tag = "socks", .protocol = .socks5, .listen = options.listen },
            },
            .outbounds = &.{
                .{
                    .tag = "ss-out",
                    .protocol = .shadowsocks,
                    .server = options.server,
                    .method = options.method,
                    .password = options.password,
                },
            },
            .route = .{ .final = "ss-out" },
        },
    };

    var diagnostic: marmo.Diagnostic = .{};
    var instance = marmo.Instance.init(init.gpa, init.io, config, &diagnostic) catch |err| {
        std.debug.print("config error: {s}\n", .{diagnostic.message()});
        return err;
    };
    defer instance.deinit();

    try instance.start();
    const tag = switch (options.mode) {
        .server => "ss-in",
        .client => "socks",
    };
    const endpoint = instance.inboundEndpoint(tag) orelse return error.NoListener;
    std.debug.print("marmo {s} listening on {f}; press Ctrl-C to stop\n", .{
        @tagName(options.mode),
        endpoint,
    });

    try instance.wait();
}

fn parseOptions(args: []const []const u8) !Options {
    var options: Options = .{};
    if (args.len < 2) return error.InvalidArguments;

    options.mode = std.meta.stringToEnum(Mode, args[1]) orelse
        return error.InvalidArguments;
    options.listen = switch (options.mode) {
        .server => "127.0.0.1:8388",
        .client => "127.0.0.1:1080",
    };

    var index: usize = 2;
    while (index < args.len) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--listen")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.listen = args[index];
        } else if (std.mem.eql(u8, argument, "--server")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.server = args[index];
        } else if (std.mem.eql(u8, argument, "--method")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.method = args[index];
        } else if (std.mem.eql(u8, argument, "--password")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.password = args[index];
        } else {
            return error.InvalidArguments;
        }
        index += 1;
    }
    return options;
}

fn usage() void {
    std.debug.print(
        \\usage: marmo-ss2022-example <server|client> [options]
        \\
        \\  --listen <addr>    inbound address (default 127.0.0.1:8388, client 1080)
        \\  --server <addr>    SS2022 server address for client mode
        \\  --method <name>    default {s}
        \\  --password <b64>   base64 PSK (demo key is public; do not use in production)
        \\
    , .{default_method});
}
