//! Minimal VLESS example.
//!
//! Server mode runs a VLESS inbound over TLS that forwards directly. Client
//! mode runs a SOCKS5 inbound whose outbound is a VLESS client over TLS.

const std = @import("std");
const marmo = @import("marmo");

const default_uuid = "00112233-4455-6677-8899-aabbccddeeff";

const Mode = enum { client, server };

const Options = struct {
    mode: Mode = .server,
    listen: []const u8 = "127.0.0.1:4433",
    server: []const u8 = "127.0.0.1:4433",
    uuid: []const u8 = default_uuid,
    certificate: []const u8 = "cert.pem",
    private_key: []const u8 = "key.pem",
    sni: []const u8 = "localhost",
    insecure: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const options = parseOptions(args) catch {
        usage();
        return error.InvalidArguments;
    };

    const config: marmo.Config = switch (options.mode) {
        .server => .{
            .inbounds = &.{
                .{
                    .tag = "vless-in",
                    .protocol = .vless,
                    .listen = options.listen,
                    .uuid = options.uuid,
                    .tls = .{
                        .certificate = options.certificate,
                        .private_key = options.private_key,
                    },
                },
            },
            .route = .{ .final = "direct" },
        },
        .client => .{
            .inbounds = &.{
                .{ .tag = "socks", .protocol = .socks5, .listen = options.listen },
            },
            .outbounds = &.{
                .{
                    .tag = "vless-out",
                    .protocol = .vless,
                    .server = options.server,
                    .uuid = options.uuid,
                    .tls = .{
                        .sni = options.sni,
                        .insecure = options.insecure,
                    },
                },
            },
            .route = .{ .final = "vless-out" },
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
        .server => "vless-in",
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
    if (args.len < 2) return error.InvalidArguments;

    var options: Options = .{
        .mode = std.meta.stringToEnum(Mode, args[1]) orelse
            return error.InvalidArguments,
    };
    options.listen = switch (options.mode) {
        .server => "127.0.0.1:4433",
        .client => "127.0.0.1:1080",
    };

    var index: usize = 2;
    while (index < args.len) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--insecure")) {
            options.insecure = true;
        } else if (std.mem.eql(u8, argument, "--listen")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.listen = args[index];
        } else if (std.mem.eql(u8, argument, "--server")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.server = args[index];
        } else if (std.mem.eql(u8, argument, "--uuid")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.uuid = args[index];
        } else if (std.mem.eql(u8, argument, "--cert")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.certificate = args[index];
        } else if (std.mem.eql(u8, argument, "--key")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.private_key = args[index];
        } else if (std.mem.eql(u8, argument, "--sni")) {
            index += 1;
            if (index >= args.len) return error.InvalidArguments;
            options.sni = args[index];
        } else {
            return error.InvalidArguments;
        }
        index += 1;
    }
    return options;
}

fn usage() void {
    std.debug.print(
        \\usage: marmo-vless-example <server|client> [options]
        \\
        \\  --listen <addr>    inbound address (server 4433, client 1080)
        \\  --server <addr>    VLESS server address for client mode
        \\  --uuid <uuid>      VLESS user id (demo default is public)
        \\  --cert <path>      PEM/DER certificate chain for server mode
        \\  --key <path>       ECDSA P-256 private key for server mode
        \\  --sni <name>       TLS server name for client mode
        \\  --insecure         skip CA verification for self-signed test certs
        \\
    , .{});
}
