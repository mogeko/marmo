//! Instance: configuration, listeners, outbounds, and connection dispatch.

const std = @import("std");
const config_module = @import("config/config.zig");
const Config = config_module.Config;
const Diagnostic = @import("core/diagnostic.zig").Diagnostic;
const Dispatch = @import("core/dispatch.zig").Dispatch;
const Metrics = @import("core/metrics.zig").Metrics;
const Endpoint = @import("net/endpoint.zig").Endpoint;
const Direct = @import("outbound/direct.zig").Direct;
const HttpConnect = @import("outbound/http_connect.zig").HttpConnect;
const Shadowsocks = @import("outbound/shadowsocks.zig").Shadowsocks;
const Selector = @import("outbound/selector.zig").Selector;
const Outbound = @import("outbound/outbound.zig").Outbound;
const s2022 = @import("protocol/shadowsocks2022.zig");
const ss_inbound = @import("inbound/shadowsocks.zig");
const ss_udp = @import("inbound/shadowsocks_udp.zig");
const Metadata = @import("routing/metadata.zig").Metadata;
const RuleSet = @import("routing/rules.zig").RuleSet;
const Action = @import("routing/router.zig").Action;
const Router = @import("routing/router.zig").Router;
const Dialer = @import("transport/dialer.zig").Dialer;
const PacketConn = @import("transport/packet.zig").PacketConn;
const Stream = @import("transport/stream.zig").Stream;
const TcpStream = @import("transport/tcp.zig").TcpStream;
const socks5 = @import("inbound/socks5.zig");
const http_inbound = @import("inbound/http.zig");

pub const InitError = error{ InvalidConfig, OutOfMemory };
pub const StartError = error{
    AlreadyRunning,
    BindFailed,
    Canceled,
    ConcurrencyUnavailable,
    OutOfMemory,
    Stopped,
};
pub const WaitError = error{Canceled};

const SpawnError = error{
    Canceled,
    ConcurrencyUnavailable,
    Stopped,
};

const BoundInbound = struct {
    tag: []const u8,
    protocol: Config.InboundProtocol,
    listen: Endpoint,
    ip: std.Io.net.IpAddress,
    server: ?std.Io.net.Server = null,
    shadowsocks: ?*ss_inbound.Context = null,
    udp_server: ?*ss_udp.Server = null,
};

const ConnContext = struct {
    instance: *Instance,
    stream: Stream,
    inbound: *BoundInbound,
};

pub const Instance = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    outbounds: []Outbound,
    inbounds: []BoundInbound,
    rules: RuleSet,
    metrics: Metrics,
    group: std.Io.Group = .init,
    spawn_mutex: std.Io.Mutex = .init,
    stop_event: std.Io.Event = .unset,
    running: bool = false,
    stopping: bool = false,

    /// `config` is borrowed: the caller must keep it and any parsed JSON arena
    /// alive for the lifetime of the instance.
    pub fn init(
        gpa: std.mem.Allocator,
        io: std.Io,
        config: Config,
        diagnostic: *Diagnostic,
    ) InitError!Instance {
        config_module.validate(config, diagnostic) catch |err| switch (err) {
            error.InvalidConfig => return error.InvalidConfig,
        };

        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        const rules = RuleSet.compile(
            allocator,
            config.route,
            diagnostic,
        ) catch |err| switch (err) {
            error.InvalidConfig => return error.InvalidConfig,
            error.OutOfMemory => return error.OutOfMemory,
        };

        const direct = try allocator.create(Direct);
        direct.* = Direct.init(gpa);

        const outbounds = try compileOutbounds(
            allocator,
            gpa,
            direct,
            config.outbounds,
            diagnostic,
        );
        const inbounds = try compileInbounds(allocator, config.inbounds, diagnostic);

        return .{
            .gpa = gpa,
            .io = io,
            .arena = arena,
            .outbounds = outbounds,
            .inbounds = inbounds,
            .rules = rules,
            .metrics = .{},
        };
    }

    pub fn start(self: *Instance) StartError!void {
        if (self.running) return error.AlreadyRunning;

        self.stopping = false;
        self.stop_event = .unset;

        for (self.inbounds) |*inbound| {
            const server = std.Io.net.IpAddress.listen(
                &inbound.ip,
                self.io,
                .{ .reuse_address = true },
            ) catch {
                self.closeServers();
                self.shutdownUdpServers();
                return error.BindFailed;
            };
            inbound.server = server;
            inbound.listen = .{ .ip = server.socket.address };
            std.log.scoped(.marmo).info("inbound '{s}' listening on {f}", .{
                inbound.tag,
                inbound.listen,
            });

            if (inbound.protocol == .shadowsocks) {
                self.bindShadowsocksUdp(inbound) catch |err| {
                    self.closeServers();
                    self.shutdownUdpServers();
                    return err;
                };
            }
        }

        self.running = true;
        for (self.inbounds) |*inbound| {
            self.spawnTask(acceptLoopWrapper, .{ self, inbound }) catch |err| {
                self.stopping = true;
                self.group.cancel(self.io);
                self.closeServers();
                self.shutdownUdpServers();
                self.running = false;
                return err;
            };
            if (inbound.udp_server) |udp_server| {
                self.spawnTask(ss_udp.Server.loopWrapper, .{udp_server}) catch |err| {
                    self.stopping = true;
                    self.group.cancel(self.io);
                    udp_server.shutdown(self.io);
                    self.closeServers();
                    self.shutdownUdpServers();
                    self.running = false;
                    return err;
                };
            }
        }
    }

    pub fn wait(self: *Instance) WaitError!void {
        self.stop_event.wait(self.io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
    }

    pub fn stop(self: *Instance) void {
        if (!self.running) return;

        self.spawn_mutex.lockUncancelable(self.io);
        const already_stopping = self.stopping;
        self.stopping = true;
        self.spawn_mutex.unlock(self.io);
        if (already_stopping) return;

        self.stop_event.set(self.io);
        self.group.cancel(self.io);
        self.closeServers();
        for (self.inbounds) |*inbound| inbound.udp_server = null;
        self.running = false;
        std.log.scoped(.marmo).info("instance stopped", .{});
    }

    pub fn deinit(self: *Instance) void {
        if (self.running) self.stop();
        self.group.cancel(self.io);

        for (self.inbounds) |*inbound| {
            if (inbound.shadowsocks) |context| context.deinit();
        }
        for (self.outbounds) |*outbound| {
            if (outbound.cleanup) |cleanup| cleanup(outbound.cleanup_ctx.?);
        }

        self.arena.deinit();
        self.* = undefined;
    }

    pub fn router(self: *Instance) Router {
        return .{ .ctx = self, .vtable = &router_vtable };
    }

    pub fn dispatch(self: *Instance) Dispatch {
        return .{ .ctx = self, .vtable = &dispatch_vtable };
    }

    pub fn metricsSnapshot(self: *const Instance) Metrics.Snapshot {
        return self.metrics.snapshot();
    }

    pub fn inboundEndpoint(self: *const Instance, tag: []const u8) ?Endpoint {
        for (self.inbounds) |inbound| {
            if (std.mem.eql(u8, inbound.tag, tag)) return inbound.listen;
        }
        return null;
    }

    fn findOutbound(self: *Instance, tag: []const u8) ?*Outbound {
        for (self.outbounds) |*outbound| {
            if (std.mem.eql(u8, outbound.tag, tag)) return outbound;
        }
        return null;
    }

    fn spawnTask(self: *Instance, function: anytype, args: anytype) SpawnError!void {
        self.spawn_mutex.lock(self.io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
        defer self.spawn_mutex.unlock(self.io);

        if (self.stopping) return error.Stopped;
        self.group.concurrent(self.io, function, args) catch |err| switch (err) {
            error.ConcurrencyUnavailable => return error.ConcurrencyUnavailable,
        };
    }

    fn closeServers(self: *Instance) void {
        for (self.inbounds) |*inbound| {
            if (inbound.server) |*server| {
                server.deinit(self.io);
                inbound.server = null;
            }
        }
    }

    fn bindShadowsocksUdp(self: *Instance, inbound: *BoundInbound) StartError!void {
        const context = inbound.shadowsocks orelse return error.BindFailed;
        var address = switch (inbound.listen) {
            .ip => |ip| ip,
            .domain => return error.BindFailed,
        };
        address.setPort(inbound.listen.port());

        const socket = std.Io.net.IpAddress.bind(
            &address,
            self.io,
            .{ .mode = .dgram, .protocol = .udp },
        ) catch return error.BindFailed;

        const server = ss_udp.Server.create(
            self.arena.allocator(),
            self.io,
            context.method,
            &context.key,
            socket,
            self.dispatch(),
            inbound.tag,
        ) catch {
            socket.close(self.io);
            return error.OutOfMemory;
        };
        inbound.udp_server = server;
    }

    fn shutdownUdpServers(self: *Instance) void {
        for (self.inbounds) |*inbound| {
            if (inbound.udp_server) |server| {
                server.shutdown(self.io);
                inbound.udp_server = null;
            }
        }
    }

    fn acceptLoop(self: *Instance, inbound: *BoundInbound) void {
        const server = if (inbound.server) |*server| server else return;

        while (true) {
            const accepted = server.accept(self.io) catch |err| switch (err) {
                error.Canceled, error.SocketNotListening => return,
                else => {
                    std.log.scoped(.marmo).warn("accept failed: {s}", .{@errorName(err)});
                    continue;
                },
            };
            self.acceptConnection(inbound, accepted);
        }
    }

    fn acceptConnection(self: *Instance, inbound: *BoundInbound, accepted: std.Io.net.Stream) void {
        const remote: Endpoint = .{ .ip = accepted.socket.address };
        const tcp = TcpStream.create(self.gpa, accepted, inbound.listen, remote) catch {
            accepted.close(self.io);
            return;
        };
        const stream = tcp.stream();

        const context = self.gpa.create(ConnContext) catch {
            stream.close(self.io);
            return;
        };
        context.* = .{ .instance = self, .stream = stream, .inbound = inbound };

        self.metrics.connectionOpened();
        self.spawnTask(connectionWrapper, .{context}) catch |err| {
            self.metrics.connectionClosed();
            stream.close(self.io);
            self.gpa.destroy(context);
            std.log.scoped(.marmo).warn("spawn failed: {s}", .{@errorName(err)});
        };
    }
};

fn acceptLoopWrapper(self: *Instance, inbound: *BoundInbound) std.Io.Cancelable!void {
    self.acceptLoop(inbound);
}

fn connectionWrapper(context: *ConnContext) std.Io.Cancelable!void {
    handleConnection(context) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.log.scoped(.marmo).warn("connection failed: {s}", .{@errorName(err)}),
    };
}

fn handleConnection(context: *ConnContext) !void {
    const self = context.instance;
    defer self.gpa.destroy(context);
    defer context.stream.close(self.io);
    defer self.metrics.connectionClosed();

    var arena = std.heap.ArenaAllocator.init(self.gpa);
    defer arena.deinit();

    const dispatch = self.dispatch();
    switch (context.inbound.protocol) {
        .socks5 => try socks5.handle(
            self.io,
            context.stream,
            context.inbound.tag,
            dispatch,
            arena.allocator(),
        ),
        .http => try http_inbound.handle(
            self.io,
            context.stream,
            context.inbound.tag,
            dispatch,
            arena.allocator(),
        ),
        .shadowsocks => try ss_inbound.handle(
            self.io,
            self.gpa,
            context.stream,
            context.inbound.tag,
            dispatch,
            context.inbound.shadowsocks orelse return error.InvalidConfig,
        ),
    }
}

fn compileOutbounds(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    direct: *Direct,
    configs: []const Config.Outbound,
    diagnostic: *Diagnostic,
) InitError![]Outbound {
    var has_direct = false;
    for (configs) |outbound| {
        if (std.mem.eql(u8, outbound.tag, "direct")) has_direct = true;
    }

    const count = configs.len + @intFromBool(!has_direct);
    const outbounds = try allocator.alloc(Outbound, count);
    var filled: usize = 0;

    if (!has_direct) {
        outbounds[filled] = .{
            .tag = "direct",
            .dialer = direct.dialer(),
            .supports_udp = true,
        };
        filled += 1;
    }

    for (configs) |config| {
        if (config.protocol == .selector) continue;
        outbounds[filled] = try compileNonSelector(
            allocator,
            gpa,
            direct,
            config,
            diagnostic,
        );
        filled += 1;
    }

    for (configs) |config| {
        if (config.protocol != .selector) continue;
        outbounds[filled] = try compileSelector(
            allocator,
            config,
            outbounds[0..filled],
            diagnostic,
        );
        filled += 1;
    }

    std.debug.assert(filled == count);
    return outbounds;
}

fn compileNonSelector(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    direct: *Direct,
    config: Config.Outbound,
    diagnostic: *Diagnostic,
) InitError!Outbound {
    return switch (config.protocol) {
        .direct => .{
            .tag = config.tag,
            .dialer = direct.dialer(),
            .supports_udp = true,
        },
        .http => blk: {
            const server_text = config.server orelse return error.InvalidConfig;
            const server = Endpoint.parse(server_text) catch return error.InvalidConfig;
            const http = try allocator.create(HttpConnect);
            http.* = .{ .gpa = gpa, .server = server, .dialer = direct.dialer() };
            break :blk .{
                .tag = config.tag,
                .dialer = http.asDialer(),
                .supports_udp = false,
            };
        },
        .shadowsocks => blk: {
            const server_text = config.server orelse return error.InvalidConfig;
            const server = Endpoint.parse(server_text) catch return error.InvalidConfig;
            const method_text = config.method orelse return error.InvalidConfig;
            const method = s2022.Method.parse(method_text) orelse {
                diagnostic.set(
                    "outbounds: unsupported shadowsocks method '{s}'",
                    .{method_text},
                );
                return error.InvalidConfig;
            };
            const password = config.password orelse return error.InvalidConfig;
            var key = s2022.Key.parse(method, password) catch {
                diagnostic.set("outbounds: invalid shadowsocks key", .{});
                return error.InvalidConfig;
            };

            const shadowsocks = allocator.create(Shadowsocks) catch {
                key.deinit();
                return error.OutOfMemory;
            };
            shadowsocks.* = .{
                .gpa = gpa,
                .server = server,
                .method = method,
                .key = key,
                .direct_dialer = direct.dialer(),
            };
            key.deinit();

            break :blk .{
                .tag = config.tag,
                .dialer = shadowsocks.asDialer(),
                .supports_udp = true,
                .cleanup = cleanupShadowsocks,
                .cleanup_ctx = shadowsocks,
            };
        },
        .selector => unreachable,
    };
}

fn compileSelector(
    allocator: std.mem.Allocator,
    config: Config.Outbound,
    pool: []Outbound,
    diagnostic: *Diagnostic,
) InitError!Outbound {
    const node_tags = config.nodes orelse return error.InvalidConfig;
    const strategy = config.strategy orelse return error.InvalidConfig;

    const nodes = try allocator.alloc(*const Outbound, node_tags.len);
    for (node_tags, 0..) |tag, index| {
        var found: ?*const Outbound = null;
        for (pool) |*candidate| {
            if (!std.mem.eql(u8, candidate.tag, tag)) continue;
            found = candidate;
            break;
        }
        if (found == null) {
            diagnostic.set("outbounds: selector node '{s}' not found", .{tag});
            return error.InvalidConfig;
        }
        nodes[index] = found.?;
    }

    const selector = Selector.init(allocator, nodes, strategy) catch
        return error.OutOfMemory;
    return .{
        .tag = config.tag,
        .dialer = selector.asDialer(),
        .supports_udp = selector.supportsUdp(),
    };
}

fn compileInbounds(
    allocator: std.mem.Allocator,
    configs: []const Config.Inbound,
    diagnostic: *Diagnostic,
) InitError![]BoundInbound {
    const inbounds = try allocator.alloc(BoundInbound, configs.len);
    for (configs, 0..) |config, index| {
        const endpoint = Endpoint.parse(config.listen) catch return error.InvalidConfig;
        const ip = switch (endpoint) {
            .ip => |ip| ip,
            .domain => return error.InvalidConfig,
        };
        inbounds[index] = .{
            .tag = config.tag,
            .protocol = config.protocol,
            .listen = endpoint,
            .ip = ip,
        };

        switch (config.protocol) {
            .shadowsocks => {
                const method_text = config.method orelse return error.InvalidConfig;
                const method = s2022.Method.parse(method_text) orelse {
                    diagnostic.set("inbounds[{d}]: unsupported shadowsocks method", .{index});
                    return error.InvalidConfig;
                };
                const password = config.password orelse return error.InvalidConfig;
                var key = s2022.Key.parse(method, password) catch {
                    diagnostic.set("inbounds[{d}]: invalid shadowsocks key", .{index});
                    return error.InvalidConfig;
                };
                const context = ss_inbound.Context.init(allocator, method, key) catch {
                    key.deinit();
                    return error.OutOfMemory;
                };
                key.deinit();
                inbounds[index].shadowsocks = context;
            },
            .http, .socks5 => {},
        }
    }
    return inbounds;
}

fn cleanupShadowsocks(ctx: *anyopaque) void {
    const self: *Shadowsocks = @ptrCast(@alignCast(ctx));
    self.deinit();
}

fn routeVtable(ctx: *anyopaque, metadata: *const Metadata) Action {
    const self: *Instance = @ptrCast(@alignCast(ctx));
    return self.rules.match(metadata);
}

fn connectVtable(
    ctx: *anyopaque,
    io: std.Io,
    tag: []const u8,
    target: Endpoint,
) Dialer.ConnectError!Stream {
    const self: *Instance = @ptrCast(@alignCast(ctx));
    const outbound = self.findOutbound(tag) orelse return error.Unsupported;
    return outbound.connect(io, target);
}

fn connectPacketVtable(
    ctx: *anyopaque,
    io: std.Io,
    tag: []const u8,
    target: Endpoint,
) Dialer.ConnectError!PacketConn {
    const self: *Instance = @ptrCast(@alignCast(ctx));
    const outbound = self.findOutbound(tag) orelse return error.Unsupported;
    return outbound.connect_packet(io, target);
}

fn metricsVtable(ctx: *anyopaque) *Metrics {
    const self: *Instance = @ptrCast(@alignCast(ctx));
    return &self.metrics;
}

const router_vtable: Router.VTable = .{ .match = routeVtable };

const dispatch_vtable: Dispatch.VTable = .{
    .route = routeVtable,
    .connect = connectVtable,
    .connect_packet = connectPacketVtable,
    .metrics = metricsVtable,
};
