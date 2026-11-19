//! Instance: configuration, listeners, outbounds, and connection dispatch.

const std = @import("std");
const config_module = @import("config/config.zig");
const Config = config_module.Config;
const Diagnostic = @import("core/diagnostic.zig").Diagnostic;
const Dispatch = @import("core/dispatch.zig").Dispatch;
const Metrics = @import("core/metrics.zig").Metrics;
const connection_guard = @import("core/connection_guard.zig");
const ConnectionGuard = connection_guard.Guard;
const LimitsRegistry = connection_guard.Registry;
const Endpoint = @import("net/endpoint.zig").Endpoint;
const Direct = @import("outbound/direct.zig").Direct;
const HttpConnect = @import("outbound/http_connect.zig").HttpConnect;
const Shadowsocks = @import("outbound/shadowsocks.zig").Shadowsocks;
const Trojan = @import("outbound/trojan.zig").Trojan;
const Vless = @import("outbound/vless.zig").Vless;
const selector_module = @import("outbound/selector.zig");
const Selector = selector_module.Selector;
const SelectorHealth = selector_module.Health;
const Outbound = @import("outbound/outbound.zig").Outbound;
const s2022 = @import("protocol/shadowsocks2022.zig");
const trojan_protocol = @import("protocol/trojan.zig");
const vless_protocol = @import("protocol/vless.zig");
const ss_inbound = @import("inbound/shadowsocks.zig");
const ss_udp = @import("inbound/shadowsocks_udp.zig");
const Metadata = @import("routing/metadata.zig").Metadata;
const RuleSet = @import("routing/rules.zig").RuleSet;
const Action = @import("routing/router.zig").Action;
const Router = @import("routing/router.zig").Router;
const Dialer = @import("transport/dialer.zig").Dialer;
const TlsDialer = @import("transport/tls_dialer.zig").TlsDialer;
const tls_server = @import("transport/tls_server.zig");
const TlsServerStream = tls_server.TlsServerStream;
const tls_credentials = @import("transport/tls_credentials.zig");
const PacketConn = @import("transport/packet.zig").PacketConn;
const Stream = @import("transport/stream.zig").Stream;
const TcpStream = @import("transport/tcp.zig").TcpStream;
const socks5 = @import("inbound/socks5.zig");
const http_inbound = @import("inbound/http.zig");
const trojan_inbound = @import("inbound/trojan.zig");
const vless_inbound = @import("inbound/vless.zig");

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
    tls: ?tls_server.Options = null,
    trojan: ?trojan_inbound.Context = null,
    vless_uuid: ?vless_protocol.Uuid = null,
};

const ConnContext = struct {
    instance: *Instance,
    stream: Stream,
    inbound: *BoundInbound,
    guard: ConnectionGuard,
};

pub const Instance = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    outbounds: []Outbound,
    selectors: []*Selector,
    inbounds: []BoundInbound,
    rules: RuleSet,
    metrics: Metrics,
    group: std.Io.Group = .init,
    spawn_mutex: std.Io.Mutex = .init,
    stop_event: std.Io.Event = .unset,
    limits: Config.Limits,
    limits_registry: LimitsRegistry,
    active_connections: std.atomic.Value(u32) = .init(0),
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

        const compiled = try compileOutbounds(
            allocator,
            gpa,
            direct,
            config.outbounds,
            diagnostic,
        );
        const inbounds = try compileInbounds(
            allocator,
            io,
            config.inbounds,
            diagnostic,
        );

        return .{
            .gpa = gpa,
            .io = io,
            .arena = arena,
            .outbounds = compiled.outbounds,
            .selectors = compiled.selectors,
            .inbounds = inbounds,
            .rules = rules,
            .limits = config.limits,
            .limits_registry = try LimitsRegistry.init(
                allocator,
                config.limits.max_connections,
            ),
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
        self.spawnTask(limitsLoopWrapper, .{self}) catch |err| {
            self.stopping = true;
            self.group.cancel(self.io);
            self.closeServers();
            self.shutdownUdpServers();
            self.running = false;
            return err;
        };
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
        for (self.selectors) |selector| {
            if (!selector.hasHealth()) continue;
            self.spawnTask(healthLoopWrapper, .{ self.io, selector }) catch |err| {
                self.stopping = true;
                self.group.cancel(self.io);
                self.closeServers();
                self.shutdownUdpServers();
                self.running = false;
                return err;
            };
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
            if (inbound.tls) |*tls| {
                std.crypto.secureZero(u8, std.mem.asBytes(&tls.private_key));
            }
            if (inbound.vless_uuid) |*uuid| {
                std.crypto.secureZero(u8, std.mem.asBytes(uuid));
            }
            if (inbound.trojan) |*context| {
                std.crypto.secureZero(
                    u8,
                    std.mem.asBytes(&context.password_hash),
                );
            }
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
            self.limits.idle_timeout_s,
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
        if (!self.reserveConnection()) {
            accepted.close(self.io);
            self.metrics.connectionRejected();
            std.log.scoped(.marmo).debug("connection rejected by limit", .{});
            return;
        }

        const remote: Endpoint = .{ .ip = accepted.socket.address };
        const tcp = TcpStream.create(self.gpa, accepted, inbound.listen, remote) catch {
            self.releaseConnection();
            accepted.close(self.io);
            return;
        };
        const stream = tcp.stream();

        const context = self.gpa.create(ConnContext) catch {
            self.releaseConnection();
            stream.close(self.io);
            return;
        };
        context.* = .{
            .instance = self,
            .stream = stream,
            .inbound = inbound,
            .guard = ConnectionGuard.init(
                self.io,
                &self.limits_registry,
                &self.metrics,
                stream,
                .{
                    .handshake_ns = @as(
                        u64,
                        self.limits.handshake_timeout_s,
                    ) * std.time.ns_per_s,
                    .idle_ns = @as(u64, self.limits.idle_timeout_s) *
                        std.time.ns_per_s,
                    .uplink_only_ns = @as(u64, self.limits.uplink_only_s) *
                        std.time.ns_per_s,
                    .downlink_only_ns = @as(u64, self.limits.downlink_only_s) *
                        std.time.ns_per_s,
                },
            ),
        };
        if (!context.guard.register()) {
            self.metrics.connectionRejected();
            self.releaseConnection();
            stream.close(self.io);
            self.gpa.destroy(context);
            return;
        }

        self.metrics.connectionOpened();
        self.spawnTask(connectionWrapper, .{context}) catch |err| {
            context.guard.stop();
            self.metrics.connectionClosed();
            self.releaseConnection();
            stream.close(self.io);
            self.gpa.destroy(context);
            std.log.scoped(.marmo).warn("spawn failed: {s}", .{@errorName(err)});
        };
    }

    fn reserveConnection(self: *Instance) bool {
        const maximum = self.limits.max_connections;
        if (maximum == 0) return false;
        var current = self.active_connections.load(.acquire);
        while (current < maximum) {
            if (self.active_connections.cmpxchgWeak(
                current,
                current + 1,
                .acq_rel,
                .acquire,
            )) |actual| {
                current = actual;
                continue;
            }
            return true;
        }
        return false;
    }

    fn releaseConnection(self: *Instance) void {
        const previous = self.active_connections.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
    }
};

fn acceptLoopWrapper(self: *Instance, inbound: *BoundInbound) std.Io.Cancelable!void {
    self.acceptLoop(inbound);
}

fn limitsLoopWrapper(self: *Instance) std.Io.Cancelable!void {
    while (true) {
        try std.Io.sleep(
            self.io,
            .{ .nanoseconds = 250 * std.time.ns_per_ms },
            .awake,
        );
        self.limits_registry.scan(self.io, connection_guard.nowNs(self.io));
    }
}

fn healthLoopWrapper(io: std.Io, selector: *Selector) std.Io.Cancelable!void {
    try selector.runHealth(io);
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
    defer self.metrics.connectionClosed();
    defer self.releaseConnection();

    var stream = context.stream;
    defer {
        context.guard.stop();
        stream.close(self.io);
    }
    if (context.inbound.tls) |tls_options| {
        var options = tls_options;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&options.private_key));
        const tls = TlsServerStream.create(
            self.io,
            self.gpa,
            stream,
            options,
        ) catch |err| return err;
        stream = tls.stream();
    }

    var arena = std.heap.ArenaAllocator.init(self.gpa);
    defer arena.deinit();

    const dispatch = self.dispatch();
    switch (context.inbound.protocol) {
        .socks5 => try socks5.handle(
            self.io,
            stream,
            context.inbound.tag,
            dispatch,
            arena.allocator(),
            &context.guard,
        ),
        .http => try http_inbound.handle(
            self.io,
            stream,
            context.inbound.tag,
            dispatch,
            arena.allocator(),
            &context.guard,
        ),
        .shadowsocks => try ss_inbound.handle(
            self.io,
            self.gpa,
            stream,
            context.inbound.tag,
            dispatch,
            context.inbound.shadowsocks orelse return error.InvalidConfig,
            &context.guard,
        ),
        .trojan => {
            var trojan_context = context.inbound.trojan orelse
                return error.InvalidConfig;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&trojan_context));
            try trojan_inbound.handle(
                self.io,
                stream,
                context.inbound.tag,
                dispatch,
                arena.allocator(),
                &trojan_context,
                &context.guard,
            );
        },
        .vless => {
            var vless_context: vless_inbound.Context = .{
                .uuid = context.inbound.vless_uuid orelse
                    return error.InvalidConfig,
            };
            defer std.crypto.secureZero(u8, std.mem.asBytes(&vless_context));
            try vless_inbound.handle(
                self.io,
                stream,
                context.inbound.tag,
                dispatch,
                arena.allocator(),
                &vless_context,
                &context.guard,
            );
        },
    }
}

const CompiledOutbounds = struct {
    outbounds: []Outbound,
    selectors: []*Selector,
};

const CompiledSelector = struct {
    outbound: Outbound,
    selector: *Selector,
};

fn compileOutbounds(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    direct: *Direct,
    configs: []const Config.Outbound,
    diagnostic: *Diagnostic,
) InitError!CompiledOutbounds {
    var has_direct = false;
    var selector_count: usize = 0;
    for (configs) |outbound| {
        if (std.mem.eql(u8, outbound.tag, "direct")) has_direct = true;
        if (outbound.protocol == .selector) selector_count += 1;
    }

    const count = configs.len + @intFromBool(!has_direct);
    const outbounds = try allocator.alloc(Outbound, count);
    const selectors = try allocator.alloc(*Selector, selector_count);
    var filled: usize = 0;
    var selector_filled: usize = 0;

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
        const compiled = try compileSelector(
            allocator,
            config,
            outbounds[0..filled],
            diagnostic,
        );
        outbounds[filled] = compiled.outbound;
        selectors[selector_filled] = compiled.selector;
        filled += 1;
        selector_filled += 1;
    }

    std.debug.assert(filled == count);
    std.debug.assert(selector_filled == selector_count);
    return .{ .outbounds = outbounds, .selectors = selectors };
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
        .trojan => try compileTrojan(allocator, gpa, direct, config),
        .vless => try compileVless(allocator, gpa, direct, config),
        .selector => unreachable,
    };
}

const TlsTransport = struct {
    dialer: Dialer,
    cleanup: ?*const fn (ctx: *anyopaque) void = null,
    cleanup_ctx: ?*anyopaque = null,
};

fn compileTlsTransport(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    direct: *Direct,
    server: Endpoint,
    tls_config: Config.Tls,
) InitError!TlsTransport {
    const server_name = tls_config.sni orelse switch (server) {
        .domain => |domain| domain.name,
        .ip => null,
    };
    const tls_dialer = try allocator.create(TlsDialer);
    tls_dialer.* = TlsDialer.init(
        gpa,
        direct.dialer(),
        server_name,
        tls_config.insecure,
        @as(u64, tls_config.handshake_timeout_s) * std.time.ns_per_s,
    );
    tls_dialer.alpn_protocols = tls_config.alpn orelse &.{};
    tls_dialer.required_alpn = tls_config.required_alpn;
    return .{
        .dialer = tls_dialer.asDialer(),
        .cleanup = cleanupTlsDialer,
        .cleanup_ctx = tls_dialer,
    };
}

fn compileTrojan(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    direct: *Direct,
    config: Config.Outbound,
) InitError!Outbound {
    const server_text = config.server orelse return error.InvalidConfig;
    const server = Endpoint.parse(server_text) catch return error.InvalidConfig;
    const password = config.password orelse return error.InvalidConfig;
    const tls_config = config.tls orelse return error.InvalidConfig;

    var password_hash = trojan_protocol.hashPassword(password);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&password_hash));

    const trojan = try allocator.create(Trojan);
    errdefer allocator.destroy(trojan);
    const transport = try compileTlsTransport(
        allocator,
        gpa,
        direct,
        server,
        tls_config,
    );
    trojan.* = .{
        .gpa = gpa,
        .server = server,
        .password_hash = password_hash,
        .transport = transport.dialer,
        .transport_cleanup = transport.cleanup,
        .transport_cleanup_ctx = transport.cleanup_ctx,
    };
    return .{
        .tag = config.tag,
        .dialer = trojan.asDialer(),
        .supports_udp = true,
        .cleanup = cleanupTrojan,
        .cleanup_ctx = trojan,
    };
}

fn compileVless(
    allocator: std.mem.Allocator,
    gpa: std.mem.Allocator,
    direct: *Direct,
    config: Config.Outbound,
) InitError!Outbound {
    const server_text = config.server orelse return error.InvalidConfig;
    const server = Endpoint.parse(server_text) catch return error.InvalidConfig;
    const uuid_text = config.uuid orelse return error.InvalidConfig;
    const uuid = vless_protocol.parseUuid(uuid_text) catch
        return error.InvalidConfig;

    var transport = direct.dialer();
    var transport_cleanup: ?*const fn (ctx: *anyopaque) void = null;
    var transport_cleanup_ctx: ?*anyopaque = null;
    if (config.tls) |tls| {
        const compiled = try compileTlsTransport(
            allocator,
            gpa,
            direct,
            server,
            tls,
        );
        transport = compiled.dialer;
        transport_cleanup = compiled.cleanup;
        transport_cleanup_ctx = compiled.cleanup_ctx;
    }

    const vless = try allocator.create(Vless);
    vless.* = .{
        .gpa = gpa,
        .server = server,
        .uuid = uuid,
        .transport = transport,
        .xudp = config.xudp,
        .transport_cleanup = transport_cleanup,
        .transport_cleanup_ctx = transport_cleanup_ctx,
    };
    return .{
        .tag = config.tag,
        .dialer = vless.asDialer(),
        .supports_udp = true,
        .cleanup = cleanupVless,
        .cleanup_ctx = vless,
    };
}

fn compileSelector(
    allocator: std.mem.Allocator,
    config: Config.Outbound,
    pool: []Outbound,
    diagnostic: *Diagnostic,
) InitError!CompiledSelector {
    const node_tags = config.nodes orelse return error.InvalidConfig;
    const strategy = config.strategy orelse return error.InvalidConfig;

    var health: ?SelectorHealth = null;
    if (config.health_check) |health_config| {
        const target = Endpoint.parse(health_config.target) catch
            return error.InvalidConfig;
        health = .{
            .target = target,
            .interval_ns = @as(u64, health_config.interval_s) * std.time.ns_per_s,
            .timeout_ns = @as(u64, health_config.timeout_s) * std.time.ns_per_s,
        };
    }

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

    const selector = Selector.init(allocator, nodes, strategy, health) catch
        return error.OutOfMemory;
    return .{
        .outbound = .{
            .tag = config.tag,
            .dialer = selector.asDialer(),
            .supports_udp = selector.supportsUdp(),
        },
        .selector = selector,
    };
}

fn loadInboundTls(
    allocator: std.mem.Allocator,
    io: std.Io,
    tls: Config.InboundTls,
    index: usize,
    diagnostic: *Diagnostic,
) InitError!tls_server.Options {
    var options = tls_credentials.loadOptions(
        allocator,
        io,
        tls.certificate,
        tls.private_key,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidCredentials => {
            diagnostic.set(
                "inbounds[{d}].tls: invalid certificate or private key",
                .{index},
            );
            return error.InvalidConfig;
        },
    };
    options.alpn_protocols = tls.alpn orelse &.{};
    options.handshake_timeout_ns =
        @as(u64, tls.handshake_timeout_s) * std.time.ns_per_s;
    return options;
}

fn compileInbounds(
    allocator: std.mem.Allocator,
    io: std.Io,
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
            .trojan => {
                const password = config.password orelse return error.InvalidConfig;
                const tls = config.tls orelse return error.InvalidConfig;
                const fallback = if (config.fallback) |text|
                    Endpoint.parse(text) catch return error.InvalidConfig
                else
                    null;
                const tls_options = try loadInboundTls(
                    allocator,
                    io,
                    tls,
                    index,
                    diagnostic,
                );
                var password_hash = trojan_protocol.hashPassword(password);
                defer std.crypto.secureZero(u8, &password_hash);
                inbounds[index].trojan = .{
                    .password_hash = password_hash,
                    .fallback = fallback,
                };
                inbounds[index].tls = tls_options;
            },
            .vless => {
                const uuid_text = config.uuid orelse return error.InvalidConfig;
                inbounds[index].vless_uuid = vless_protocol.parseUuid(uuid_text) catch
                    return error.InvalidConfig;
                const tls = config.tls orelse return error.InvalidConfig;
                inbounds[index].tls = try loadInboundTls(
                    allocator,
                    io,
                    tls,
                    index,
                    diagnostic,
                );
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

fn cleanupVless(ctx: *anyopaque) void {
    const self: *Vless = @ptrCast(@alignCast(ctx));
    self.deinit();
}

fn cleanupTrojan(ctx: *anyopaque) void {
    const self: *Trojan = @ptrCast(@alignCast(ctx));
    self.deinit();
}

fn cleanupTlsDialer(ctx: *anyopaque) void {
    const self: *TlsDialer = @ptrCast(@alignCast(ctx));
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
