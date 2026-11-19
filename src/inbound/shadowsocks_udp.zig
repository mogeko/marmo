//! Shadowsocks 2022 UDP server: per-client-session relay sockets.

const std = @import("std");
const Dispatch = @import("../core/dispatch.zig").Dispatch;
const s2022 = @import("../protocol/shadowsocks2022.zig");
const Metadata = @import("../routing/metadata.zig").Metadata;

const max_sessions = 128;

const Session = struct {
    used: bool = false,
    client_session_id: [8]u8 = @splat(0),
    server_session_id: [8]u8 = @splat(0),
    socket: std.Io.net.Socket = undefined,
    packet_counter: u64 = 0,
    window: s2022.Window = .{},
    client_address: std.Io.net.IpAddress = undefined,
    last_active_s: i64 = 0,
    mutex: std.Io.Mutex = .init,
    future: ?std.Io.Future(void) = null,
    reply_failed: std.atomic.Value(bool) = .init(false),
    server: *Server = undefined,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    method: s2022.Method,
    key: *const s2022.Key,
    listener: std.Io.net.Socket,
    dispatch: Dispatch,
    inbound_tag: []const u8,
    /// Zero disables idle expiry; otherwise an idle session is evicted.
    session_timeout_s: u32,
    sessions: [max_sessions]Session = @splat(Session{}),
    closed: std.atomic.Value(bool) = .init(false),

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        method: s2022.Method,
        key: *const s2022.Key,
        listener: std.Io.net.Socket,
        dispatch: Dispatch,
        inbound_tag: []const u8,
        session_timeout_s: u32,
    ) !*Server {
        const self = try allocator.create(Server);
        self.* = .{
            .gpa = allocator,
            .io = io,
            .method = method,
            .key = key,
            .listener = listener,
            .dispatch = dispatch,
            .inbound_tag = inbound_tag,
            .session_timeout_s = session_timeout_s,
        };
        return self;
    }

    pub fn loopWrapper(self: *Server) std.Io.Cancelable!void {
        self.run(self.io);
    }

    fn run(self: *Server, io: std.Io) void {
        defer self.shutdown(io);

        var packet: [s2022.max_payload]u8 = undefined;
        var plaintext: [s2022.max_payload]u8 = undefined;
        while (true) {
            const message = self.listener.receive(io, &packet) catch return;
            self.handleDatagram(io, message.from, message.data, &plaintext) catch |err| {
                if (err == error.Canceled) return;
                std.log.scoped(.marmo).debug("ss udp drop: {s}", .{@errorName(err)});
            };
        }
    }

    fn handleDatagram(
        self: *Server,
        io: std.Io,
        source: std.Io.net.IpAddress,
        packet: []const u8,
        plaintext: []u8,
    ) !void {
        const decoded = try s2022.decodeUdpPacket(
            io,
            self.method,
            self.key.slice(),
            packet,
            .client_to_server,
            null,
            plaintext,
        );
        const now = s2022.nowSeconds(io);
        const session = try self.findOrCreate(io, decoded.session_id, source, now);

        if (!session.window.accept(decoded.packet_id)) return;

        session.mutex.lock(io) catch return error.Canceled;
        session.client_address = source;
        session.last_active_s = now;
        session.mutex.unlock(io);

        const metadata: Metadata = .{
            .network = .udp,
            .source = .{ .ip = source },
            .destination = decoded.source,
            .domain = switch (decoded.source) {
                .domain => |domain| domain.name,
                .ip => null,
            },
            .inbound = self.inbound_tag,
        };

        const action = self.dispatch.route(&metadata);
        const tag = switch (action) {
            .route => |route_tag| route_tag,
            .direct => "direct",
            .reject, .hijack_dns => return,
        };
        if (!std.mem.eql(u8, tag, "direct")) return;

        const address = decoded.source.resolve(io) catch return error.ResolveFailed;
        session.socket.send(io, &address, decoded.payload) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.SendFailed,
        };
        self.dispatch.metrics().addToRemote(decoded.payload.len);
    }

    fn findOrCreate(
        self: *Server,
        io: std.Io,
        client_session_id: [8]u8,
        source: std.Io.net.IpAddress,
        now: i64,
    ) !*Session {
        var free_session: ?*Session = null;
        for (&self.sessions) |*session| {
            if (!session.used) {
                if (free_session == null) free_session = session;
                continue;
            }
            if (std.mem.eql(u8, &session.client_session_id, &client_session_id)) {
                if (session.reply_failed.load(.acquire)) {
                    self.stopSession(io, session);
                    if (free_session == null) free_session = session;
                    continue;
                }
                return session;
            }
            // The reply task updates this under the same mutex.
            session.mutex.lock(io) catch return error.Canceled;
            const last_active_s = session.last_active_s;
            session.mutex.unlock(io);
            if (self.session_timeout_s != 0 and
                now - last_active_s >= self.session_timeout_s)
            {
                self.stopSession(io, session);
                if (free_session == null) free_session = session;
            }
        }

        const session = free_session orelse return error.SessionsFull;
        try self.initSession(io, session, client_session_id, source, now);
        return session;
    }

    fn initSession(
        self: *Server,
        io: std.Io,
        session: *Session,
        client_session_id: [8]u8,
        source: std.Io.net.IpAddress,
        now: i64,
    ) !void {
        const bind_address: std.Io.net.IpAddress = switch (source) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = std.Io.net.IpAddress.bind(
            &bind_address,
            io,
            .{ .mode = .dgram, .protocol = .udp },
        ) catch return error.BindFailed;

        var server_session_id: [8]u8 = undefined;
        std.Io.randomSecure(io, &server_session_id) catch {
            socket.close(io);
            return error.RandomFailed;
        };
        if (std.mem.eql(u8, &server_session_id, &client_session_id)) {
            server_session_id[0] +%= 1;
        }

        session.* = .{
            .used = true,
            .client_session_id = client_session_id,
            .server_session_id = server_session_id,
            .socket = socket,
            .client_address = source,
            .last_active_s = now,
            .server = self,
        };
        session.future = std.Io.concurrent(io, replyLoop, .{session}) catch |err| {
            socket.close(io);
            session.used = false;
            return switch (err) {
                error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
            };
        };
    }

    fn stopSession(self: *Server, io: std.Io, session: *Session) void {
        _ = self;
        if (!session.used) return;
        if (session.future) |*future| {
            _ = future.cancel(io);
            session.future = null;
        }
        session.socket.close(io);
        session.used = false;
    }

    pub fn shutdown(self: *Server, io: std.Io) void {
        if (self.closed.swap(true, .acq_rel)) return;
        for (&self.sessions) |*session| {
            self.stopSession(io, session);
        }
        self.listener.close(io);
    }
};

fn replyLoop(session: *Session) void {
    const server = session.server;
    defer session.reply_failed.store(true, .release);
    var payload_buffer: [s2022.max_payload]u8 = undefined;
    var packet: [s2022.max_payload]u8 = undefined;

    while (true) {
        const message = session.socket.receive(server.io, &payload_buffer) catch return;

        session.mutex.lock(server.io) catch return;
        const client_address = session.client_address;
        session.last_active_s = s2022.nowSeconds(server.io);
        session.mutex.unlock(server.io);

        const packet_id = s2022.nextCounter(&session.packet_counter) catch return;
        const packet_len = s2022.encodeUdpPacketWithTime(
            server.method,
            server.key.slice(),
            session.server_session_id,
            packet_id,
            .server_to_client,
            session.client_session_id,
            .{ .ip = message.from },
            message.data,
            0,
            s2022.timestampNow(server.io) catch return,
            &packet,
        ) catch return;

        server.listener.send(server.io, &client_address, packet[0..packet_len]) catch return;
        server.dispatch.metrics().addToClient(message.data.len);
    }
}
