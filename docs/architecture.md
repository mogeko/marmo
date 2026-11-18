# Architecture

Status: Phase 1 design. ADR-0001–0009 are accepted; implement Phase 1 only.

## 1. Purpose

marmo is an embeddable Zig library that accepts L4/L7 proxy traffic, decides
where it should go, and forwards it through a proxy protocol or directly.

This repository contains the library only: no CLI, daemon, GUI, or system
service. Applications that embed marmo own the process lifecycle, signal
handling, and configuration storage.

## 2. Goals

- L4 proxying: TCP streams and UDP datagrams, including UDP-over-stream
  (SOCKS5 UDP ASSOCIATE, VLESS/VMess UDP, Shadowsocks UDP, Trojan UDP).
- L7 proxying: HTTP/1.1 `CONNECT` and forward proxying, and L7 transports used
  by proxy protocols (TLS, WebSocket, HTTP/2, gRPC, QUIC).
- Inbounds: SOCKS5, HTTP, mixed, Shadowsocks, Trojan, VLESS, VMess, TUIC,
  Hysteria2; TUN later.
- Outbounds: direct, SOCKS5, HTTP CONNECT, Shadowsocks, VMess, VLESS, Trojan,
  TUIC, Hysteria2.
- Rule-based routing on domain, IP/CIDR, GEOIP/GEOSITE, port, network,
  inbound, and process.
- Outbound groups with manual, round-robin, random, fallback, and
  least-latency selection plus health checks.
- Bounded memory, explicit cancellation, graceful shutdown, no global state.
- Linux and macOS first; Windows after the core is stable.

## 3. Non-goals (v1)

- TLS interception or MITM with generated certificates.
- A CLI, daemon, GUI, subscription-format parsing, or provider ecosystem
  compatibility.
- Fake-IP DNS, transparent proxying (`iptables`/TPROXY), TUN inbounds before
  phase 4.
- HTTP caching, content rewriting, or a general-purpose HTTP server.
- Snell (deferred for now: no official specification) and WireGuard (an L3 VPN,
  not a stream proxy; explicitly abandoned, see ADR-0002).
- A userspace TCP/IP stack.
- Windows-specific APIs before phase 4.

## 4. Constraints (verified against Zig 0.17.1)

- **Runtime**: `std.Io` is the concurrency and I/O interface. `Io.Threaded`
  works everywhere. `Io.Evented` exists only where fiber switching is
  implemented: `aarch64`, `x86_64`, `riscv64`; Linux uses io_uring, BSD uses
  kqueue, Apple uses Dispatch. Other architectures and Windows must use
  `Io.Threaded`.
- **No own event loop**: the library takes `io: std.Io` and never creates
  threads, an event loop, or a global allocator. The embedder owns the runtime.
- **std gaps that must be filled in-tree** (ADR-0007):
  - TLS: client only (`std.crypto.tls.Client`); the TLS 1.3 server is in-tree
    work in Phase 2.
  - QUIC, HTTP/2, and a WebSocket client: none; implemented in-tree.
  - DNS: system resolver via `IpAddress.resolve`, no DoH/DoT client.
- **No external transport backends**: no C toolchain and no optional backend
  selected by a build flag. Missing transports are implemented in this
  repository (ADR-0007), so a config that needs one is rejected until it lands.
- **std-first**: `std` is the preferred implementation. An in-tree transport is
  a stopgap; when a pinned Zig upgrade provides the same primitive, switch to
  `std`, delete the in-tree code, and keep the interop and fuzz coverage.
- **License**: LGPL-2.1. Protocol code must be written from specifications;
  GPL/AGPL/MPL implementations must not be ported (see ADR-0009).
- **Pinned toolchain**: Zig 0.17.x. `std.Io` is still evolving, so the
  architecture isolates it behind a small set of interfaces.

## 5. Runtime model

All public operations take `io: std.Io` and an explicit allocator. Nothing is
implicitly spawned; long-running work is created with `io.async`,
`io.concurrent`, or an `Io.Group` owned by a listener or instance.

```zig
var threaded: std.Io.Threaded = .init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();
```

Rules:

- One `Io.Group` per inbound listener. `stop` cancels the group members before
  closing listeners, then waits.
- Per-connection work must be cancelable. `close` on a stream or socket is
  required to unblock pending reads and writes; the interface specifies this
  instead of relying on a separate cancel token.
- Timeouts use `Io.Timeout` / `io.operateTimeout`, never `std.Thread.sleep` or
  blocking `poll`.
- No CPU-heavy work (large rule-set parsing, certificate parsing, compression)
  on the I/O path. Parse config and rule sets before `start`.
- Library code must be usable from a single-threaded embedder; do not depend on
  thread-local storage or global mutable state.

## 6. Layers

| Layer | Responsibility | Must not know about |
| --- | --- | --- |
| `core` | `Io`, allocator, buffer pools, limits, cancellation, errors, logging, metrics | protocols, sockets |
| `net` | addresses, endpoints, socket options, dial/listen primitives, DNS resolver interface | proxy protocols |
| `transport` | byte-stream and datagram adapters: TLS, WebSocket, HTTP/2, QUIC, multiplexing, framing | routing, config |
| `protocol` | wire codecs for proxy protocols (header encode/decode, auth, per-connection state) | routing, config, listeners |
| `inbound` | accept loops, protocol handshakes, connection metadata | outbound selection |
| `outbound` | dialers, protocol handshakes, groups, health checks | inbound parsing |
| `routing` | metadata, rules, rule sets, sniffing, DNS resolution policy | transport details |

There is no `app` layer. `Instance` (the public facade) is the composition root:
it parses config, owns listeners and selector state, and wires layers together.
It may depend on every layer; no layer may import it.

Dependency direction is strictly downward: `Instance` → every layer,
`inbound`/`outbound` → `protocol`/`transport`/`net`/`core`, `protocol` →
`transport`/`net`/`core`. `routing` depends on `net` and `core` only.

## 7. Component overview

```
                    +-------------------------------------------+
  config (JSON) --> | Instance: API, config, wiring, metrics    |
                    +---------------------+---------------------+
                                          |
        +-----------------+---------------+------------------+
        |                 |                                  |
  +-----v-----+     +-----v------+                    +------v-----+
  |  inbound  |     |  routing   |                    |  outbound  |
  |  accept   | --> |  rules     | -----------------> |  groups    |
  |  + codecs |     |  + sniffer |                    |  + dialers |
  +-----+-----+     +-----+------+                    +------+-----+
        |                 |                                  |
        |           +-----v------+                           |
        |           |    dns     |                           |
        |           |  resolver  |                           |
        |           +-----+------+                           |
        |                 |                                  |
        +-----------------+---------------+------------------+
                                          |
                     +--------------------v----------------------+
                     | transport: stream | datagram | relay     |
                     | tls | ws | h2 | quic | framing          |
                     +--------------------+----------------------+
                                          |
                     +--------------------v----------------------+
                     | net: tcp | udp | unix | dns              |
                     +--------------------+----------------------+
                                          |
                     +--------------------v----------------------+
                     | core: std.Io | allocator | limits         |
                     +-------------------------------------------+
```

## 8. Core interfaces

Interfaces are vtable-based because the protocol and transport set is chosen at
runtime from config. Concrete implementations stay internal; only the public
root module re-exports the interfaces. See ADR-0003 for the alternative.

### 8.1 Stream

Duplex, ordered bytes with half-close support. This is the only thing relay
code needs to know.

```zig
pub const Stream = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, io: std.Io, bufs: [][]u8) ReadError!usize,
        write: *const fn (ctx: *anyopaque, io: std.Io, bufs: []const []const u8) WriteError!usize,
        shutdown: *const fn (ctx: *anyopaque, io: std.Io, how: ShutdownHow) ShutdownError!void,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
        local: *const fn (ctx: *anyopaque) Endpoint,
        remote: *const fn (ctx: *anyopaque) Endpoint,
    };
};
```

Contract:

- `read` returns `0` only on clean EOF. `error.Canceled` means the operation was
  interrupted.
- `write` writes everything or returns an error; partial writes are retried
  internally.
- `close` is idempotent, unblocks in-flight operations, and does not free the
  underlying memory (the owner does).
- `shutdown(.send)` propagates TCP half-close; relay code must not turn a
  half-close into a full close.

### 8.2 PacketConn

Datagrams with per-packet source/destination. Used by UDP inbounds/outbounds,
QUIC datagrams, and TUN (later).

```zig
pub const PacketConn = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        sendTo: *const fn (ctx: *anyopaque, io: std.Io, dest: Endpoint, data: []const u8) SendError!void,
        recvFrom: *const fn (ctx: *anyopaque, io: std.Io, buf: []u8) ReceiveError!Received,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
        maxDatagramSize: *const fn (ctx: *anyopaque) usize,
    };
};
```

`Received` carries the payload length and the source `Endpoint`. Implementations
must bound queues; dropping is a policy decision made by the session layer, not
by silently blocking the socket.

### 8.3 Dialer and transports

`Dialer.connect(io, target)` returns a `Stream`; `Dialer.connectPacket` is
optional and returns a `PacketConn` when the protocol supports UDP natively.
Transports wrap a dialer and add framing/encryption:

```
Outbound -> [quic | tls | ws | h2 | tcp] -> Dialer
```

Composition order follows the protocol spec (for example VLESS over TLS over
WebSocket over TCP). A transport may require metadata (SNI, ALPN, host header)
provided at dial time, not from global config.

### 8.4 Inbound and connection metadata

```zig
pub const Connection = struct {
    stream: ?Stream,          // null for datagram-only inbounds
    packets: ?PacketConn,
    metadata: Metadata,
    arena: *std.heap.ArenaAllocator,
};

pub const Metadata = struct {
    network: Network,          // tcp | udp
    source: Endpoint,
    destination: Endpoint,     // literal IP or unresolved domain + port
    domain: ?[]const u8,       // from inbound protocol or sniffer (arena-owned)
    inbound: []const u8,       // configured tag
    process: ?ProcessInfo,     // filled lazily, opt-in
    sniffed: ?SniffedProtocol, // tls | http | quic
};
```

Metadata is immutable once routing starts. Anything allocated for it lives in
the connection arena and dies with the connection.

### 8.5 Outbound

An outbound exposes a dialer, an optional packet dialer, a capability set
(TCP/UDP), and a health state. Groups (§11) implement the same interface so
they can be nested, but nesting is limited to one level in v1.

### 8.6 Router

`Router.match(metadata) -> Action`, allocation-free on the hot path. Actions
are `route(tag)`, `direct`, `reject(reason)`, `hijack_dns`. Rules are compiled
once at startup; `match` is safe for concurrent use.

### 8.7 Resolver and sniffer

The resolver interface returns A/AAAA records with TTLs from a cache. The
sniffer peeks at the first bytes of a stream and returns a domain (TLS SNI,
HTTP `Host`, or HTTP/2 `:authority` later) plus the protocol. Sniffed bytes are
buffered and replayed to the relay so no data is lost.

### 8.8 Codec

Wire codecs are plain functions plus per-connection state structs; they do not
perform I/O. `protocol` modules are shared by inbound and outbound halves so
header/auth logic has one implementation. Every decoder takes a bounded input
and returns `error.Malformed` rather than panicking.

## 9. Data flow

### 9.1 TCP

1. Inbound accepts, builds `Metadata` (destination from the protocol header).
2. Optional sniffing fills `metadata.domain` / `sniffed`; buffered bytes are
   kept for replay.
3. Router evaluates rules; the selected outbound dials the target through its
   transport stack.
4. Relay runs two tasks (client→remote, remote→client) with fixed buffers
   (`32 KiB` default, configurable). Each loop reads, writes, and propagates
   half-close. Idle timeout and byte counters are applied per direction.
5. First terminal error cancels the peer via `io` group cancel/close, then both
   streams are closed and metrics are recorded once.

Handshake (protocol auth) and connect timeouts share a `connect_timeout`;
`idle_timeout` applies only after the relay starts.

### 9.2 UDP

1. Inbound receives a datagram and derives a session key:
   `(client_endpoint, target_endpoint, inbound_tag)` plus protocol-specific
   association ID for SOCKS5/Trojan/VLESS.
2. The session table (sharded, bounded, LRU-ish) creates a session on first
   use; routing runs once per session and the chosen outbound is sticky for the
   session lifetime.
3. A per-session recv loop sends replies back to the client using the original
   path. Sessions expire on idle timeout or when the table is full (oldest
   idle first).
4. Datagrams that exceed `max_datagram_size` are rejected with a counter, never
   fragmented by the library.

UDP sessions are the unit of limits: `max_udp_sessions`, per-session queue
depth, and idle timeout. No unbounded per-packet allocation is allowed.

### 9.3 L7 HTTP

- `CONNECT host:port` becomes a TCP relay; the response is sent only after the
  outbound connects.
- Forward-proxy requests keep their absolute URI; HTTP/1.1 only in phase 1.
- No request rewriting, caching, or authentication beyond optional inbound
  credentials.
- L7 transports (WebSocket, HTTP/2, gRPC) are implemented as `transport`
  adapters, not in the HTTP inbound.

### 9.4 DNS

- Inbound-provided domains (SOCKS5/HTTP) are authoritative and avoid DNS on the
  proxy side until the outbound needs an IP.
- Sniffing is opt-in; it never replaces an inbound-provided domain.
- The resolver is used for outbound dials that need an IP and for rules that
  need one. Resolution policy (system, DoH later) is configurable per outbound
  or globally; `direct` uses the system resolver by default.
- Fake-IP is out of scope until a TUN inbound exists.

## 10. Routing model

Rules are an ordered list; the first match wins; the last rule is an explicit
default. Each rule has an action and one or more matchers (AND within a rule).

Matchers in v1:

| Matcher | Notes |
| --- | --- |
| `domain` | exact, suffix, keyword; no regex in v1 (backtracking and cost) |
| `domain_set` | compiled set (GEOSITE-style) |
| `ip_cidr` | sorted ranges + binary search |
| `geoip` | compiled country → ranges |
| `port` / `port_range` | destination port |
| `network` | `tcp` / `udp` |
| `inbound` | inbound tag |
| `process_name` / `process_path` | best-effort, opt-in, OS-specific |
| `protocol` | sniffed protocol |

Compiled rule sets use a versioned binary format: header, counts, sorted
domain/IP tables, CRC. They are produced by a separate tool from plain text or
public data and memory-mapped read-only at startup. No network access at
runtime. Data licensing (for example GeoLite2) is tracked in the tool's docs.

Process matching is best-effort: Linux `/proc`, macOS `proc_pidpath`, Windows
later. It may require privileges; failure returns "unknown" and must not fail
the connection.

## 11. Outbound groups and selection

Groups implement the outbound interface and contain an ordered node list.

| Type | Behavior |
| --- | --- |
| `manual` | fixed node |
| `round_robin` | rotate per new connection/session |
| `random` | uniform choice |
| `fallback` | first node, advance on connect failure, sticky until config reload |
| `least_latency` | EWMA latency from health checks, lowest wins; ties by order |

Health checks are explicit per group: `tcp_connect` to a host:port or
`http_head` to a URL, with interval, timeout, and jitter. Results feed an EWMA
(`alpha = 0.2`) and a failure counter with exponential backoff. Checks are off
by default; no traffic is generated unless configured.

Per-connection selection is independent. UDP sessions keep the selected node
for the session lifetime. Selection state is shared across tasks; use atomics
for counters and a mutex only around node-set replacement (config reload).

## 12. Protocol support matrix

| Protocol | Transport | TCP | UDP | Inbound | Outbound | Phase | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Direct | any | yes | yes | — | yes | 1 | system resolver |
| SOCKS5 | TCP (+UDP ASSOCIATE) | yes | yes | yes | yes | 1 | RFC 1928/1929 |
| HTTP proxy | TCP | yes | no | yes | yes | 1 | CONNECT + forward |
| Shadowsocks | TCP/UDP | yes | yes | yes | yes | 1 | AEAD + 2022 (BLAKE3) |
| Trojan | TLS | yes | yes | yes | yes | 2 | inbound needs in-tree TLS server |
| VLESS | TCP/TLS/WS/H2/gRPC | yes | yes | yes | yes | 2 | XTLS Vision later; gRPC in phase 3 |
| VMess | TCP/TLS/WS/H2/gRPC | yes | yes | yes | yes | 2 | legacy CFB not planned; gRPC in phase 3 |
| TUIC | QUIC | yes | yes | yes | yes | 3 | in-tree QUIC |
| Hysteria2 | QUIC + TLS | yes | yes | yes | yes | 3 | Salamander, Brutal CC |

Phasing:

- **Phase 0**: docs, ADRs, build scaffold, CI, core interfaces, public facade.
- **Phase 1 (MVP)**: `std.Io` core, TCP/UDP relay, SOCKS5 (CONNECT + UDP
  ASSOCIATE), HTTP/1.1 proxy (CONNECT + forward), HTTP CONNECT outbound, direct
  outbound, Shadowsocks 2022, domain/IP-CIDR/port rules, manual group, JSON
  config, counters.
- **Phase 2**: VLESS/Trojan/VMess, in-tree TLS 1.3 server, WS/H2 transports,
  sniffing, compiled rule sets, process rules, groups and health checks, DNS
  cache/DoH.
- **Phase 3**: in-tree QUIC, TUIC, Hysteria2, gRPC transport.
- **Phase 4**: optional TUN/transparent proxying, Windows, transport hardening
  and external audit.

Hysteria v1 is not planned; Hysteria2 is the target. Snell is deferred and
WireGuard is explicitly out of scope (ADR-0002).

## 13. Dependencies and in-tree transports

There is exactly one build configuration: std-only, no C toolchain, no optional
backend selected by a flag (ADR-0007). A transport that `std` lacks is
implemented in this repository, but in-tree code is always second choice:
re-check every transport on each Zig upgrade and migrate to `std` as soon as it
provides the same primitive, deleting the in-tree version.

- **TLS client**: `std.crypto.tls.Client` (Phase 1/2).
- **TLS 1.3 server**: in-tree on `std.crypto`, Phase 2; TLS 1.3 only, ALPN/SNI,
  caller-provided certificate and key, no renegotiation or weak ciphers.
- **WebSocket / HTTP/2 / gRPC**: in-tree, Phase 2/3; HTTP/2 is limited to
  transport needs (framing, HPACK, SETTINGS, GOAWAY).
- **QUIC**: in-tree, Phase 3; QUIC v1, stream multiplexing, datagrams, and
  pluggable congestion control (NewReno, Brutal). No 0-RTT in v1.
- **Config validation** rejects a transport or protocol that is not implemented
  yet; there is no runtime fallback or hidden backend.

Crypto primitives come from `std.crypto` only; never implement AES, ChaCha20,
Poly1305, BLAKE, SHA, HKDF, or X25519 by hand. `std.crypto.hash.Md5` exists but
is only acceptable for legacy VMess compatibility, which is not planned.
Hand-written handshakes require transcript fixtures, fuzzing, and external
review before any production-readiness claim.

## 14. Public API and configuration

Library lifecycle:

```zig
var diagnostic: marmo.Diagnostic = .{};
defer diagnostic.deinit();

var instance = marmo.Instance.init(gpa, io, config, &diagnostic) catch |err| {
    std.log.err("config: {f}", .{diagnostic});
    return err;
};
defer instance.deinit();
try instance.start();
try instance.wait();   // or block until the embedder calls stop()
try instance.stop();
```

- `init` parses and validates everything, allocates all long-lived state, and
  fills `diagnostic` on failure. It performs no I/O.
- `start` binds listeners, starts health checks, and returns. Partial startup
  failures roll back already-bound listeners.
- `stop` is idempotent, cancel-safe, and bounded by a configurable grace period.
- Config is JSON parsed with `std.json` in strict mode (unknown fields are
  errors) and validated with path-aware diagnostics (`inbounds[0].port`).
  Parsing is a library API, not an application layer; `Config` can also be built
  directly and goes through the same validator.
- Secrets are never logged; `Debug` output redacts passwords, UUIDs, and keys.
- No C ABI in v1. Semver applies to the Zig API; pre-1.0 may break between
  minor versions.

There is no CLI, daemon, or `app` layer in this repository. Embedders create
`Io.Threaded` (or `Io.Evented`), decide how to wait and shut down, and install
their own signal handlers. `Instance` is the only composition root.

## 15. Repository layout (planned)

```
build.zig
build.zig.zon
src/root.zig              public API re-exports
src/core/                 Io usage, limits, buffers, errors, logging
src/net/                  endpoints, sockets, resolver interface
src/transport/            tcp, tls, ws, h2, quic, framing
src/protocol/             shadowsocks, vmess, vless, trojan, tuic, hysteria2
src/inbound/              socks5, http, mixed, shadowsocks, ...
src/outbound/             direct, proxies, groups, health
src/routing/              rules, rule sets, sniffer
src/dns/                  resolver, cache
src/instance.zig          public facade: config, wiring, metrics
src/config/               schema, JSON, validation
docs/
  architecture.md
  decisions/
  protocols/              per-protocol notes and sources
tests/                    interop fixtures and loopback integration tests
```

Module boundaries are enforced by review, not by the compiler; do not import
`inbound` from `transport`, or `outbound` from `routing`.

## 16. Testing strategy

- Unit tests live beside the code (`test "..."` blocks) and must not need
  network access.
- Integration tests bind loopback listeners on port 0 and exercise real
  sockets through `Io.Threaded`; run the same suite with `Io.Evented` where the
  architecture supports fibers.
- Protocol tests use captured byte fixtures: handshake transcripts and packet
  captures in `tests/fixtures/<protocol>/`. No live third-party servers in CI.
- Every decoder has a fuzz target: `zig build fuzz -Dcodec=<name>` (once the
  build scaffold exists); malformed input must return an error, never panic.
- CI matrix: Linux x86_64 and macOS arm64 at minimum; a single-threaded build
  catches hidden thread assumptions.
- Benchmarks are opt-in and never part of `zig build test`.

## 17. Observability

- `std.log` with scoped fields (`inbound`, `outbound`, `session`, `rule`) and
  levels; default level is `info`.
- Counters: accepted/active/failed connections, bytes per direction, UDP
  sessions, rule hits, health-check latency/failures, dropped datagrams.
- Optional `MetricsSink` interface for embedders; no Prometheus dependency in
  the core.
- Never log payload bytes, credentials, UUIDs, or full SNI at `info`.

## 18. Risks and open questions

| Risk | Mitigation |
| --- | --- |
| `std.Io` API churn before 1.0 | pin Zig, isolate behind core interfaces |
| std lacks TLS server, QUIC, H2, WS | implement in-tree per ADR-0007, phase gates |
| Hand-written TLS/QUIC state machines | narrow scope, test vectors, fuzzing, external review; no production claim before audit |
| GEOIP/GEOSITE data licensing | tool-level docs, user-supplied data |
| Process matching portability/privileges | best-effort, opt-in, never fatal |
| Decoder attack surface | fuzzing, bounded parsing, no panics |
| LGPL-2.1 static linking obligations | document in README; legal review before release |
| Dynamic config reload races | rebuild state, then atomic swap; no in-place mutation |

## 19. Decision index

| ADR | Topic | Status |
| --- | --- | --- |
| [0001](decisions/0001-io-runtime.md) | I/O and concurrency runtime | Accepted |
| [0002](decisions/0002-scope-and-phasing.md) | Scope and delivery phases | Accepted |
| [0003](decisions/0003-core-abstractions.md) | Core interfaces and dispatch | Accepted |
| [0004](decisions/0004-transport-composition.md) | Transport composition | Accepted |
| [0005](decisions/0005-routing-engine.md) | Routing engine | Accepted |
| [0006](decisions/0006-outbound-selection.md) | Outbound groups and selection | Accepted |
| [0007](decisions/0007-tls-quic-dependencies.md) | TLS, QUIC, crypto dependencies (std-first) | Accepted |
| [0008](decisions/0008-api-and-config.md) | Public API, config, errors | Accepted |
| [0009](decisions/0009-licensing-and-interop.md) | Licensing and interop hygiene | Accepted |
