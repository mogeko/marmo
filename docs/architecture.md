# Architecture

Status: **Current Rust architecture.** Accepted decisions are ADR-0017 through
ADR-0029. The library is the only implementation in this repository; there is
no CLI, daemon, GUI, or application layer.

## 1. Purpose

marmo is an embeddable Rust library that accepts L4/L7 proxy traffic, decides
where it should go, and forwards it through a proxy protocol or directly.

The repository contains the library only: no CLI, daemon, GUI, or system
service. Applications that embed marmo own the process lifecycle, signal
handling, and configuration storage.

## 2. Goals

- L4 proxying: TCP streams and UDP datagrams, including UDP-over-stream
  (SOCKS5 UDP ASSOCIATE, VLESS UDP, Shadowsocks UDP, Trojan UDP).
- L7 proxying: HTTP/1.1 `CONNECT` and forward proxying, and L7 transports used
  by proxy protocols (TLS, WebSocket, HTTP/2, gRPC, QUIC).
- Inbounds: SOCKS5, HTTP, mixed, Shadowsocks, Trojan, VLESS, VMess, TUIC,
  Hysteria2; TUN later.
- Outbounds: direct, HTTP CONNECT, Shadowsocks, VMess, VLESS, Trojan, TUIC,
  Hysteria2; SOCKS5 outbound is later work.
- Rule-based routing on domain, IP/CIDR, GEOIP/GEOSITE, port, network,
  inbound, and process.
- Outbound groups with manual, round-robin, random, fallback, and
  least-latency selection plus health checks.
- Bounded memory, explicit cancellation, graceful shutdown, no global state.
- Linux, macOS, and Windows from the first release of the Rust tree.

## 3. Non-goals

- TLS interception or MITM with generated certificates.
- A CLI, daemon, GUI, subscription-format parsing, or provider ecosystem
  compatibility.
- Fake-IP DNS, transparent proxying (`iptables`/TPROXY), TUN inbounds before a
  later phase.
- HTTP caching, content rewriting, or a general-purpose HTTP server.
- Snell (deferred: no official specification) and WireGuard (an L3 VPN, not a
  stream proxy; abandoned, see ADR-0002).
- A userspace TCP/IP stack.

## 4. Constraints

- **Language**: Rust, edition 2024. The MSRV is the lowest stable release that
  satisfies the pinned dependency set; it starts at 1.87 and is recorded in
  `Cargo.toml`. CI builds both the current stable and 1.87.0. The MSRV rose
  from 1.85 to 1.87 for `ctutils` >= 0.4.4 (RUSTSEC-2026-0385). Raising it
  again needs a commit message that names the dependency and the version that
  forced it.
- **Runtime**: tokio is the only supported runtime. The embedder owns the
  runtime; the library takes a `tokio::runtime::Handle` and never builds one
  implicitly. Codecs and policy code are runtime-free, but the I/O layer is
  not runtime-agnostic. See ADR-0017 for the cost of the alternative.
- **Dependencies**: crates.io dependencies are allowed, including a C
  toolchain for the crypto provider. TLS, HTTP/2, and WebSocket are upstream
  crates. See ADR-0018.
- **License**: MIT OR Apache-2.0 (ADR-0020). Protocol work remains
  clean-room: implement from specifications, never port GPL/AGPL/MPL code, and
  keep fixture provenance.
- **Platforms**: Linux (x86_64, aarch64), macOS (arm64, x86_64), and Windows
  (x86_64) are CI targets from the first milestone. Other targets are
  best-effort.
- **Bounded state**: every queue, session table, cache, buffer, and
  library-owned index has an upper bound fixed at initialization; injected
  provider data is bounded by the embedder contract.
- **No global state**: no global allocator, logger, runtime, or process signal
  handler in the library.

### 4.1 Scope

The current release covers the implemented protocol and transport set.
Everything else is post-1.0 work (§19):

| Current | Future |
| --- | --- |
| SOCKS5 CONNECT + UDP ASSOCIATE inbound | — |
| HTTP CONNECT + forward inbound | QUIC, TUIC, Hysteria2 |
| HTTP CONNECT outbound | gRPC and XHTTP transports |
| Shadowsocks 2022 TCP/UDP | DNS cache, DoH/DoT |
| Trojan inbound/outbound (TLS, TCP/UDP, fallback) | — |
| VLESS inbound/outbound (TCP/TLS/WS/H2, TCP/UoT/XUDP, Mux.Cool) | — |
| VMess inbound/outbound (AEAD, TCP/UDP, Mux.Cool, TLS/WS/H2) | — |
| TLS 1.3 client/server, ALPN, mTLS | `http_head` probes, jitter, backoff |
| manual/RR/random/fallback/least-latency, TCP probes | root-level H2 pooling |
| domain/suffix/keyword/CIDR/port/range/inbound rules; injected domain/IP sets | TUN, transparent proxying |
| process rules via an injected `ProcessResolver` | Windows-specific process matching |
| strict JSON config, limits, metrics | — |
| TLS/HTTP/H2 sniffing with buffered replay | — |

## 5. Runtime model

tokio is the runtime and the cancellation model. The embedder creates the
runtime; the builder defaults to `Handle::try_current()` and can be given an
explicit handle. The library spawns only through that handle and owns every
task it creates.

```rust
let config = marmo::Config::from_json(&text)?;
let instance = marmo::Instance::builder(config).build()?;
instance
    .serve_with_shutdown(async { tokio::signal::ctrl_c().await.ok(); })
    .await?;
```

Rules:

- **One cancellation tree.** `Instance` owns a root
  `CancellationToken`; listeners and connections hold child tokens. Shutdown
  cancels the root and awaits the task sets with a grace timeout.
- **Every task is owned.** Listeners use a `JoinSet`; UDP sessions use a
  `TaskTracker`. No bare `tokio::spawn` outside those owners.
- **Timeouts are local.** Handshake, idle, and half-close deadlines use
  `tokio::time::timeout` or `Sleep` inside `select!`. There is no reaper and no
  global deadline registry; admission control is a `Semaphore` permit.
- **Dropping is cancellation.** A dropped connection future must leave the
  session table, metrics, and peer stream in a consistent state. Every
  `select!` branch is either cancel-safe or is not dropped (ADR-0017).
- **No filesystem I/O in the library.** TLS credentials arrive as inline PEM
  in the configuration and are parsed during `bind()`; the embedder reads
  files or fetches secrets (ADR-0023). Rule-set data and process identity are
  injected as `DomainSet`/`IpSet` and `ProcessResolver` implementations; the
  embedder owns storage, OS access, and reload (ADR-0028, ADR-0029).
- **Config is immutable per instance.** Reload is post-1.0: it
  builds a new `CompiledConfig` and publishes it through `ArcSwap`, so the data
  plane never locks.

The library still works under a current-thread runtime. Tests run both
flavors; no design decision may assume a work-stealing scheduler.

## 6. Layers

| Layer | Crate | Responsibility | Must not know about |
| --- | --- | --- | --- |
| core | `marmo` | limits, errors, metrics, config, logging | protocols, sockets |
| net | `marmo-net` | addresses, endpoints, network | proxy protocols |
| transport | `marmo-transport` | stream/datagram adapters: TLS, WebSocket, HTTP/2, QUIC, relay | routing, config |
| protocol | `marmo-proto` | wire codecs (header encode/decode, auth, per-connection state) | routing, config, listeners |
| inbound | `marmo` | accept loops, protocol handshakes, connection metadata | outbound selection |
| outbound | `marmo` | dialers, protocol handshakes, groups, health checks | inbound parsing |
| routing | `marmo` | metadata, compiled rules, action selection | transport details |

There is no `app` layer. `Instance` is the composition root: it parses config,
owns listeners and selector state, and wires the layers together. Dependency
direction is strictly downward: `marmo` → every crate, `marmo-proto` →
`marmo-net` (address parsing only), `marmo-net` → nothing. `marmo-transport`
depends only on upstream crates and the erased stream boundary.

## 7. Component overview

```
                    +-------------------------------------------+
  config (JSON) --> | Instance: API, config, wiring, limits      |
                    +---------------------+---------------------+
                                          |
        +-----------------+---------------+------------------+
        |                 |                                  |
  +-----v-----+     +-----v------+                    +------v-----+
  |  inbound  |     |  routing   |                    |  outbound  |
  |  accept   | --> |  rules     | -----------------> |  groups    |
  |  + codecs |     |            |                    |  + dialers |
  +-----+-----+     +-----+------+                    +------+-----+
        |                 |                                  |
        |           +-----v------+                           |
        |           |    dns     | (post-1.0)                      |
        |           |  resolver  |                           |
        |           +-----+------+                           |
        |                 |                                  |
        +-----------------+---------------+------------------+
                                          |
                     +--------------------v----------------------+
                     | transport: stream | datagram | relay     |
                     | rustls | ws-net           | h2 | quinn  |
                     +--------------------+----------------------+
                                          |
                     +--------------------v----------------------+
                     | net: tokio tcp/udp | socket2 | resolver   |
                     +--------------------+----------------------+
                                          |
                     +--------------------v----------------------+
                     | core: tokio runtime handle | limits      |
                     +-------------------------------------------+
```

## 8. Workspace and interfaces

### 8.1 Crates

| Crate | Published | Contents |
| --- | --- | --- |
| `marmo` | yes | public facade, `Instance`, config, routing, inbounds, outbounds, metrics |
| `marmo-proto` | yes | HTTP/1, SOCKS5, SS2022, Trojan, VLESS, VMess, Mux.Cool codecs; no I/O, no tokio |
| `marmo-net` | yes | `Endpoint`, CIDR, `Network` |
| `marmo-transport` | yes | stream traits, TLS/WS/H2 layers, relay |

Four crates. `inbound`, `outbound`, `routing`, and `config` stay inside
`marmo` because `Instance` wires all of them and splitting would only add
re-export churn. All crates version together at `0.x` until the API is stable.

### 8.2 Streams and datagrams

`Stream` is a bound, not a bespoke trait. This is the only thing relay code
needs to know.

```rust
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream>;
pub type BoxFuture<'a, T> =
    Pin<Box<dyn Future<Output = T> + Send + 'a>>;
```

Contract:

- `poll_read` returning `Ok(0)` means clean EOF.
- `poll_shutdown` propagates TCP half-close; relay code must not turn a
  half-close into a full close.
- Dropping a stream closes it; there is no `close` method and no
  "must unblock pending I/O" contract. Cancellation is `select!` plus drop.
- Ownership is explicit: the connection task owns both streams and every
  buffer they borrow.

Datagrams use `tokio::net::UdpSocket` for the direct case and a small trait for
protocol-owned channels:

```rust
pub trait Datagram: Send + Sync + 'static {
    fn send_to<'a>(&'a self, data: &'a [u8], dest: &'a Endpoint)
        -> BoxFuture<'a, Result<(), DatagramError>>;
    fn recv_from<'a>(&'a self, buf: &'a mut [u8])
        -> BoxFuture<'a, Result<(usize, Endpoint), DatagramError>>;
    fn max_datagram_size(&self) -> usize;
}
```

Implementations bound their queues. Dropping a datagram is a session-layer
policy decision, not a silent block inside the socket.

### 8.3 Transport composition

Composition keeps ADR-0004's model: a protocol dialer wraps transport layers,
which wrap a base connect.

```
Outbound -> protocol -> [quic | tls | ws | h2 | tcp] -> base connect
```

`Dialer` and `Transport` are builders, not per-operation vtables. A transport
layer implements `Layer` once; the stack is composed at startup and the hot
path only sees the resulting `BoxStream`.

```rust
pub trait Layer: Send + Sync {
    fn wrap<'a>(
        &'a self,
        inner: BoxStream,
        opts: &'a LayerOptions,
    ) -> BoxFuture<'a, Result<BoxStream, TransportError>>;
}
```

Layers are compiled from config into a `Vec<Box<dyn Layer>>` in spec order (for
example VLESS → TLS → WebSocket → TCP). Transport parameters (SNI, ALPN,
`Host`, path, subprotocols) come from the outbound config at dial time, never
from globals. Inbound stacks mirror the same order.

### 8.4 Inbound and metadata

```rust
pub struct Connection {
    pub stream: Option<BoxStream>,      // None for datagram-only inbounds
    pub datagrams: Option<Box<dyn Datagram>>,
    pub metadata: Metadata,
}

pub struct Metadata {
    pub network: Network,               // tcp | udp
    pub source: Endpoint,
    pub destination: Endpoint,          // literal IP or unresolved domain + port
    pub domain: Option<Arc<str>>,       // inbound protocol or sniffer
    pub inbound: InboundId,             // compiled tag index
    pub process: Option<ProcessInfo>,   // injected resolver, opt-in
}
```

`Metadata` is immutable once routing starts. It is a plain struct owned by the
connection task; there is no arena and no allocator threading. Anything that
must outlive the task is an `Arc`.

### 8.5 Outbound

```rust
pub trait Outbound: Send + Sync {
    fn connect<'a>(
        &'a self,
        target: &'a Endpoint,
        opts: &'a ConnectOptions,
    ) -> BoxFuture<'a, Result<BoxStream, ConnectError>>;

    fn connect_datagram<'a>(
        &'a self,
        target: &'a Endpoint,
        opts: &'a ConnectOptions,
    ) -> BoxFuture<'a, Result<Box<dyn Datagram>, ConnectError>>;

    fn capabilities(&self) -> Capabilities;   // tcp, udp
    fn health(&self) -> HealthSnapshot;
}
```

Groups implement the same trait and contain an ordered node list. Nesting is
limited to one level, as before. `Box<dyn Outbound>` is created once at
startup; the connection path makes one virtual call per dial, not per byte.

### 8.6 Router

```rust
pub trait Router: Send + Sync {
    fn route(&self, metadata: &Metadata) -> Action;
}
```

`route` is synchronous, allocation-free, and safe for concurrent reads. Rule
targets compile to `OutboundId(u16)` instead of `&str`, so a match returns a
small copy type. Rules are immutable after construction and live behind an
`Arc`.

### 8.7 Resolver and sniffer

The resolver interface (TTL cache, DoH/DoT policy) is post-1.0; current dials
go through the system resolver (`tokio::net::lookup_host`). The sniffer is
opt-in per inbound (`"sniffing": { "enabled": true, "protocols": [...] }`). It
peeks at a bounded prefix of the stream and returns a domain from a TLS
`ClientHello` server name, an HTTP/1 `Host` header, or the first plaintext
HTTP/2 `:authority`. Sniffed bytes are buffered and replayed to the relay so no
data is lost. An inbound-provided domain always wins; sniffing only fills the
routing domain when the request carried an IP destination. TLS interception is
not performed, so HTTP/2 inside TLS is identified by SNI only.

### 8.8 Codec

Wire codecs are plain functions plus per-connection state structs. They do not
perform I/O and do not import tokio. `marmo-proto` is shared by inbound and
outbound halves so header/auth logic has one implementation. Every decoder
takes a bounded input (`&mut Bytes` or `&[u8]`), returns a typed error, never
panics, and never allocates based on an unvalidated length.

## 9. Data flow

### 9.1 TCP

1. The listener accepts, acquires a `Semaphore` permit, and creates a child
   cancellation token.
2. The inbound handshake fills `Metadata` (destination from the protocol
   header) under `handshake_timeout`.
3. Routing selects an `OutboundId`; the outbound dials the target through its
   layer stack under the same deadline.
4. Relay runs `copy_bidirectional_with_sizes(32 KiB)` wrapped in counters and
   an activity-based idle deadline. Half-close is propagated in both
   directions.
5. The first terminal error cancels the peer direction, then both streams are
   dropped and metrics are recorded once. The permit is released when the
   connection task ends.

`limits.max_connections` is enforced by `try_acquire_owned` before the
handshake, so an overloaded instance rejects instead of queueing. Idle and
half-close deadlines are per-connection timers, not a shared scan.

### 9.2 UDP

1. The inbound receives a datagram and derives a session key:
   `(client_endpoint, target_endpoint, inbound_id)` plus the protocol
   association ID for SOCKS5/Trojan/VLESS.
2. The session table (bounded, sharded, LRU-ish) creates a session on first
   use; routing runs once per session and the chosen outbound is sticky for
   the session lifetime.
3. A per-session task holds a session permit, a bounded `mpsc` queue, and an
   idle deadline. Replies go back to the client on the original path.
4. Sessions expire on idle timeout or when the table is full (oldest idle
   first). In current the table capacity is fixed at initialization per inbound
   (128 for the Shadowsocks UDP listener, matching the initial implementation); a
   configurable `max_udp_sessions` is post-1.0. UDP caps stay separate from
   `max_connections`, as in ADR-0015.

Datagrams above `max_datagram_size` are rejected with a counter, never
fragmented by the library. There is no per-packet heap allocation on the
forwarding path.

Trojan and SOCKS5 UDP associations are per-stream rather than table entries.
Each datagram is routed independently; the first accepted datagram selects the
outbound tag, and later datagrams that select a different tag are dropped. A
Trojan association may send to multiple destinations through the same
datagram channel when the selected outbound supports it (direct and Trojan;
VLESS simple UoT binds one destination).

### 9.3 L7 HTTP

- `CONNECT host:port` becomes a TCP relay; the response is sent only after the
  outbound connects.
- Forward-proxy requests are rewritten from absolute-form to origin-form, with
  `Host` taken from the URI authority and hop-by-hop headers stripped. Upstream
  is forced to `Connection: close`; v1 handles one request per connection.
- HTTP/1.1 only; no request rewriting beyond the request line and headers.
- No caching, content rewriting, or authentication beyond optional inbound
  credentials.
- L7 transports (WebSocket, HTTP/2, gRPC) are transport adapters, not part of
  the HTTP inbound.

### 9.4 DNS

- Inbound-provided domains (SOCKS5/HTTP) are authoritative and avoid DNS on the
  proxy side until the outbound needs an IP.
- The resolver is used for outbound dials that need an IP and for rules that
  need one. `direct` uses the system resolver by default; DoH/DoT and a cache
  arrive in post-1.0.
- Sniffing is opt-in per inbound and never replaces an inbound-provided
  domain. It fills the routing domain from TLS SNI, HTTP/1 `Host`, or plaintext
  HTTP/2 `:authority`; the peeked bytes are replayed unchanged.
- Fake-IP is out of scope until a TUN inbound exists.

## 10. Routing model

Rules are an ordered list; the first match wins; the last rule is an explicit
default. Each rule has an action and one or more matchers (AND within a rule).

Matchers in the current set:

| Matcher | Notes |
| --- | --- |
| `domain` | exact match, ASCII-case-insensitive |
| `domain_suffix` | suffix match on label boundaries, no regex |
| `domain_keyword` | compiled `aho-corasick` automaton, no regex |
| `domain_set` | injected `DomainSet` by tag; provider defines exact/suffix/keyword semantics |
| `ip_cidr` | sorted ranges + binary search |
| `geoip` | injected `IpSet` by tag; sorted membership query |
| `port` | destination port |
| `port_range` | inclusive ranges, normalized and merged |
| `network` | `tcp` / `udp` |
| `inbound` | inbound tag |
| `process_name` | exact executable name from an injected `ProcessResolver` |
| `process_path` | exact executable path from an injected `ProcessResolver` |

`domain_set` and `geoip` do not have a library-owned file format. The embedder
registers an `Arc<dyn DomainSet>` or `Arc<dyn IpSet>` at build time; the data
may live in a tree, a sorted array, a SQLite snapshot, or another store. The
provider contract requires an in-memory, non-blocking, allocation-free,
bounded, panic-free `contains`. Set data can be swapped inside the provider
without rebuilding the instance; rule/config reload remains future work.

Process identity is best-effort and opt-in. The embedder injects a
`ProcessResolver`; the library owns the `process_name`/`process_path` matchers,
a bounded cache, a lookup timeout, and an in-flight limit. Unknown, timeout,
resolver panic, and platform absence all return "unknown" and never fail the
connection. Process matching is not a security boundary.

Sniffed `protocol` matching remains deferred; it is not part of the current
matcher set.

## 11. Outbound groups and selection

| Type | Behavior |
| --- | --- |
| `manual` | fixed node |
| `round_robin` | rotate per new connection/session |
| `random` | uniform choice |
| `fallback` | first node, advance on connect failure, sticky until config reload |
| `least_latency` | EWMA latency, lowest wins; ties by order |

Selection state is `AtomicU64`/`AtomicU32` per node; node-set replacement, when
reload lands post-1.0, uses `ArcSwap` and never appears on the connect path. Health checks
are opt-in per group: `tcp_connect` to a host:port with interval and timeout,
driven by a task owned by the instance's `JoinSet`. Results feed an EWMA
(`alpha = 0.2`) and a failure counter. `http_head`, jitter, and exponential
backoff are post-1.0. No traffic is generated unless configured.

## 12. Protocol support matrix

`Supported` means the feature is implemented and covered by the current test
and interop suite. `Future` means it is not part of the current release.

| Protocol | Transport | TCP | UDP | Inbound | Outbound | Scope |
| --- | --- | --- | --- | --- | --- | --- |
| Direct | any | yes | yes | — | yes | supported |
| SOCKS5 | TCP (+UDP ASSOCIATE) | yes | yes | yes | no | supported |
| HTTP proxy | TCP | yes | no | yes | yes | supported |
| Shadowsocks 2022 | TCP/UDP | yes | yes | yes | yes | supported |
| Trojan | TLS | yes | yes | yes | yes | supported |
| VLESS | TCP/TLS/WS/H2 | yes | yes | yes | yes | supported |
| VMess | TCP/TLS/WS/H2 | yes | yes | yes | yes | supported |
| TUIC | QUIC | — | — | — | — | future |
| Hysteria2 | QUIC + TLS | — | — | — | — | future |

VLESS supports TCP, simple UoT, and XUDP over TCP, TLS, WebSocket, and HTTP/2,
with the strict `transport` object of ADR-0016. Its inbound terminates full
Mux.Cool for TCP and UDP sessions (ADR-0026); `mux: true` pools outbound TCP
and UDP sessions over up to four physical connections (ADR-0027). `Instance`
serves one VLESS stream per HTTP/2 connection; root-level multiplexing/pooling
is future work.
gRPC is future work built on `h2`/`tonic`. XHTTP is future work for current
Xray compatibility (roadmap P3-6); it needs an ADR and `h3` depends on the QUIC
adapter. VMess implements the AEAD header only; legacy CFB is not planned. Its
inbound terminates Mux.Cool for TCP and UDP sessions; the outbound uses direct
UDP by default and `mux: true` for client-side pooling (ADR-0027).

## 13. Dependencies and transports

| Need | Crate | Notes |
| --- | --- | --- |
| Runtime, TCP/UDP, timers, sync | `tokio` | only supported runtime |
| Cancellation, task tracking, codecs | `tokio-util` | `CancellationToken`, `TaskTracker`, `Framed` |
| TLS 1.3 client/server, ALPN, mTLS | `rustls`, `tokio-rustls` | TLS 1.3 only; platform verifier |
| HTTP/2 | `h2` | framing, HPACK, flow control, 1xx, trailers |
| WebSocket | `ws-net` | RFC 6455, permessage-deflate, subprotocols |
| HTTP/1.1 | `httparse` (+ `hyper` only if needed) | the inbound is minimal; no general server |
| VMess crypto | `md-5`, `sha3`, `hmac`, `chacha20poly1305` | CmdKey, SHAKE128 masks, HMAC KDF, ChaCha body |
| QUIC (post-1.0) | `quinn` | streams, datagrams, custom congestion control |
| DNS (post-1.0) | `hickory-resolver` | system, DoH, DoT, cache |
| Config | `serde`, `serde_json`, `serde_path_to_error` | strict parsing, path-aware errors |
| Errors | `thiserror` | typed errors; `anyhow` only in examples/tests |
| Secrets | `secrecy`, `zeroize` | no secret in `Debug` or logs |
| Buffers | `bytes` | zero-copy header parsing |
| Reload (post-1.0) | `arc-swap` | lock-free config swap |
| Sockets | `socket2` | keepalive, buffer sizes, `SO_REUSEADDR` |
| IP/CIDR | `ipnet` | compiled ranges |
| Domain keywords | `aho-corasick` | inline `domain_keyword` automata |
| Domain/IP sets and process identity | embedder-provided | `DomainSet`/`IpSet` and `ProcessResolver`; no library file or OS access |

Rules:

- **No forked TLS, HTTP/2, or WebSocket.** When a needed capability is missing
  upstream, pin a newer version; do not fork a transport into this repository.
- **One crypto provider.** `aws-lc-rs` (the `rustls` default) is pinned; it
  requires a C toolchain and assembly. `ring` is not a second supported
  backend. ADR-0018 records the accepted build prerequisite.
- **Crypto primitives** come from the TLS provider or RustCrypto crates
  (`aes-gcm`, `chacha20poly1305`, `blake3`, `sha2`, `sha3`, `hmac`, `md-5`);
  never implement AES, ChaCha20, Poly1305, BLAKE, SHA, HKDF, or X25519 by
  hand.
- **License gate.** CI rejects GPL/AGPL/MPL with a `cargo tree --format '{l}'`
  check; dependency-changing PRs record the same output as a license review.
  `cargo-audit` covers advisories; `Cargo.lock` is committed and CI uses
  `--locked`.
- **Config validation** rejects a transport or protocol that is not
  implemented yet; there is no runtime fallback or hidden backend.

## 14. Public API and configuration

The API follows the shape Rust network libraries converged on: a builder for
construction, a future for running, and a cloneable handle for control. Hyper
separates protocol construction (`Builder`) from connection driving
(`serve_connection`); marmo separates instance construction (`InstanceBuilder`)
from listener driving (`bind`/`serve`). Hyper's `Service` is per request; the
per-connection equivalent here is `Inbound`/`Outbound`.

| Idiom (hyper / axum / tokio) | marmo |
| --- | --- |
| `hyper::server::conn::http1::Builder` | `Instance::builder(config)` |
| `Builder::serve_connection(io, service)` | `Instance::bind().await` → `BoundInstance::serve()` |
| `axum::serve(listener, app)` | `Instance::serve()` / `serve_with_shutdown(fut)` |
| `.with_graceful_shutdown(signal)` | `serve_with_shutdown(signal)` |
| `hyper_util::server::graceful::GracefulShutdown` | `InstanceHandle::shutdown()` + drain |
| `TcpListener::bind(addr).await` | `Instance::bind().await` |
| `tokio::spawn(task)` | `handle()` then spawn `serve()` |
| `tower::Service` | `Inbound` / `Outbound` traits (internal) |

Design rules:

- **Build is pure; bind and serve do I/O.** `Config::from_json` parses and
  validates the schema; `build()` compiles rules and selector graphs and
  allocates long-lived state. Neither opens a socket nor reads a file.
- **No `&mut self` lifecycle.** `bind`/`serve` consume the instance, and
  `handle()` returns a `Clone` control handle, so ownership stays obvious.
- **Shutdown is a future, not a timeout argument.** Cancellation is a
  `Future<Output = ()>` (a signal, a `CancellationToken::cancelled()`, or
  `std::future::pending()`), and the grace period is a builder option.
- **The runtime is ambient by default.** The builder uses
  `Handle::try_current()` and fails with `BuildError::NoRuntime` outside a
  runtime; `.runtime(handle)` overrides it.
- **Errors are values, not a side channel.** No `Diagnostic` out-parameter;
  `thiserror` enums carry the config path and the inbound tag.

### 14.1 Lifecycle

```rust
// Pure: parse, validate, compile rules.
let config = marmo::Config::from_json(&text)?;

// Pure: no sockets, no files, no tasks.
let instance = marmo::Instance::builder(config)
    .runtime(runtime.handle().clone())        // optional; Handle::try_current()
    .metrics(sink)                            // optional
    .shutdown_grace(Duration::from_secs(10))  // default 10 s
    .build()?;

// Batteries-included: bind, accept, and drain when the signal resolves.
instance
    .serve_with_shutdown(async {
        tokio::signal::ctrl_c().await.ok();
    })
    .await?;
```

### 14.2 Explicit binding and control

For readiness, port 0 in tests, or a GUI that starts and stops the proxy:

```rust
let bound = instance.bind().await?;      // binds every inbound, rolls back on error
for addr in bound.local_addrs() {
    tracing::info!(tag = addr.tag, network = ?addr.network, %addr.addr, "listening");
}

let ctl = bound.handle();                // Clone + Send + Sync
let serve = tokio::spawn(bound.serve()); // drains when ctl.shutdown() is called
ctl.shutdown();                          // non-blocking, idempotent
serve.await??;
```

`BoundInstance::serve()` runs until the handle shuts down or a listener fails.
`serve_with_shutdown(fut)` additionally stops when `fut` resolves; the internal
handle and the external future are combined with `select!`. Dropping a serve
future cancels it but does not wait.

### 14.3 Types

```rust
pub struct Config { /* owned; no borrows */ }

impl Config {
    /// Strict JSON, version 2. Unknown fields and duplicate keys are errors.
    pub fn from_json(text: &str) -> Result<Self, ConfigError>;
}

impl std::str::FromStr for Config {
    type Err = ConfigError;
    fn from_str(text: &str) -> Result<Self, Self::Err> { Self::from_json(text) }
}

pub struct Instance { /* Arc<Inner> */ }        // Send + Sync + 'static

impl Instance {
    pub fn builder(config: Config) -> InstanceBuilder;
    pub fn handle(&self) -> InstanceHandle;

    pub async fn bind(self) -> Result<BoundInstance, BindError>;
    pub async fn serve(self) -> Result<(), ServeError>;
    pub async fn serve_with_shutdown<F>(self, shutdown: F) -> Result<(), ServeError>
    where
        F: Future<Output = ()> + Send + 'static;
}

pub struct InstanceBuilder { /* ... */ }

impl InstanceBuilder {
    pub fn runtime(self, handle: tokio::runtime::Handle) -> Self;
    pub fn metrics(self, sink: Arc<dyn MetricsSink>) -> Self;
    pub fn shutdown_grace(self, grace: Duration) -> Self;
    pub fn build(self) -> Result<Instance, BuildError>;
}

pub struct BoundInstance { /* bound listeners + compiled state */ }

impl BoundInstance {
    pub fn local_addrs(&self) -> impl Iterator<Item = BoundAddr<'_>>;
    pub fn handle(&self) -> InstanceHandle;
    pub async fn serve(self) -> Result<(), ServeError>;
    pub async fn serve_with_shutdown<F>(self, shutdown: F) -> Result<(), ServeError>
    where
        F: Future<Output = ()> + Send + 'static;
}

pub struct BoundAddr<'a> {
    pub tag: &'a str,
    pub network: Network,
    pub addr: SocketAddr,
}

#[derive(Clone)]
pub struct InstanceHandle { /* CancellationToken */ }

impl InstanceHandle {
    pub fn shutdown(&self);          // non-blocking, idempotent
    pub fn is_shutdown(&self) -> bool;
}
```

Errors:

- `ConfigError` renders the JSON path (`inbounds[0].port`) via
  `serde_path_to_error`; it is the only error a config typo produces.
- `BuildError` covers `NoRuntime`, unresolved outbound/tag references, and
  selector-graph invariants. No I/O happens here.
- `BindError` carries the inbound tag, the resolved address, and the
  `io::Error`. A partial bind rolls back every listener already bound.
- `ServeError` is fatal listener failure or a drain failure; normal shutdown
  returns `Ok(())`. `serve()` binds internally, so bind failures surface as
  `ServeError::Bind`; `bind()` returns `BindError` directly.
- All are `#[non_exhaustive]` and implement `std::error::Error`; `anyhow` never
  appears in a public signature.

`Config` implements `FromStr`, so `text.parse()?` is equivalent to
`Config::from_json(text)`. There is no `tower::Service` at the facade: a
proxy's unit of work is a connection, not a request. `Inbound` and `Outbound`
are the runtime-chosen traits, and `tower` compatibility is not promised.

### 14.4 Configuration and secrets

- Config is strict JSON (`"version": 2`): unknown fields rejected, duplicate
  keys rejected, defaults documented. TLS credentials are inline PEM in the
  configuration (ADR-0023), so a version 1 document with file paths is
  rejected explicitly rather than parsed as DER.
- Global `limits` (`max_connections`, `handshake_timeout_s`,
  `idle_timeout_s`, `uplink_only_s`, `downlink_only_s`) are validated in
  `build()`. UDP session caps remain per-inbound fixed bounds.
- The library performs no filesystem I/O for credentials: `build()` and
  `bind()` never read files, and `spawn_blocking` is not needed on this path.
- Secrets use `SecretString`/`zeroize`; `Debug` redacts passwords, UUIDs, and
  keys. No payload, credential, or SNI is logged at `info`.
- The library installs no global tracing subscriber and no signal handler; the
  embedder owns both.
- No C ABI in v1. Semver applies to the Rust API; pre-1.0 may break between
  minor versions.

There is no CLI, daemon, or `app` layer. `Instance` is the only composition
root.

## 15. Repository layout

```text
Cargo.toml                 workspace + MSRV
crates/
  marmo/                   facade: Instance, config, routing, inbound, outbound
    tests/                 loopback integration tests
    examples/              runnable examples
  marmo-proto/             codecs, no I/O
  marmo-net/               endpoints, CIDR, network
  marmo-transport/         stream traits, Layer adapters, relay
fuzz/                      cargo-fuzz crate and corpus
docs/
  architecture.md          this file
  decisions/               ADR index and records
  protocols/               protocol notes and sources
  security/                threat model, audit findings
```

Module boundaries inside `marmo` are enforced by review, not by the compiler.

## 16. Testing strategy

- Unit tests live beside the code and need no network. `#[tokio::test]` runs
  both `current_thread` and `multi_thread` flavors for concurrency-sensitive
  tests.
- `tokio::io::duplex` replaces sockets for codec and relay tests;
  `tokio::time::pause()` makes timeout and half-close tests deterministic.
- Integration tests bind loopback port 0 and exercise real sockets through
  tokio. No live third-party servers in CI.
- Protocol tests use synthetic vectors and the fuzz corpus in `fuzz/corpus/`;
  no fixture is a capture of real traffic.
- `proptest` covers parsers and config validation; `cargo-fuzz` covers every
  decoder and the framing glue we own (nightly only). Malformed input returns
  a typed error, never panics.
- Interop runs against self-hosted reference binaries outside CI. No GPL code
  is linked, ported, or distributed.
- CI matrix: Linux x86_64, macOS arm64, Windows x86_64; `cargo fmt --check`,
  `clippy -D warnings`, `cargo test`, `cargo audit`, and the copyleft check.
- Benchmarks (`criterion`) and `miri`/`loom` runs are opt-in and never part of
  the default test job.

## 17. Observability

- `tracing` spans per connection (`inbound`, `outbound`, `network`, hashed
  SNI) and per UDP session; default level is `info`.
- Counters: accepted/active/rejected/failed connections, bytes per direction,
  UDP sessions, rule hits, health-check latency/failures, dropped datagrams.
- Optional `MetricsSink` for embedders; no Prometheus dependency in the core.
- Secrets and payloads are never recorded as span fields; redaction is a
  review checklist item, not a best-effort filter.

## 18. Security

- The threat model, audit findings, obligations, and residual risks are in
  [`docs/security/audit.md`](security/audit.md).
- Untrusted bytes never panic, recurse, or allocate unboundedly. Decoders are
  fuzzed; length fields are bounded before allocation.
- Secrets are zeroized and compared in constant time; `unsafe` is
  `forbid`-denied in `marmo-proto` and `marmo` and requires a written
  justification in `marmo-transport`.
- Dependency surface is part of the security surface: pinned lockfile, the
  copyleft check, `cargo-audit`, and a documented review before accepting a new
  crate with `unsafe` or a build script.
- Cancellation safety is a security property: a dropped protocol state machine
  must not leave a half-authenticated session reachable.
- Injected `DomainSet`/`IpSet` and `ProcessResolver` implementations are
  trusted embedder code. The library bounds tag count, cache size, lookup
  timeout, and in-flight calls, but it cannot verify provider memory bounds,
  checksums, or platform behavior. Process identity is not a security
  boundary; process names and paths are never logged.

## 19. Roadmap

The current release line is `0.0.3`. The dependency-ordered work list is in
[`roadmap.md`](roadmap.md); the summary is:

| Item | Enabled by |
| --- | --- |
| QUIC, TUIC, Hysteria2 | `quinn` |
| DNS cache and DoH/DoT | `hickory-resolver` |
| gRPC transport | `h2`/`tonic` |
| XHTTP transport | `h2`, later `quinn` (`h3`) |
| Rule sets, GEOIP/GEOSITE | injected `DomainSet`/`IpSet` |
| Process rules | injected `ProcessResolver` |
| HTTP/2 root multiplexing and pooling | `h2` |
| `http_head` health checks, jitter, backoff | `tokio::time` |

## 20. Risks and open questions

| Risk | Mitigation |
| --- | --- |
| Cancellation-safety bugs in protocol state machines | drop-mid-await tests; `select!` review |
| Dependency supply chain | pinned lockfile, `--locked`, copyleft check, `cargo-audit`, review new build scripts |
| Injected provider contract violations | documented contract, fake-provider tests, per-provider audit; library bounds tags, cache, timeout, and in-flight calls |
| C toolchain friction on Windows/macOS | one pinned provider, CI images documented; a platform that cannot build `aws-lc-rs` needs a new ADR, not a silent backend switch |
| License-change consent | both copyright holders must agree; ADR-0020 records the decision |
| Tokio lock-in | accepted in ADR-0017; codecs and policy remain runtime-free |
| Ecosystem churn in `rustls`/`quinn`/`h2` | adapters isolate versions; pin minor ranges |
| External audit | not yet commissioned; required before a production-readiness claim |

Open questions:

- Whether a second runtime is required by an actual embedder (revisit ADR-0017
  only with a named embedder and a budget).
- Whether to publish crates individually or only `marmo` at 1.0.
- Whether Hysteria2's Brutal controller fits `quinn`'s controller trait.

## 21. Decision index

Current decisions are ADR-0017 through ADR-0029. Historical decisions from the
initial implementation are ADR-0001 through ADR-0016 and remain in
[`docs/decisions/`](decisions/README.md); their bodies are unchanged.

| ADR | Topic | Status |
| --- | --- | --- |
| [0017](decisions/0017-language-and-runtime.md) | Language, runtime, and interface model | Accepted |
| [0018](decisions/0018-dependencies-and-crypto.md) | Dependencies and crypto backend | Accepted |
| [0019](decisions/0019-workspace-and-packaging.md) | Workspace layout and packaging | Accepted |
| [0020](decisions/0020-license.md) | License change | Accepted |
| [0021](decisions/0021-websocket-backend.md) | WebSocket backend and permessage-deflate | Accepted |
| [0022](decisions/0022-vless-http2-method.md) | VLESS HTTP/2 transport method | Accepted |
| [0023](decisions/0023-tls-credentials-inline.md) | TLS credentials as inline configuration | Accepted |
| [0024](decisions/0024-drop-testkit.md) | Drop the unused testkit crate | Accepted |
| [0025](decisions/0025-vmess-aead.md) | VMess AEAD, UDP, and Mux.Cool | Accepted |
| [0026](decisions/0026-vless-mux.md) | VLESS inbound Mux.Cool | Accepted |
| [0027](decisions/0027-client-mux.md) | Client-side Mux.Cool outbound | Accepted |
| [0028](decisions/0028-rule-sets.md) | Injected rule sets | Accepted |
| [0029](decisions/0029-process-identity.md) | Process identity injection | Accepted |
