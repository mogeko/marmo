# ADR-0030: DNS cache and DoH/DoT resolver

- Status: Accepted (2026-11-22)
- Date: 2026-11-22
- Deciders: @mogeko
- Related: ADR-0005, ADR-0017, ADR-0018, ADR-0023, ADR-0029

## Context

P2-11 adds a DNS resolver with a TTL cache and DoH/DoT policy. Today every
direct dial calls `tokio::net::lookup_host`: there is no cache, no encrypted
resolver, no query timeout, no in-flight bound, and no explicit policy for a
plaintext fallback. The system resolver may also read `/etc/resolv.conf` and
`/etc/hosts`, which is filesystem I/O the library otherwise forbids.

The resolver is on the dial path and is security-sensitive:

- Query names reveal the destinations a client requests, so they must not be
  logged and plaintext fallback must be an explicit choice.
- DNS answers are untrusted input and must be bounded before use.
- A resolver is a new network egress from the library; it must not become an
  implicit proxy detour or an unbounded task/queue owner.

ADR-0018 names `hickory-resolver` for DoH, DoT, and cache. Use 0.26.3, the
current release, which requires Rust 1.88. Raising the workspace MSRV from 1.87
to 1.88 is accepted for this dependency and must be recorded in `Cargo.toml`,
`CHANGELOG.md`, `AGENTS.md`, `README.md`, `crates/README.md`,
`docs/architecture.md`, and CI; the commit message names `hickory-resolver`
0.26.3. The crate and its `moka` cache dependency are permissively licensed
(MIT/Apache-2.0). The default `system-config` feature reads host files and must
be disabled.

ADR-0005 says DNS is resolved only when a selected outbound needs an IP. The
current `ip_cidr` and `geoip` matchers see a literal destination IP only; a
domain destination does not match them. This ADR keeps that behavior.

## Decision (recommended)

Add an opt-in DNS subsystem behind a non-default `dns` Cargo feature, with a
built-in `hickory-resolver` implementation and a public `DnsResolver` override
for embedders.

Without the `dns` feature, no hickory dependency, resolver runtime, or public
DNS trait is compiled. The configuration schema still parses a `dns` block and
rejects it with a clear validation error. Without a `dns` block (with the
feature enabled), current `tokio::net::lookup_host` behavior is unchanged.

### Feature

- `marmo` gets `default = []` and `dns = ["dep:hickory-resolver"]`.
- `hickory-resolver` is an optional dependency.
- The DNS runtime, public trait, builder method, and DNS tests are
  `#[cfg(feature = "dns")]`.
- The `Dns` configuration data types stay unconditional so the schema is
  stable. When the feature is off, `Config::validate` rejects any `dns` block
  with "dns support is not compiled in; enable the `dns` feature".
- The four DNS counters and the `DnsFallback`/`DnsFailure` event variants stay
  unconditional so the public metrics shape does not depend on features; they
  remain zero or unemitted without `dns`.
- `dns` is a capability gate, not a backend selector. There is no runtime
  fallback or hidden backend choice.

### Dependency and features

Use `hickory-resolver = "0.26.3"` with default features disabled and only:

```toml
features = ["tokio", "tls-aws-lc-rs", "https-aws-lc-rs", "rustls-platform-verifier"]
```

- No `system-config`: the library never reads `resolv.conf`, `hosts`, or
  platform DNS settings.
- No `ring`, QUIC, H3, DNSSEC, or `webpki-roots`; `aws-lc-rs` remains the only
  crypto provider (ADR-0018).
- Set `ResolverOpts::{cache_size = 0, use_hosts_file = Never, attempts = 1}`.
  The library owns the cache; hickory must not add a second, differently
  bounded one, and it must not read a hosts file.
- Set `trust_negative_responses = false` on each `NameServerConfig` so a
  negative answer from one primary server can be checked against the other
  primaries before it is cached. A final negative still does not trigger the
  fallback tier.
- Build the TLS client config explicitly with TLS 1.3, `aws-lc-rs`, and the
  platform verifier, and install it with `ResolverBuilder::with_tls_config`
  (0.26.3). When `dns.tls.ca` is present, that PEM bundle is the complete trust
  store instead. There is no `insecure` DNS switch.
- Retry and fallback policy lives in `marmo` so the total deadline is explicit.

### Public override

The built-in resolver and an injected resolver share one public abstraction:

```rust
pub type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct DnsAnswer {
    /* private addresses and ttl, with accessors and a constructor */
}

#[non_exhaustive]
pub enum DnsError {
    /// Name does not exist or has no records: cache negatively, do not fall back.
    NotFound,
    /// Query exceeded the deadline.
    Timeout,
    /// Transport or upstream failure: eligible for fallback.
    Unavailable,
    /// The library's in-flight limit was reached.
    Busy,
    /// The name cannot be represented as a DNS name.
    InvalidName,
}

pub trait DnsResolver: Send + Sync {
    fn resolve<'a>(&'a self, name: &'a str)
        -> DnsFuture<'a, Result<DnsAnswer, DnsError>>;
}
```

- `InstanceBuilder::dns_resolver(Arc<dyn DnsResolver>)` installs an embedder
  resolver. It is available only with the `dns` feature.
- The injected resolver replaces the built-in upstream. The library still
  applies its cache, `timeout_ms`, `max_inflight`, negative-caching policy,
  address deduplication, and the 16-address cap around it. This mirrors the
  injected `ProcessResolver` boundary (ADR-0029).
- `DnsAnswer` carries the address list and a positive TTL. The library clamps
  the TTL to `[min_ttl_s, max_ttl_s]`. An empty address list is treated as
  `NotFound`. Set `cache_capacity = 0` when the injected resolver already
  caches and the library should not add a second layer.
- With an injected resolver, `dns.servers`, `dns.fallback`, and `dns.tls` must
  be absent: the embedder owns upstreams, encryption, and fallback. Policy
  fields (`timeout_ms`, `max_inflight`, `cache_capacity`, TTLs) are allowed and
  use their defaults when the `dns` block is absent. Injection is the opt-in,
  as with `process_resolver`.
- If both an injected resolver and built-in server fields are configured,
  `build()` fails with `BuildError::DnsResolverConflict`.
- The injected resolver is trusted embedder code. It must be bounded, must not
  panic, and its future must be cancel-safe because the library drops it on
  timeout or connection cancellation. A panic is a contract violation and may
  terminate the connection task. The library never logs queried names or
  injected error messages.
- The built-in hickory backend implements the same internal contract, so cache,
  timeout, and failure policy have one implementation for both paths.

### Configuration

```json
{
  "dns": {
    "servers": [
      {
        "protocol": "https",
        "address": "1.1.1.1:443",
        "server_name": "cloudflare-dns.com",
        "path": "/dns-query"
      },
      {
        "protocol": "tls",
        "address": "8.8.8.8:853",
        "server_name": "dns.google"
      }
    ],
    "fallback": [
      { "protocol": "udp", "address": "1.0.0.1:53" }
    ],
    "timeout_ms": 5000,
    "max_inflight": 64,
    "cache_capacity": 1024,
    "min_ttl_s": 0,
    "max_ttl_s": 3600,
    "negative_ttl_s": 30,
    "tls": { "ca": "-----BEGIN CERTIFICATE----- ..." }
  }
}
```

- `servers` is required for the built-in resolver and holds 1-8 entries.
  `fallback` holds 0-8 entries. The combined count is at most 16.
- `protocol` is `udp`, `tcp`, `tls`, or `https`. Each entry maps to a
  hickory `NameServerConfig` with the address IP and a `ConnectionConfig`
  carrying the protocol and the configured port.
- `address` must parse as a literal `SocketAddr` with a non-zero port. Hostname
  addresses are rejected: resolving a resolver's hostname needs DNS, and a
  bootstrap list would add a second policy surface. Operators use the
  resolver's IP address.
- `server_name` is optional for `tls`/`https` and defaults to the address
  literal. Set it when the certificate is name-based. It is rejected for
  `udp`/`tcp`.
- `path` is optional for `https`, defaults to `/dns-query`, must start with
  `/`, and is at most 512 bytes. It is rejected for other protocols.
- `tls.ca` is optional inline PEM; when set it replaces platform roots for
  every `tls`/`https` server. It follows ADR-0023: no file paths and no
  filesystem reads.
- Defaults: `timeout_ms = 5000` (range 100-30000), `max_inflight = 64`
  (range 1-1024), `cache_capacity = 1024` (range 0-65535; `0` disables the
  cache), `min_ttl_s = 0`, `max_ttl_s = 3600` (range 1-86400,
  `min_ttl_s <= max_ttl_s`), `negative_ttl_s = 30` (range 0-3600; `0`
  disables negative caching).
- Duplicate `(protocol, address)` pairs are configuration errors.
- With an injected resolver, an empty `dns` object is valid; it supplies policy
  defaults. `servers`/`fallback`/`tls` are then rejected.

### Lookup policy

- `servers` is the preferred tier. `fallback` is consulted only when every
  primary server fails with a transport error, refusal, or timeout.
- `NXDOMAIN` and `NODATA` are answers, not transport failures: they do not
  trigger fallback. They are cached negatively for `negative_ttl_s`.
- There is no implicit system-resolver fallback and no implicit plaintext
  query. A `udp`/`tcp` entry in `servers` or `fallback` is the operator's
  explicit plaintext choice.
- `timeout_ms` is one total budget across the primary tier and the fallback
  tier, not a per-tier budget.
- `max_inflight` is a `Semaphore` acquired with `try_acquire`. Saturation
  returns `DnsError::Busy` and fails the dial instead of queueing without
  bound. Single-flight deduplication is not part of P2-11.
- Server names and query names are never logged. Errors carry an error kind,
  not the queried name.

### Cache

The resolver owns a `Mutex`-protected bounded cache in `marmo/src/dns.rs`,
modelled on the process cache (ADR-0029):

- Key: the domain lowercased with any trailing dot removed.
- Positive value: the deduplicated IP list. TTL comes from `DnsAnswer::ttl`
  for an injected resolver and from hickory's `LookupIp::valid_until()` for
  the built-in one; both are clamped to `[min_ttl_s, max_ttl_s]`.
- Negative value: an NXDOMAIN/NODATA marker with `negative_ttl_s`. Transport
  errors and timeouts are not cached.
- Capacity: `cache_capacity` entries, FIFO eviction using the same
  `HashMap` + `VecDeque` shape as `ProcessRuntime`. Expired entries are
  removed lazily. `cache_capacity = 0` disables reads and writes.
- At most 16 addresses per name are returned, in resolver order, duplicates
  removed. The cap is applied before the list reaches the dial path, including
  for injected answers.
- The cache lock is never held across an await.
- A cache value survives across fallback: a primary success and a fallback
  success are stored identically.

### Dial integration

`Context` receives `Option<Arc<DnsRuntime>>` from `Instance`.

- `direct` uses the resolver for a domain target; a literal IP bypasses it.
- Direct UDP uses the resolver for each target and selects an address of the
  socket's family. The per-association `HashMap` in `outbound/udp.rs` and the
  per-session cache in `inbound/shadowsocks_udp.rs` are removed; the shared
  resolver cache replaces both.
- Every proxy outbound that dials its configured `server` (HTTP CONNECT,
  Shadowsocks, Trojan, VLESS, VMess) receives the same resolver, including the
  Shadowsocks UDP server dial in `shadowsocks/udp.rs`. These dials happen
  before the protocol handshake, so they are direct dials.
- A protocol outbound that accepts a domain destination sends it unresolved;
  remote DNS remains the default for proxied traffic.
- `ip_cidr` and `geoip` continue to match literal IP destinations only. DNS is
  not performed to satisfy a routing rule: that would query for traffic a
  remote outbound could resolve itself and would create a resolver-detour
  circularity. Any future routing-time resolution needs its own ADR.
- Resolver configuration is built during `InstanceBuilder::build`, which stays
  pure (no sockets, files, or tasks). Queries run in the connection tasks on
  the instance runtime. A failure to construct the resolver is
  `BuildError::Dns { reason }`.
- Resolver errors become `io::Error` with `TimedOut`, `AddrNotAvailable`, or
  `Other` kinds. A DNS failure fails the dial; it never silently reaches the
  system resolver.

### Observability

Add `dns_queries`, `dns_cache_hits`, `dns_fallbacks`, and `dns_failures` to
`MetricsSnapshot`. Emit a `MetricEvent` only for fallback and failure; a
per-query sink event is unnecessary. No metric label or log field contains a
domain or server name.

### Task ownership

`hickory-proto`'s `TokioRuntimeProvider` owns its connection work in its own
`JoinSet`, which is reaped and dropped with the resolver. The library still
spawns no bare task of its own for DNS. This dependency-owned task set is
bounded by the nameserver count, `max_inflight`, and the resolver's connection
reuse; it is documented in the audit notes.

### Implementation outline

1. Spike the optional `hickory-resolver` 0.26.3 dependency, the exact APIs
   (`ResolverBuilder::with_tls_config`, `ResolverOpts::{cache_size,
   use_hosts_file, attempts}`, `ResolverConfig::from_name_servers`,
   `NameServerConfig`/`ConnectionConfig`, `LookupIp::valid_until`, NXDOMAIN
   classification), the feature matrix, and the MSRV 1.88 CI change.
2. Add `Dns` configuration, strict validation, and the feature-off error.
3. Add the public `DnsResolver`/`DnsAnswer`/`DnsError` boundary, the built-in
   hickory backend, the bounded cache, timeout, in-flight limit, fallback
   policy, and metrics. Unit-test cache and policy with a fake resolver.
4. Wire the resolver into `direct` TCP/UDP, every proxy-server dial, and
   Shadowsocks UDP; delete the duplicate per-session caches.
5. Add loopback UDP, DoT, and DoH fixtures. Test cache hit/expiry, eviction,
   fallback, NXDOMAIN, injection, private CA, and a proxy-server dial. No
   public resolver in CI.
6. Update architecture, roadmap, audit, CHANGELOG, README, MSRV docs, and the
   CI feature matrix; close P2-11.

Estimate: 3-4 days, including the loopback DoH/DoT fixtures, the injection
boundary, and the MSRV/feature work.

## Alternatives

1. **Inject a `DnsResolver` only, with no built-in resolver.** Smallest
   dependency surface, but every embedder would reimplement DoH/DoT, TTL,
   negative caching, and fallback. ADR-0018 already selected
   `hickory-resolver` for this feature. Rejected, but the override is still
   offered alongside the built-in.
2. **Use hickory's system configuration and fallback.** Simplest, but reads
   host files, makes behavior platform-dependent, and silently leaks queries
   in plaintext. Rejected.
3. **Accept DoH/DoT URLs with hostnames and a bootstrap resolver.** More
   familiar configuration, but adds a second DNS dependency and a circular
   bootstrap policy. IP literals plus an optional `server_name` cover public
   and private resolvers without a bootstrap.
4. **Use only hickory's built-in cache.** Correct DNS semantics and less code,
   but one hickory cache cannot span a primary and a fallback resolver, its
   capacity counts records rather than names, and TTL/capacity behavior is not
   directly assertable. The library cache gives one policy for both tiers and
   for injected resolvers.
5. **Stay on `hickory-resolver` 0.25.2 and keep MSRV 1.87.** Avoids the MSRV
   bump, but pins an older minor and delays the unavoidable upgrade. The
   decider accepts 1.88 for the current release. Rejected.
6. **Always compile DNS without a feature.** Simplest feature matrix, but every
   default build pays for hickory and its transitive crates even when DNS is
   unused. Rejected.
7. **Split `dns` into a policy feature and a separate hickory feature.** Lets
   an injection-only embedder avoid hickory, but adds a second feature and a
   backend-shaped flag. One `dns` feature is enough for P2-11; split later if
   the build cost matters.
8. **Add `insecure` for loopback DoT/DoH tests.** Rejected: a private CA in
   `dns.tls.ca` is both testable and useful for real private resolvers, and
   does not create a verification bypass.
9. **Resolve before routing so `ip_cidr`/`geoip` match domains.** Rejected for
   P2-11: it leaks queries for remotely resolved traffic and needs a detour
   policy. Keep it as a separate future item.
10. **Route DNS through an outbound group.** Not supported in P2-11; resolver
    servers are dialed directly. A detour needs the same policy work as
    routing-time resolution.

## Consequences

Positive:

- Direct dials, proxy-server dials, and direct UDP share one bounded TTL cache
  and one explicit DoH/DoT policy.
- The default build stays free of `hickory-resolver`; `dns` is a deliberate
  capability opt-in.
- Embedders can replace the built-in upstream while keeping the library's
  cache, timeout, and in-flight bounds.
- `dns` absent preserves the current system-resolver behavior.
- Queries do not read host files, do not use `ring`, and are never logged.
- Plaintext fallback is explicit and observable through a counter.

Negative:

- MSRV rises from 1.87 to 1.88 for `hickory-resolver` 0.26.3. This affects
  every build, even without the `dns` feature; it is recorded in the changelog
  and current docs because it is a repository-wide toolchain change.
- A new optional dependency tree (`hickory-resolver`, `moka`, and their
  transitive crates) increases build time and audit surface when the feature is
  enabled. Pin 0.26.3 and record the license review.
- An embedder that only wants injection still enables `dns` and therefore
  compiles hickory. A future split can remove that cost.
- Resolver construction and task ownership move into a dependency; the
  dependency's `JoinSet` is trusted to reap its own tasks.
- `hickory-resolver` disables SNI for DoT; this is upstream behavior and is
  documented rather than patched.
- hickory emits its own `tracing` events, which the embedder's subscriber
  controls. The library adds no name fields, but a trace-level subscriber may
  expose query names; the audit notes call this out.
- Server hostnames must be resolved outside marmo, so operators must know the
  resolver IPs.
- `max_inflight` saturation fails a dial rather than waiting. A burst of
  distinct cold names can produce a transient failure.
- Negative caching can delay recovery from an upstream misconfiguration by up
  to `negative_ttl_s`.

Tests:

- Default feature: the workspace builds and tests without hickory; a `dns`
  block fails validation with the feature error.
- Unit: cache hit/miss, TTL expiry, capacity eviction, disabled cache, negative
  caching, no negative cache on transport errors, address dedup/cap, total
  deadline, in-flight saturation, name normalization, fallback only on
  transport errors, no system fallback, injected resolver cache/policy, and the
  built-in/injected conflict.
- Integration (`tests/dns.rs`, `--features dns`): local UDP DNS server with
  configurable TTL and answers; local DoT server using the repository TLS
  fixtures with `dns.tls.ca`; a minimal local DoH h2 server; SOCKS5 and direct
  UDP paths; proxy-server dial through the resolver; fallback after primary
  refusal; no fallback on NXDOMAIN.
- Config tests: strict fields, unknown fields, duplicate servers, address and
  port validation, protocol-specific fields, TTL ordering, range checks,
  round-trip, feature-off rejection.
- Injection tests: a fake `DnsResolver` proves the library cache, TTL clamp,
  address cap, and `NotFound` policy apply to embedder answers.
- No new fuzz target: the DNS wire decoder is hickory's, not ours.

Docs and closeout: update architecture sections 4, 4.1, 7, 8.7, 9.4, 13, 19,
and 21; roadmap P2-11; CHANGELOG; `docs/security/audit.md` threat model and
open obligations; README and `crates/README.md` for the feature and MSRV;
`AGENTS.md`; the CI workflow. Keep interop runs against public resolvers out
of CI.

## Approval

- [x] Accept the recommendation (feature-gated library-owned
      `hickory-resolver` 0.26.3, MSRV 1.88, opt-in `dns` block, built-in plus
      injected resolver, two-tier fallback, library-owned TTL cache, dial-only
      resolution).
- [ ] Stay on `hickory-resolver` 0.25.2 and MSRV 1.87.
- [ ] Use an injected `DnsResolver` only.
- [ ] Compile DNS without a feature.
- [ ] Resolve DNS before routing as well.
- [ ] Choose an alternative: ...
