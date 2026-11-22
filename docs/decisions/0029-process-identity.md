# ADR-0029: Process identity injection

- Status: Accepted (2026-11-22)
- Date: 2026-11-22
- Deciders: @mogeko
- Related: ADR-0005, ADR-0018, ADR-0028

## Context

P2-10 adds `process_name` and `process_path` matchers. ADR-0005 already lists
them as v1 matchers, and `Metadata` reserves a process field. The routing value
is real: the same destination may need different outbounds when it comes from
`curl`, a browser, or a downloader.

The process identity is not carried by the proxy protocol. It must be derived
from the client socket: source address to PID, then PID to executable name or
path. That requires platform-specific system interfaces (Linux `/proc`, macOS
libproc or a socket-table API, Windows later). It also requires filesystem or
kernel access.

Putting that lookup in `marmo` would break the library's stated boundary:
architecture section 5 says the library performs no filesystem I/O, `marmo`
denies unsafe code, and ADR-0018 requires review for every platform dependency.
It would also tie library releases to `sysinfo`, `netstat2`, and OS behavior
that belongs to the embedder's environment.

Process matching is best-effort by definition. Remote clients have no local
process on the proxy host, containers and network namespaces may not expose one,
and permissions can hide it. A missing identity must never fail a connection.
It is also not a security boundary: a local process can rename its executable.

The requirement is therefore an abstraction boundary, not an OS integration.
ADR-0028 applies the same principle to rule-set data: the library defines the
matcher, and the embedder supplies the storage-backed implementation.

## Decision (recommended)

Keep process matching policy in `marmo`; inject the environment-specific
lookup from the embedder or CLI.

### Public interface

Add `marmo::process` with:

```rust
pub struct ProcessRequest {
    pub network: Network,
    pub source: Endpoint,
    pub destination: Endpoint,
}

pub struct ProcessInfo { /* private name/path, accessors, redacted Debug */ }

impl ProcessInfo {
    pub fn new(
        name: Option<Arc<str>>,
        path: Option<Arc<str>>,
    ) -> Self;
    pub fn name(&self) -> Option<&str>;
    pub fn path(&self) -> Option<&str>;
}

pub trait ProcessResolver: Send + Sync {
    /// Called on a blocking thread; must be bounded and must not panic.
    fn resolve(&self, request: &ProcessRequest) -> Option<ProcessInfo>;
}
```

- Add `InstanceBuilder::process_resolver(Arc<dyn ProcessResolver>)`. There is no
  default resolver.
- `ProcessInfo` fields are private and `Debug` is redacted so a process path
  cannot leak through a derived `Debug` on `Metadata`.
- The resolver is trusted embedder code. Its return value is routing input, not
  untrusted wire data.
- The library does not open `/proc`, call libproc, spawn a helper, or depend on
  `sysinfo`/`netstat2`. The resolver runs through `spawn_blocking`; the
  blocking work is the embedder's.

### Configuration

- Add `process_name` and `process_path` to a rule. Both are lists of exact
  strings, ANDed with the other matchers. Duplicates and empty values are
  config errors; names are at most 255 bytes and paths at most 4096 bytes, with
  no NUL.
- Add an optional top-level `process` object for bounds:
  - `cache_ttl_s`: default `5`; `0` disables the library cache;
  - `cache_capacity`: default `1024`; `0` disables the library cache;
  - `lookup_timeout_ms`: default `50`; range `1..=500`;
  - `max_inflight`: default `64`; range `1..=1024`.
- There is no `process.enabled` switch. Injection is the opt-in: a config with
  process matchers and no resolver fails `build()`, while a resolver injected
  with no process matcher is never called.
- A build error from a missing resolver is deliberate: a configuration mistake
  is loud. An unknown process at runtime is quiet.

### Runtime behavior

- `Router` exposes `needs_process()`; it is true when any compiled rule has a
  process matcher.
- `Context::route` becomes the single async routing entry point. It performs a
  lookup only when `needs_process()` is true and the metadata has no process
  yet. `Router::route` remains synchronous and allocation-free.
- Cache key is `(network, source IP, source port)`. A miss creates a
  `ProcessRequest` from the metadata, takes an in-flight permit, calls the
  resolver on a blocking thread, and waits at most `lookup_timeout_ms`.
- Cache values include `None` (unknown) with the same TTL; this prevents an
  expensive miss from being repeated on every connection. Entries expire on
  TTL or eviction by capacity.
- If the in-flight limit is reached, the lookup fails open immediately instead
  of queueing without bound.
- A resolver panic, a `JoinError`, a runtime shutdown, or a timeout all become
  `None`. The rule does not match and evaluation continues to the next rule or
  the final action.
- The cache lock is never held across an await. A timed-out blocking call may
  continue until it returns, but the in-flight semaphore bounds how many can
  exist.
- Process identity is never logged by the library.

### Platform support

- The library is platform-neutral. A fake resolver is used in all unit and
  integration tests on Linux, macOS, and Windows.
- The actual OS lookup is implemented by a downstream CLI or embedder; a
  dev-only example may demonstrate Linux/macOS. Windows-specific matching
  remains P5-10 and is likewise an embedder concern.
- If no implementation is supplied, process rules cannot be built; this is
  intentional rather than silently returning unknown for every connection.

## Alternatives

1. **Implement `sysinfo`/`netstat2` inside `marmo`.** Keeps the feature
   self-contained but adds platform dependencies, filesystem access, an
   exception to the no-I/O boundary, and new unsafe/build-script review for
   every target. Rejected.
2. **Use an async resolver trait.** More flexible for IPC-based resolvers, but
   object safety needs boxed futures, and it pushes the blocking-work decision
   onto implementers. A synchronous trait plus `spawn_blocking` is smaller and
   safer; an async adapter can be added later without changing the matcher.
3. **Add a generic `ConnectionClassifier` with arbitrary labels.** More
   general, but dynamic labels allocate on the routing path and turn the
   matcher into an untyped lookup. Process name/path is the concrete need.
   Rejected until a second identity source justifies the complexity.
4. **Add a connection hook that returns arbitrary metadata.** Flexible, but
   expands the public lifecycle and creates hard-to-bound extension points.
   Rejected.
5. **Let the CLI inject the OS lookup as a closure only.** Simpler surface,
   but harder to name, test, and document than a trait. A closure can wrap the
   trait later; the trait is the stable boundary. Rejected.
6. **Drop P2-10 and keep only inline routing.** Avoids the abstraction, but
   loses the application-based routing use case. This remains the fallback if
   the boundary is not worth it; it requires moving P2-10 out of Phase 2.
7. **Pre-resolve process identity before the library accepts.** The embedder
   does not see the accepted stream or source metadata at the right point, and
   mux/UDP sessions would need parallel hooks. Rejected.

## Consequences

- P2-10 becomes a library abstraction plus matcher: no `sysinfo`, no
  `/proc`, no platform modules, and no filesystem-I/O exception in `marmo`.
- The embedder, not the library, owns platform behavior, permissions, caching
  choices outside the library cache, and Windows support.
- The library gains a public trait and builder method, an async routing entry
  point, a bounded cache, and new config fields. `Router::route` and all
  existing matchers stay synchronous and allocation-free.
- Lookups add up to `lookup_timeout_ms` of latency on a cache miss; unknowns
  continue routing. A resolver that blocks longer than the timeout still holds
  an in-flight permit until it returns.
- Cache TTL and source-port reuse can produce a stale identity; this is
  accepted as best-effort and documented.
- Tests: fake resolver hit/miss, no call without a process rule, positive and
  negative caching, TTL expiry, capacity eviction, timeout, in-flight
  saturation, resolver panic, missing resolver build error, and all-platform
  behavior with the fake. Platform lookup tests live with the CLI or the
  dev-only example.
- Docs: update architecture sections 5, 8.4, 10, 13, 19, and 21; remove
  `sysinfo` from the library dependency table; update roadmap P2-10 and P5-10,
  the ADR index, security notes, and README examples.
- Estimated 1-1.5 days for the library boundary, matcher, cache, and tests. A
  Linux/macOS CLI implementation is separate, roughly 2-3 days.

## Approval

- [x] Accept the recommendation (injected `ProcessResolver`, bounded cache,
      `spawn_blocking`, fail-open).
- [ ] Implement the OS lookup inside the library instead.
- [ ] Use an async resolver trait instead.
- [ ] Defer P2-10 and move it out of Phase 2.
- [ ] Choose an alternative: ...
