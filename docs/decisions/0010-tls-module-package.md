# ADR-0010: TLS module as a replaceable package

- Status: Accepted (2026-11-19)
- Date: 2026-11-19
- Deciders: @mogeko
- Related: ADR-0004, ADR-0007, ADR-0009

## Context

The TLS client currently lives in `src/transport/tls_client.zig` and
`src/transport/tls_dialer.zig`. It imports marmo's `Stream`, `Endpoint`, and
`Dialer`, so the TLS record and handshake code is entangled with the proxy
library. The next phase needs an in-tree TLS 1.3 server, and later transports
(WebSocket, HTTP/2, gRPC) will also sit above TLS. Embedding TLS in the root
source tree makes a backend replacement or an independent test run invasive.

The project is std-only with no optional backends (ADR-0007), so the solution
must not add a build flag that selects TLS implementations at runtime or build
time. It also must not add an external dependency (ADR-0009, zero dependencies).

## Decision (recommended)

Make TLS a first-party package under `packages/tls13/`, with its own
`build.zig` and `build.zig.zon`, and depend on it from the root package by
path.

- The package is std-only and imports nothing from marmo. Its public API is:
  - `Client.init(io, *std.Io.Reader, *std.Io.Writer, Options)` for the TLS
    handshake;
  - `Client.reader()`, `Client.writer()`, `Client.end()`, `Client.eof()`, and
    `Client.deinit()` for the established session;
  - `Options` with `server_name`, `verify`, `ca`, and
    `allow_truncation_attacks`;
  - `Ca` for lazy system CA loading with a shared lock;
  - `min_buffer_len` so callers can size the transport buffers.
- The root package keeps `src/transport/tls_client.zig` as a thin adapter from
  marmo's `Stream` to `std.Io.Reader`/`Writer`, and
  `src/transport/tls_dialer.zig` as the transport composition. Those are the
  only root files that import `tls13`.
- The root `build.zig.zon` declares `tls13` as a path dependency and
  `build.zig` exposes it as a module import. Replacing TLS means replacing that
  dependency with another package that implements the same API; there is no
  runtime or build-flag backend selection.
- The package targets TLS 1.3. Its first backend delegates to
  `std.crypto.tls.Client`; an in-tree TLS 1.3 client/server will replace the
  backend internals without changing the root adapter.
- CI runs the root tests and each package's `zig build test` independently;
  formatting covers `build.zig`, `src`, `tests`, and `packages`.

## Alternatives

1. **Keep TLS in `src/transport`.** Simplest today, but couples TLS to marmo
   types and makes the in-tree TLS server and future transports share code
   through root imports. Rejected.
2. **Add a TLS backend interface selected by a build flag.** Contradicts
   ADR-0007's no-optional-backends rule and adds two code paths to test.
   Rejected.
3. **Publish or consume TLS as an external package.** Adds a dependency and a
   supply-chain surface, contrary to the zero-dependency policy. Rejected.
4. **Separate package that still imports marmo `Stream`/`Dialer`.** Moves files
   without reducing coupling. Rejected.

## Consequences

- Positive: TLS handshake, CA handling, and session state have a stable seam
  that the future in-tree TLS 1.3 server can share; the package is testable with
  only `std`; the root adapter stays small.
- Negative: one more build file and a path dependency; package and root
  versions are independent; the root `marmo` module gains an import; package
  tests must run separately.
- Behavior is unchanged in this step: the std-backed client may still negotiate
  TLS 1.2 when a server does not offer 1.3. The package name states the target;
  the in-tree backend will make 1.3 the only supported version.
- Tested by the package's unit tests, the root integration tests (including the
  TLS handshake failure path), and the local-only TLS/VLESS interop check.
- Follow-up: replace the std client with the in-tree TLS 1.3 implementation
  inside the package, add transcript fixtures and fuzzing, and keep the package
  API stable.

## Approval

- [x] Accept the recommendation.
- [ ] Choose an alternative: ...

## Amendment (2026-11-19)

The server side is now implemented in-tree inside `packages/tls13` on
`std.crypto`: TLS 1.3 only, X25519, AES-128-GCM/SHA-256, and ECDSA P-256
certificates. The client still delegates to `std.crypto.tls.Client` until the
in-tree client replaces it. The package exports `Server`, `ServerOptions`, and
`readSome` in addition to the client API; the root package adds the thin
`src/transport/tls_server.zig` adapter and does not encode TLS records itself.
