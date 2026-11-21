# ADR-0019: Workspace layout and packaging

- Status: Accepted (2026-11-21)
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0003, ADR-0004, ADR-0010, ADR-0013, ADR-0014, ADR-0018

## Context

The Zig tree splits `packages/tls13`, `packages/http2`, and `packages/ws` into
first-party packages because a module rooted at `src/root.zig` cannot import
outside its path, and because those implementations had to be isolated and
tested independently (ADR-0010, ADR-0013, ADR-0014). Rust has no equivalent
constraint: a Cargo workspace gives isolation, independent test targets, and
path dependencies without separate repositories.

What still needs isolation is the wire-codec layer: it must stay free of I/O
and tokio so it can be fuzzed and reused by inbound and outbound halves. That
is a real boundary, not a packaging accident.

## Decision (recommended)

A five-crate Cargo workspace: `marmo`, `marmo-proto`, `marmo-net`,
`marmo-transport`, and `marmo-testkit`.

| Crate | Contents | Published |
| --- | --- | --- |
| `marmo` | `Instance`, config, routing, inbounds, outbounds, metrics, public API | yes |
| `marmo-proto` | SOCKS5, HTTP/1, SS2022, Trojan, VLESS, XUDP codecs; no I/O, no tokio | yes |
| `marmo-net` | `Endpoint`, CIDR, socket options, resolver policy | yes |
| `marmo-transport` | stream/datagram traits, TLS/WS/H2/QUIC adapters, relay | yes |
| `marmo-testkit` | fake streams, fixture loader, loopback helpers | no |

- Dependency direction: `marmo` → all; `marmo-transport` → `marmo-net`;
  `marmo-proto` → `marmo-net` (address parsing only); `marmo-net` → nothing.
- `marmo` is the only public facade. `inbound`, `outbound`, `routing`, and
  `config` stay inside it because `Instance` wires all of them.
- All crates version together at `0.x` until the API is stable. Publishing is
  deferred until parity; `marmo-testkit` is `publish = false`.
- `unsafe` is `forbid`-denied in `marmo-proto` and `marmo`; in
  `marmo-transport` it is denied by default and requires a written
  justification per block.
- No Cargo feature selects a backend or a transport implementation. Features
  are limited to test/bench support.
- Workspace-level integration tests live in `tests/`; unit tests live beside
  the code in each crate.

On acceptance, this ADR supersedes ADR-0010, ADR-0013, and ADR-0014.
ADR-0004's composition model carries over; its "implemented in-tree per
ADR-0007" clause is superseded by ADR-0018.

## Alternatives

1. **One crate.** Simplest build, but codecs lose their I/O-free guarantee,
   fuzz targets lose a natural isolation boundary, and incremental builds
   recompile everything. Rejected.
2. **One crate per layer (eight or more).** Mirrors the Zig file layout, but
   `inbound`/`outbound`/`routing`/`config` are cyclic through `Instance` and
   would only add re-export churn. Rejected.
3. **Keep separate TLS, HTTP/2, and WebSocket crates.** They are deleted in
   favour of upstream crates, so there is nothing left to package. Rejected.
4. **Publish each crate independently from day one.** Adds release automation
   and version skew before there is an external consumer. Rejected for parity.

## Consequences

- One workspace, one lockfile, one CI invocation; Windows/macOS/Linux builds
  share the same commands.
- Cross-crate refactors cost a `Cargo.toml` edit and a version bump only at
  publish time; during parity everything is path-linked.
- `marmo-proto` can be fuzzed and benchmarked without linking tokio, TLS, or
  the rest of the library.
- Publishing at 1.0 requires deciding whether the four public crates are
  released together or only `marmo`; deferred by §20 of
  `docs/architecture.md`.

## Approval

- [x] Accept the recommendation (five crates).
- [ ] Choose a different layout: ...

Accepted 2026-11-21 as recommended.
