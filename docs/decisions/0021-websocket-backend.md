# ADR-0021: WebSocket backend with permessage-deflate

- Status: Accepted (2026-11-21)
- Date: 2026-11-21
- Deciders: @mogeko
- Related: ADR-0014, ADR-0016, ADR-0018, ADR-0020

## Context

ADR-0018 selects `tokio-tungstenite` for WebSocket and states that it provides
`permessage-deflate`. That statement is incorrect: no released version of
`tungstenite` (checked 0.17 through 0.30) implements RFC 7692, and
`tokio-tungstenite` only forwards the `tungstenite` feature set. ADR-0016 and
the Zig-era package make `transport.compression` a real config option, so R3f
cannot claim parity while silently ignoring it.

The initial R3f implementation used `tokio-tungstenite` and rejected
`compression: true` at build time. Everything else — path, Host,
subprotocols, ALPN defaults, TCP/UoT/XUDP over WS — is complete and tested.

The alternatives were checked before this ADR:

- **`fastwebsockets` 0.10** (Apache-2.0): its README says permessage-deflate is
  not supported, its frame parser rejects any RSV1 bit, so an external RFC 7692
  codec cannot be attached without forking. Its HTTP upgrade path depends on
  `hyper`.
- **`tokio-websockets` 0.13**: no deflate feature.
- **`sockudo-ws` 3.1** (MIT): supports permessage-deflate, but it is an
  HFT-focused library with a large feature surface (HTTP/2, HTTP/3, io_uring,
  compio, TLS roots) and a young major version.
- **`ws-pmd`**: an RFC 7692 codec only, version 0.1.0 with very low adoption;
  it would still require a WS frame engine that permits RSV1.

`ws-net` 0.10 (2026-11-18, Apache-2.0 OR MIT, MSRV 1.85) is a sans-IO RFC 6455
engine with a `deflate` feature implementing RFC 7692 negotiation and the
DEFLATE codec. It forbids unsafe code. Its dependencies are three small crates
by the same author: `parse-net`, `mod-rand`, and `compress-lib` (the last only
with `deflate`), all Apache-2.0 OR MIT. At evaluation time `ws-net` had about
310 downloads, `parse-net` about 2,800, `mod-rand` about 3,300, and
`compress-lib` about 550. The engine exposes:

- resumable client/server handshakes (`ClientHandshake`, `Acceptor`/`ServerHandshake`)
- `Connection` with `feed`, `read_buf`/`commit`, `poll`, `send_binary`,
  `output`/`advance_output`, automatic Pong and Close
- explicit limits (`Limits`: frame, message, output, input buffer)
- subprotocol and Origin policies

A spike (local branch `spike/wsnet`, commit `329ccdb`, not merged) replaced the
`tokio-tungstenite` adapter with a `ws-net` adapter and a tokio byte-stream
pump of about 450 lines. Results:

- `cargo test --workspace`: 156 passed
- `marmo-transport`: 19 passed, including compression negotiation
- VLESS integration: 6 passed, including VLESS over compressed WebSocket
- in-memory duplex echo: 600.7 MiB/s (release, 8 MiB in 64 KiB writes)
- 200 KB of repeated bytes: 200,050 wire bytes uncompressed, 973 compressed
- `cargo +1.87.0 test --workspace`: passed; `cargo audit` and the copyleft gate
  are clean; `ws-net`, `compress-lib`, `mod-rand`, and `parse-net` are all
  Apache-2.0 OR MIT

The concrete failure this decision prevents: keeping a config option that is
accepted by the schema and rejected at build time, or silently sending
uncompressed frames when a peer expects a negotiated extension.

## Decision (recommended)

Replace the WebSocket adapter backend with `ws-net` 0.10 with the `deflate`
feature, keeping the public `marmo-transport::ws` surface and the ADR-0016
configuration semantics.

- `WsClientOptions` and `WsServerOptions` keep `host`, `path`, and
  `subprotocols`, and gain `compression: bool`.
- `WsConnection` keeps `stream` and `subprotocol`, and exposes whether
  compression was negotiated.
- One adapter module owns a tokio pump over `ws_net::Connection`: handshake
  head reads bounded at 8 KiB, `feed`/`commit` for input, `poll` for events,
  `output`/`advance_output` for writes, and `AsyncRead`/`AsyncWrite`.
- Limits: 1 MiB message, 64 KiB frame, 1 MiB pending output, matching the Zig
  package and ADR-0016. Writes are split at 64 KiB.
- Subprotocols keep the server-preference rule from R3f: a configured list
  requires a match, and the client rejects a selection it did not offer.
- Origin policy is `OriginPolicy::any_origin()` for parity with the Zig server,
  which does not inspect `Origin`. A strict same-origin mode is a later config
  addition, not part of this decision.
- Compression is offered and accepted only when `transport.compression` is
  true, with `ws-net`'s defaults (15-bit window, no context takeover, level 1).
- TLS and ALPN are unchanged: WS over TLS offers `http/1.1` when `tls.alpn` is
  absent and does not require a selection (ADR-0016).
- Direct dependencies removed: `tokio-tungstenite`, `tungstenite`, `http`, and
  `futures-util`. Added: `ws-net`, with `compress-lib`, `mod-rand`, and
  `parse-net` as its only transitive dependencies.
- MSRV stays 1.87 (the library's current MSRV); `ws-net` requires 1.85.

This supersedes the WebSocket crate choice in ADR-0018. It does not change the
TLS, HTTP/2, crypto-provider, or license decisions.

## Alternatives

1. **Keep `tokio-tungstenite` and leave `compression` rejected.** Smallest
   change and the current R3f state, but it leaves a config field that the Zig
   implementation honours and makes the WS parity row permanently incomplete.
   Rejected as the final state; acceptable as a rollback.
2. **Use `fastwebsockets`.** It is fast and well tested, but it has no
   permessage-deflate, rejects RSV1 outright, and needs `hyper` (or an in-tree
   HTTP upgrade) for the handshake. It would replace one gap with the same gap
   and a larger dependency. Rejected.
3. **Use `sockudo-ws`.** It has deflate, but its HFT focus, very large feature
   surface, and young major version are a poor fit for a proxy library that
   only needs RFC 6455 and RFC 7692. Rejected.
4. **Implement RFC 7692 in-tree over a low-level frame crate.** This conflicts
   with ADR-0018's no-in-tree-transport rule and adds a security-sensitive
   decompressor. Rejected unless `ws-net` fails review.
5. **Pin an older `tungstenite`.** No released version ever had deflate.
   Rejected.

## Consequences

Positive:

- `transport.compression` works end to end; the VLESS WS row can be called
  complete.
- The direct WebSocket dependency becomes smaller and has no `unsafe` in the
  engine; the adapter owns a single explicit pump instead of relying on a
  Sink/Stream adapter.
- `ws-net` enforces RFC 6455 details (masking direction, RSV bits, UTF-8,
  control-frame rules, close handshake) and exposes explicit memory limits.
- The spike shows compression reduces repetitive 200 KB payloads to under 1 KB
  while staying above 600 MiB/s on an in-memory loopback.

Negative:

- `ws-net` is very new (0.10, November 2026, about 310 downloads at evaluation
  time), and all four crates come from one author with low adoption. Their
  sources need a security review before cutover, the lockfile must pin exact
  versions, and future releases may change the API.
- The async pump is our code: partial writes, output backpressure, EOF, and
  close handling must be reviewed and kept under test. The adapter is about
  450 lines instead of a thin wrapper.
- Keepalive and the engine's message timeout are not wired; connection idle
  handling remains the ADR-0015 relay deadline, and the handshake is covered
  by the Instance handshake deadline.
- `OriginPolicy::any_origin()` deliberately matches the Zig server; callers
  that want browser same-origin protection need a future config field.
- Two implementations overlap during the transition; `tokio-tungstenite` and
  its dependencies disappear only in the adopting slice.

Testing and observation:

- Port the existing WS adapter tests: path rejection, missing subprotocol,
  server-preferred subprotocol, 200 KB binary message, echo.
- Add a compression test that asserts the negotiated extension, round-trips a
  repetitive payload, and checks the wire size is far below the payload size.
- Run the VLESS integration matrix over WS with and without compression, for
  TCP and simple UoT.
- Keep `cargo +1.87.0 test --workspace`, `cargo audit`, and the copyleft gate
  green; record the new dependency tree in the adopting PR.

Rollback: revert to the `tokio-tungstenite` adapter from the initial R3f
implementation; compression returns to a build error. No on-disk or public API change makes rollback
expensive.

## Approval

- [x] Accept the recommendation (`ws-net` 0.10 + tokio pump; compression
      enabled).
- [ ] Choose an alternative: keep `tokio-tungstenite` with `compression`
      rejected, or another backend.
