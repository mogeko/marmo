# Security audit

- Date: 2026-11-20
- Base revision: post-Trojan plus ALPN/HTTP2/WS transport work
- Status: internal review plus bounded in-tree fuzzing; no external audit.
- Scope owners: repository maintainers.

## 1. Method

The review combined manual code reading with the bounded fuzz harness added in
this change (`tests/fuzz.zig`, `zig build fuzz`). Default runs use fixed seeds
and 1024 inputs per target; the audit run used 5000 inputs per target with the
default seed and 2000 inputs with a second seed. Corpus fixtures in
`tests/fixtures/` run deterministically in `zig build test`.

The fuzz targets assert, by construction:

- no panic or undefined behavior on arbitrary bytes;
- no network I/O and no live servers (in-memory streams only);
- bounded input lengths and bounded allocations (fixed buffers, per-iteration
  arena/caches);
- only typed errors propagate; a successful decode is checked for bounds.

`zig build test`, `zig build test -Doptimize=ReleaseSafe`, `zig build check`,
and `zig build examples` pass. The test count is recorded in `AGENTS.md`.

## 2. Threat model

Assets: client credentials (VLESS UUID, Shadowsocks PSK, Trojan password
hash), TLS private keys and session secrets, routing policy, and process
availability.

Adversaries considered:

1. An unauthenticated network peer that can send arbitrary bytes to an inbound
   listener, including slow or truncated handshakes.
2. An authenticated but malicious proxy client (holds a configured UUID/PSK)
   that sends hostile framing after authentication.
3. A malicious or compromised upstream TLS server or proxy peer.
4. A malicious configuration file is treated as trusted input from the
   embedder; parsing is still bounded so a huge file cannot allocate without
   limit.

Out of scope: a compromised embedder process, OS/kernel bugs, physical access,
side-channel and micro-architectural attacks, traffic analysis, and protocols
not implemented in this revision (QUIC, VMess, TUIC, Hysteria2).

## 3. Findings

Severity uses: Critical = remote unauthenticated code execution or key
disclosure; High = remote unauthenticated crash/security bypass or request
smuggling; Medium = authenticated crash, data race, or bounded resource
exhaustion; Low = local/robustness/spec issue with limited impact.

| ID | Severity | Status | Area | Summary |
| --- | --- | --- | --- | --- |
| F-01 | High | Fixed | HTTP inbound | Raw control characters in the request target and a permissive HTTP version check allowed request-line injection into forward requests. |
| F-02 | Medium | Fixed | SS2022 TCP | A 16-bit addition of an authenticated frame length and the AEAD tag overflowed, panicking on a maximum-length header. |
| F-03 | Medium | Fixed | SS2022 UDP | The session reaper read `last_active_s` without the mutex used by the reply task. |
| F-04 | Low | Fixed | TLS server | Post-handshake `change_cipher_spec` records were silently ignored instead of rejected. |
| F-05 | Low | Fixed | TLS records | Encrypted records accepted a legacy record version other than `0x0303`. |
| F-06 | Low | Fixed | Diagnostics | A truncated diagnostic reported the whole buffer, exposing uninitialized bytes to embedder logs. |
| F-07 | Low | Fixed | TLS credentials | PEM/DER parsing leaked certificate/key file buffers and partial chains on some error paths; base64 output was not exact-sized. |
| F-08 | Low | Fixed | HTTP parser | `parseAuthority` indexed an empty authority before checking it (reachable through the newly public helper). |
| F-09 | Low | Fixed | VLESS outbound | The outbound UUID was not zeroized on instance teardown. |
| F-10 | Low | Fixed | Config | JSON parsing had no document-size limit. |
| F-11 | Low | Fixed | Endpoints | Domain hosts accepted raw control characters. |
| F-12 | Low | Fixed | HTTP CONNECT outbound | A valid response head exactly 8192 bytes long was rejected. |
| F-13 | Medium | Fixed | Inbounds | No connect/handshake idle timeout for SOCKS5/HTTP and no maximum connection count. ADR-0015 adds `max_connections` and an absolute handshake deadline from accept. |
| F-14 | Medium | Fixed | Relay | No idle-timeout enforcement after relay start. ADR-0015 adds idle and half-close timers enforced by a per-Instance reaper. |
| F-15 | Low | Open | TLS | KeyUpdate/client auth/PSK/tickets are not implemented (ALPN is implemented). Post-handshake KeyUpdate/alert/truncation paths have regression tests but no end-to-end authenticated-stream fuzz target. |
| F-16 | Low | Open | General | No external audit, no side-channel review, and no long-running soak/fuzz campaign. |
| F-17 | Low | Fixed | Trojan | The authentication-prefix read is covered by the handshake deadline; UDP association traffic resets the idle deadline. |
| F-18 | Low | Fixed | TLS client | A partial TLS record could be reported as EOF, losing the final application data when a peer split a record or closed immediately after sending it. Found during trojan-gfw UDP interop; added a regression test. |
| F-19 | Low | Open | WS/H2 | The WebSocket and HTTP/2 parsers are new: no external audit, and HTTP/2 supports one active stream per connection. Bounded parser fuzz targets exist. |
| F-20 | Low | Open | WS/H2 | H2 flow-control stalls are not soak-tested under a peer that stops reading; H2 still carries a large fixed per-connection header workspace. |
| F-21 | Critical | Fixed | TLS client | Certificate paths did not check issuer `basicConstraints CA:TRUE` / `keyUsage keyCertSign`, so a CA:FALSE leaf could act as an intermediate and MITM the connection. |
| F-22 | Medium | Fixed | TLS client | Post-handshake plaintext alerts were accepted, `close_notify` truncation was indistinguishable from clean EOF, `allow_truncation_attacks` was dead, and `insecure` also skipped host-name verification. |
| F-23 | High | Fixed | HTTP/2 | Server rejected client `ENABLE_PUSH`, treated peer `END_STREAM` as a full close, used a 16-entry HPACK table cap, accepted cross-stream HEADERS, mapped RST/GOAWAY to clean EOF, and allowed empty CONTINUATION floods. |
| F-24 | Medium | Fixed | WebSocket | `readHead` discarded bytes after the HTTP terminator (losing a coalesced first frame), and close state was checked outside the write lock. |
| F-25 | High | Fixed | Adapters | `close()` freed adapter state while reads/writes might still be in flight. In-flight guards now make close wait for operations to drain. |

### F-01 HTTP request-line injection (High, fixed)

`parseAbsolute` copied the URI path into the upstream request line without
rejecting raw control bytes, and `handleForward` accepted any version starting
with `HTTP/1.`. A client could put a bare LF in the target (the head reader
only terminates on `\r\n\r\n`) and inject text into the origin request line or
headers.

Fix: reject `<= 0x20` and `0x7f` in the whole absolute URI
(`src/inbound/http.zig:188`), require exactly `HTTP/1.<digit>`
(`src/inbound/http.zig:351`), and reject control characters in endpoint hosts
(`src/net/endpoint.zig:69`). Tests:
`src/inbound/http.zig:408` and `src/inbound/http.zig:420`.

### F-02 SS2022 16-bit length overflow (Medium, fixed)

After successful AEAD, `variable_len` and payload lengths are `u16`. Adding the
16-byte tag before widening overflowed at values above `65519`, panicking in
safe builds. Fixed by widening immediately to `usize`
(`src/protocol/shadowsocks2022.zig:865`, `:909`, `:1068`, `:1201`). Regression:
`tests/fuzz.zig:996` builds an authenticated request claiming `0xffff` bytes
with a truncated body and expects `EndOfStream` instead of a panic. The layout
target `ss2022_request_layout` covers the same path with generated data.

### F-03 SS2022 UDP session reaper race (Medium, fixed)

`findOrCreate` read `last_active_s` while the per-session reply task updated it
under `session.mutex`. The read now takes the same mutex
(`src/inbound/shadowsocks_udp.zig:151`). The bounded session table (128) and the
atomic `reply_failed` flag were already present.

### F-04/F-05 TLS protocol strictness (Low, fixed)

RFC 8446 requires post-handshake CCS to be a protocol error; the server now
returns `ProtocolViolation` (`packages/tls13/src/server.zig:451`, test at
`:693`). Encrypted records must use legacy version `0x0303`; `record.open` now
checks it (`packages/tls13/src/record.zig:138`, test at `:190`). A plaintext
`close_notify` maps to clean EOF and has a regression test
(`packages/tls13/src/server.zig:713`).

### F-06 Diagnostic truncation (Low, fixed)

`Diagnostic.set` used `bufPrint`'s failure path to set the length to the whole
buffer, so logs could include uninitialized stack bytes. It now uses a fixed
writer and reports only written bytes (`src/core/diagnostic.zig:18`, test at
`:37`).

### F-07 Credential parsing leaks and exact sizes (Low, fixed)

`loadOptions` now frees the certificate text and zeroizes + frees the key text
on every path, frees the chain on later errors, and `decodeBase64` resizes to
the exact decoded length so callers can free it
(`src/transport/tls_credentials.zig:49`, `:64`, `:174`). The `tls_credentials`
and `tls_server_handshake` fuzz targets exercise success and failure paths
under the testing allocator, which reports leaks.

### F-08–F-12 Lower-severity parser and hygiene fixes

- Empty HTTP authority is rejected before indexing
  (`src/inbound/http.zig:229`, test `:402`).
- VLESS outbound `deinit` zeroizes the UUID (`src/outbound/vless.zig:22`, test
  `:107`).
- Config documents larger than 4 MiB are rejected before JSON parsing
  (`src/config/config.zig:95`, `:112`, test `:593`).
- Endpoint domain hosts containing control characters are rejected
  (`src/net/endpoint.zig:69`).
- HTTP CONNECT responses of exactly 8192 bytes are accepted
  (`src/outbound/http_connect.zig:171`).

## 4. Area review notes

### A. TLS 1.3 server (`packages/tls13`)

- ClientHello/extension parsing is length-checked field by field; extension
  lengths are bounded by the message; the handshake buffer is 16 KiB.
- Record lengths are capped at 16 KiB + 256 and the read buffer is checked
  before use.
- AEAD failure is distinguishable from a successful open and maps to
  `BadRecord`/`ProtocolViolation`; the sequence number only advances after a
  successful operation.
- Finished uses `std.crypto.timing_safe.eql`.
- Transcript/HKDF labels were checked against RFC 8446 and against the std
  client over loopback.
- Certificate/key parsing bounds DER lengths, caps the chain at 8, and checks
  that the leaf is P-256 and matches the key. It does not perform server-side
  chain trust validation; that is the client's job.
- Padding is the TLS 1.3 inner-plaintext zero padding; the last non-zero byte
  is the content type. `tls_record_open_valid` fuzzes this path.
- Fuzzed: request parsing, mutated near-valid ClientHellos, records, valid
  seal/open round trips, server handshake state machine, credential parsing,
  and the key schedule.

### B. VLESS and XUDP

- UUID comparison is constant time; addon and address lengths are bounded;
  UUID parsing rejects non-canonical/hyphenated-bad forms.
- XUDP metadata is capped at 512 bytes and data at 65535; New/Keep/End/
  KeepAlive status and session 0 are enforced; GlobalID is either absent or
  8 bytes.
- Inbound XUDP binds the stream to the first New target and rejects later
  target changes; the target domain is copied into the connection arena before
  the metadata buffer is reused.
- Fuzzed: request/response header parsing and frames. One-target enforcement is
  covered by code review and integration tests, not by a dedicated stateful
  fuzz target.

### C. Shadowsocks 2022

- Key derivation uses BLAKE3 as specified; AES-GCM is from `std.crypto`.
- TCP/UDP headers are authenticated before structural parsing; lengths are
  widened to `usize` before arithmetic (F-02).
- Replay cache is bounded at 4096 entries with 60-second expiry; UDP window is
  a 64-packet bitmap.
- The UDP server caps sessions at 128 and drops when full; routing is limited
  to `direct` as documented.
- Fuzzed: raw request/datagram AEAD failures, authenticated request layouts,
  authenticated chunk lengths, and UDP body layouts. The replay cache/window
  are unit-tested for duplicate and stale IDs.

### D. SOCKS5 and HTTP inbounds

- SOCKS5 greeting, CONNECT, and UDP request parsing are length-checked; UDP
  replies are bounded and the client address is pinned to the TCP peer IP.
- HTTP heads are capped at 8192 bytes; forward rewriting strips hop-by-hop
  headers and rejects duplicate `Content-Length`, `Transfer-Encoding` conflicts,
  obs-fold, invalid tokens, and control characters. F-01 closed the request-line
  injection path.
- Fuzzed: greeting/address/UDP request, header reading, absolute-form parsing,
  forward-head rewriting, and the full HTTP handler with a rejecting dispatch.

### E. Config

- Strict JSON (unknown fields and duplicate fields are errors), a 4 MiB
  document cap, and path-aware diagnostics.
- Endpoint/CIDR/UUID/key/selector/health-check validation is covered by unit
  tests and `config_json`/`primitives` fuzzing.
- Config is trusted embedder input; it is not fetched from the network.

### F. Cross-cutting checks

- **Secrets**: VLESS UUIDs and Shadowsocks/TLS keys are zeroized on teardown;
  Finished and UUID comparisons are constant time. No log statement includes
  payloads, passwords, UUIDs, or keys.
- **Hostile lengths**: `@intCast` is guarded by preceding bounds in the audited
  decoders; the two SS2022 overflows found by fuzzing were fixed. Network data
  is read with `std.mem.readInt`, never by pointer-casting a struct.
- **Allocation**: long-lived state is in `Instance.init`; per-connection state
  uses a bounded arena; the relay uses two fixed 32 KiB buffers; hot-path
  decoders do not allocate. The fuzz harness uses fixed buffers and bounded
  per-iteration caches.
- **Caps**: handshake message 16 KiB, TLS record 16 KiB + 256, HTTP head 8 KiB,
  WS handshake 8 KiB, WS read frame 1 MiB (writes fragment at 64 KiB),
  H2 frame 16 KiB, H2 header block 64 KiB,
  H2 dynamic table 4 KiB, XUDP meta 512, VLESS domain 255, Trojan request 320
  and authentication prefix 58, Trojan UDP frame 65535, SS2022 payload 65535,
  SS UDP sessions 128, config 4 MiB.
- **Slow peers**: TLS and WS client handshakes default to 10 s; the WS server
  adapter defaults to no internal timer and relies on the ADR-0015 reaper.
  H2 handshakes use the same configurable timeout. SOCKS5/HTTP handshakes, Trojan
  authentication-prefix reads, Trojan UDP associations, and relay idle time
  are not bounded yet (F-13/F-14/F-17).
- **Trojan fallback**: unauthenticated traffic is replayed to a configured,
  routed TCP endpoint (ADR-0011). Only the consumed prefix is buffered; the
  operator is responsible for the fallback service and for keeping the route
  acyclic. Invalid authentication does not produce a distinguishable error
  response when fallback is configured.
- **Cancellation/close**: TLS adapters serialize writes and use the abort path
  without `close_notify` to avoid racing a writer. SS UDP sessions take the
  session mutex for mutable fields. Teardown of UDP associations is reviewed
  but not stress-tested under cancellation.
- **Oracles**: handle failures return a generic protocol error or a SOCKS5/HTTP
  status code; no payload or credential is reflected.

### H. WebSocket and HTTP/2 transports

Remediation (2026-11-20): TLS now enforces issuer CA/keyUsage/pathLen/name
constraints, rejects plaintext post-handshake alerts and unannounced truncation,
parses known extensions strictly, and zeroizes secret copies; H2 accepts client
`ENABLE_PUSH`, keeps the peer half-close separate from local writes, uses a
byte-budgeted HPACK table, scopes HEADERS to the active stream, reports
RST/truncating GOAWAY as resets, caps CONTINUATION frames, serializes writers,
validates request headers/paths, and validates settings/window arithmetic; WS
preserves coalesced first frames, serializes close state, validates close
codes/UTF-8, rejects strict-handshake violations, bounds messages/control
frames, and uses a small masking scratch; all stream adapters wait for
in-flight operations before freeing on `close`.


- WebSocket handshake parsing is capped at 8 KiB; the request line, required
  upgrade headers, version, path, and `Sec-WebSocket-Key` are validated, and
  `Sec-WebSocket-Accept` is compared in constant time. Reads accept a single
  frame up to the 1 MiB message limit, writes fragment at 64 KiB, control
  frames are capped at 125 bytes and must not be fragmented, client frames
  must be masked, and server frames must be unmasked. Text frames are
  accepted without UTF-8 validation because the transport is byte-oriented.
- HTTP/2 caps frames at 16 KiB, header blocks at 64 KiB, the HPACK dynamic
  table at 4 KiB, and each header name/value at 256/4096 bytes. Integer and
  Huffman decoding are bounded; SETTINGS values are range-checked; only one
  active stream is accepted. Flow control is replenished per DATA frame, and a
  writer waits for WINDOW_UPDATE.
- Fuzzed: WS frame parsing, WS HTTP head parsing, H2 frame parsing, and HPACK
  decoding. Loopback integration covers WS and H2 over TLS with ALPN.
- Residual: no external audit; no WS extensions/compression; no H2
  multiplexing, server push, or PRIORITY effects; a peer that stops reading
  can stall an H2 writer.

### G. Licensing and interop

- Protocol logic was implemented from the public specifications listed in
  `docs/protocols/`; no GPL/AGPL/MPL code was copied.
- No reference-implementation binaries, harnesses, or captured real traffic
  are committed. Fixtures are synthetic and documented in
  `tests/fixtures/README.md`.
- Interop claims in the protocol notes are limited to the self-hosted checks
  recorded there; the harnesses are not in the repository.

## 5. How to reproduce

```sh
zig build test                       # includes deterministic corpus smoke
zig build fuzz                       # 1024 inputs/target, fixed seed
zig build fuzz -Dfuzz-iterations=5000 -Dfuzz-seed=4660
zig build check
zig build test -Doptimize=ReleaseSafe
zig build examples
```

`zig build test --fuzz` additionally runs the same corpus tests under Zig's
unbounded built-in fuzzer; it is opt-in and not part of CI.

## 6. Residual risks and next steps

1. **F-13/F-14/F-17 (ADR needed)**: add a configurable connect/handshake
   timeout, relay idle timeout, Trojan prefix timeout, and a maximum concurrent
   connection count. The architecture already describes these limits, but the
   config schema and enforcement are a design change, so they are not
   implemented in this audit.
2. **TLS post-handshake fuzzing**: add an authenticated-state harness for
   empty records, alerts, and KeyUpdate (currently KeyUpdate is rejected by
   design).
3. **External review**: the hand-written TLS handshake/key schedule should get
   an independent cryptographic review before any production-readiness claim.
4. **Long campaign**: run a multi-hour fuzz campaign with coverage and a
   corpus, especially for TLS ClientHello extensions and SS2022 authenticated
   layouts.
5. **Side channels**: timing behavior of routing and TLS alert handling was not
   measured. Secret comparisons use constant-time helpers, but this is not a
   complete side-channel analysis.


## 6. Second re-audit (2026-11-20)

A second strict pass compared the packages with OpenSSL 4.1, curl/nghttp2,
Python `h2`/`hpack`, and Python `websockets`. Fixed before this note:

- TLS: DER boundary prevalidation before std certificate parsing; negative
  pathLen; trust-anchor and IP name constraints; intermediate CA EKU;
  `allow_truncation_attacks` in outbound config.
- HTTP/2: server preface SETTINGS order; HEADERS before client ACK; local
  `END_STREAM` no longer closes the TCP write side; legal server
  `ENABLE_PUSH=0`; truncation to `ConnectionReset`; optional request path and
  pseudo-header syntax; response `:status` validation; max header list
  advertised; HPACK size-update placement.
- WebSocket: continuation opcodes for writes over 64 KiB; close 1009 for an
  oversized frame; control-frame keepalive limit; strict close handling.
- ADR-0015: independent idle/grace deadlines, zero grace immediate, and peer
  stream abort on timeout.

Residual: TLS RA-05 (outbound connect/DNS cannot yet be canceled by the
handshake deadline), WebSocket handshake timeout still uses a per-connection
sleep task, single WS frames remain capped at 64 KiB, and H2 remains limited to
one stream per connection. These are tracked for the next hardening pass.

## 7. Third re-audit (2026-11-20)

The third pass replayed the second-round findings and added end-to-end probes
against OpenSSL 4.1, curl/nghttp2, Python `h2`/`hpack`, and Python
`websockets`. Fixed before this note:

- TLS: the DER prevalidator now mirrors the std parser's accesses — certificate
  and TBSCertificate field order/types, Name/RDN/ATV bounds, validity times,
  SPKI and RSA public-key shape, non-empty BIT STRINGs (including the
  signature), extension wrappers, and SAN `GeneralNames`. Malformed SANs and
  zero-length signature BIT STRINGs are rejected before `std` can index past
  the end. RSA-PSS CertificateVerify lengths must equal the modulus.
- ADR-0015: the reaper aborts the peer with `.both` (no write lock and no
  protocol close frame) and `Guard.stop`/relay exit clear the peer reference,
  closing the dangling-peer window. HTTP/2 `.both` cancels waiters.
- HTTP/2: a blocked writer pumps frames while waiting for window credit, so
  `WINDOW_UPDATE` is still processed after the peer half-closes; the reader
  task can be gone. DATA padding is stripped and validated.
- WebSocket: the handshake uses a single timer task that aborts the transport
  instead of spawning two tasks, and `ServerOptions` defaults to no internal
  timer so inbound servers rely on the ADR-0015 reaper.

Residual (P2/P3): outbound connect/DNS still cannot be canceled by a
handshake deadline (TLS-07/RA-05); protocol violations from the WS frame codec
do not always send Close 1002; WS needs a handshake-level soak; H2 still uses a
single stream per connection; TLS CN fallback and leaf keyUsage differ from
OpenSSL policy; H2 1xx and strict token validation remain open.

## 8. Fourth re-audit (2026-11-20)

The fourth pass replayed the third-round P0/P1 fixes and fuzzed the new
certificate-shape validator and transport abort paths. Fixed before this note:

- TLS: non-canonical `[3]` wrappers (0x43/0x83/0xc3) are parsed for extension
  validation because std compares only the low five tag bits; malformed SANs
  can no longer reach `verifyHostName`. RSA moduli whose bit length is more
  than six bits short of a byte are rejected before the std PSS assertion.
- ADR-0015: the reaper holds `peer_lock` across the non-blocking `.both`
  abort, so relay cleanup cannot free the adapter mid-abort; registry removal
  and peer updates are uncancelable.
- HTTP/2: the waiting writer only pumps frames after `END_STREAM` (a second
  buffered DATA frame previously aborted the stream), no WINDOW_UPDATE is
  sent after `END_STREAM`, and a second HEADERS block is rejected instead of
  overwriting the request headers.
- WebSocket: reads accept standard-client single frames up to the 1 MiB
  message limit, empty/zero-length frame floods are bounded per read, and a
  handshake falls back to inline execution when timer concurrency is
  unavailable.

Residual (P2/P3): outbound connect/DNS cannot be canceled by a handshake
deadline; WS client handshakes still use one timer task; WS protocol
violations from the frame codec do not always send Close 1002; WS `close` is
not idempotent for callers that free the adapter; H2 control-frame writes
share the data write lock (head-of-line blocking); H2 remains single-stream;
TLS CN fallback, leaf keyUsage, and key-strength policy differ from OpenSSL.

## 9. Fifth re-audit (2026-11-20)

The fifth pass re-ran the fourth-round PoCs against OpenSSL 4.1, curl/nghttp2,
Python `h2`/`hpack`, Python `websockets`, and Node/undici, and added
structured certificate mutation (79k ReleaseSafe cases) plus stateful H2/HPACK
fuzzing. Fixed before this note:

- TLS: certificates with extensions must be v3, and issuer/subject unique
  identifiers are rejected. Previously a v1 certificate (or a uniqueID before
  the extensions wrapper) made std ignore the SAN and fall back to CN while
  this module still validated the SAN. Fixed.
- HTTP/2: a failed WINDOW_UPDATE write no longer discards the DATA frame that
  was already copied; delivery continues and the next read reports the
  transport error. The server's `acceptStream` marks the first HEADERS block,
  so trailer HEADERS cannot overwrite request headers.
- WebSocket: the empty-frame regression test now uses valid masked frames, and
  the handshake-failure path zeroizes the socket buffers.

Residual (P2/P3): WS client handshakes still use one timer task and the
single-threaded fallback drops the configured timeout; a WebSocket connection
reserves 1 MiB for large frames before the handshake; `Io.Threaded` runs about
two worker threads per relay; outbound connect/DNS cannot be canceled by a
handshake deadline; TLS still falls back to CN when no SAN is present and does
not check leaf keyUsage; H2 remains single-stream and shares one write lock
between data and control frames. The global reaper design is recorded as an
amendment inside ADR-0015 rather than a superseding ADR; this is a governance
gap, not a runtime issue.

## 10. Sixth re-audit (2026-11-20)

The sixth pass replayed the fifth-round fixes and audited the certificate
extension aliases used by Zig std. Fixed before this note:

- TLS: the legacy subjectAltName OID `2.5.29.7` is rejected. std still maps it
  to the SAN field and parses it without bounds, while OpenSSL ignores it, so
  a malformed legacy SAN could panic the client before chain validation or
  authorize a host OpenSSL would reject.
- ADR-0015: the reaper aborts `abort_stream` with `.both` rather than `.send`.
  `.send` on a wrapped TLS/WS/H2 stream can wait on a writer that a
  backpressured peer is holding, which previously froze the global scan,
  `stop`, and the accept loop. In-tree `Instance` passes the raw TCP stream,
  where both calls are non-blocking; `.both` makes the contract independent of
  the embedder's choice.
- TLS adapters fall back to an inline handshake when the Io implementation
  cannot provide timer concurrency.

Residual (P2/P3): a `TcpStream`/H2 close still releases the file descriptor
before waiting for in-flight reads, so a racing read can observe EBADF in
Debug; WS client handshakes still use one timer task and the single-threaded
fallback drops the configured timeout; a WS connection reserves 1 MiB before
the handshake; outbound connect/DNS cannot be canceled by a handshake deadline;
TLS still falls back to CN when no SAN is present and does not check leaf
keyUsage; H2 remains single-stream and shares one write lock between data and
control frames.

## 11. Seventh re-audit (2026-11-20)

The seventh pass replayed the sixth-round fixes and checked every OID alias
that Zig std maps for certificate fields. Fixed before this note:

- TLS: trust-anchor validity is checked (`not_before`/`not_after`) before the
  anchor is accepted. `Bundle.verify` checks the subject's validity but not
  the anchor's, so an expired root such as a retired cross-sign could still
  anchor a chain.
- WebSocket: a fragmented message that exceeds 1 MiB (or the fragment count)
  now sends Close 1009 before failing, matching the documented message limit;
  the empty-frame regression test appends a valid data frame so removing the
  bound changes the result instead of ending at EOF.

Residual (P2/P3): the WS adapter reserves about 1 MiB per connection before
the handshake (not reachable through an in-tree inbound yet); WS frame
protocol violations still do not all send Close 1002 and text UTF-8 is not
validated; `close` releases the file descriptor before waiting for in-flight
I/O; the single-threaded WS fallback drops the configured handshake timeout;
the WS client handshake still uses one timer task; outbound connect/DNS cannot
be canceled by a handshake deadline; TLS still falls back to CN when no SAN is
present and does not check leaf keyUsage; H2 remains single-stream and shares
one write lock between data and control frames.

## 12. Post-audit implementation update (2026-11-21)

The high-priority functional gaps identified in the release review were
implemented in three isolated worktrees and merged after package and root
tests:

- TLS: client authentication (`none`/`optional`/`required`), AES-256-GCM and
  ChaCha20-Poly1305, X25519/P-256 ECDHE, and KeyUpdate. Root config adds the
  client certificate/key and inbound client-CA policy. PSK/resumption/tickets/
  0-RTT, TLS 1.2, revocation, ECH, record padding, SNI multi-certificate
  selection, and RSA/Ed25519 credentials remain out of scope.
- HTTP/2: bounded 16-stream multiplexing, per-stream flow control, 1xx and
  trailers, GOAWAY/RST_STREAM, strict header validation, HPACK integer and
  header-list fixes, and buffer zeroization. Config/Instance wiring, server
  push/PRIORITY, h2c, HTTP/2 WebSocket, and gRPC framing remain out of scope.
- WebSocket: RFC 7692 permessage-deflate and subprotocol negotiation, plus
  incremental text UTF-8 validation and correct Close codes. Config/Instance
  wiring, Origin/auth, redirects, HTTP/2 WebSocket, true half-close, and lazy
  compression/frame memory remain out of scope.

The full suite is now 251 tests (61 root, 4 public API, 29 integration, 47
tls13, 36 http2, 60 ws, 14 fuzz). TLS, HTTP/2, and WebSocket interop was
rechecked locally against OpenSSL 4.1, curl/nghttp2, Python `h2`/`hpack`,
Python `websockets`, and Node `ws`.

## 13. Post-audit H2/WS follow-up (2026-11-21)

An independent audit of the newly added multiplexing and compression code
found no P0, two HTTP/2 P1s, and one WebSocket P2 regression. Fixed:

- HTTP/2: field blocks on closed/refused streams are fully decompressed before
  discard, and an oversized header list closes the connection with
  COMPRESSION_ERROR instead of leaving a half-updated HPACK table. Connection
  window credit is returned for discarded/aborted DATA; the 17th stream, a
  stream WINDOW_UPDATE overflow, and a bad PRIORITY length are stream errors;
  `ServerOptions.path` is enforced; DATA before the final response is rejected;
  the HPACK header count is 256 so legal 8 KiB lists are accepted.
- WebSocket: pings queue instead of dropping under writer contention, valid
  close codes are echoed, non-minimal lengths/BFINAL/malformed extensions/
  duplicate subprotocols are rejected, `close_sent` is atomic, remaining
  buffers are zeroized, and `ws_deflate`/`ws_connection_deflate` fuzz targets
  were added.

Remaining recorded gaps: server-sent 1xx and stateful H2 fuzz coverage,
the H2 8 KiB stream window throughput trade-off, borrowed `headers()` slices,
WS Origin/auth and lazy compression memory, and external audit.
