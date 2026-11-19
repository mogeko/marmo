# Security audit

- Date: 2026-11-19
- Base revision: `339db44` ("Bound TLS handshakes with a configurable timeout")
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

Assets: client credentials (VLESS UUID, Shadowsocks PSK), TLS private keys and
session secrets, routing policy, and process availability.

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
not implemented in this revision (QUIC, HTTP/2, WebSocket, VMess, Trojan,
TUIC, Hysteria2).

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
| F-13 | Medium | Open | Inbounds | No connect/handshake idle timeout for SOCKS5/HTTP and no maximum connection count. Requires a config/architecture decision (ADR). |
| F-14 | Medium | Open | Relay | No idle-timeout enforcement after relay start; a silent peer can hold a relay pair open indefinitely. Requires a config/architecture decision (ADR). |
| F-15 | Low | Open | TLS | KeyUpdate/client auth/PSK/tickets/ALPN are not implemented; post-handshake handling is unit-tested but not end-to-end fuzzed. |
| F-16 | Low | Open | General | No external audit, no side-channel review, and no long-running soak/fuzz campaign. |

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
  XUDP meta 512, VLESS domain 255, SS2022 payload 65535, SS UDP sessions 128,
  config 4 MiB.
- **Slow peers**: TLS handshakes have a configurable timeout (default 10 s).
  SOCKS5/HTTP handshakes and relay idle time are not bounded yet (F-13/F-14).
- **Cancellation/close**: TLS adapters serialize writes and use the abort path
  without `close_notify` to avoid racing a writer. SS UDP sessions take the
  session mutex for mutable fields. Teardown of UDP associations is reviewed
  but not stress-tested under cancellation.
- **Oracles**: handle failures return a generic protocol error or a SOCKS5/HTTP
  status code; no payload or credential is reflected.

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

1. **F-13/F-14 (ADR needed)**: add a configurable connect/handshake timeout,
   relay idle timeout, and a maximum concurrent connection count. The
   architecture already describes these limits, but the config schema and
   enforcement are a design change, so they are not implemented in this audit.
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
