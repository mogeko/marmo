# Security audit

- Status: current Rust implementation, internally audited. No external
  independent audit is planned for the 0.x line; that is an accepted risk
  (§3.1, §4). The release must not claim independent security assurance.
- Scope: threat model, implemented controls, open obligations, accepted
  security-assurance decisions, and the remaining release checks.
- Related: ADR-0009 (clean-room), ADR-0018 (dependencies and crypto),
  ADR-0020 (license), ADR-0028 (injected rule sets), ADR-0029 (process
  identity injection), ADR-0030 (DNS resolver).

## 1. Threat model

Assets: client credentials (VLESS UUID, Shadowsocks PSK, Trojan password
hash), TLS private keys and session secrets, routing policy, and process
availability.

Adversaries:

1. An unauthenticated network peer that can send arbitrary bytes to an inbound
   listener, including slow or truncated handshakes.
2. An authenticated but malicious proxy client that sends hostile framing after
   authentication.
3. A malicious or compromised upstream TLS server, proxy peer, or DNS resolver.
4. A malicious configuration file is treated as trusted input from the
   embedder; parsing is still bounded so a huge file cannot allocate without
   limit.

Out of scope: a compromised embedder process, OS/kernel bugs, physical access,
side-channel and micro-architectural attacks, traffic analysis, and protocols
not implemented in this revision (QUIC, TUIC, Hysteria2).

## 2. Implemented controls

- **Transport parsers are upstream.** TLS is `rustls`; HTTP/2 is `h2`;
  WebSocket is `ws-net`. The library owns configuration and adapters, not the
  protocol state machines.
- **Bounded input.** Config is capped at 4 MiB. HTTP heads, protocol headers,
  UDP packets, WebSocket messages, and HTTP/2 frames have fixed bounds checked
  before allocation or copying.
- **Cancellation.** Every connection owns a child token; spawned tasks are
  owned by a `JoinSet`, a `TaskTracker`, or an explicitly held abort handle. A
  dropped handshake does not leave an authenticated session reachable. Process
  resolver calls run on `spawn_blocking`; a lookup timeout detaches the
  blocking call and relies on the provider's own bound.
- **Limits.** `max_connections`, handshake deadline, idle deadline, and
  half-close grace are enforced by the instance (ADR-0015). Multiplexed HTTP/2
  adds fixed bounds: one connection serves at most 16 streams, the outbound
  pool holds four connections and 64 streams in flight, and inbound streams
  have a separate `max_connections` budget so a single TCP connection cannot
  bypass the connection cap without bound (ADR-0031). Mux.Cool has its own
  per-instance logical-session budget in addition to the 128-session physical
  cap.
- **Secrets.** Credential-bearing public types (passwords, UUIDs,
  certificates, keys, and Shadowsocks request/response state) have redacted
  `Debug`; owned derived keys are zeroized, and UUID/password comparisons are
  constant time. No payload, credential, or SNI is logged by the library.
- **Configuration.** Strict JSON schema version 2; unknown and duplicate fields
  are errors. TLS credentials are inline PEM; file paths are rejected
  (ADR-0023). `tls.insecure` is accepted only for a literal loopback IP
  address; a name such as `localhost` is resolved later and is rejected.
  Message domains are canonicalized to ASCII/punycode with IDNA before routing
  and resolution.
- **Dependency surface.** `Cargo.lock` is committed and CI uses `--locked`;
  CI rejects GPL/AGPL/MPL and runs `cargo-audit` when dependencies change.
- **Fuzzing.** Every decoder in `marmo-proto`, including HTTP/1 and Mux.Cool
  metadata, has a fuzz target. Wire-format fixtures cover the encoder-backed
  codecs; the Mux.Cool frame reader is covered by unit tests rather than a
  separate target. Corpus provenance is recorded in
  `fuzz/corpus/README.md`; CI runs a short bounded smoke for every target on
  relevant pull requests and on manual dispatch. The SS2022 and VMess targets
  feed raw ciphertext, so mutations mostly stop at the AEAD open; only the
  encoder-produced seed corpus reaches post-auth parsing. Authenticated-input
  fuzzing remains future work and is not claimed as coverage. A 24-hour soak is
  no longer a release gate.
- **VMess AEAD.** Only the AEAD header is accepted; legacy MD5/CFB and body
  None/Zero are rejected. Auth IDs are verified by AES decryption, CRC32, and a
  120-second window, then inserted into a bounded 4,096-entry replay filter.
  The 16-bit chunk counter is capped at 65,536 per direction to prevent GCM
  nonce reuse. MD5 appears only where the protocol mandates it: CmdKey
  derivation and the ChaCha20-Poly1305 key expansion. Both replay filters
  reject new entries when full instead of evicting an active entry.
- **Mux.Cool.** The VMess and VLESS inbounds share one dispatcher bounded to 128
  sessions per physical connection, a 16-frame queue per session, 64 KiB
  frames, 512-byte metadata, the instance idle timeout, a per-instance
  logical-session permit, and a 1,024-permit (about 64 MiB) frame-memory budget.
  Sessions own one task and are aborted with the physical connection; a session
  dial has the standard handshake deadline. Downlink writes notify the physical
  connection's activity deadline. A session that cannot acquire frame memory is
  closed rather than blocking other connections.
- **Mux.Cool outbound.** The client pool is bounded to four physical
  connections, 128 sessions per connection, 16 queued frames per session, and a
  4 MiB in-flight downlink budget. TCP downlink applies backpressure; UDP drops
  under queue pressure. Session ids are never reused, and all pool tasks are
  tracked and cancelled with the instance.
- **Direct UDP replies.** Direct sockets are wildcard-bound for multi-target
  associations, so the outbound and the Shadowsocks UDP server keep a bounded
  set of destinations they have sent to and drop replies from unknown source
  addresses. IP source spoofing within an allowed destination remains a
  residual risk.
- **DNS.** The optional resolver uses explicit IP endpoints and never reads
  `resolv.conf` or `hosts`. DoT/DoH verify against the platform trust store or
  an explicit inline CA; there is no `insecure` switch. Answers are capped at
  16 addresses, the cache is bounded, each lookup has a total deadline and an
  in-flight limit, and query names are never logged. Plaintext fallback is an
  explicit configuration choice; there is no implicit system fallback. The
  DNS wire decoder and transports are hickory's, not ours.
- **Injected routing providers.** `DomainSet`, `IpSet`, `ProcessResolver`, and
  `DnsResolver` are trusted embedder code. The library bounds tag count,
  process and DNS cache size, lookup timeout, and in-flight resolver calls;
  provider data bounds and storage integrity are outside the library. Process
  identity is best-effort, is not a security boundary, and is never logged. A
  provider error is a non-match or lookup failure, not a panic path; a provider
  panic is a contract violation.

## 3. Open obligations

| Area | Obligation |
| --- | --- |
| Fuzzing | Keep the short bounded CI smoke for every decoder target and maintain the committed corpus. |
| Interop | Keep reference-server interop outside CI and record results in `docs/protocols/`. |
| TLS | Re-check `rustls` verification, TLS 1.3 floor, ALPN, and mTLS on dependency upgrades. |
| HTTP/1 | Keep the request/forward/CONNECT parser fuzzed and bounded as it evolves. |
| Cancellation | Audit every `select!` branch and keep drop-mid-await tests for protocol state machines. |
| Resource bounds | Re-check every queue, table, and cache on new features; no unbounded per-peer state. |
| Injected providers | Audit each `DomainSet`/`IpSet`/`ProcessResolver` implementation for the declared contract: in-memory, non-blocking, allocation-free, bounded, and panic-free. |
| Process identity | Treat process matching as policy convenience, not authorization; do not log names or paths. |
| DNS | Review the `hickory-resolver` dependency on upgrades; keep the cache, deadline, and in-flight bounds; verify that no query name reaches logs or metrics. |
| Secrets | Keep redaction and zeroization tests for every new credential-bearing type. |
| Supply chain | Review new build scripts, proc macros, and `unsafe`; keep the lockfile and audit gate current. |

### 3.1 Accepted security-assurance decision (2026-11-25)

- **External independent audit: not required for the current 0.x line.** The
  cost is accepted as a residual risk. Revisit before a 1.0 production-readiness
  claim, a regulated deployment, or an embedder contract that requires
  independent assurance. Until then, documentation and release notes must say
  "internal audit only, no external audit".
- **Fuzzing: CI short runs instead of a 24-hour soak.** Every decoder target
  runs the bounded CI smoke (`-runs=1000 -max_len=4096 -timeout=25`) on relevant
  pull requests and manual dispatch. A long soak is optional local work, not a
  release gate.
- These decisions do not reduce the other obligations: dependency audit,
  copyleft check, interop records, cancellation review, resource-bound review,
  and secret-handling tests remain required.

## 4. Residual risks

- No external independent audit of the Rust tree exists. This is an accepted
  risk for the 0.x line, not evidence of absence of unknown defects; see §3.1.
- `rustls`, `h2`, `ws-net`, `tokio`, and `aws-lc-rs` are external trust
  anchors; their advisories are covered by Dependabot and `cargo-audit`.
- Side channels were not measured.
- Direct UDP paths reject replies from destinations they have not sent to, but
  an attacker able to spoof an allowed source IP/port can still inject a reply.
  This is a property of unauthenticated UDP, not something the library can
  fully prevent.
- `ip_cidr` and `geoip` match literal destination IPs only. A domain
  destination is resolved after routing, so CIDR rules are not an egress
  firewall: a domain that resolves into a blocked range can bypass them. An
  unauthenticated SOCKS5/HTTP listener with a direct final route is an open
  proxy/SSRF surface by configuration.
- The `aws-lc-rs` provider requires a C toolchain; a platform that cannot build
  it needs an ADR, not a silent backend switch.
- The library is a proxy: a configuration mistake can expose a listener or
  disable verification for a loopback test target. Validation narrows the
  latter but does not make arbitrary configuration safe.
- A deliberately configured plaintext DNS upstream exposes query names to the
  path between the library and that upstream. An embedder that enables
  trace-level `hickory-resolver` logging may also expose names outside the
  library's own logging policy.

## 5. Audit plan

1. Re-run the config, HTTP/1, codec, and cancellation regression tests on the
   release candidate.
2. Run the short bounded CI fuzz smoke for every decoder target with the
   committed corpus; a longer local run is optional.
3. Re-run reference interop for SOCKS5, HTTP, Shadowsocks 2022, Trojan, VLESS
   TCP/UoT/XUDP/WS/H2.
4. Review the `rustls` configuration: verification, TLS 1.3 floor, ALPN, mTLS,
   platform verifier, and the loopback-only `insecure` path.
5. Review the DNS resolver: explicit upstreams, TLS trust, cache bounds,
   deadline, fallback policy, and the absence of query names in logs.
6. Run `cargo audit` and the copyleft check; record the dependency tree and
   provider version.
7. Confirm the release text says "internal audit only; no external audit" and
   record any new accepted risk in §3.1.
