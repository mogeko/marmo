# Security audit

- Status: Rust implementation in `crates/`; R4 hardening in progress.
- Scope: durable threat model, findings carried over from the Zig audit, and
  the audit plan for the Rust tree.
- Zig-era record: [`../archive/security-audit-zig.md`](../archive/security-audit-zig.md)
  (2026-11-20/21, 25 findings, six re-audit rounds plus two follow-ups).
- Related: ADR-0009 (clean-room), ADR-0018 (dependencies and crypto),
  ADR-0020 (license).

## 1. Threat model

This section is language-neutral and carries over unchanged from the Zig audit.

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
not implemented in this revision (VMess, QUIC, TUIC, Hysteria2).

## 2. What changed with the Rust target

- **Closed by deletion.** The in-tree TLS 1.3, HTTP/2, and WebSocket
  implementations (15,465 lines) are replaced by `rustls`, `h2`, and
  `ws-net` (ADR-0018, ADR-0021). Findings in those parsers are closed by
  deleting the code; they are not ported. The assurance argument becomes
  "upstream project plus our configuration", not "our parser".
- **New surface.** Crates and their build scripts, the `aws-lc-rs` C/assembly
  provider, tokio's cancellation and task model, and rustls configuration.
- **Unchanged surface we still own.** SOCKS5, HTTP/1 proxy, Shadowsocks 2022,
  Trojan, VLESS/XUDP codecs, config validation, routing, relay, UDP sessions,
  and metrics. Most Zig-era findings live here and become Rust obligations.

## 3. Carried findings and Rust obligations

Every finding that applies to code we still own gets a regression test in R1-R4.
Findings marked "closed" are closed by removing the code, not by assuming the
replacement is correct.

| Zig finding | Rust obligation |
| --- | --- |
| F-01 HTTP request-line injection | Reject CTLs (`<= 0x20`, `0x7f`) in the request target and `Host`; parse with `httparse` and validate the version; loopback + fixture tests. |
| F-02 SS2022 16-bit length overflow | Widen to `usize` before adding the AEAD tag; checked arithmetic; fuzz authenticated layouts. |
| F-03 SS2022 UDP session race | One owner per session task, or a lock around `last_active`; `loom` test for the table. |
| F-06 diagnostic truncation | No `Diagnostic` buffer; `tracing` fields only; redaction test. |
| F-08 empty HTTP authority | Keep the empty-authority rejection test. |
| F-09 VLESS UUID zeroize | `zeroize` on drop; no `Debug` for credential types. |
| F-10 unbounded config JSON | Keep the 4 MiB document cap before parsing. |
| F-11 control characters in domain hosts | Validate `Endpoint` hosts on parse. |
| F-12 8 KiB HTTP head boundary | Bounded head parser; test exactly-at-limit and one-over. |
| F-13 connection cap / handshake deadline | `Semaphore` permit before handshake; `timeout` around handshake+dial. |
| F-14 relay idle/half-close deadline | Idle adapter + half-close grace inside `select!`; paused-time tests. |
| F-17 Trojan prefix deadline | Covered by the handshake deadline; UDP association resets idle. |
| F-16 no external audit | Still open; R4 requires an external review before any production claim. |
| F-21/F-22 certificate-path and truncation bugs | `rustls` with the platform verifier; TLS 1.3 only; `insecure` is loopback-only and validation rejects it for a non-loopback server; regression test that a public server cannot disable verification. |
| F-04/F-05/F-07/F-15/F-18 TLS internals | Closed by deleting `packages/tls13`; covered by `rustls` upstream. |
| F-19/F-20/F-23/F-24 WS/H2 internals | Closed by deleting `packages/ws` and `packages/http2`; upstream crates own the parsers. |
| F-25 adapter close race | Closed by the drop model; replaced by the cancel-safety obligation below. |

## 4. Rust-specific risks

| Risk | Mitigation |
| --- | --- |
| Dependency supply chain | `Cargo.lock` committed, `--locked` CI, a `cargo tree` copyleft check, `cargo-audit`; review every new build script, proc macro, and `unsafe` block |
| C crypto provider | One pinned provider (`aws-lc-rs`); CI builds it on all three OS targets; no runtime switch |
| Unsafe code | `forbid(unsafe_code)` in `marmo-proto` and `marmo`; per-block justification in `marmo-transport` |
| Cancel-safety | Every `select!` branch audited; drop-mid-await tests; no `MutexGuard` across `.await`; `loom` for session state |
| Panic on untrusted input | Fuzz every decoder; no `unwrap`/`expect`/indexing on network data; `panic = "abort"` is not a substitute for validation |
| TLS misconfiguration | TLS 1.3 only, ALPN/mTLS tested; the only verification bypass is `tls.insecure`, restricted to loopback test servers |
| Secret leakage | `secrecy` + `zeroize`; no secrets in `Debug` or span fields; constant-time comparisons |
| Resource bounds | Every queue/table/cache bound at init; `Semaphore` for TCP and UDP; no unbounded `spawn` |
| Supply-chain license drift | CI copyleft check from ADR-0020; GPL/AGPL/MPL denied; dependency PRs record a license review |

## 5. Audit plan (R4)

1. Re-create the F-01, F-02, F-08, F-10, F-11, F-12, F-13, F-14, and F-17
   regression tests against the Rust tree.
2. Fuzz every decoder (`marmo-proto`) and config parser for 24 hours per target
   with the migrated corpus.
3. Run interop against self-hosted `shadowsocks-rust` and `sing-box` for SS2022,
   Trojan, and VLESS, in both directions.
4. Review the rustls configuration: verification, TLS 1.3 floor, ALPN, mTLS,
   platform verifier, and the loopback-only `insecure` restriction.
5. Run the copyleft check and `cargo-audit`; record the dependency tree and the
   provider version in the audit.
6. Commission an external review before any production-readiness claim. The
   scope is the codecs, config, relay/cancellation paths, and dependency
   configuration; TLS/H2/WS parsers are upstream.

## 6. Residual risks

- No external audit of the Rust tree exists yet.
- No long-running soak or coverage-guided campaign; R4 runs a bounded campaign
  only.
- Side channels were not measured in the Zig tree and are not measured here;
  constant-time comparisons are used for secrets, but that is not a complete
  analysis.
- `rustls`, `h2`, `quinn`, and `tokio` are external trust anchors; their
  advisories are followed through `cargo-audit`, not independently reviewed.
- The Rust port can reintroduce a Zig-era bug under a new shape; the table in
  §3 exists to prevent that, and each row needs a test before cutover.
