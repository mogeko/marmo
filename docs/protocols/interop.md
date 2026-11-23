# Differential interop records

This file records local differential checks: the same protocol path is run
against a reference implementation and against marmo, in both directions where
the reference supports it. It is evidence for P2-13, not a CI job.

Rules:

- Only self-hosted references on loopback are used. No live third-party
  servers.
- Reference binaries, configs, certificates, and the harness are not committed;
  only the observations below are.
- Reference projects may be GPL/AGPL/MPL. Only their published wire behavior
  was exercised; no code, patch, or fixture is copied (ADR-0009).
- A missing direction or transport is a gap, not an implied pass.
- Records below were collected during Phase 2 development (2026-11-19 through
  2026-11-24) unless a different date is noted.

## Summary

| Protocol | Reference | Version | Directions checked | Transport / mode | TCP | UDP | Mux | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HTTP/1 | curl | 8.7.1 | client -> marmo | forward proxy | yes | — | — | pass |
| HTTP/1 | curl | 8.7.1 | client -> marmo | CONNECT proxy | yes | — | — | pass |
| SOCKS5 | curl | 8.7.1 | client -> marmo | CONNECT | yes | — | — | pass |
| SOCKS5 | loopback tests | — | client -> marmo | UDP ASSOCIATE | — | yes | — | pass |
| Shadowsocks 2022 | shadowsocks-rust | 1.25.0 | both | TCP, UDP | yes | yes | — | pass |
| Trojan | Xray-core | 26.11.9 | both | TLS | yes | yes | — | pass |
| Trojan | trojan-gfw | 1.16.0 | both | TLS | yes | yes | — | pass |
| VLESS | Xray-core | 26.11.9 | both | TLS, TCP/UDP/XUDP/Mux | yes | yes | yes | pass |
| VLESS | Xray-core | 26.11.9 | both | TLS + WebSocket | yes | yes | opt-in | pass |
| VLESS | V2Ray | 5.53 | both | HTTP/2 `PUT` | yes | yes | opt-in | pass |
| VMess | Xray-core | 26.11.9 | both | TCP, TLS + WebSocket | yes | yes | yes | pass |
| Mux.Cool | Xray-core | 26.11.9 | both | carried by VLESS and VMess | yes | yes | yes | pass |

## HTTP/1 and SOCKS5

These are RFC-conformance checks rather than third-party proxy interop:

- Local HTTP server: Python `http.server` on loopback.
- Local reference client: curl 8.7.1 (macOS, LibreSSL build).
- `curl -x http://127.0.0.1:<http-port> http://127.0.0.1:<echo-port>/`:
  forward request passed through the marmo HTTP inbound.
- `curl -p -x http://127.0.0.1:<http-port> http://127.0.0.1:<echo-port>/`:
  proxied CONNECT passed.
- `curl --socks5-hostname 127.0.0.1:<socks-port> http://127.0.0.1:<echo-port>/`:
  SOCKS5 CONNECT passed.
- SOCKS5 UDP ASSOCIATE has no curl path in this build; it is covered by the
  loopback integration tests listed in [`socks5.md`](socks5.md).

Checked 2026-11-24.

## Shadowsocks 2022

Local self-hosted `shadowsocks-rust` 1.25.0:

- reference client -> marmo Shadowsocks inbound: TCP and UDP passed;
- marmo outbound -> reference server: TCP and UDP passed;
- both directions used the same 2022-blake3 AES-128-GCM method.

The harness is intentionally not committed. The protocol notes and limits are
in [`shadowsocks.md`](shadowsocks.md).

## Trojan

Local self-hosted references:

- Xray-core 26.11.9: SOCKS client -> marmo Trojan inbound over TLS -> direct
  TCP/UDP passed; marmo SOCKS client -> Xray Trojan server over TLS -> direct
  TCP/UDP passed. The Xray client pinned the local self-signed ECDSA P-256
  certificate with `pinnedPeerCertSha256`; the Xray server needed `finalRules`
  to allow loopback targets.
- trojan-gfw 1.16.0 (macOS x86_64 under Rosetta 2): TCP and UDP passed in both
  directions. The reference client used an empty ALPN list and `verify: false`;
  the server used TLS 1.3 and `cipher_tls13: TLS_AES_128_GCM_SHA256`.
- The trojan-gfw client sends UDP ASSOCIATE to `0.0.0.0:0`; marmo routes the
  first datagram, so the association works.

Details and known TLS caveats are in [`trojan.md`](trojan.md).

## VLESS

- Xray-core 26.11.9:
  - Xray client with mux enabled -> marmo VLESS inbound: TCP and UDP passed over
    TLS with a pinned test certificate;
  - marmo VLESS outbound with `mux: true` -> Xray VLESS inbound: TCP and UDP
    passed;
  - TCP and UDP/XUDP passed in both directions over TLS, WebSocket, and HTTP/2.
- V2Ray 5.53: HTTP/2 `PUT` client and server paths passed. V2Ray requires the
  configured `:authority` to match exactly, so `transport.host` must match the
  reference's host.
- Xray 26.11 and later removed HTTP/2 in favour of XHTTP; V2Ray 5.53 and Xray
  1.8-era builds remain the HTTP/2 references.

Details are in [`vless.md`](vless.md).

## VMess

- Xray-core 26.11.9, both directions:
  - marmo outbound -> Xray: TCP and WebSocket, with and without `mux: true`;
  - Xray -> marmo inbound: TCP and UDP, with mux disabled and enabled.
- The mux-enabled client exercised XUDP session `0`.
- AES-128-GCM and ChaCha20-Poly1305 body ciphers were exercised by the local
  loopback suite; reference interop used the default AES-128-GCM path.

Details are in [`vmess.md`](vmess.md).

## Mux.Cool

Mux.Cool was checked through both carriers:

- Xray mux client -> marmo VLESS/VMess inbound: concurrent TCP and UDP sessions
  on one physical stream passed;
- marmo VLESS/VMess outbound with `mux: true` -> Xray: TCP and UDP sessions
  passed, including the XUDP session-`0` path.

The shared codec is documented in [`vless.md`](vless.md) and
[`vmess.md`](vmess.md).

## Gaps

- No live third-party servers are used.
- HTTP/2 reference interop depends on V2Ray or older Xray builds.
- Hysteria2, TUIC, gRPC, XHTTP, and TUN are out of scope for this record.
- Reference binaries are not part of CI; the committed fixtures provide the
  offline regression surface.
