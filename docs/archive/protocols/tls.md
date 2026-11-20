# TLS 1.3

> **Archived: Zig era.** These are notes for the in-tree `packages/tls13`
> implementation, deleted under ADR-0018. The Rust target uses `rustls`; see
> [`../../architecture.md`](../../architecture.md) §13 and the live index at
> [`../../protocols/README.md`](../../protocols/README.md).

Sources consult: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
(TLS 1.3), [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) (example
handshake traces), [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) (ALPN),
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) (certificate paths), and the
Zig 0.17.1 `std.crypto` APIs for crypto primitives. Both client and server are
implemented in `packages/tls13` (ADR-0007, ADR-0010, ADR-0012 and its
2026-11-20 amendment).

## Implemented scope

- TLS 1.3 only (`supported_versions` must advertise `0x0304`).
- Cipher suites `TLS_AES_128_GCM_SHA256` (`0x1301`),
  `TLS_AES_256_GCM_SHA384` (`0x1302`), and
  `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`). The transcript hash, HKDF hash,
  secret and Finished lengths, and record key length follow the suite.
- Key exchange groups `x25519` (`0x001d`) and secp256r1 (`0x0017`). The client
  sends both key shares; the server selects a group the client shared. No
  HelloRetryRequest is needed between conforming peers. A retry is parsed and
  rejected because the client already offered every supported group.
- Signature `ecdsa_secp256r1_sha256` (`0x0403`) for server and client
  `CertificateVerify`.
- Server handshake: ClientHello, ServerHello, middlebox-compatibility CCS,
  EncryptedExtensions (including ALPN), optional CertificateRequest,
  Certificate, CertificateVerify, Finished, optional client Certificate and
  CertificateVerify, client Finished verification, and `close_notify`.
- Client handshake: ClientHello with SNI, supported groups, two key shares,
  signature algorithms, and optional ALPN; ServerHello, encrypted server
  flight with chain/host verification, optional CertificateRequest,
  server Finished verification, optional client certificate flight, and the
  client Finished.
- Client authentication: the client sends a configured ECDSA P-256 chain and
  `CertificateVerify` when the server requests one, or an empty Certificate
  when it has none. The server verifies the client chain against a configured
  trust bundle, applies `none`/`optional`/`required` policy, and enforces CA
  name constraints against every DNS/IP SAN in the client certificate. The
  CertificateRequest advertises the signature schemes the server accepts, and
  the handshake-internal certificate_request_context must be zero.
- Record protection: AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305, 12-byte
  per-direction nonce XORed with a 64-bit sequence number, 16-byte tag,
  maximum plaintext 16 KiB, maximum ciphertext 16 KiB + 256.
- Key schedule: HKDF-SHA256 or HKDF-SHA384 with `HKDF-Expand-Label`,
  transcript hashes, and constant-time Finished comparison.
- Certificate/key loading from PEM `CERTIFICATE` blocks or DER, and a PKCS#8
  or SEC1 ECDSA P-256 private key. Server and client leaves must be P-256 and
  match the key. Peers accept ECDSA P-256/P-384, Ed25519, and RSA certificate
  signatures and verify chains against a configured bundle or the system CA
  bundle.
- ALPN (RFC 7301): the client sends `alpn_protocols`; the server selects the
  first configured protocol the client offered; a non-empty server list with
  no overlap fails the handshake.
- KeyUpdate (RFC 8446 §4.6.3): both roles accept complete or fragmented
  post-handshake KeyUpdate messages, replace read keys, and send a reciprocal
  update before the next application record when `update_requested` is set.
  Both roles can send a KeyUpdate and replace their write keys.

No PSK, session tickets, HelloRetryRequest continuation, 0-RTT, TLS 1.2,
revocation, ECH, or record padding is implemented.

## Key schedule checks

The labels used are `derived`, `c hs traffic`, `s hs traffic`, `finished`,
`c ap traffic`, `s ap traffic`, `key`, `iv`, and `traffic upd`. Transcript
input is the handshake message bytes including the 4-byte handshake header;
CCS is not part of the transcript. The transcript hash is SHA-256 for
AES-128-GCM and ChaCha20-Poly1305, and SHA-384 for AES-256-GCM. Application
traffic secrets are derived through the server Finished; the client Finished
covers the optional client Certificate and CertificateVerify. Loopback matrix
tests cover every suite/group combination in both directions.

## Fixtures

`tests/fixtures/tls/` contains synthetic inputs constructed from the RFC wire
layout: a ClientHello, a plaintext record containing it, a truncated encrypted
application-data record, and an invalid PEM block. There are no captured
traces and no private keys. Provenance and license are recorded in
`tests/fixtures/README.md`.

## Fuzz targets

`zig build fuzz` exercises `tls_client_hello`, `tls_client_hello_mutated`,
`tls_record_read`, `tls_record_open`, `tls_record_open_valid`,
`tls_record_seal`, `tls_server_handshake`, `tls_server_handshake_mutated`,
`tls_server_hello`, `tls_credentials`, `tls_key_schedule`, `tls_key_update`,
and `tls_cert_path`. The short corpus smoke runs in `zig build test`; see
`docs/archive/security-audit-zig.md`.

## Known gaps

- PSK/session resumption, tickets, 0-RTT, TLS 1.2, revocation/OCSP/CRL, ECH,
  and record padding are not implemented.
- Server and client credentials are ECDSA P-256 only; no RSA or Ed25519
  credential keys and no SNI multi-certificate selection.
- Certificate policy still differs from OpenSSL in a few areas: no-SAN
  certificates fall back to CN, leaf `keyUsage` is not checked, and anchor
  `pathLen`/`keyUsage` are not enforced. A trust anchor with `pathLen=0` can
  still sign an intermediate.
- A HelloRetryRequest is rejected rather than retried, because the client
  always offers X25519 and P-256 shares.
- No post-handshake end-to-end fuzz target: KeyUpdate parsing is fuzzed, but an
  authenticated post-handshake stream is covered by unit/integration tests.
- No external cryptographic review. The implementation uses `std.crypto`
  primitives only; it does not implement AES, GCM, ChaCha20-Poly1305, SHA-256,
  SHA-384, HKDF, X25519, or P-256 by hand.
