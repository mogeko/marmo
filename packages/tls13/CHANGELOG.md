# Changelog

## Unreleased

> Package version not bumped yet; the root release decides when this becomes
> a tagged package version.

### Security

- Certificates are structurally validated before `std.crypto.Certificate`
  parses them: certificate/TBSCertificate fields, Name/RDN/ATV bounds, validity,
  SPKI and RSA public keys, non-empty BIT STRINGs, extension wrappers, and SAN
  `GeneralNames`. Malformed DER now returns a typed rejection instead of
  aborting in std.
- Non-canonical `[3]` extension wrappers (0x43/0x83/0xc3) are parsed for
  validation, the legacy subjectAltName OID 2.5.29.7 is rejected, and v1/v2
  certificates carrying extensions or issuer/subject unique identifiers are
  rejected. A SAN can no longer be hidden from std's host-name verifier.
- RSA-PSS CertificateVerify signatures must match the certificate modulus
  byte length and bit length; 2041/3065/4089-bit moduli are rejected instead
  of tripping a std assertion.
- Trust-anchor validity (`not_before`/`not_after`) is checked, pathLen
  integers are non-negative and minimally encoded, IP name constraints and
  trust-anchor name constraints are enforced, and intermediate CA EKU is checked.

### Added

- Client authentication (mTLS): the client sends a configured ECDSA P-256
  chain and CertificateVerify; the server sends CertificateRequest, verifies
  the client chain against a configured trust bundle with `clientAuth` EKU
  checks, and enforces `none`/`optional`/`required` policy.
- `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` alongside
  `TLS_AES_128_GCM_SHA256`, with suite-specific transcript hash, HKDF hash,
  secret/Finished lengths, and record keys. Negotiation is preference-ordered
  on both roles, and a client rejects a suite it did not offer.
- secp256r1 (P-256) ECDHE alongside X25519. The client sends both key shares;
  the server selects a group that was shared. HelloRetryRequest is parsed and
  rejected because the client already offered every supported group.
- KeyUpdate in both roles: peer updates replace read traffic secrets and read
  keys, `update_requested` is answered before the next application record, and
  `Client.keyUpdate`/`Server.keyUpdate` can initiate an update. Read and write
  key transitions touch disjoint state; the response flag is atomic.
- Root config fields `tls.client_certificate`/`client_private_key` for
  outbound TLS and `tls.client_ca`/`tls.client_auth` for inbound TLS, plus
  credential loading through `src/transport/tls_credentials.zig`.
- `tls_key_update` fuzz target, package loopback matrices for every
  suite/group, mTLS policy tests, KeyUpdate-under-traffic tests, and
  HelloRetryRequest parser tests.
- Client-certificate chains now enforce CA name constraints on every SAN
  (DNS and IP), not just the server host name. Client CA files are
  shape-checked before std parsing, DER CA files are accepted, and
  `tls.client_ca` without `client_auth` is a config error.
- CertificateRequest advertises every signature scheme the server accepts;
  the client sends a zero-length certificate_request_context and the server
  rejects a non-zero context.
- `negotiatedCipherSuite()` uses a dedicated post-handshake field, so KeyUpdate
  read paths no longer read a field the write path concurrently replaces.
  X25519 ephemeral and loaded client-key stack copies are zeroized.

- ALPN negotiation on the client and server. `Options.alpn_protocols`,
  `ServerOptions.alpn_protocols`, and `negotiatedProtocol()` are available on
  both roles; a non-empty server list with no overlap fails the handshake
  (ADR-0012).
- In-tree TLS 1.3 client with X25519/P-256, the three AEAD suites, and ECDSA
  P-256/P-384, Ed25519, and RSA server-certificate verification. It replaced
  `std.crypto.tls.Client`, which cannot send ALPN. The client rejects
  TLS 1.2-only servers; KeyUpdate is now supported.
- Package tests for ALPN selection and the client/server handshake path.

### Fixed

- `readSome` now waits for a complete TLS record instead of returning 0 when a
  record is split across reads. Peers that close after sending a record could
  otherwise lose the final application data; found during trojan-gfw UDP
  interop. Added a regression test.

### Known limitations

- TLS 1.3 only. X25519 and P-256 ECDHE; no P-384/X25519MLKEM or other groups,
  and HelloRetryRequest is rejected rather than retried.
- No PSK, session resumption, tickets, 0-RTT, TLS 1.2, ECH, record padding, or
  CRL/OCSP revocation checking.
- Server and client credentials are ECDSA P-256 only, with a single
  certificate/key pair; no RSA/Ed25519/P-384 credentials or SNI certificate
  selection.
- Certificate policy still differs from OpenSSL: no-SAN certificates fall back
  to CN, leaf `keyUsage` is not checked, and anchor `pathLen`/`keyUsage` are
  not enforced.
- Client-auth chain validation uses the configured bundle only; a future
  `certificate_authorities` request hint and per-identity policy are out of
  scope.
- Trust-anchor `pathLen`/`keyUsage` and leaf `keyUsage` are still not
  enforced; a CA with `pathLen=0` can sign an intermediate. No TLS alert is
  sent on most handshake failures.
- No external cryptographic audit. Tests: 48 package tests.

## 0.0.1 - 2026-11-19

- Initial release of the first-party TLS package.
- TLS client API over `std.Io.Reader`/`Writer`, with lazy system CA loading.
- In-tree TLS 1.3 server: X25519, AES-128-GCM/SHA-256, ECDSA P-256
  certificates, UUID-agnostic transport API, and `close_notify`.
- `readSome` helper for proxy-style partial reads.
- Package tests for handshake failure, option validation, and a full
  client/server loopback exchange with runtime-generated test certificates.
