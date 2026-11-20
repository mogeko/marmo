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

- ALPN negotiation on the client and server. `Options.alpn_protocols`,
  `ServerOptions.alpn_protocols`, and `negotiatedProtocol()` are available on
  both roles; a non-empty server list with no overlap fails the handshake
  (ADR-0012).
- In-tree TLS 1.3 client with X25519, AES-128-GCM/SHA-256, and ECDSA
  P-256/P-384, Ed25519, and RSA server-certificate verification. It replaces
  `std.crypto.tls.Client`, which cannot send ALPN. The client now rejects
  TLS 1.2-only servers and rejects post-handshake KeyUpdate.
- Package tests for ALPN selection and the client/server handshake path.

### Fixed

- `readSome` now waits for a complete TLS record instead of returning 0 when a
  record is split across reads. Peers that close after sending a record could
  otherwise lose the final application data; found during trojan-gfw UDP
  interop. Added a regression test.

### Known limitations

- TLS 1.3 only, with X25519 and `TLS_AES_128_GCM_SHA256`; no AES-256-GCM,
  ChaCha20-Poly1305, secp256r1/secp384r1 key exchange, or HelloRetryRequest.
- No client authentication, PSK, session tickets, 0-RTT, KeyUpdate, TLS 1.2,
  or CRL/OCSP revocation checking.
- Server credentials are ECDSA P-256 only and a single certificate/key pair;
  no RSA/Ed25519/P-384 server keys or SNI certificate selection.
- Certificate policy still differs from OpenSSL: no-SAN certificates fall back
  to CN, leaf `keyUsage` is not checked, and anchor `pathLen`/`keyUsage` are
  not enforced.
- No external cryptographic audit. Tests: 34 package tests.

## 0.0.1 - 2026-11-19

- Initial release of the first-party TLS package.
- TLS client API over `std.Io.Reader`/`Writer`, with lazy system CA loading.
- In-tree TLS 1.3 server: X25519, AES-128-GCM/SHA-256, ECDSA P-256
  certificates, UUID-agnostic transport API, and `close_notify`.
- `readSome` helper for proxy-style partial reads.
- Package tests for handshake failure, option validation, and a full
  client/server loopback exchange with runtime-generated test certificates.
