# ADR-0012: TLS ALPN negotiation

- Status: Accepted (2026-11-19, on direct implementation request)
- Date: 2026-11-19
- Deciders: @mogeko
- Related: ADR-0007, ADR-0010, ADR-0013, ADR-0014

## Context

HTTP/2 and WebSocket-over-TLS transports must agree on an application protocol
before the first byte. `std.crypto.tls.Client` (Zig 0.17.1) builds a fixed
ClientHello and cannot send the `application_layer_protocol_negotiation`
extension (RFC 7301), and the in-tree server explicitly had no ALPN support.
A client that cannot advertise `h2` cannot use HTTP/2 over TLS; a server that
cannot select `h2`/`http/1.1` cannot serve both transports on one port.

The project is std-only, so adding an external TLS library is not an option
(ADR-0007). ADR-0010 already lists replacing the std client with the in-tree
client as follow-up work.

## Decision

Implement ALPN in `packages/tls13` on both client and server, and replace the
std-backed client with the in-tree TLS 1.3 client so the ClientHello is under
our control.

- `Client.Options.alpn_protocols: []const []const u8` advertises the list in
  ClientHello order. `Client.negotiatedProtocol() ?[]const u8` returns the
  server's selection, or null when ALPN was not offered or not selected.
- `ServerOptions.alpn_protocols: []const []const u8` selects the first server
  entry that the client offered. `Server.negotiatedProtocol()` returns it.
  A non-empty server list with no overlap fails the handshake instead of
  silently continuing.
- Protocol names are 1–255 bytes, lists are bounded by the 16 KiB handshake
  limit, and the selected name is copied into connection-owned storage.
- The in-tree client keeps the existing TLS 1.3 scope: X25519,
  AES-128-GCM/SHA-256, server certificates (ECDSA P-256/P-384, Ed25519, RSA),
  certificate and host verification through `Ca`, and `allow_truncation_attacks`.
  It has no client authentication, PSK, tickets, KeyUpdate, or 0-RTT.
- The package API stays compatible; `Client`, `Options`, `Server`, and
  `ServerOptions` gain fields/accessors, not new entry points. Root adapters
  pass ALPN through and expose the negotiated name.

## Alternatives

1. **Keep the std client and skip client ALPN.** HTTP/2 and WebSocket could
   only be used without TLS, or against a non-standard ALPN-less server.
   Rejected: it defeats the transport stack.
2. **Patch or vendor `std.crypto.tls.Client`.** Copying a large std state
   machine into the package adds maintenance and a second TLS implementation
   without a seam. Rejected.
3. **Add a TLS backend flag.** Contradicts ADR-0007's no-optional-backends
   rule. Rejected.
4. **Implement only server-side ALPN now.** Half the transport story; inbound
   and outbound could not share the same primitives. Rejected.

## Consequences

- Positive: one TLS implementation in-tree; ALPN is available to every
  transport; the client no longer depends on a std API that may change.
- Negative: the in-tree client is larger attack surface than the thin std
  wrapper. It is covered by package handshake tests, loopback integration
  tests, and the existing TLS fuzz targets; it is not production-ready before
  external review (`docs/security/audit.md`).
- Behavior change: the client now negotiates TLS 1.3 only, matching the
  server. TLS 1.2-only servers are rejected.
- Tested with in-tree client/server ALPN matrices (match, no overlap, absent)
  and by H2/WS transport tests that require the negotiated name.

## Amendment (2026-11-20, direct implementation request by @mogeko)

The TLS 1.3 scope listed above is extended. This amendment does not change the
ALPN decision; it records the additional negotiated features and their bounds.

- **Client authentication (mTLS).** The client can send a configured ECDSA
  P-256 certificate chain and `CertificateVerify`. The server can send
  `CertificateRequest`, verify the client chain against a configured trust
  bundle, enforce `clientAuth` EKU on the leaf and any constrained CA, and
  apply a `none`/`optional`/`required` policy. An empty client Certificate is
  accepted only under `optional`; `required` fails the handshake.
- **Cipher suites.** `TLS_AES_256_GCM_SHA384` (`0x1302`) and
  `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) join
  `TLS_AES_128_GCM_SHA256`. The transcript hash, HKDF hash, secret length,
  AEAD key length, and Finished length follow the selected suite. The client
  offers its configured preference order; the server picks its first entry
  the client offered and rejects a selection that was not offered.
- **Key exchange groups.** secp256r1 (`0x0017`) joins X25519. The client sends
  both key shares, so a conforming server needs no HelloRetryRequest; the
  server selects a group for which the client supplied a share. A
  HelloRetryRequest is parsed and rejected because this client has already
  offered every group it supports.
- **KeyUpdate.** Both roles accept a peer KeyUpdate, replace the read traffic
  secret and read keys, and answer `update_requested` before the next
  application record. Either role can also send a KeyUpdate, which replaces
  its write secret and write keys. Read and write key state is disjoint; the
  write path stays serialized by the caller, and the pending-response flag is
  atomic so the read path never mutates write keys.
- **Root adapters.** Config gains `tls.client_certificate`/`client_private_key`
  for outbound TLS, and `tls.client_ca`/`tls.client_auth` for inbound TLS.
  Credentials and client CA files load through `tls_credentials.zig`.

Still out of scope: session resumption/PSK/tickets/0-RTT, TLS 1.2,
revocation/OCSP/CRL, ECH, record padding, SNI multi-certificate selection,
RSA/Ed25519 server or client credentials, and external audit.
