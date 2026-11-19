# Trojan example

A standalone example with its own `build.zig` and `build.zig.zon`. It embeds
marmo as a path dependency and exposes both sides of standard Trojan:

- `server`: a Trojan inbound over TLS that forwards directly and can route
  unauthenticated probes to a fallback HTTP server.
- `client`: a SOCKS5 inbound whose outbound is a Trojan client over TLS.

The demo password is public. Change it before using this outside a loopback
test.

## Certificate

The in-tree TLS 1.3 server currently accepts an ECDSA P-256 certificate and a
PEM PKCS#8 or SEC1 private key. For local testing:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 1 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
```

## Run a server

```sh
cd examples/trojan
zig build run -- server \
  --listen 127.0.0.1:14433 \
  --password change-me \
  --cert cert.pem --key key.pem
```

The server accepts Trojan TCP `CONNECT` and UDP `ASSOCIATE` over TLS and
forwards to the implicit `direct` outbound.

## Run a client

```sh
cd examples/trojan
zig build run -- client \
  --listen 127.0.0.1:11080 \
  --server 127.0.0.1:14433 \
  --password change-me \
  --sni localhost --insecure
```

Then point a SOCKS5 client at `127.0.0.1:11080`:

```sh
curl --socks5-hostname 127.0.0.1:11080 http://example.com/
```

The SOCKS5 inbound supports `CONNECT` and `UDP ASSOCIATE`; the Trojan outbound
keeps one UDP association per SOCKS5 association and allows different
destination addresses within it.

`--insecure` skips CA-chain verification for self-signed test certificates;
hostname matching against the certificate remains enabled. For a trusted
certificate, omit `--insecure` and set `--sni` to the certificate name.

## Fallback

Start a local HTTP service, then pass its address to the server:

```sh
python3 -m http.server 18080 --bind 127.0.0.1

zig build run -- server \
  --listen 127.0.0.1:14433 \
  --password change-me \
  --fallback 127.0.0.1:18080 \
  --cert cert.pem --key key.pem
```

A TLS client that does not send a valid Trojan authentication line is relayed
to the fallback service. With the self-signed certificate:

```sh
curl -k https://127.0.0.1:14433/
```

The server's route is `final: direct`, so the fallback target is reached
directly. In a larger configuration, fallback traffic follows the normal
routing rules; see `docs/protocols/trojan.md` and ADR-0011.

Without `--fallback`, an authentication failure closes the connection, which
is observable to an active prober.

## Reference interop (local-only)

Local checks were run against self-hosted Xray-core 26.11.9 and trojan-gfw
1.16.0. Binaries, configs, certificates, and the harness are not committed and
are not part of CI.

| Client | Server | TCP | UDP |
| --- | --- | --- | --- |
| Xray SOCKS | marmo `server` | passed | passed |
| marmo `client` | Xray Trojan inbound | passed | passed |
| trojan-gfw SOCKS | marmo `server` | passed | passed |
| marmo `client` | trojan-gfw server | passed | passed |

Practical notes from the checks:

- The Xray client pins the self-signed certificate:
  `xray tls hash --cert cert.pem` prints the value for
  `pinnedPeerCertSha256`. Xray v26 removed `allowInsecure`.
- trojan-gfw needs `"alpn": []` on both sides because the in-tree TLS 1.3
  server does not negotiate ALPN. The trojan-gfw server also used
  `cipher_tls13: TLS_AES_128_GCM_SHA256`.
- trojan-gfw was run with `verify: false`; the marmo client used `--insecure`.
- trojan-gfw sends UDP ASSOCIATE to `0.0.0.0:0` when the target is the marmo
  server. marmo routes the first datagram, so the association works.
- The checks found and fixed a TLS client bug where a partial TLS record could
  be reported as EOF, losing split trojan-gfw UDP replies. See
  `packages/tls13/src/reader.zig`.

## Notes

- `--listen` defaults to `127.0.0.1:4433` for server mode and
  `127.0.0.1:1080` for client mode.
- `--cert` defaults to `cert.pem`; `--key` defaults to `key.pem`.
- The Trojan inbound and outbound both require TLS in the config schema; this
  example has no plaintext mode.
- Only standard Trojan is implemented. Trojan-Go WebSocket, Mux, and XTLS are
  not supported.
- The in-tree TLS 1.3 server supports X25519, AES-128-GCM/SHA-256, and ECDSA
  P-256 certificates. It has no TLS 1.2, RSA certificates, ALPN, or session
  tickets.
- The authentication prefix and UDP association have no protocol-level idle
  timeout yet; see `docs/security/audit.md` (F-17).
- Both modes block until the process is interrupted. The library does not
  install signal handlers; the example process is terminated with Ctrl-C.
- The example depends on the parent package through `../..`; run it from this
  directory so the path resolves.
- Interop results are recorded above; the reference binaries and harness are
  local-only and not committed.
