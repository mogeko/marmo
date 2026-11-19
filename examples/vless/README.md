# VLESS example

A standalone example with its own `build.zig` and `build.zig.zon`. It embeds
marmo as a path dependency and exposes both sides of VLESS:

- `server`: a VLESS inbound over TLS that forwards directly.
- `client`: a SOCKS5 inbound whose outbound is a VLESS client over TLS.

The demo UUID is public. Generate your own UUID before using this outside a
loopback test.

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
cd examples/vless
zig build run -- server \
  --listen 127.0.0.1:14433 \
  --uuid 00112233-4455-6677-8899-aabbccddeeff \
  --cert cert.pem --key key.pem
```

The server accepts VLESS TCP, simple UDP command `2`, and XUDP command `3`
over TLS.

## Run a client

```sh
cd examples/vless
zig build run -- client \
  --listen 127.0.0.1:11080 \
  --server 127.0.0.1:14433 \
  --uuid 00112233-4455-6677-8899-aabbccddeeff \
  --sni localhost --insecure
```

Add `--xudp` to use XUDP instead of simple UoT:

```sh
zig build run -- client \
  --listen 127.0.0.1:11080 \
  --server 127.0.0.1:14433 \
  --uuid 00112233-4455-6677-8899-aabbccddeeff \
  --sni localhost --insecure --xudp
```

Then point a SOCKS5 client at `127.0.0.1:11080`:

```sh
curl --socks5-hostname 127.0.0.1:11080 http://example.com/
```

`--insecure` skips CA-chain verification for self-signed test certificates;
hostname matching against the certificate remains enabled. For a trusted
certificate, omit `--insecure` and set `--sni` to the certificate name.

Both modes block until the process is interrupted. The library does not install
signal handlers; the example process is terminated with Ctrl-C.

## Reference interop (local-only)

The reference checks use Xray-core. The harness and binaries are not committed
and are not part of CI.

### Xray client -> marmo server

1. Start the marmo example server as above.
2. Start a local HTTP origin:
   `python3 -m http.server 18080 --bind 127.0.0.1`.
3. Run Xray with a SOCKS inbound and a VLESS outbound. Xray v26 removed
   `allowInsecure`; pin the self-signed certificate instead:

```sh
openssl x509 -noout -fingerprint -sha256 -in cert.pem
```

```json
{
  "inbounds": [
    { "tag": "socks", "listen": "127.0.0.1", "port": 11080,
      "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "tag": "vless",
      "protocol": "vless",
      "settings": {
        "vnext": [
          { "address": "127.0.0.1", "port": 14433,
            "users": [{ "id": "00112233-4455-6677-8899-aabbccddeeff",
                        "encryption": "none" }] }
        ]
      },
      "streamSettings": {
        "network": "tcp", "security": "tls",
        "tlsSettings": {
          "serverName": "localhost",
          "pinnedPeerCertSha256": "<sha256 output above>"
        }
      }
    }
  ]
}
```

4. Verify TCP through both layers:

```sh
curl --socks5-hostname 127.0.0.1:11080 http://127.0.0.1:18080/
```

### marmo client -> Xray server

1. Run Xray with a VLESS inbound (TLS) and a freedom outbound:

```json
{
  "inbounds": [
    {
      "tag": "vless-in", "listen": "127.0.0.1", "port": 14434,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "00112233-4455-6677-8899-aabbccddeeff" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp", "security": "tls",
        "tlsSettings": {
          "certificates": [
            { "certificateFile": "cert.pem", "keyFile": "key.pem" }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct", "protocol": "freedom",
      "settings": {
        "finalRules": [
          { "action": "allow", "network": "tcp,udp",
            "ip": ["127.0.0.0/8", "::1/128"] }
        ]
      }
    }
  ]
}
```

   Xray v26 blocks private/loopback targets from proxy inbounds by default.
   The `finalRules` above is only for this local interop setup.

2. Start the marmo example client against port `14434`:

```sh
zig build run -- client \
  --listen 127.0.0.1:11081 \
  --server 127.0.0.1:14434 \
  --uuid 00112233-4455-6677-8899-aabbccddeeff \
  --sni localhost --insecure
```

   Add `--xudp` to exercise XUDP instead of simple UoT.

3. Verify:

```sh
curl --socks5-hostname 127.0.0.1:11081 http://127.0.0.1:18080/
```

## Interop results

Local checks with Xray-core `26.11.9` (not committed, not CI):

- Xray SOCKS client -> marmo VLESS server over TLS -> direct HTTP: passed.
- marmo SOCKS client -> Xray VLESS server over TLS -> direct HTTP: passed.
- marmo UDP client -> Xray VLESS server (simple command `2`): passed.
- marmo UDP client with `--xudp` -> Xray VLESS server (XUDP command `3`):
  passed.
- Xray UDP client -> marmo VLESS server (XUDP command `3`): passed.
- Internal loopback covers both simple UDP and XUDP outbound/inbound.

## Notes

- `--listen` defaults to `127.0.0.1:4433` for server mode and
  `127.0.0.1:1080` for client mode.
- `--cert` defaults to `cert.pem`; `--key` defaults to `key.pem`.
- The VLESS inbound always requires TLS. The outbound defaults to TLS; there is
  no plaintext flag in this example.
- UDP is supported through the same TLS stream. Simple UoT is the default
  outbound encoding; `--xudp` enables XUDP.
- Both simple UDP and XUDP bind one fixed destination per association. XUDP
  cone NAT/GlobalID is not implemented.
- The example depends on the parent package through `../..`; run it from this
  directory so the path resolves.
