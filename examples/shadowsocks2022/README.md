# Shadowsocks 2022 example

A standalone example with its own `build.zig` and `build.zig.zon`. It embeds
marmo as a path dependency and exposes both sides of SIP022:

- `server`: an SS2022 inbound that forwards directly.
- `client`: a SOCKS5 inbound whose outbound is an SS2022 client.

The demo PSK is public. Generate your own base64 key before using this outside
a loopback test:

```sh
openssl rand -base64 16   # 2022-blake3-aes-128-gcm
openssl rand -base64 32   # 2022-blake3-aes-256-gcm
```

## Run a server

```sh
cd examples/shadowsocks2022
zig build run -- server \
  --listen 127.0.0.1:8388 \
  --method 2022-blake3-aes-128-gcm \
  --password "$(openssl rand -base64 16)"
```

## Run a client

Use the same method and password as the server:

```sh
cd examples/shadowsocks2022
zig build run -- client \
  --listen 127.0.0.1:1080 \
  --server 127.0.0.1:8388 \
  --method 2022-blake3-aes-128-gcm \
  --password "<same base64 key>"
```

Then point a SOCKS5 client at `127.0.0.1:1080`:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://example.com/
```

Both modes block until the process is interrupted. The library does not install
signal handlers; the example process is terminated with Ctrl-C.

## Notes

- `--listen` defaults to `127.0.0.1:8388` for server mode and
  `127.0.0.1:1080` for client mode.
- `--method` defaults to `2022-blake3-aes-128-gcm`.
- `--password` defaults to the public test key; never use it in production.
- The example depends on the parent package through `../..`; run it from this
  directory so the path resolves.
