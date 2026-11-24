# Sniffing notes

Sniffing is a routing aid, not a protocol termination. It inspects a bounded
prefix of an inbound stream and extracts a domain for rule matching; the bytes
are then replayed to the relay unchanged.

## Sources consulted

- RFC 8446 §4.1.2: TLS 1.3 `ClientHello`, including the `server_name`
  extension (type 0).
- RFC 7540 §3.5 and §6: the HTTP/2 connection preface, frame header, and
  `HEADERS`/`CONTINUATION` framing.
- RFC 7541: HPACK static table, integer/string representation, dynamic table,
  and Appendix B Huffman codes.
- RFC 7230 §5.4: HTTP/1.1 `Host`.

## Recognised prefixes

| Protocol | Detection | Domain source |
| --- | --- | --- |
| TLS | record type `0x16`, version `0x03xx`, handshake type `0x01` | `server_name` extension, host-name type 0 |
| HTTP/1 | ASCII method token, space, then a complete request head | `Host` header, or an absolute-form request target |
| HTTP/2 | the 24-byte client preface, then frames until the first complete `HEADERS` block | `:authority` (or `host`) |

HTTP/2 is plaintext only. Inside TLS, the sniffer reports the SNI from the
`ClientHello`; it does not decrypt or intercept TLS (that remains a non-goal).

## Bounds and failure behavior

- The peeked prefix is capped at 16 KiB (`SNIFF_MAX`).
- HPACK strings are capped at 8 KiB, the dynamic table at 4096 bytes and 128
  entries, and single HTTP/2 frames at 16 KiB.
- An unrecognised or malformed prefix ends sniffing immediately and replays
  every byte. A prefix that is only plausible as HTTP starts with an uppercase
  ASCII method token; arbitrary binary and line protocols such as SSH are not
  delayed waiting for a request head.
- A truncated prefix waits for more bytes under the inbound handshake deadline.
  A deadline expiry closes the connection; EOF during the peek ends the peek,
  replays the buffered bytes, and continues routing without a sniffed domain.
- An inbound-provided domain (SOCKS5 domain request, HTTP absolute target,
  VLESS/VMess/Trojan target) always wins over a sniffed domain.
- UDP datagrams and Mux.Cool sessions are not sniffed; they are routed on the
  target carried by their own protocol header.

## Proxy replies

SOCKS5 and HTTP `CONNECT` clients wait for a success reply before sending
application bytes, so an inbound with sniffing enabled sends that reply before
the peek. If the sniffed domain then selects `reject` or the outbound cannot
connect, the established tunnel is closed instead of returning a second proxy
error. Inbounds without sniffing keep the usual connect-then-reply order.

## Test vectors

Unit vectors build a synthetic TLS `ClientHello`, HTTP/1 head, and HTTP/2
preface plus `HEADERS` block. The Huffman case uses the RFC 7541 C.4.1 encoding
of `www.example.com`. The fuzz corpus seeds in `fuzz/corpus/sniff/` are the same
synthetic forms; none is a capture of real traffic.
