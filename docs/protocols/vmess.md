# VMess

Sources: the V2Fly VMess specification
(<https://www.v2fly.org/developer/protocols/vmess.html>) and the VMess AEAD
design note (<https://github.com/v2fly/v2fly-github-io/issues/20>), both
consulted 2026-11-22. Behavior that the specifications leave ambiguous was
resolved against a local Xray 26.11.9 peer and is marked "observed" below.

## Implemented

- VMess AEAD header authentication only. The legacy MD5 + AES-128-CFB header is
  rejected: there is no downgrade and no fallback.
- Body ciphers AES-128-GCM (`0x03`) and ChaCha20-Poly1305 (`0x04`). Legacy CFB
  (`0x01`), None (`0x05`), and Zero (`0x06`) are rejected with typed errors.
- TCP (`0x01`), direct UDP (`0x02`), and Mux.Cool (`0x03`) request commands. The
  inbound terminates Mux.Cool TCP and UDP sessions; the outbound uses direct
  UDP and does not pool Mux connections.
- Transports: TCP, TLS 1.3, WebSocket, and HTTP/2 through the ADR-0016
  `transport` object. The inbound requires TLS for ws/h2; plain TCP is allowed.
- One UUID per listener, matching the VLESS inbound. No multi-user, alterId,
  dynamic-port, or legacy-header options are exposed.
- A bounded replay filter keyed by the encrypted auth ID (120 s, 4,096 entries
  per inbound, insertion only after authentication).
- The 16-bit chunk counter is closed after 65,536 chunks per direction (about
  1 GiB at the maximum chunk size) so a GCM nonce cannot repeat.

## Key schedule

```text
CmdKey = MD5(uuid ++ "c48619fe-8f02-49e0-b9e9-edf763e17e21")

H0(y)  = HMAC-SHA256("VMess AEAD KDF", y)
Hn(y)  = H(n-1)(opad || H(n-1)(ipad || y))   with the path item as HMAC key
KDF(key, path...) = H(len(path))(key)         where path items are the keys
```

`KDF` nests the previous HMAC as the next HMAC's hash function; it is **not** a
chain of HMAC keys. A plain keyed chain does not interoperate. Path items are
the ASCII labels below, the auth ID, and the connection nonce.

- `AES Auth ID Encryption`
- `VMess Header AEAD Key_Length`, `VMess Header AEAD Nonce_Length`
- `VMess Header AEAD Key`, `VMess Header AEAD Nonce`
- `AEAD Resp Header Len Key`, `AEAD Resp Header Len IV`
- `AEAD Resp Header Key`, `AEAD Resp Header IV`

MD5 appears only in the spec-mandated `CmdKey` derivation; the AEAD tags
provide integrity.

## Request

```text
[16B EAuID][18B encrypted length][8B connection nonce][N+16B instruction]
```

### EAuID

Plaintext: `[8B Unix seconds, big-endian][4B random][4B CRC32 IEEE of the
first 12 bytes]`, encrypted as one AES-128-ECB block with
`KDF(CmdKey, "AES Auth ID Encryption")[:16]`.

The receiver decrypts the block, verifies CRC32, and accepts a timestamp within
120 seconds of its own clock. It does not need to search a set of candidate
timestamps; a random block has a negligible chance of passing.

### Encrypted length and instruction

`ELength` is the two-byte big-endian instruction length sealed with AES-128-GCM:

- key `KDF(CmdKey, "VMess Header AEAD Key_Length", EAuID, nonce)[:16]`
- nonce `KDF(CmdKey, "VMess Header AEAD Nonce_Length", EAuID, nonce)[:12]`
- associated data `EAuID`

The instruction is sealed the same way with the `Key`/`Nonce` labels. The
nonce is the eight-byte connection nonce. The instruction length is rejected
above 317 bytes before decryption.

### Instruction

| Field | Size | Notes |
| --- | --- | --- |
| Version | 1 | `0x01` |
| Request body IV | 16 | random |
| Request body key | 16 | random |
| Response auth value | 1 | echoed in the response header |
| Option | 1 | `S=0x01`, `R=0x02`, `M=0x04`, `P=0x08`, `A=0x10` |
| Padding length / security | 1 | high nibble padding, low nibble cipher |
| Reserved | 1 | must be `0` |
| Command | 1 | TCP `1`, UDP `2`, Mux `3` |
| Port | 2 | big-endian; omitted for Mux |
| Address | 1+N | type, address; omitted for Mux |
| Padding | 0..15 | cover bytes |
| Checksum | 4 | FNV-1a 32 over all preceding bytes, big-endian |

For the Mux command the port and address are absent; the instruction ends after
the command byte, then the padding and checksum. The synthetic target is
`v1.mux.cool` (Xray writes no port/address; its server substitutes
`v1.mux.cool`).

We require the `S` option, implement `M`, and require `P` to be accompanied by
`M`. The deprecated `R` bit is ignored because it does not change framing.
`A` (authenticated length) and the reserved `X` bits are rejected. The `P`
nibble counts padding bytes; the chunk padding length is separate.

Xray 26.11.9 sends the option byte `0x0d` (`S|M|P`) for both TCP and Mux.

## Response

The response key and IV are derived from the request body material:

```text
response key = SHA256(request body key)[:16]
response IV  = SHA256(request body IV)[:16]
```

The response header is four bytes of plaintext `[response auth value, 0, 0,
0]`. A two-byte length (the total header plaintext length, observed as `4`) is
sealed with AES-128-GCM using
`KDF(response key, "AEAD Resp Header Len Key")[:16]` and
`KDF(response IV, "AEAD Resp Header Len IV")[:12]`, with no associated data.
The four-byte plaintext is sealed with `AEAD Resp Header Key`/`IV`.

The client validates the auth value and requires command `0` and command length
`0`; dynamic-port instructions are rejected.

## Body chunks

```text
[2B length][ciphertext][padding]
```

- `length` is the total chunk length including the tag and padding, masked when
  `M` is set.
- The ciphertext is `plaintext ++ 16B tag`; the tag is not separate framing.
- Padding is 0..63 bytes; its length comes from the mask stream when `P` is set.
- The AEAD nonce is `count (2B big-endian) ++ body IV[2..12]`, with `count`
  starting at `0` in each direction.
- AES-128-GCM uses the 16-byte body key. ChaCha20-Poly1305 uses
  `MD5(key) ++ MD5(MD5(key))`.

Masking consumes the SHAKE128 stream in this order, observed in Xray 26.11.9:

1. two bytes for the padding length (`% 64`) when `P` is set;
2. two bytes XORed with the wire length.

Padding bytes are random and are not drawn from the mask stream; the receiver
only needs the padding count. Getting the order or the padding-byte consumption
wrong desynchronizes the mask and breaks authentication.

The response direction uses the same framing with the response key, IV, and a
fresh mask stream over the response IV.

## UDP

The UDP command names one target in the request header. Each chunk carries one
datagram in each direction; empty chunks are skipped. The association has one
fixed target, matching VLESS simple UoT.

Xray 26.11.9 clients send UDP through Mux.Cool by default (the "cone"
optimization): a Mux request whose New frame carries the UDP target and data.
The inbound supports both direct UDP and Mux.

## Mux.Cool

```text
[2B metadata length][metadata][2B data length][data]
```

Metadata starts with a 2-byte session id, a status, and an option byte. A target
(network `1` TCP or `2` UDP, port, address) follows for New and for targeted
Keep frames. A New frame may end with eight GlobalID bytes (XUDP); they are
accepted and ignored. The data-length field is present only when the data option
(`0x01`) is set.

| Status | Meaning |
| --- | --- |
| `1` | New session; target required |
| `2` | Keep; data for an existing session, optional UDP target |
| `3` | End; closes the session |
| `4` | Keep-alive; no data |

Session `0` is used by Xray's XUDP UDP sessions; a New frame with session `0`
is accepted. Keep-alives also use session `0`. Duplicate New ids close the
physical connection.

Bounds: 128 sessions per physical connection, a 16-frame uplink queue per
session, 64 KiB data per frame, 512-byte metadata, and the instance idle
timeout on the physical connection. A UDP session may change its destination
on Keep; replies carry the source address.

## Limits and known gaps

- Legacy MD5/CFB, body None/Zero, and the authenticated-length option are not
  implemented.
- Client-side Mux.Cool pooling is not implemented; the outbound opens one
  physical connection per stream or UDP association using direct UDP.
- One UUID per listener. No multi-user, alterId, dynamic port, or request
  addons.
- A body direction is closed after 65,536 chunks (about 1 GiB at the maximum
  chunk size) to prevent nonce reuse.
- `SessionHistory` (reference reuse tracking keyed by body key/IV) is not
  implemented; the auth-ID replay filter covers request replay.
- No anti-probing response on authentication failure: the connection is closed.

## Config example

```json
{
  "inbounds": [
    {
      "tag": "vmess-in",
      "protocol": "vmess",
      "listen": "0.0.0.0:443",
      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
      "tls": { "certificate": "...", "private_key": "..." },
      "transport": { "network": "ws", "path": "/vmess" }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vmess",
      "server": "example.com:443",
      "uuid": "00112233-4455-6677-8899-aabbccddeeff",
      "security": "aes-128-gcm",
      "tls": { "sni": "cdn.example.com" },
      "transport": { "network": "ws", "path": "/vmess" }
    }
  ],
  "route": { "final": "proxy" }
}
```

## Tests

- Unit vectors: KDF outputs for one- and three-item paths; EAuID
  round-trip and window rejection; instruction round-trip for TCP, UDP, and
  Mux; response round-trip; chunk round-trip for both ciphers with masking,
  padding, and every read split; tamper and truncation rejection; checksum
  vectors (CRC32 `123456789` → `0xCBF43926`, FNV-1a of empty input).
- Loopback: TCP, TLS, WebSocket, and HTTP/2 through `Instance`; AES-128-GCM and
  ChaCha20-Poly1305; direct UDP; Mux TCP and UDP sessions; replay and bad-UUID
  rejection.
- Reference interop with Xray 26.11.9: marmo outbound to Xray over TCP and
  WebSocket (TCP and UDP); Xray to marmo inbound over TCP (TCP and UDP), with
  mux disabled and enabled. The mux-enabled client exercised XUDP session `0`.
- Synthetic request, chunk, response, and Mux corpus files live in
  `fuzz/corpus/vmess/`; the `vmess` target runs under `cargo +nightly fuzz
  run`.
