# ws

WebSocket (RFC 6455) for marmo, isolated as a package. It depends only on
`std`; it does not import marmo's `Stream`, `Dialer`, `Endpoint`, or config.

## API

```zig
pub const DeflateOptions = struct {
    enabled: bool = false,
    no_context_takeover: bool = false,
    peer_no_context_takeover: bool = false,
    max_window_bits: u4 = 15,
    peer_max_window_bits: u4 = 15,
};

pub const ClientOptions = struct {
    host: []const u8,
    path: []const u8 = "/",
    subprotocols: []const []const u8 = &.{},
    deflate: DeflateOptions = .{},
};

pub const ServerOptions = struct {
    path: []const u8 = "/",
    subprotocols: []const []const u8 = &.{},
    deflate: DeflateOptions = .{},
};

pub const Connection = struct {
    pub fn read(self: *Connection, buffers: [][]u8) Error!usize;
    pub fn write(self: *Connection, buffers: []const []const u8) Error!usize;
    pub fn end(self: *Connection) Error!void;
    pub fn closeWithCode(self: *Connection, code: u16) Error!void;
    pub fn deinit(self: *Connection) void;
    pub fn selectedSubprotocol(self: *const Connection) ?[]const u8;
    pub fn compressionEnabled(self: *const Connection) bool;
};

pub fn clientHandshake(
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    connection: *Connection,
    options: ClientOptions,
) Error!void;

pub fn serverHandshake(
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    connection: *Connection,
    options: ServerOptions,
) Error!void;
```

The caller owns `input` and `output` and keeps them alive for the connection.
`read` returns 0 after a close frame; `write` sends one binary message per call;
`end` sends close code 1000. Abrupt EOF before a close frame is a protocol
error. `closeWithCode` sends an application policy code (for example 1008) and
stops the connection. `selectedSubprotocol` and `compressionEnabled` expose the
opening-handshake result. The package also exports `handshake`, `frame`,
`Error`, `max_handshake` (8 KiB), `max_read_payload`/`max_message` (1 MiB),
`max_frame_payload` (64 KiB), `max_compressed_message`, and
`max_subprotocol` (64) for fuzzing and adapters.

## Scope

- Client and server opening handshake, bounded to 8 KiB, with
  `Sec-WebSocket-Accept` verification. Bytes after the HTTP terminator stay in
  the reader, so a frame coalesced with the handshake is not lost.
- Subprotocol negotiation (RFC 6455 §4.1/4.2). The client sends
  `Sec-WebSocket-Protocol` from `ClientOptions.subprotocols`; the server selects
  the first of `ServerOptions.subprotocols` that the client offered. A
  non-empty server list rejects a request with no match, and the client rejects
  a selection it did not request. The selected token is available through
  `selectedSubprotocol`.
- `permessage-deflate` (RFC 7692). Both sides offer/accept the extension and its
  `server_no_context_takeover`, `client_no_context_takeover`,
  `server_max_window_bits`, and `client_max_window_bits` parameters. RSV1 is
  accepted only on the first data frame of a compressed message; control and
  continuation frames are never compressed. Decompressed messages are bounded
  at 1 MiB, compressed input at `max_compressed_message`, and an invalid or
  over-large compressed message closes with 1002/1009.
- Binary and text messages, continuation, ping/pong, and close. Text messages
  are validated incrementally across fragments (including a sequence split
  between two frames); invalid UTF-8 closes with 1007. Writes are binary.
- Close codes are validated; invalid codes/reasons get 1002/1007. Messages are
  capped at 1 MiB and 1024 fragments; control frames per read are capped.
- Protocol failures send the correct Close frame (1002, 1007, 1009) without
  blocking behind a data writer: the reader queues the code with a non-blocking
  `tryLock`, and a concurrent writer flushes it at its next frame boundary.
  `closeWithCode` provides 1008 and other application codes.
- Client masking is mandatory and server frames must be unmasked. Reads accept
  a single frame up to the 1 MiB message limit; writes fragment at 64 KiB.
- Handshake parsing is strict: obs-fold, whitespace before the colon, duplicate
  required headers, duplicate/unknown extension parameters, and body-bearing
  upgrades are rejected. The client rejects an extension it did not offer; the
  server declines unknown or unacceptable extension offers.
- One reader and one writer may run concurrently; writes are serialized
  internally. Pongs are best-effort and dropped under writer contention. Close
  state is checked under that lock, so no data or pong is sent after a close,
  and the adapter waits for in-flight operations before releasing memory.

## Memory

Each connection is about 2.5 MiB: a 1 MiB read frame buffer, a 1.125 MiB
compressed-message accumulator, a 64 KiB write scratch, a 64 KiB DEFLATE ring,
a 128 KiB hash table, and a 64 KiB inflater window. The buffers are reserved
even when compression is not negotiated. Lazy allocation of the compression
state is a recorded later optimization; the current design keeps the package
allocator-free and bounded.

The root package wraps this API in `src/transport/ws_{client,server,dialer}.zig`
and composes it with TCP/TLS dialers. The adapter does not inspect TLS ALPN;
when composing over TLS, set `TlsDialer.required_alpn = "http/1.1"` (or the
configured protocol) explicitly. Compression, subprotocols, and close codes are
not wired into `Config`/`Instance` yet; programmatic callers pass the options.

## Tests

```sh
cd packages/ws
zig build test
```
