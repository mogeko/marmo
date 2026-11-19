# ws

WebSocket (RFC 6455) for marmo, isolated as a package. It depends only on
`std`; it does not import marmo's `Stream`, `Dialer`, `Endpoint`, or config.

## API

```zig
pub const ClientOptions = struct { host: []const u8, path: []const u8 = "/" };
pub const ServerOptions = struct { path: []const u8 = "/" };

pub const Connection = struct {
    pub fn read(self: *Connection, buffers: [][]u8) Error!usize;
    pub fn write(self: *Connection, buffers: []const []const u8) Error!usize;
    pub fn end(self: *Connection) Error!void;
    pub fn deinit(self: *Connection) void;
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
`read` returns 0 after a close frame; `write` sends one binary message per
call; `end` sends close code 1000. Abrupt EOF before a close frame is a
protocol error. The package also exports `handshake`, `frame`, `Error`,
`max_handshake` (8 KiB), and `max_frame_payload` (64 KiB) for fuzzing and
adapters.

## Scope

- Client and server opening handshake, bounded to 8 KiB, with
  `Sec-WebSocket-Accept` verification.
- Binary and text messages, continuation, ping/pong, and close.
- Client masking is mandatory and server frames must be unmasked.
- No extensions (including `permessage-deflate`), redirects, subprotocol
  negotiation, or HTTP authentication.
- One reader and one writer may run concurrently; writes are serialized
  internally, and a pong from the reader shares that lock.

The root package wraps this API in `src/transport/ws_{client,server,dialer}.zig`
and composes it with TCP/TLS dialers.

## Tests

```sh
cd packages/ws
zig build test
```
