# http2

HTTP/2 for marmo, isolated as a package. It depends only on `std` and operates
on `std.Io.Reader`/`Writer`; it does not import marmo's `Stream`, `Dialer`, or
config.

## API

```zig
pub const Header = struct { name: []const u8, value: []const u8 };

pub const Client = struct {
    pub fn init(io: std.Io, input: *std.Io.Reader, output: *std.Io.Writer)
        Error!Client;
    pub fn openStream(self: *Client, headers: []const Header) Error!Stream;
    pub fn stream(self: *Client) ?Stream;
    pub fn deinit(self: *Client) void;
};

pub const Server = struct {
    pub fn init(io: std.Io, input: *std.Io.Reader, output: *std.Io.Writer)
        Error!Server;
    pub fn acceptStream(self: *Server) Error!Stream;
    pub fn headers(self: *const Server) []const Header;
    pub fn stream(self: *Server) ?Stream;
    pub fn deinit(self: *Server) void;
};

pub const Stream = struct {
    pub fn read(self: Stream, buffers: [][]u8) Error!usize;
    pub fn write(self: Stream, buffers: []const []const u8) Error!usize;
    pub fn close(self: Stream) Error!void;
};
```

`Client` sends the connection preface and SETTINGS, completes the SETTINGS
exchange, and opens stream 1. `Server` reads the preface, requires SETTINGS
first, and accepts the first HEADERS frame. The caller sends response headers
through `Client`/`Server` streams at the HTTP/2 layer; the package exposes
`hpack` and `frame` for that wiring and for fuzzing.

## Scope

- HTTP/2 framing, SETTINGS/ACK, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE, and
  CONTINUATION.
- HPACK decoding with static and dynamic tables and RFC 7541 Huffman decoding;
  encoding uses static indices and literals without Huffman.
- One active stream per connection (`MAX_CONCURRENT_STREAMS = 1`), with
  per-stream and connection flow control.
- Bounds: 16 KiB frames, 64 KiB header blocks, 4 KiB HPACK dynamic table,
  1 MiB initial stream window, and a 16 KiB read-ahead buffer.
- Not implemented: server push, PRIORITY effects, HTTP/2-to-HTTP/1.1
  translation, multiple concurrent streams, or a general request router.

`write` may wait for WINDOW_UPDATE; the receive side must be reading frames on
the same connection. The root adapter always runs a read loop concurrently.

## Tests

```sh
cd packages/http2
zig build test
```
