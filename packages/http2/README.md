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
    pub fn closeGracefully(self: *Client) Error!void;
    pub fn deinit(self: *Client) void;
};

pub const Server = struct {
    pub fn init(io: std.Io, input: *std.Io.Reader, output: *std.Io.Writer)
        Error!Server;
    pub fn initWithOptions(io: std.Io, input: *std.Io.Reader,
        output: *std.Io.Writer, options: ServerOptions) Error!Server;
    pub fn acceptStream(self: *Server) Error!Stream;
    pub fn headers(self: *Server) []const Header;
    pub fn stream(self: *Server) ?Stream;
    pub fn closeGracefully(self: *Server) Error!void;
    pub fn deinit(self: *Server) void;
};

pub const Stream = struct {
    pub fn read(self: Stream, buffers: [][]u8) Error!usize;
    pub fn write(self: Stream, buffers: []const []const u8) Error!usize;
    pub fn close(self: Stream) Error!void;
    pub fn cancel(self: Stream) void;
    pub fn reset(self: Stream, error_code: u32) Error!void;
    pub fn sendHeaders(self: Stream, headers: []const Header,
        end_stream: bool) Error!void;
    pub fn sendTrailers(self: Stream, headers: []const Header) Error!void;
    pub fn headers(self: Stream) []const Header;
    pub fn trailers(self: Stream) []const Header;
    pub fn informationalStatus(self: Stream) u16;
};
```

`Client` sends the connection preface and SETTINGS, completes the SETTINGS
exchange, and then allows repeated `openStream` calls. `Server` reads the
preface, requires SETTINGS first, and allows repeated `acceptStream` calls.
Each stream is a duplex byte stream over DATA frames. `:status` response
headers, informational (1xx) responses, and trailers are exposed separately:
`headers()` is the initial request/response block, `trailers()` is the second
HEADERS block, and `informationalStatus()` is the last 1xx `:status` (0 if
none).

API changes from 0.0.1:

- `MAX_CONCURRENT_STREAMS` is now the real bound: 16 concurrent streams per
  connection instead of one.
- `stream()` returns the most recently opened or accepted stream; callers that
  need several streams keep the handles returned by `openStream` /
  `acceptStream`.
- `Server.headers()` returns the headers of the most recently accepted stream;
  use `Stream.headers()` for a specific stream.
- A second HEADERS block is no longer rejected; it is decoded as trailers.
- `closeGracefully()` sends GOAWAY with `NO_ERROR` and stops new streams;
  `Stream.close()` is a per-stream half-close.

## Scope

- HTTP/2 framing, SETTINGS/ACK, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE,
  CONTINUATION, and unknown-frame ignoring.
- Multiplexing with a fixed 16-entry stream table, odd/even stream ids,
  OPEN/HALF_CLOSED/CLOSED transitions, per-stream header and DATA storage, and
  a frame pump that demultiplexes frames for concurrent readers.
- HPACK decoding with static and dynamic tables and RFC 7541 Huffman decoding;
  encoding uses static indices and literals without Huffman or dynamic-table
  insertion. The decoder enforces the RFC 9113 32-byte-per-entry header-list
  accounting and the advertised `MAX_HEADER_LIST_SIZE` (8 KiB).
- Per-stream and connection flow control in both directions. Receive windows
  are 8 KiB per stream and 128 KiB per connection; WINDOW_UPDATE is sent when
  data is consumed, padding is credited on receipt, and violations send
  `FLOW_CONTROL_ERROR` in GOAWAY.
- Strict header validation: pseudo-header order/uniqueness and known names,
  lowercase token field names, forbidden connection-specific fields, `TE:
  trailers` only, request/response/CONNECT rules, and trailer blocks without
  pseudo-headers and with END_STREAM.
- Graceful close and local protocol errors send GOAWAY; stream errors send
  RST_STREAM and leave the connection usable. Frame/header/DATA buffers and
  the HPACK table are zeroized on deinit and on stream abort/reuse.
- Bounds: 16 KiB frames, 64 KiB raw header blocks (16 continuation frames),
  8 KiB header lists, 4 KiB HPACK dynamic table, and fixed stream storage. No
  per-connection allocator and no allocation on the data path.

Not implemented: server push and PRIORITY effects, HTTP/1.1 upgrade/h2c,
HTTP/2 WebSocket, connection pooling, HPACK encoder Huffman/dynamic-table
insertion, and gRPC message framing (application-level). VLESS config can select
the H2 transport (ADR-0016), but the root `Instance` currently serves one stream
per H2 connection; the package multiplexer remains available to programmatic
callers.

`write` may wait for WINDOW_UPDATE. When it does, it pumps incoming frames
itself, so a single-threaded embedder does not need a separate reader; DATA for
the same stream stays queued in the bounded receive buffer. The root adapter
still runs a read loop concurrently.

## Tests

```sh
cd packages/http2
zig build test
```

The suite includes multi-stream interleaving, per-stream flow control, 1xx
plus trailers, SETTINGS deltas, GOAWAY/RST behavior, strict header validation,
and a bounded stateful frame-pump smoke test. Differential checks against
Python `h2` 4.4.1 / `hpack` 4.2.0 and curl 8.7.1 (nghttp2 1.69.0) were run
locally; the harness is not committed.
