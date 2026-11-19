# tls13

TLS for marmo, isolated as a package. It depends only on `std`; it does not
import marmo's `Stream`, `Dialer`, `Endpoint`, routing, or config types.

The package targets TLS 1.3. The initial client backend delegates to
`std.crypto.tls.Client`, which can negotiate TLS 1.2 when a server does not
offer 1.3. The server is an in-tree TLS 1.3 implementation. The in-tree client
will replace the std backend without changing the API below.

## API contract

```zig
pub const Ca = struct {
    pub fn init(gpa: std.mem.Allocator) Ca;
    pub fn ensure(self: *Ca, io: std.Io) error{ Canceled, LoadFailed }!void;
    pub fn deinit(self: *Ca) void;
};

pub const Options = struct {
    server_name: ?[]const u8,
    verify: bool = true,
    ca: ?*Ca = null,
    read_buffer: []u8,
    write_buffer: []u8,
    allow_truncation_attacks: bool = true,
};

pub const Client = struct {
    pub fn init(
        io: std.Io,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        options: Options,
    ) error{ Canceled, HandshakeFailed }!Client;
    pub fn reader(self: *Client) *std.Io.Reader;
    pub fn writer(self: *Client) *std.Io.Writer;
    pub fn end(self: *Client) std.Io.Writer.Error!void;
    pub fn eof(self: Client) bool;
    pub fn deinit(self: *Client) void;
};

pub const ServerOptions = struct {
    certificate_chain: []const []const u8,
    private_key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    read_buffer: []u8,
    write_buffer: []u8,
};

pub const Server = struct {
    pub fn create(
        io: std.Io,
        gpa: std.mem.Allocator,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        options: ServerOptions,
    ) Error!*Server;
    pub fn reader(self: *Server) *std.Io.Reader;
    pub fn writer(self: *Server) *std.Io.Writer;
    pub fn serverName(self: *const Server) ?[]const u8;
    pub fn readError(self: *const Server) ?Error;
    pub fn writeError(self: *const Server) ?Error;
    pub fn flush(self: *Server) Error!void;
    pub fn end(self: *Server) Error!void;
    pub fn deinit(self: *Server) void;
};

pub fn readSome(reader: *std.Io.Reader, buffers: [][]u8)
    std.Io.Reader.ShortError!usize;

pub fn validateCredentials(
    certificate_chain: []const []const u8,
    private_key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
) Error!void;

pub const min_buffer_len: usize;
```

`input.buffer.len` and `output.buffer.len` must be at least
`min_buffer_len` on the client; plaintext `read_buffer` and `write_buffer`
must be non-empty (4 KiB is a reasonable default). `Client.init` performs the
handshake, including lazy CA loading and certificate verification.
`Client.deinit` zeroizes the session state but does not touch caller-owned
buffers.

`Server.create` performs the handshake and returns an allocated `*Server`.
`Server.deinit` zeroizes and frees it. The caller owns `input`, `output`, the
plaintext buffers, the certificate chain, and the private key; keep them alive
through the handshake. `Server.end` sends `close_notify`; `deinit` does not.

`validateCredentials` checks chain bounds, the leaf key algorithm, and that the
key pair matches the leaf. It is used by config loading before a listener
starts. The package API itself is synchronous and unbounded; the root adapters
race handshakes with `handshake_timeout_s` (default 10 seconds).

`readSome` waits for at least one complete TLS record before returning the
plaintext that is currently buffered. This handles records split across reads
and peers that close immediately after sending data. It does not try to fill
the caller's whole buffer, so use it instead of `Reader.readVec` for proxy
streams. The reader must be blocking: a non-blocking reader that returns 0
without EOF can cause the retry loop to spin. It returns 0 on clean end of
stream.

A replacement package must provide the same exports and semantics:
`Client`, `Options`, `Ca`, `Server`, `ServerOptions`, `validateCredentials`,
`readSome`, and `min_buffer_len`.

The package also exports `test_cert` (runtime-generated self-signed
certificates; no private key is committed) and the `handshake`/`record` wire
modules. The latter two are used by the root fuzz harness and have no API
stability guarantee.

## Server scope

The server is TLS 1.3 only:

- X25519 key exchange; no HelloRetryRequest.
- `TLS_AES_128_GCM_SHA256` only.
- ECDSA P-256/SHA-256 server certificates; the leaf certificate's public key
  must match `private_key`.
- No client authentication, PSK, session tickets, ALPN selection, 0-RTT, or
  KeyUpdate. Post-handshake handshake messages are rejected.
- A middlebox-compatibility `change_cipher_spec` is sent after `ServerHello`.
  Incoming dummy CCS records are ignored only while the handshake is still in
  progress; a post-handshake CCS is a protocol error (RFC 8446 §5).
- The server accepts fragmented ClientHello messages up to 16 KiB and
  certificate chains up to 16 KiB after encoding.
- One task may read while another writes, but writes must be serialized by the
  caller; the root adapters use a per-connection write mutex.

## Replacement

The root package consumes `tls13` as a path dependency:

```zig
// build.zig.zon
.dependencies = .{
    .tls13 = .{ .path = "packages/tls13" },
},
```

To replace the backend, point that dependency at another package (or swap the
single `@import("tls13")` in the root adapters). There is no runtime or
build-flag backend selection; ADR-0007 forbids optional backends. The adapters
in the root package are the only places that know about marmo's `Stream`.

## Tests

```sh
cd packages/tls13
zig build test
```

The package tests cover handshake failure mapping, option validation, and a
full TLS 1.3 client/server exchange over loopback TCP with a runtime-generated
self-signed ECDSA certificate. No private key is committed. The server was also
checked locally against `openssl s_client` (handshake, echo, and close); that
harness is not committed.
