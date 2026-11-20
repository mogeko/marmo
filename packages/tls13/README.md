# tls13

TLS for marmo, isolated as a package. It depends only on `std`; it does not
import marmo's `Stream`, `Dialer`, `Endpoint`, routing, or config types.

The package targets TLS 1.3. Both client and server are in-tree on
`std.crypto`, with ALPN, client authentication, X25519/P-256 ECDHE, three AEAD
suites, and KeyUpdate. The client replaced the `std.crypto.tls.Client` backend
because that backend builds a fixed ClientHello and cannot send the ALPN
extension.

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
    alpn_protocols: []const []const u8 = &.{},
    required_alpn: ?[]const u8 = null,
    cipher_suites: []const CipherSuite = &CipherSuite.list,
    client_certificate_chain: []const []const u8 = &.{},
    client_private_key: ?EcdsaP256Sha256.KeyPair = null,
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
    ) error{ Canceled, Closed, HandshakeFailed }!Client;
    pub fn reader(self: *Client) *std.Io.Reader;
    pub fn writer(self: *Client) *std.Io.Writer;
    pub fn negotiatedProtocol(self: *const Client) ?[]const u8;
    pub fn negotiatedCipherSuite(self: *const Client) CipherSuite;
    pub fn keyUpdate(self: *Client, request_update: bool) InitError!void;
    pub fn end(self: *Client) std.Io.Writer.Error!void;
    pub fn eof(self: Client) bool;
    pub fn deinit(self: *Client) void;
};

pub const ServerOptions = struct {
    certificate_chain: []const []const u8,
    private_key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    alpn_protocols: []const []const u8 = &.{},
    cipher_suites: []const CipherSuite = &CipherSuite.list,
    key_exchange_group: ?u16 = null,
    client_auth: ClientAuth = .none,
    client_ca: ?*const std.crypto.Certificate.Bundle = null,
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
    pub fn negotiatedProtocol(self: *const Server) ?[]const u8;
    pub fn negotiatedCipherSuite(self: *const Server) CipherSuite;
    pub fn negotiatedGroup(self: *const Server) u16;
    pub fn keyUpdate(self: *Server, request_update: bool) Error!void;
    pub fn readError(self: *const Server) ?Error;
    pub fn writeError(self: *const Server) ?Error;
    pub fn flush(self: *Server) Error!void;
    pub fn end(self: *Server) Error!void;
    pub fn deinit(self: *Server) void;
};

pub fn readSome(reader: *std.Io.Reader, buffers: [][]u8)
    std.Io.Reader.ShortError!usize;

pub const ClientAuth = enum { none, optional, required };
pub const CipherSuite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,
};

pub fn validateCredentials(
    certificate_chain: []const []const u8,
    private_key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
) Error!void;

pub const min_buffer_len: usize;
```

`input.buffer.len` and `output.buffer.len` must be at least
`min_buffer_len` on the client; plaintext `read_buffer` and `write_buffer`
must be non-empty (4 KiB is a reasonable default). `Client.init` performs the
handshake, including lazy CA loading, certificate verification, and ALPN
selection.
`Client.deinit` zeroizes the session state but does not touch caller-owned
buffers. A client certificate chain and key must be supplied together; the
server requests them only when configured. `Client.keyUpdate` and
`Server.keyUpdate` replace the sending keys, so the caller must serialize them
with any other writer task.

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
`Client`, `Options`, `Ca`, `Server`, `ServerOptions`, `ClientAuth`,
`CipherSuite`, `validateCredentials`, `readSome`, and `min_buffer_len`.

The package also exports `test_cert` (runtime-generated self-signed
certificates; no private key is committed) and the `handshake`/`record` wire
modules. The latter two are used by the root fuzz harness and have no API
stability guarantee.

## Server scope

The server is TLS 1.3 only:

- X25519 and secp256r1 (P-256) key exchange. It selects a group for which the
  client supplied a key share; `key_exchange_group` can pin the preference.
  HelloRetryRequest is not sent.
- `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and
  `TLS_CHACHA20_POLY1305_SHA256`, selected by server preference from the
  client's offer.
- ECDSA P-256/SHA-256 server certificates; the leaf certificate's public key
  must match `private_key`.
- Optional or required client authentication. A CertificateRequest is sent
  when `client_auth` is not `.none`; the client chain is verified against
  `client_ca` with `clientAuth` EKU checks. An empty client Certificate is
  accepted only for `.optional`.
- ALPN: the server selects the first configured protocol the client offered,
  and a non-empty server list with no overlap fails the handshake.
- KeyUpdate is accepted and answered; `Server.keyUpdate` can also initiate one.
  `NewSessionTicket`, PSK, and 0-RTT are not implemented.
- A middlebox-compatibility `change_cipher_spec` is sent after `ServerHello`.
  Incoming dummy CCS records are ignored only while the handshake is still in
  progress; a post-handshake CCS is a protocol error (RFC 8446 §5).
- The server accepts fragmented ClientHello messages up to 16 KiB and
  certificate chains up to 16 KiB after encoding.
- One task may read while another writes, but writes must be serialized by the
  caller; the root adapters use a per-connection write mutex. Read and write
  key updates touch disjoint state, and the pending-update response is atomic.

## Client scope

The client is TLS 1.3 only:

- X25519 and secp256r1 (P-256) ECDHE, with both key shares sent so conforming
  servers do not need HelloRetryRequest.
- All three cipher suites, selected from `Options.cipher_suites`; a server
  selection that was not offered fails the handshake.
- Server certificates using ECDSA P-256/P-384, Ed25519, or RSA with PKCS#1
  v1.5/PSS signatures.
- Certificate-chain verification against the system CA bundle, including
  issuer `basicConstraints CA:TRUE`, `keyUsage keyCertSign`, `pathLenConstraint`,
  DNS name constraints, and leaf EKU; host-name verification through
  `server_name` is independent of chain verification, so `verify = false`
  still pins the host when a name is present.
- Optional client authentication: when the server sends CertificateRequest,
  the client sends its configured chain and `CertificateVerify`, or an empty
  Certificate. The chain itself is validated locally before the handshake.
- ALPN is offered from `Options.alpn_protocols`; a server selection that was
  not offered fails the handshake. `required_alpn` makes a specific selection
  mandatory. `negotiatedProtocol()` returns the result.
- Post-handshake `NewSessionTicket` is ignored. KeyUpdate is accepted,
  updates read keys, and is answered before the next application record;
  `Client.keyUpdate` can initiate one. Post-handshake alerts must be
  encrypted; a plaintext alert is a protocol error.
- A missing `close_notify` is a truncation error unless
  `allow_truncation_attacks` is set; the root adapters default to strict
  handling and map truncation to `ConnectionReset`.
- No PSK, tickets, or 0-RTT; no HelloRetryRequest continuation. Supported
  versions and known extensions are parsed strictly; duplicate known
  extensions fail the handshake.

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

The package tests cover handshake failure mapping, option validation, ALPN
selection (including no overlap), every cipher-suite/key-exchange-group
combination over loopback TCP, client authentication success and failure
policies, KeyUpdate under traffic, and HelloRetryRequest parsing. No private
key is committed; certificates are generated at runtime. The package was also
checked locally against OpenSSL 4.1 `s_server`/`s_client` for each suite and
group in both directions, mTLS in both directions, and KeyUpdate in both
directions; that interop harness is not committed.
