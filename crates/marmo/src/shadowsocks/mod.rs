//! Shadowsocks 2022 TCP stream adapter.
//!
//! `marmo-proto` owns the wire format; this module sequences it over an async
//! stream: the request/response headers, then length-prefixed chunks. Every
//! read is bounded by the fixed chunk length (at most `u16::MAX`) and every
//! write is capped at one chunk.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use marmo_net::Endpoint;
use marmo_proto::shadowsocks::{
    Key, Method, ServerResponseFixed, SsError, TAG_LENGTH, decode_client_fixed,
    decode_client_variable, decode_server_fixed, decode_server_variable, derive_subkey,
    encode_client_request, encode_server_response, next_counter, nonce_from_counter, open,
    seal_chunk,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

mod udp;

pub(crate) use udp::SsUdpClient;

/// Length of the fixed header before encryption.
const FIXED_HEADER: usize = 11;
/// Length of the length field in front of every chunk payload.
const CHUNK_LENGTH: usize = 2;
/// Largest payload that fits in one chunk.
const MAX_CHUNK: usize = u16::MAX as usize;
/// Longest client padding this adapter emits.
const MAX_PADDING: usize = 64;
/// Largest encoded address: atyp + length + domain + port.
const MAX_ADDRESS: usize = 1 + 1 + 255 + 2;

#[derive(Clone, Copy, Debug)]
enum ReadState {
    /// Client: waiting for the server response header.
    Header,
    /// Client: waiting for the first payload announced by the fixed header.
    ResponseBody,
    /// Waiting for a chunk length.
    ChunkLength,
    /// Waiting for the payload of the chunk whose length was read.
    ChunkBody(usize),
    /// The peer closed at a frame boundary.
    Done,
}

/// A Shadowsocks 2022 client or server stream over an inner async stream.
pub(crate) struct SsStream<S> {
    inner: S,
    method: Method,
    key: Arc<Key>,
    salt_len: usize,
    request_salt: [u8; 32],
    send_key: [u8; 32],
    send_ready: bool,
    send_counter: u64,
    recv_key: [u8; 32],
    recv_counter: u64,
    read_state: ReadState,
    read_buf: Vec<u8>,
    read_len: usize,
    response: Option<ServerResponseFixed>,
    plain: Vec<u8>,
    plain_pos: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    write_accepted: usize,
}

impl<S> SsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Sends a client request for `target` and returns the wrapped stream.
    pub(crate) async fn connect(
        mut inner: S, method: Method, key: Arc<Key>, target: &Endpoint,
    ) -> io::Result<Self> {
        let salt_len = method.salt_len();
        let salt = random_bytes::<32>()?;
        let random = random_bytes::<{ MAX_PADDING + 1 }>()?;
        let padding_len = 1 + (usize::from(random[0]) % MAX_PADDING);
        let mut out =
            vec![
                0_u8;
                salt_len + FIXED_HEADER + TAG_LENGTH + MAX_ADDRESS + 2 + MAX_PADDING + TAG_LENGTH
            ];
        let length = encode_client_request(
            method,
            key.as_bytes(),
            &salt[..salt_len],
            target,
            unix_now(),
            &random[1..=padding_len],
            b"",
            &mut out,
        )
        .map_err(ss_error)?;
        inner.write_all(&out[..length]).await?;
        let send_key = derive_subkey(method, key.as_bytes(), &salt[..salt_len]);

        Ok(Self {
            inner,
            method,
            key,
            salt_len,
            request_salt: salt,
            send_key,
            send_ready: true,
            send_counter: 2,
            recv_key: [0_u8; 32],
            recv_counter: 0,
            read_state: ReadState::Header,
            read_buf: Vec::new(),
            read_len: 0,
            response: None,
            plain: Vec::new(),
            plain_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            write_accepted: 0,
        })
    }

    /// Reads the client request header, returning the requested target.
    pub(crate) async fn accept(
        mut inner: S, method: Method, key: Arc<Key>,
    ) -> io::Result<(Self, Endpoint)> {
        let salt_len = method.salt_len();
        let mut header = vec![0_u8; salt_len + FIXED_HEADER + TAG_LENGTH];
        inner.read_exact(&mut header).await?;
        let fixed =
            decode_client_fixed(method, key.as_bytes(), &header, unix_now()).map_err(ss_error)?;
        let mut variable = vec![0_u8; fixed.variable_len + TAG_LENGTH];
        inner.read_exact(&mut variable).await?;
        let mut plain = vec![0_u8; fixed.variable_len];
        let (target, payload_len) = {
            let (target, payload) =
                decode_client_variable(method, &fixed, &variable, &mut plain).map_err(ss_error)?;
            (target, payload.len())
        };

        let stream = Self {
            inner,
            method,
            key,
            salt_len,
            request_salt: fixed.salt,
            send_key: [0_u8; 32],
            send_ready: false,
            send_counter: 0,
            recv_key: fixed.recv_key,
            recv_counter: 2,
            read_state: ReadState::ChunkLength,
            read_buf: Vec::new(),
            read_len: 0,
            response: None,
            plain,
            plain_pos: fixed.variable_len - payload_len,
            write_buf: Vec::new(),
            write_pos: 0,
            write_accepted: 0,
        };
        Ok((stream, target))
    }

    fn header_len(&self) -> usize {
        self.salt_len + FIXED_HEADER + self.salt_len + TAG_LENGTH
    }

    fn end_read(&mut self) {
        self.read_buf.clear();
        self.read_len = 0;
    }

    /// Reads exactly `need` ciphertext bytes; `false` means a clean EOF.
    fn poll_read_step(&mut self, cx: &mut TaskContext<'_>, need: usize) -> Poll<io::Result<bool>> {
        if self.read_buf.len() != need {
            self.read_buf.clear();
            self.read_buf.resize(need, 0_u8);
            self.read_len = 0;
        }
        while self.read_len < need {
            let Self {
                inner,
                read_buf,
                read_len,
                ..
            } = self;
            let mut buf = ReadBuf::new(&mut read_buf[*read_len..need]);
            match Pin::new(inner).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let filled = buf.filled().len();
                    if filled == 0 {
                        if *read_len == 0 {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated shadowsocks frame",
                        )));
                    }
                    *read_len += filled;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(true))
    }

    /// Fills `plain` with the next chunk, or returns empty at EOF.
    fn poll_fill(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::Done => return Poll::Ready(Ok(())),
                ReadState::Header => {
                    let need = self.header_len();
                    if !ready!(self.poll_read_step(cx, need))? {
                        self.read_state = ReadState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    let fixed = {
                        let Self {
                            method,
                            key,
                            request_salt,
                            salt_len,
                            read_buf,
                            ..
                        } = self;
                        decode_server_fixed(
                            *method,
                            key.as_bytes(),
                            &request_salt[..*salt_len],
                            &read_buf[..need],
                            unix_now(),
                        )
                        .map_err(ss_error)?
                    };
                    self.recv_key = fixed.send_key;
                    self.response = Some(fixed);
                    self.end_read();
                    self.read_state = ReadState::ResponseBody;
                }
                ReadState::ResponseBody => {
                    let Some(first_len) = self.response.as_ref().map(|fixed| fixed.first_len)
                    else {
                        return Poll::Ready(Err(missing_header()));
                    };
                    let need = first_len + TAG_LENGTH;
                    if !ready!(self.poll_read_step(cx, need))? {
                        self.read_state = ReadState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    let mut plain = vec![0_u8; first_len];
                    {
                        let Self {
                            method,
                            response,
                            read_buf,
                            ..
                        } = self;
                        let fixed = response.as_ref().ok_or_else(missing_header)?;
                        decode_server_variable(*method, fixed, &read_buf[..need], &mut plain)
                            .map_err(ss_error)?;
                    }
                    self.response = None;
                    self.recv_counter = 2;
                    self.end_read();
                    self.read_state = ReadState::ChunkLength;
                    self.plain = plain;
                    self.plain_pos = 0;
                    return Poll::Ready(Ok(()));
                }
                ReadState::ChunkLength => {
                    let need = CHUNK_LENGTH + TAG_LENGTH;
                    if !ready!(self.poll_read_step(cx, need))? {
                        self.read_state = ReadState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    let mut length_plain = [0_u8; CHUNK_LENGTH];
                    let counter = next_counter(&mut self.recv_counter).map_err(ss_error)?;
                    open(
                        self.method,
                        &self.recv_key,
                        nonce_from_counter(counter),
                        &self.read_buf[..need],
                        &mut length_plain,
                    )
                    .map_err(ss_error)?;
                    let length = usize::from(u16::from_be_bytes(length_plain));
                    if length == 0 {
                        return Poll::Ready(Err(invalid("empty shadowsocks chunk")));
                    }
                    self.end_read();
                    self.read_state = ReadState::ChunkBody(length);
                }
                ReadState::ChunkBody(length) => {
                    let need = length + TAG_LENGTH;
                    if !ready!(self.poll_read_step(cx, need))? {
                        self.read_state = ReadState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    let mut plain = vec![0_u8; length];
                    let counter = next_counter(&mut self.recv_counter).map_err(ss_error)?;
                    let opened = open(
                        self.method,
                        &self.recv_key,
                        nonce_from_counter(counter),
                        &self.read_buf[..need],
                        &mut plain,
                    )
                    .map_err(ss_error)?;
                    if opened != length {
                        return Poll::Ready(Err(invalid("shadowsocks chunk length mismatch")));
                    }
                    self.end_read();
                    self.read_state = ReadState::ChunkLength;
                    self.plain = plain;
                    self.plain_pos = 0;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    /// Encodes one write as a response header plus payload, or as a chunk.
    fn encode(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write_buf.clear();
        self.write_pos = 0;
        if self.send_ready {
            let mut out = vec![0_u8; CHUNK_LENGTH + TAG_LENGTH + payload.len() + TAG_LENGTH];
            let length = seal_chunk(
                self.method,
                &self.send_key,
                &mut self.send_counter,
                payload,
                &mut out,
            )
            .map_err(ss_error)?;
            out.truncate(length);
            self.write_buf = out;
            return Ok(());
        }

        // The server's first write carries the response header and payload.
        let salt = random_bytes::<32>()?;
        let mut out = vec![
            0_u8;
            self.salt_len
                + FIXED_HEADER
                + self.salt_len
                + TAG_LENGTH
                + payload.len()
                + TAG_LENGTH
        ];
        let length = encode_server_response(
            self.method,
            self.key.as_bytes(),
            &self.request_salt[..self.salt_len],
            &salt[..self.salt_len],
            unix_now(),
            payload,
            &mut out,
        )
        .map_err(ss_error)?;
        out.truncate(length);
        self.send_key = derive_subkey(self.method, self.key.as_bytes(), &salt[..self.salt_len]);
        self.send_counter = 2;
        self.send_ready = true;
        self.write_buf = out;
        Ok(())
    }

    /// Writes pending ciphertext, returning `Pending` once the socket blocks.
    fn poll_flush_pending(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let Self {
                inner,
                write_buf,
                write_pos,
                ..
            } = self;
            match Pin::new(inner).poll_write(cx, &write_buf[*write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "shadowsocks stream closed while writing",
                    )));
                }
                Poll::Ready(Ok(written)) => *write_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for SsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if me.plain_pos == me.plain.len() {
            me.plain.clear();
            me.plain_pos = 0;
            ready!(me.poll_fill(cx))?;
        }
        let available = me.plain.len() - me.plain_pos;
        if available == 0 {
            return Poll::Ready(Ok(()));
        }
        let copied = available.min(buf.remaining());
        buf.put_slice(&me.plain[me.plain_pos..me.plain_pos + copied]);
        me.plain_pos += copied;
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for SsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        loop {
            ready!(me.poll_flush_pending(cx))?;
            if me.write_accepted > 0 {
                let accepted = me.write_accepted;
                me.write_accepted = 0;
                return Poll::Ready(Ok(accepted));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let take = buf.len().min(MAX_CHUNK);
            me.encode(&buf[..take])?;
            me.write_accepted = take;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_flush_pending(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_flush_pending(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// Resolves a configured method and base64 password into a key.
pub(crate) fn credentials(
    method: Option<&str>, password: Option<&str>,
) -> io::Result<(Method, Arc<Key>)> {
    let method = method.and_then(Method::parse).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported shadowsocks method",
        )
    })?;
    let password = password.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing shadowsocks password")
    })?;
    let key = Key::parse(method, password)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid shadowsocks password"))?;
    Ok((method, Arc::new(key)))
}

pub(crate) fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).map_err(|_| io::Error::other("random source unavailable"))?;
    Ok(out)
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn ss_error(error: SsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn missing_header() -> io::Error {
    invalid("missing shadowsocks response header")
}
