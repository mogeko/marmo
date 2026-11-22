//! VMess stream adapters and the inbound replay filter.
//!
//! `ChunkStream` turns the VMess chunked body into an `AsyncRead`/`AsyncWrite`
//! stream. `ChunkReader`/`ChunkWriter` expose datagram boundaries for the UDP
//! command and for Mux.Cool framing.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use marmo_proto::vmess::{
    AUTH_ID_LEN, CHUNK_PLAINTEXT_MAX, CHUNK_WIRE_MAX, ChunkDecoder, ChunkEncoder, ChunkProgress,
    Request, ResponseProgress, TIMESTAMP_WINDOW_S, VmessError, response_keys, response_progress,
};
use marmo_transport::BoxStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Bytes requested from the stream per read.
const READ_CHUNK: usize = 8 * 1024;
/// Largest encrypted buffer kept while a chunk is incomplete.
const MAX_READ_BUFFER: usize = CHUNK_WIRE_MAX + READ_CHUNK;
/// Accepted auth IDs retained for the replay window.
const REPLAY_CAPACITY: usize = 4_096;

/// Reads encrypted VMess bytes and exposes decrypted bytes.
pub(crate) struct ChunkStream {
    inner: BoxStream,
    decoder: ChunkDecoder,
    encoder: ChunkEncoder,
    response: Option<Request>,
    read_buf: Vec<u8>,
    filled: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    pending: Vec<u8>,
    pending_pos: usize,
    pending_plain: usize,
}

impl ChunkStream {
    /// Wraps a server-side stream: the response header has already been sent.
    pub(crate) fn server(
        inner: BoxStream, request: &Request, padding_source: [u8; 64], prefix: &[u8],
    ) -> Self {
        let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
        let decoder = ChunkDecoder::new(
            request.security,
            &request.body_key,
            &request.body_iv,
            request.option,
        );
        let encoder = ChunkEncoder::new(
            request.security,
            &response_key,
            &response_iv,
            request.option,
            padding_source,
        );
        Self::new(inner, decoder, encoder, None, prefix)
    }

    /// Wraps a client-side stream: the response header is read lazily.
    pub(crate) fn client(
        inner: BoxStream, request: Request, padding_source: [u8; 64], prefix: &[u8],
    ) -> Self {
        let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
        let decoder = ChunkDecoder::new(
            request.security,
            &response_key,
            &response_iv,
            request.option,
        );
        let encoder = ChunkEncoder::new(
            request.security,
            &request.body_key,
            &request.body_iv,
            request.option,
            padding_source,
        );
        Self::new(inner, decoder, encoder, Some(request), prefix)
    }

    fn new(
        inner: BoxStream, decoder: ChunkDecoder, encoder: ChunkEncoder, response: Option<Request>,
        prefix: &[u8],
    ) -> Self {
        let mut read_buf = vec![0_u8; prefix.len().max(READ_CHUNK)];
        read_buf[..prefix.len()].copy_from_slice(prefix);
        Self {
            inner,
            decoder,
            encoder,
            response,
            read_buf,
            filled: prefix.len(),
            plain: Vec::new(),
            plain_pos: 0,
            pending: Vec::new(),
            pending_pos: 0,
            pending_plain: 0,
        }
    }

    fn consume(&mut self, count: usize) {
        self.read_buf.copy_within(count..self.filled, 0);
        self.filled -= count;
    }

    fn fill_or_pending(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<bool>> {
        if self.filled == self.read_buf.len() {
            if self.read_buf.len() >= MAX_READ_BUFFER {
                return Poll::Ready(Err(invalid("VMess read buffer is full")));
            }
            let length = (self.read_buf.len() * 2).min(MAX_READ_BUFFER);
            self.read_buf.resize(length, 0);
        }
        let start = self.filled;
        let mut read = ReadBuf::new(&mut self.read_buf[start..]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let read = read.filled().len();
                self.filled += read;
                Poll::Ready(Ok(read != 0))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn finish_pending(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess stream closed while writing",
                    )));
                }
                Poll::Ready(Ok(written)) => self.pending_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for ChunkStream {
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.plain_pos < me.plain.len() {
                let count = buf.remaining().min(me.plain.len() - me.plain_pos);
                buf.put_slice(&me.plain[me.plain_pos..me.plain_pos + count]);
                me.plain_pos += count;
                return Poll::Ready(Ok(()));
            }
            if let Some(request) = me.response.as_ref() {
                match response_progress(&me.read_buf[..me.filled], request) {
                    ResponseProgress::Complete { consumed } => {
                        me.consume(consumed);
                        me.response = None;
                        continue;
                    }
                    ResponseProgress::Invalid => {
                        return Poll::Ready(Err(invalid("invalid VMess response header")));
                    }
                    ResponseProgress::NeedMore { .. } => match me.fill_or_pending(cx) {
                        Poll::Ready(Ok(true)) => continue,
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(truncated("VMess response header")));
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    },
                }
            }
            match me.decoder.progress(&me.read_buf[..me.filled]) {
                Ok(ChunkProgress::Complete { consumed, data }) => {
                    me.consume(consumed);
                    me.plain = data;
                    me.plain_pos = 0;
                    continue;
                }
                Ok(ChunkProgress::NeedMore { .. }) => match me.fill_or_pending(cx) {
                    Poll::Ready(Ok(true)) => continue,
                    Poll::Ready(Ok(false)) => {
                        if me.filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(truncated("VMess chunk")));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                },
                Err(error) => return Poll::Ready(Err(chunk_error(error))),
            }
        }
    }
}

impl AsyncWrite for ChunkStream {
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.pending_pos < me.pending.len() {
            match me.finish_pending(cx) {
                Poll::Ready(Ok(())) => {
                    let accepted = me.pending_plain;
                    me.pending_plain = 0;
                    return Poll::Ready(Ok(accepted));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = buf.len().min(CHUNK_PLAINTEXT_MAX);
        if let Err(error) = me.encoder.encode(&buf[..count], &mut me.pending) {
            return Poll::Ready(Err(chunk_error(error)));
        }
        me.pending_plain = count;
        match me.finish_pending(cx) {
            Poll::Ready(Ok(())) => {
                me.pending_plain = 0;
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pending_pos < me.pending.len() {
            match me.finish_pending(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pending_pos < me.pending.len() {
            match me.finish_pending(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// Reads one datagram per chunk from a split VMess stream.
pub(crate) struct ChunkReader<R> {
    inner: R,
    decoder: ChunkDecoder,
    buffer: Vec<u8>,
    filled: usize,
    response: Option<Request>,
}

impl<R: AsyncRead + Unpin> ChunkReader<R> {
    /// Starts a reader, treating `prefix` as bytes already read.
    pub(crate) fn new(inner: R, decoder: ChunkDecoder, prefix: &[u8]) -> Self {
        let mut buffer = vec![0_u8; prefix.len().max(READ_CHUNK)];
        buffer[..prefix.len()].copy_from_slice(prefix);
        Self {
            inner,
            decoder,
            buffer,
            filled: prefix.len(),
            response: None,
        }
    }

    /// Starts a client-side reader that validates the response header before
    /// the first chunk.
    pub(crate) fn with_response(
        inner: R, decoder: ChunkDecoder, prefix: &[u8], request: Request,
    ) -> Self {
        let mut reader = Self::new(inner, decoder, prefix);
        reader.response = Some(request);
        reader
    }

    /// Reads the next datagram, or `None` at a clean end of stream.
    pub(crate) async fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(request) = self.response.take() {
            let leftover = read_response_header(&mut self.inner, &request).await?;
            self.prepend(&leftover);
        }
        loop {
            match self.decoder.progress(&self.buffer[..self.filled]) {
                Ok(ChunkProgress::Complete { consumed, data }) => {
                    self.buffer.copy_within(consumed..self.filled, 0);
                    self.filled -= consumed;
                    return Ok(Some(data));
                }
                Ok(ChunkProgress::NeedMore { .. }) => {
                    if !self.fill().await? {
                        return if self.filled == 0 {
                            Ok(None)
                        } else {
                            Err(truncated("VMess chunk"))
                        };
                    }
                }
                Err(error) => return Err(chunk_error(error)),
            }
        }
    }

    fn prepend(&mut self, prefix: &[u8]) {
        if prefix.is_empty() {
            return;
        }
        let needed = self.filled + prefix.len();
        if needed > self.buffer.len() {
            self.buffer.resize(needed, 0);
        }
        self.buffer.copy_within(0..self.filled, prefix.len());
        self.buffer[..prefix.len()].copy_from_slice(prefix);
        self.filled = needed;
    }

    async fn fill(&mut self) -> io::Result<bool> {
        if self.filled == self.buffer.len() {
            if self.buffer.len() >= MAX_READ_BUFFER {
                return Err(invalid("VMess read buffer is full"));
            }
            let length = (self.buffer.len() * 2).min(MAX_READ_BUFFER);
            self.buffer.resize(length, 0);
        }
        let start = self.filled;
        let read = self.inner.read(&mut self.buffer[start..]).await?;
        self.filled += read;
        Ok(read != 0)
    }
}

/// Writes one datagram per chunk to a split VMess stream.
pub(crate) struct ChunkWriter<W> {
    inner: W,
    encoder: ChunkEncoder,
    pending: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> ChunkWriter<W> {
    /// Wraps a write half with the direction's chunk encoder.
    pub(crate) fn new(inner: W, encoder: ChunkEncoder) -> Self {
        Self {
            inner,
            encoder,
            pending: Vec::new(),
        }
    }

    /// Encodes and flushes one datagram.
    pub(crate) async fn write(&mut self, payload: &[u8]) -> io::Result<()> {
        self.encoder
            .encode(payload, &mut self.pending)
            .map_err(chunk_error)?;
        self.inner.write_all(&self.pending).await?;
        self.inner.flush().await
    }
}

/// Bounded replay filter keyed by the encrypted auth ID.
pub(crate) struct ReplayFilter {
    entries: HashMap<[u8; AUTH_ID_LEN], u64>,
    order: VecDeque<([u8; AUTH_ID_LEN], u64)>,
}

impl ReplayFilter {
    /// Builds an empty filter.
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Inserts `auth_id` and returns false when it was already present.
    ///
    /// Entries older than the timestamp window are evicted first; when the
    /// table is full the oldest entry is dropped.
    pub(crate) fn check_and_insert(&mut self, auth_id: [u8; AUTH_ID_LEN], now: u64) -> bool {
        while let Some((old, time)) = self.order.front() {
            if now.saturating_sub(*time) > TIMESTAMP_WINDOW_S {
                let old = *old;
                self.entries.remove(&old);
                self.order.pop_front();
            } else {
                break;
            }
        }
        if self.entries.contains_key(&auth_id) {
            return false;
        }
        if self.entries.len() >= REPLAY_CAPACITY
            && let Some((old, _)) = self.order.pop_front()
        {
            self.entries.remove(&old);
        }
        self.entries.insert(auth_id, now);
        self.order.push_back((auth_id, now));
        true
    }
}

/// Returns the current Unix time in seconds.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Fills a fixed-size buffer from the operating system RNG.
pub(crate) fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).map_err(|_| io::Error::other("random source unavailable"))?;
    Ok(out)
}

pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn truncated(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, format!("{what} is truncated"))
}

fn chunk_error(error: VmessError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Reads and validates a response header, returning any bytes read past it.
pub(crate) async fn read_response_header(
    inner: &mut (impl AsyncRead + Unpin), request: &Request,
) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(64);
    let mut chunk = [0_u8; 256];
    loop {
        match response_progress(&buffer, request) {
            ResponseProgress::Complete { consumed } => {
                buffer.drain(..consumed);
                return Ok(buffer);
            }
            ResponseProgress::Invalid => {
                return Err(invalid("invalid VMess response header"));
            }
            ResponseProgress::NeedMore { needed } => {
                let want = needed.saturating_sub(buffer.len()).max(1);
                let want = want.min(chunk.len());
                let read = inner.read(&mut chunk[..want]).await?;
                if read == 0 {
                    return Err(truncated("VMess response header"));
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > 512 {
                    return Err(invalid("VMess response header is too long"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmo_net::Endpoint;
    use marmo_proto::vless::Uuid;
    use marmo_proto::vmess::{
        COMMAND_TCP, ChunkDecoder, ChunkEncoder, RequestSecrets, RequestSpec, Security,
        encode_request, request_progress,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn request() -> Request {
        let uuid = Uuid::parse("00112233-4455-6677-8899-aabbccddeeff").expect("uuid");
        let key = marmo_proto::vmess::CmdKey::derive(&uuid);
        let target = Endpoint::from_domain("example.com", 443).expect("target");
        let secrets = RequestSecrets {
            body_iv: [0x11; 16],
            body_key: [0x22; 16],
            response_auth: 0x33,
            auth_rand: [0x44; 4],
            connection_nonce: [0x55; 8],
        };
        let mut buffer = [0_u8; marmo_proto::vmess::REQUEST_HEADER_MAX];
        let length = encode_request(
            &key,
            &RequestSpec {
                target: &target,
                command: COMMAND_TCP,
                security: Security::Aes128Gcm,
                timestamp: 1_700_000_000,
                padding: &[],
                secrets: &secrets,
            },
            &mut buffer,
        )
        .expect("encode");
        let marmo_proto::vmess::RequestProgress::Complete(request) =
            request_progress(&buffer[..length], &key, 1_700_000_000)
        else {
            panic!("request");
        };
        request
    }

    #[test]
    fn replay_filter_bounds_the_window() {
        let mut filter = ReplayFilter::new();
        let id = [7_u8; AUTH_ID_LEN];
        assert!(filter.check_and_insert(id, 100));
        assert!(!filter.check_and_insert(id, 100));
        assert!(filter.check_and_insert(id, 100 + TIMESTAMP_WINDOW_S + 1));
        for index in 0..REPLAY_CAPACITY {
            let mut next = [0_u8; AUTH_ID_LEN];
            next[0] = (index & 0xff) as u8;
            next[1] = (index >> 8) as u8;
            assert!(filter.check_and_insert(next, 1000));
        }
        assert!(filter.entries.len() <= REPLAY_CAPACITY);
    }

    #[tokio::test]
    async fn streams_chunks_over_duplex() {
        let (mut peer, inner) = duplex(64 * 1024);
        let request = request();
        let key = request.body_key;
        let iv = request.body_iv;
        let security = request.security;
        let option = request.option;
        let mut stream = ChunkStream::server(Box::new(inner), &request, [0x5a; 64], &[]);

        let mut encoder = ChunkEncoder::new(security, &key, &iv, option, [0x11; 64]);
        let mut wire = Vec::new();
        encoder
            .encode(b"client payload", &mut wire)
            .expect("encode");
        let writer = tokio::spawn(async move {
            peer.write_all(&wire).await.expect("write");
            peer.shutdown().await.expect("shutdown");
        });

        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.expect("read");
        assert_eq!(received, b"client payload");
        writer.await.expect("writer");
    }

    #[tokio::test]
    async fn writes_chunks_that_the_peer_decodes() {
        let (mut peer, inner) = duplex(64 * 1024);
        let request = request();
        let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
        let mut stream = ChunkStream::server(Box::new(inner), &request, [0x5a; 64], &[]);
        stream.write_all(b"server payload").await.expect("write");
        stream.flush().await.expect("flush");

        let mut decoder = ChunkDecoder::new(
            request.security,
            &response_key,
            &response_iv,
            request.option,
        );
        let mut buffer = Vec::new();
        let mut read = [0_u8; 4096];
        loop {
            let count = peer.read(&mut read).await.expect("read");
            assert!(count > 0);
            buffer.extend_from_slice(&read[..count]);
            if let Ok(ChunkProgress::Complete { data, .. }) = decoder.progress(&buffer) {
                assert_eq!(data, b"server payload");
                break;
            }
        }
    }
}
