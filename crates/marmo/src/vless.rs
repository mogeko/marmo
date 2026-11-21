//! VLESS stream helpers: lazy response header and UoT framing.

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use marmo_proto::vless::{
    ADDON_LEN_MAX, MAX_UDP_PAYLOAD, UdpProgress, VERSION, encode_udp_header, udp_progress,
};
use marmo_transport::BoxStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Bytes requested from the stream per read.
const READ_CHUNK: usize = 8 * 1024;
/// Largest UoT frame including its length.
const MAX_FRAME: usize = 2 + MAX_UDP_PAYLOAD;
/// Largest buffer kept while a frame is incomplete.
const MAX_BUFFER: usize = MAX_FRAME + READ_CHUNK;

/// Reads the VLESS response header on the first read, then passes through.
pub(crate) struct ClientStream {
    inner: BoxStream,
    header: [u8; 2],
    header_len: usize,
    addons_left: usize,
    ready: bool,
}

impl ClientStream {
    pub(crate) fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            header: [0_u8; 2],
            header_len: 0,
            addons_left: 0,
            ready: false,
        }
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.ready {
                return Pin::new(&mut me.inner).poll_read(cx, buf);
            }
            if me.addons_left > 0 {
                let mut discard = [0_u8; 64];
                let wanted = me.addons_left.min(discard.len());
                let mut bound = ReadBuf::new(&mut discard[..wanted]);
                match Pin::new(&mut me.inner).poll_read(cx, &mut bound) {
                    Poll::Ready(Ok(())) => {
                        let filled = bound.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(truncated()));
                        }
                        me.addons_left -= filled;
                        if me.addons_left == 0 {
                            me.ready = true;
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            while me.header_len < 2 {
                let start = me.header_len;
                let mut bound = ReadBuf::new(&mut me.header[start..]);
                match Pin::new(&mut me.inner).poll_read(cx, &mut bound) {
                    Poll::Ready(Ok(())) => {
                        let filled = bound.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(truncated()));
                        }
                        me.header_len += filled;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if me.header[0] != VERSION {
                return Poll::Ready(Err(invalid("invalid VLESS response version")));
            }
            me.addons_left = usize::from(me.header[1]);
            if me.addons_left == 0 {
                me.ready = true;
            }
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Reads and validates a VLESS response header, discarding addons.
pub(crate) async fn read_response_header<R>(reader: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Err(invalid("invalid VLESS response version"));
    }
    let mut addons = [0_u8; ADDON_LEN_MAX];
    let length = usize::from(header[1]);
    if length > 0 {
        reader.read_exact(&mut addons[..length]).await?;
    }
    Ok(())
}

/// Splits a byte stream into UoT frames.
pub(crate) struct UotReader {
    buffer: Vec<u8>,
    filled: usize,
}

impl UotReader {
    /// Starts a reader, treating `prefix` as already read from the stream.
    pub(crate) fn new(prefix: &[u8]) -> io::Result<Self> {
        if prefix.len() > MAX_FRAME {
            return Err(invalid("UoT prefix is too long"));
        }
        Ok(Self {
            buffer: prefix.to_vec(),
            filled: prefix.len(),
        })
    }

    /// Reads the next frame, or `None` at a clean end of stream.
    pub(crate) async fn next<R>(&mut self, reader: &mut R) -> io::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            match udp_progress(&self.buffer[..self.filled]) {
                UdpProgress::Complete { payload_len } => {
                    let total = 2 + payload_len;
                    while self.filled < total {
                        if !self.read_more(reader).await? {
                            return Err(truncated());
                        }
                    }
                    let payload = self.buffer[2..total].to_vec();
                    self.buffer.drain(..total);
                    self.filled -= total;
                    return Ok(Some(payload));
                }
                UdpProgress::NeedMore => {
                    if !self.read_more(reader).await? {
                        return if self.filled == 0 {
                            Ok(None)
                        } else {
                            Err(truncated())
                        };
                    }
                }
            }
        }
    }

    async fn read_more<R>(&mut self, reader: &mut R) -> io::Result<bool>
    where
        R: AsyncRead + Unpin,
    {
        if self.filled >= MAX_BUFFER {
            return Err(invalid("UoT frame buffer is full"));
        }
        let end = (self.filled + READ_CHUNK).min(MAX_BUFFER);
        self.buffer.resize(end, 0);
        let read = reader.read(&mut self.buffer[self.filled..end]).await?;
        self.buffer.truncate(self.filled + read);
        self.filled += read;
        Ok(read != 0)
    }
}

/// Writes one UoT frame.
pub(crate) async fn write_udp_frame<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0_u8; 2];
    encode_udp_header(payload.len(), &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    Ok(())
}

fn truncated() -> io::Error {
    invalid("VLESS header or frame is truncated")
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn waits_for_the_response_header() {
        let (mut writer, reader) = duplex(64);
        let producer = tokio::spawn(async move {
            writer.write_all(&[0, 0]).await.expect("header");
            writer.write_all(b"payload").await.expect("payload");
        });
        let mut stream = ClientStream::new(Box::new(reader));
        let mut buffer = [0_u8; 7];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"payload");
        producer.await.expect("producer");
    }

    #[tokio::test]
    async fn skips_response_addons() {
        let (mut writer, reader) = duplex(64);
        let producer = tokio::spawn(async move {
            writer.write_all(&[0, 2, 0xaa, 0xbb]).await.expect("header");
            writer.write_all(b"x").await.expect("payload");
        });
        let mut stream = ClientStream::new(Box::new(reader));
        let mut buffer = [0_u8; 1];
        stream.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"x");
        producer.await.expect("producer");
    }

    #[tokio::test]
    async fn rejects_a_bad_response_version() {
        let (mut writer, reader) = duplex(16);
        writer.write_all(&[1, 0]).await.expect("header");
        writer.shutdown().await.expect("shutdown");
        let mut stream = ClientStream::new(Box::new(reader));
        let mut buffer = [0_u8; 1];
        assert!(stream.read(&mut buffer).await.is_err());
    }

    #[tokio::test]
    async fn reads_multiple_uot_frames() {
        let (mut writer, reader) = duplex(64);
        let first = {
            let mut frame = vec![0, 5];
            frame.extend_from_slice(b"first");
            frame
        };
        let second = vec![0, 0];
        let mut all = first;
        all.extend_from_slice(&second);
        let producer = tokio::spawn(async move {
            for chunk in all.chunks(3) {
                writer.write_all(chunk).await.expect("write");
            }
        });
        let mut reader = reader;
        let mut frames = UotReader::new(&[]).expect("reader");
        assert_eq!(
            frames
                .next(&mut reader)
                .await
                .expect("first")
                .expect("frame"),
            b"first"
        );
        assert_eq!(
            frames
                .next(&mut reader)
                .await
                .expect("second")
                .expect("frame"),
            Vec::<u8>::new()
        );
        producer.await.expect("producer");
    }

    #[tokio::test]
    async fn reports_eof_and_truncation() {
        let (mut writer, reader) = duplex(16);
        writer.shutdown().await.expect("shutdown");
        let mut reader = reader;
        let mut frames = UotReader::new(&[]).expect("reader");
        assert!(frames.next(&mut reader).await.expect("eof").is_none());

        let (mut writer, reader) = duplex(16);
        writer.write_all(&[0, 4, b'a']).await.expect("partial");
        writer.shutdown().await.expect("shutdown");
        let mut reader = reader;
        let mut frames = UotReader::new(&[]).expect("reader");
        assert!(frames.next(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn writes_frames_that_the_reader_accepts() {
        let (mut writer, mut reader) = duplex(64);
        write_udp_frame(&mut writer, b"out").await.expect("write");
        writer.shutdown().await.expect("shutdown");
        let mut frames = UotReader::new(&[]).expect("reader");
        assert_eq!(
            frames
                .next(&mut reader)
                .await
                .expect("frame")
                .expect("payload"),
            b"out"
        );
    }
}
