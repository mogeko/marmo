//! Mux.Cool frame IO over a byte stream.
//!
//! The frame codec lives in `marmo_proto::mux`; this module adds bounded
//! streaming reads and serialized writes.

use std::io;

use marmo_net::Endpoint;
use marmo_proto::mux::{
    MAX_DATA_LEN, MAX_META_LEN, Meta, OPTION_ERROR, encode_end_meta, encode_header,
    encode_keep_meta, encode_new_meta, parse_meta,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bytes requested from the stream per read.
const READ_CHUNK: usize = 8 * 1024;
/// Largest complete frame.
const MAX_FRAME: usize = 2 + MAX_META_LEN + 2 + MAX_DATA_LEN;
/// Largest buffer kept while a frame is incomplete.
const MAX_BUFFER: usize = MAX_FRAME + READ_CHUNK;

/// One decoded Mux.Cool frame.
pub(crate) struct Frame {
    pub(crate) meta: Meta,
    pub(crate) data: Vec<u8>,
}

/// Splits a byte stream into Mux.Cool frames.
pub(crate) struct MuxReader<R> {
    inner: R,
    buffer: Vec<u8>,
    start: usize,
    filled: usize,
}

impl<R: AsyncRead + Unpin> MuxReader<R> {
    /// Starts a reader, treating `prefix` as already read from the stream.
    pub(crate) fn new(inner: R, prefix: &[u8]) -> io::Result<Self> {
        if prefix.len() > MAX_FRAME {
            return Err(invalid("Mux.Cool prefix is too long"));
        }
        Ok(Self {
            inner,
            buffer: prefix.to_vec(),
            start: 0,
            filled: prefix.len(),
        })
    }

    /// Reads the next frame, or `None` at a clean end of stream.
    pub(crate) async fn next(&mut self) -> io::Result<Option<Frame>> {
        if self.filled == 0 && !self.read_more().await? {
            return Ok(None);
        }
        self.ensure(2).await?;
        let meta_len = usize::from(u16::from_be_bytes([
            self.buffer[self.start],
            self.buffer[self.start + 1],
        ]));
        if !(4..=MAX_META_LEN).contains(&meta_len) {
            return Err(invalid("invalid Mux.Cool metadata length"));
        }
        self.ensure(2 + meta_len).await?;
        let meta = parse_meta(&self.buffer[self.start + 2..self.start + 2 + meta_len])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        let mut offset = 2 + meta_len;
        let data = if meta.option & marmo_proto::mux::OPTION_DATA != 0 {
            self.ensure(offset + 2).await?;
            let data_len = usize::from(u16::from_be_bytes([
                self.buffer[self.start + offset],
                self.buffer[self.start + offset + 1],
            ]));
            offset += 2;
            self.ensure(offset + data_len).await?;
            let data = self.buffer[self.start + offset..self.start + offset + data_len].to_vec();
            offset += data_len;
            data
        } else {
            Vec::new()
        };

        self.start += offset;
        self.filled -= offset;
        self.compact();
        Ok(Some(Frame { meta, data }))
    }

    async fn ensure(&mut self, need: usize) -> io::Result<()> {
        while self.filled < need {
            if !self.read_more().await? {
                return Err(truncated());
            }
        }
        Ok(())
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        if self.start >= READ_CHUNK || self.start * 2 >= self.buffer.len() {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
    }

    async fn read_more(&mut self) -> io::Result<bool> {
        if self.filled >= MAX_BUFFER {
            return Err(invalid("Mux.Cool frame buffer is full"));
        }
        let end = self.start + (self.filled + READ_CHUNK).min(MAX_BUFFER);
        if self.buffer.len() < end {
            self.buffer.resize(end, 0);
        }
        let read = self
            .inner
            .read(&mut self.buffer[self.start + self.filled..end])
            .await?;
        self.buffer.truncate(self.start + self.filled + read);
        self.filled += read;
        Ok(read != 0)
    }
}

/// Serializes Mux.Cool frames onto one write half.
pub(crate) struct MuxWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> MuxWriter<W> {
    /// Wraps a write half.
    pub(crate) fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Writes a New frame.
    pub(crate) async fn new_session(
        &mut self, session: u16, target: &Endpoint, network: u8, data: &[u8],
    ) -> io::Result<()> {
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_new_meta(session, target, network, &mut meta).map_err(frame_error)?;
        self.frame(&meta[..length], data).await
    }

    /// Writes a Keep frame, optionally carrying a destination.
    pub(crate) async fn keep(
        &mut self, session: u16, target: Option<&Endpoint>, data: &[u8],
    ) -> io::Result<()> {
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_keep_meta(session, target, &mut meta).map_err(frame_error)?;
        self.frame(&meta[..length], data).await
    }

    /// Writes a keep-alive frame.
    pub(crate) async fn keepalive(&mut self) -> io::Result<()> {
        self.frame(&marmo_proto::mux::KEEPALIVE_META, &[]).await
    }

    /// Writes an End frame.
    pub(crate) async fn end(&mut self, session: u16) -> io::Result<()> {
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_end_meta(session, &mut meta).map_err(frame_error)?;
        self.frame(&meta[..length], &[]).await
    }

    /// Writes an End frame carrying an error message.
    pub(crate) async fn end_error(&mut self, session: u16, message: &[u8]) -> io::Result<()> {
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_end_meta(session, &mut meta).map_err(frame_error)?;
        meta[3] |= OPTION_ERROR | marmo_proto::mux::OPTION_DATA;
        self.frame(&meta[..length], message).await
    }

    async fn frame(&mut self, meta: &[u8], data: &[u8]) -> io::Result<()> {
        let mut header = [0_u8; 2 + MAX_META_LEN + 2];
        let length = if meta[3] & marmo_proto::mux::OPTION_DATA != 0 {
            let length = encode_header(meta, data.len(), &mut header).map_err(frame_error)?;
            self.inner.write_all(&header[..length]).await?;
            if !data.is_empty() {
                self.inner.write_all(data).await?;
            }
            length
        } else {
            // Without the data option there is no data-length field.
            let meta_len = u16::try_from(meta.len()).map_err(|_| invalid("meta too long"))?;
            let length = 2 + meta.len();
            header[..2].copy_from_slice(&meta_len.to_be_bytes());
            header[2..length].copy_from_slice(meta);
            self.inner.write_all(&header[..length]).await?;
            length
        };
        let _ = length;
        self.inner.flush().await
    }
}

fn frame_error(error: marmo_proto::mux::MuxError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn truncated() -> io::Error {
    invalid("Mux.Cool frame is truncated")
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmo_proto::mux::{NETWORK_TCP, NETWORK_UDP, STATUS_NEW};
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trips_frames() {
        let (writer, reader) = duplex(4096);
        let target = Endpoint::from_domain("example.com", 53).expect("target");
        let mut writer = MuxWriter::new(writer);
        writer
            .new_session(1, &target, NETWORK_TCP, b"first")
            .await
            .expect("new");
        writer.keep(1, None, b"second").await.expect("keep");
        writer.end_error(1, b"failure").await.expect("end");
        drop(writer);

        let mut reader = MuxReader::new(reader, &[]).expect("reader");
        let frame = reader.next().await.expect("read").expect("new");
        assert_eq!(frame.meta.session, 1);
        assert_eq!(frame.meta.status, STATUS_NEW);
        assert_eq!(frame.meta.network, NETWORK_TCP);
        assert_eq!(frame.data, b"first");
        let frame = reader.next().await.expect("read").expect("keep");
        assert_eq!(frame.data, b"second");
        assert_eq!(frame.meta.target, None);
        let frame = reader.next().await.expect("read").expect("end");
        assert_eq!(frame.meta.option & OPTION_ERROR, OPTION_ERROR);
        assert_eq!(frame.data, b"failure");
        assert!(reader.next().await.expect("eof").is_none());
    }

    #[tokio::test]
    async fn reports_truncation() {
        let (mut writer, reader) = duplex(64);
        writer.write_all(&[0, 7]).await.expect("partial");
        writer.shutdown().await.expect("shutdown");
        let mut reader = MuxReader::new(reader, &[]).expect("reader");
        assert!(reader.next().await.is_err());
    }

    #[tokio::test]
    async fn carries_udp_targets() {
        let (writer, reader) = duplex(4096);
        let target = Endpoint::from_domain("example.com", 53).expect("target");
        let mut writer = MuxWriter::new(writer);
        writer
            .keep(2, Some(&target), b"datagram")
            .await
            .expect("keep");
        drop(writer);
        let mut reader = MuxReader::new(reader, &[]).expect("reader");
        let frame = reader.next().await.expect("read").expect("keep");
        assert_eq!(frame.meta.network, NETWORK_UDP);
        assert_eq!(frame.meta.target.as_ref(), Some(&target));
    }
}
