//! XUDP frame streaming shared by VLESS inbound and outbound paths.

use std::io;

use marmo_net::Endpoint;
use marmo_proto::xudp::{
    KEEP_META, MAX_DATA_LEN, MAX_META_LEN, Meta, OPTION_DATA, encode_header, encode_new_meta,
    parse_meta,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bytes requested from the stream per read.
const READ_CHUNK: usize = 8 * 1024;
/// Largest complete frame.
const MAX_FRAME: usize = 2 + MAX_META_LEN + 2 + MAX_DATA_LEN;
/// Largest buffer kept while a frame is incomplete.
const MAX_BUFFER: usize = MAX_FRAME + READ_CHUNK;

/// One decoded XUDP frame.
pub(crate) struct Frame {
    pub(crate) meta: Meta,
    pub(crate) data: Vec<u8>,
}

/// Splits a byte stream into XUDP frames.
pub(crate) struct XudpReader {
    buffer: Vec<u8>,
    filled: usize,
}

impl XudpReader {
    /// Starts a reader, treating `prefix` as already read from the stream.
    pub(crate) fn new(prefix: &[u8]) -> io::Result<Self> {
        if prefix.len() > MAX_FRAME {
            return Err(invalid("XUDP prefix is too long"));
        }
        Ok(Self {
            buffer: prefix.to_vec(),
            filled: prefix.len(),
        })
    }

    /// Reads the next frame, or `None` at a clean end of stream.
    pub(crate) async fn next<R>(&mut self, reader: &mut R) -> io::Result<Option<Frame>>
    where
        R: AsyncRead + Unpin,
    {
        if self.filled == 0 && !self.read_more(reader).await? {
            return Ok(None);
        }
        self.ensure(2, reader).await?;
        let meta_len = usize::from(u16::from_be_bytes([self.buffer[0], self.buffer[1]]));
        if !(4..=MAX_META_LEN).contains(&meta_len) {
            return Err(invalid("invalid XUDP metadata length"));
        }
        self.ensure(2 + meta_len, reader).await?;
        let meta = parse_meta(&self.buffer[2..2 + meta_len])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        let mut offset = 2 + meta_len;
        let data = if meta.option & OPTION_DATA != 0 {
            self.ensure(offset + 2, reader).await?;
            let data_len = usize::from(u16::from_be_bytes([
                self.buffer[offset],
                self.buffer[offset + 1],
            ]));
            offset += 2;
            self.ensure(offset + data_len, reader).await?;
            let data = self.buffer[offset..offset + data_len].to_vec();
            offset += data_len;
            data
        } else {
            Vec::new()
        };

        self.buffer.drain(..offset);
        self.filled -= offset;
        Ok(Some(Frame { meta, data }))
    }

    async fn ensure<R>(&mut self, need: usize, reader: &mut R) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
    {
        while self.filled < need {
            if !self.read_more(reader).await? {
                return Err(truncated());
            }
        }
        Ok(())
    }

    async fn read_more<R>(&mut self, reader: &mut R) -> io::Result<bool>
    where
        R: AsyncRead + Unpin,
    {
        if self.filled >= MAX_BUFFER {
            return Err(invalid("XUDP frame buffer is full"));
        }
        let end = (self.filled + READ_CHUNK).min(MAX_BUFFER);
        self.buffer.resize(end, 0);
        let read = reader.read(&mut self.buffer[self.filled..end]).await?;
        self.buffer.truncate(self.filled + read);
        self.filled += read;
        Ok(read != 0)
    }
}

/// Writes a New frame carrying `target` and optional data.
pub(crate) async fn write_new<W>(writer: &mut W, target: &Endpoint, data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut meta = [0_u8; MAX_META_LEN];
    let length = encode_new_meta(target, &mut meta)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    write_frame(writer, &meta[..length], data).await
}

/// Writes a Keep frame carrying data for the fixed target.
pub(crate) async fn write_keep<W>(writer: &mut W, data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_frame(writer, &KEEP_META, data).await
}

async fn write_frame<W>(writer: &mut W, meta: &[u8], data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0_u8; 2 + MAX_META_LEN + 2];
    let length = encode_header(meta, data.len(), &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    writer.write_all(&header[..length]).await?;
    writer.write_all(data).await?;
    Ok(())
}

fn truncated() -> io::Error {
    invalid("XUDP frame is truncated")
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmo_proto::xudp::{STATUS_KEEP, STATUS_NEW};
    use tokio::io::duplex;

    fn target() -> Endpoint {
        Endpoint::from_domain("example.com", 53).expect("domain")
    }

    #[tokio::test]
    async fn reads_new_and_keep_frames() {
        let (mut writer, mut reader) = duplex(4096);
        write_new(&mut writer, &target(), b"first")
            .await
            .expect("new");
        write_keep(&mut writer, b"second").await.expect("keep");
        writer.shutdown().await.expect("shutdown");

        let mut frames = XudpReader::new(&[]).expect("reader");
        let frame = frames.next(&mut reader).await.expect("read").expect("new");
        assert_eq!(frame.meta.status, STATUS_NEW);
        assert_eq!(frame.meta.target.as_ref(), Some(&target()));
        assert_eq!(frame.data, b"first");
        let frame = frames.next(&mut reader).await.expect("read").expect("keep");
        assert_eq!(frame.meta.status, STATUS_KEEP);
        assert_eq!(frame.meta.target, None);
        assert_eq!(frame.data, b"second");
        assert!(frames.next(&mut reader).await.expect("eof").is_none());
    }

    #[tokio::test]
    async fn consumes_a_prefix() {
        let (mut writer, mut reader) = duplex(4096);
        let mut bytes = Vec::new();
        let mut header = [0_u8; 2 + MAX_META_LEN + 2];
        let length = encode_header(&KEEP_META, 3, &mut header).expect("header");
        bytes.extend_from_slice(&header[..length]);
        bytes.extend_from_slice(b"abc");

        let split = 5;
        let prefix = bytes[..split].to_vec();
        let rest = bytes[split..].to_vec();
        let producer = tokio::spawn(async move {
            writer.write_all(&rest).await.expect("write");
        });

        let mut frames = XudpReader::new(&prefix).expect("reader");
        let frame = frames
            .next(&mut reader)
            .await
            .expect("read")
            .expect("frame");
        assert_eq!(frame.data, b"abc");
        producer.await.expect("producer");
    }

    #[tokio::test]
    async fn reports_truncation() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&[0, 7]).await.expect("partial");
        writer.shutdown().await.expect("shutdown");
        let mut frames = XudpReader::new(&[]).expect("reader");
        assert!(frames.next(&mut reader).await.is_err());
    }
}
