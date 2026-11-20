//! Trojan UDP frame streaming shared by inbound and outbound paths.

use std::io;

use marmo_net::Endpoint;
use marmo_proto::trojan::{
    MAX_UDP_PAYLOAD, UDP_HEADER_MAX, UdpFrameProgress, encode_udp_header, udp_frame_progress,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bytes requested from the stream per read.
const READ_CHUNK: usize = 8 * 1024;
/// Largest complete frame: header plus payload.
const MAX_FRAME: usize = UDP_HEADER_MAX + MAX_UDP_PAYLOAD;
/// Largest buffer kept while a frame or the next header is incomplete.
const MAX_BUFFER: usize = MAX_FRAME + READ_CHUNK;

/// Splits a byte stream into Trojan UDP frames.
pub(crate) struct FrameReader {
    buffer: Vec<u8>,
    filled: usize,
}

impl FrameReader {
    /// Starts a reader, treating `prefix` as already read from the stream.
    pub(crate) fn new(prefix: &[u8]) -> io::Result<Self> {
        if prefix.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trojan frame prefix is too long",
            ));
        }
        Ok(Self {
            buffer: prefix.to_vec(),
            filled: prefix.len(),
        })
    }

    /// Reads the next frame, or `None` at a clean end of stream.
    pub(crate) async fn next<R>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Option<(Endpoint, Vec<u8>)>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            match udp_frame_progress(&self.buffer[..self.filled]) {
                UdpFrameProgress::Complete {
                    source,
                    payload_len,
                    header_len,
                } => {
                    let total = header_len + payload_len;
                    while self.filled < total {
                        if !self.read_more(reader).await? {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "trojan frame is truncated",
                            ));
                        }
                    }
                    let payload = self.buffer[header_len..total].to_vec();
                    self.buffer.drain(..total);
                    self.filled -= total;
                    return Ok(Some((source, payload)));
                }
                UdpFrameProgress::Invalid => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid trojan frame",
                    ));
                }
                UdpFrameProgress::NeedMore => {
                    if !self.read_more(reader).await? {
                        return if self.filled == 0 {
                            Ok(None)
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "trojan frame is truncated",
                            ))
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trojan frame buffer is full",
            ));
        }
        let end = (self.filled + READ_CHUNK).min(MAX_BUFFER);
        self.buffer.resize(end, 0);
        let read = reader.read(&mut self.buffer[self.filled..end]).await?;
        self.buffer.truncate(self.filled + read);
        self.filled += read;
        Ok(read != 0)
    }
}

/// Writes one address, length, and payload frame.
pub(crate) async fn write_frame<W>(
    writer: &mut W,
    source: &Endpoint,
    payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0_u8; UDP_HEADER_MAX];
    let length = encode_udp_header(source, payload.len(), &mut header)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    writer.write_all(&header[..length]).await?;
    writer.write_all(payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    fn frame(target: &Endpoint, payload: &[u8]) -> Vec<u8> {
        let mut header = [0_u8; UDP_HEADER_MAX];
        let length = encode_udp_header(target, payload.len(), &mut header).expect("header");
        let mut frame = header[..length].to_vec();
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test]
    async fn reads_multiple_frames_across_reads() {
        let target = Endpoint::from_domain("example.com", 53).expect("domain");
        let first = frame(&target, b"first");
        let second = frame(&target, b"second");
        let mut all = first.clone();
        all.extend_from_slice(&second);

        let (mut writer, reader) = duplex(64);
        let producer = tokio::spawn(async move {
            for chunk in all.chunks(5) {
                writer.write_all(chunk).await.expect("write");
            }
        });

        let mut reader = reader;
        let mut frames = FrameReader::new(&[]).expect("reader");
        let (source, payload) = frames
            .next(&mut reader)
            .await
            .expect("first")
            .expect("frame");
        assert_eq!(source, target);
        assert_eq!(payload, b"first");
        let (_, payload) = frames
            .next(&mut reader)
            .await
            .expect("second")
            .expect("frame");
        assert_eq!(payload, b"second");
        producer.await.expect("producer");
    }

    #[tokio::test]
    async fn consumes_a_prefix_before_reading() {
        let target = Endpoint::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 80);
        let bytes = frame(&target, b"prefix");
        let (mut writer, reader) = duplex(64);
        let split = 5;
        let prefix = bytes[..split].to_vec();
        let rest = bytes[split..].to_vec();
        let producer = tokio::spawn(async move {
            writer.write_all(&rest).await.expect("write");
        });

        let mut reader = reader;
        let mut frames = FrameReader::new(&prefix).expect("reader");
        let (source, payload) = frames
            .next(&mut reader)
            .await
            .expect("next")
            .expect("frame");
        assert_eq!(source, target);
        assert_eq!(payload, b"prefix");
        producer.await.expect("producer");
    }

    #[tokio::test]
    async fn reports_clean_eof_and_truncation() {
        let (mut writer, reader) = duplex(16);
        writer.shutdown().await.expect("shutdown");
        let mut reader = reader;
        let mut frames = FrameReader::new(&[]).expect("reader");
        assert!(frames.next(&mut reader).await.expect("eof").is_none());

        let target = Endpoint::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 80);
        let mut bytes = frame(&target, b"payload");
        bytes.truncate(bytes.len() - 1);
        let (mut writer, reader) = duplex(64);
        writer.write_all(&bytes).await.expect("write");
        writer.shutdown().await.expect("shutdown");
        let mut reader = reader;
        let mut frames = FrameReader::new(&[]).expect("reader");
        assert!(frames.next(&mut reader).await.is_err());
    }
}
