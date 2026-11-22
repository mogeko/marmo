//! Shadowsocks 2022 UDP client used by datagram outbounds.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use marmo_net::Endpoint;
use marmo_proto::shadowsocks::{
    Direction, Key, Method, SsError, UdpPacket, Window, decode_udp_packet, encode_udp_packet,
    next_counter,
};
use tokio::net::UdpSocket;

use crate::direct::Dialer;

use super::{random_bytes, unix_now};

/// Largest payload carried by one UDP packet.
const MAX_PAYLOAD: usize = 65_535;
/// Largest encoded packet: separate header, body header, address, payload, tag.
const MAX_ENCODED: usize = 16 + 1 + 8 + 8 + 2 + 259 + MAX_PAYLOAD + 16;
/// Datagrams examined before a receive attempt gives up on unrelated packets.
const RECEIVE_ATTEMPTS: usize = 8;

/// A Shadowsocks 2022 UDP association with one server.
pub(crate) struct SsUdpClient {
    socket: UdpSocket,
    method: Method,
    key: Arc<Key>,
    session_id: [u8; 8],
    counter: u64,
    server_session_id: Option<[u8; 8]>,
    window: Window,
    send_scratch: Vec<u8>,
    recv_scratch: Vec<u8>,
    plain_scratch: Vec<u8>,
}

impl SsUdpClient {
    /// Resolves the server and binds a client socket of the same family.
    pub(crate) async fn connect(
        dialer: &Dialer, server: &Endpoint, method: Method, key: Arc<Key>,
    ) -> io::Result<Self> {
        let target = dialer.resolve(server).await?;
        let bind = if target.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(target).await?;

        Ok(Self {
            socket,
            method,
            key,
            session_id: random_bytes::<8>()?,
            counter: 0,
            server_session_id: None,
            window: Window::default(),
            send_scratch: vec![0_u8; MAX_ENCODED],
            recv_scratch: vec![0_u8; MAX_ENCODED],
            plain_scratch: vec![0_u8; MAX_PAYLOAD],
        })
    }

    /// Encodes one datagram for `target` and sends it to the server.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        let packet_id = next_counter(&mut self.counter).map_err(ss_error)?;
        let packet = UdpPacket {
            direction: Direction::ClientToServer,
            session_id: self.session_id,
            packet_id,
            client_session_id: None,
            destination: target,
            payload,
            padding_len: 0,
            timestamp: unix_now(),
        };
        let length = encode_udp_packet(
            self.method,
            self.key.as_bytes(),
            &packet,
            &mut self.send_scratch,
        )
        .map_err(ss_error)?;
        self.socket.send(&self.send_scratch[..length]).await?;
        Ok(())
    }

    /// Receives one datagram, returning its payload length and source.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        for _ in 0..RECEIVE_ATTEMPTS {
            let length = self.socket.recv(&mut self.recv_scratch).await?;
            let decoded = match decode_udp_packet(
                self.method,
                self.key.as_bytes(),
                &self.recv_scratch[..length],
                Direction::ServerToClient,
                Some(self.session_id),
                &mut self.plain_scratch,
            ) {
                Ok(decoded) => decoded,
                Err(_) => continue,
            };
            match self.server_session_id {
                Some(session) if session != decoded.session_id => {
                    self.server_session_id = Some(decoded.session_id);
                    self.window = Window::default();
                }
                None => self.server_session_id = Some(decoded.session_id),
                Some(_) => {}
            }
            if !self.window.accept(decoded.packet_id) {
                continue;
            }
            let payload_len = decoded.payload.len();
            if payload_len > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "shadowsocks datagram exceeds the output buffer",
                ));
            }
            buffer[..payload_len].copy_from_slice(decoded.payload);
            return Ok((payload_len, decoded.destination));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no valid shadowsocks datagram",
        ))
    }
}

fn ss_error(error: SsError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
