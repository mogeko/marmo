//! VLESS loopback tests through the public `Instance`.

use std::net::SocketAddr;
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, ServeError};
use marmo_transport::Layer;
use marmo_transport::h2::{H2Client, H2ClientOptions};
use marmo_transport::tls::{TlsClient, TlsClientOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const SERVER_CERT: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.pem");
const SERVER_KEY: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.key");
const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

async fn echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (address, task)
}

async fn udp_echo() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let address = socket.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let _ = socket.send_to(&buffer[..length], peer).await;
        }
    });
    (address, task)
}

async fn start(
    json: &str,
) -> (
    SocketAddr,
    InstanceHandle,
    JoinHandle<Result<(), ServeError>>,
) {
    let config = Config::from_json(json).expect("config");
    let instance = Instance::builder(config).build().expect("build");
    let bound = instance.bind().await.expect("bind");
    let address = bound.local_addrs().next().expect("inbound").addr;
    let handle = bound.handle();
    let task = tokio::spawn(bound.serve());
    (address, handle, task)
}

async fn stop(handle: InstanceHandle, task: JoinHandle<Result<(), ServeError>>) {
    handle.shutdown();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("serve timeout")
        .expect("join")
        .expect("serve");
}

async fn socks5_connect(client: &mut TcpStream, target: SocketAddr) {
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);

    let SocketAddr::V4(target) = target else {
        panic!("test target must be IPv4");
    };
    let mut request = Vec::with_capacity(10);
    request.extend_from_slice(&[5, 1, 0, 1]);
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.expect("request");
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[0], 5);
    assert_eq!(reply[1], 0);
}

async fn udp_associate(client: &mut TcpStream) -> (UdpSocket, SocketAddr) {
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);
    client
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0);
    let relay = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            reply[4], reply[5], reply[6], reply[7],
        )),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("udp bind");
    (socket, relay)
}

fn udp_request(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(target) = target else {
        panic!("test target must be IPv4");
    };
    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0, 0, 0, 1]);
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn json_string(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control < ' ' => {
                let _ = write!(escaped, "\\u{:04x}", u32::from(control));
            }
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

fn vless_inbound() -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "listen": "127.0.0.1:0",
             "uuid": "{UUID}",
             "tls": {{ "certificate": {}, "private_key": {} }} }}"#,
        json_string(SERVER_CERT),
        json_string(SERVER_KEY)
    )
}

fn vless_outbound(server: SocketAddr) -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "server": "{server}",
             "uuid": "{UUID}", "tls": {{ "insecure": true }} }}"#
    )
}

fn vless_mux_outbound(server: SocketAddr) -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "server": "{server}",
             "uuid": "{UUID}", "tls": {{ "insecure": true }}, "mux": true }}"#
    )
}

fn vless_ws_inbound() -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "listen": "127.0.0.1:0",
             "uuid": "{UUID}",
             "tls": {{ "certificate": {}, "private_key": {} }},
             "transport": {{ "network": "ws", "path": "/ws",
                             "subprotocols": ["marmo"] }} }}"#,
        json_string(SERVER_CERT),
        json_string(SERVER_KEY)
    )
}

fn vless_ws_outbound(server: SocketAddr) -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "server": "{server}",
             "uuid": "{UUID}", "tls": {{ "insecure": true }},
             "transport": {{ "network": "ws", "path": "/ws",
                             "subprotocols": ["marmo"] }} }}"#
    )
}

fn vless_ws_compressed_inbound() -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "listen": "127.0.0.1:0",
             "uuid": "{UUID}",
             "tls": {{ "certificate": {}, "private_key": {} }},
             "transport": {{ "network": "ws", "path": "/ws",
                             "subprotocols": ["marmo"], "compression": true }} }}"#,
        json_string(SERVER_CERT),
        json_string(SERVER_KEY)
    )
}

fn vless_ws_compressed_outbound(server: SocketAddr) -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "server": "{server}",
             "uuid": "{UUID}", "tls": {{ "insecure": true }},
             "transport": {{ "network": "ws", "path": "/ws",
                             "subprotocols": ["marmo"], "compression": true }} }}"#
    )
}

fn vless_h2_inbound() -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "listen": "127.0.0.1:0",
             "uuid": "{UUID}",
             "tls": {{ "certificate": {}, "private_key": {} }},
             "transport": {{ "network": "h2", "path": "/h2" }} }}"#,
        json_string(SERVER_CERT),
        json_string(SERVER_KEY)
    )
}

fn vless_h2_outbound(server: SocketAddr) -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "server": "{server}",
             "uuid": "{UUID}", "tls": {{ "insecure": true }},
             "transport": {{ "network": "h2", "path": "/h2" }} }}"#
    )
}

fn vless_xudp_outbound(server: SocketAddr) -> String {
    format!(
        r#"{{ "tag": "vl", "protocol": "vless", "server": "{server}",
             "uuid": "{UUID}", "tls": {{ "insecure": true }}, "xudp": true }}"#
    )
}

#[tokio::test]
async fn relays_through_vless_tcp() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {} ],
          "route": {{ "final": "vl" }}
        }}"#,
        vless_outbound(proxy_address)
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut client = TcpStream::connect(front_address).await.expect("connect");
    socks5_connect(&mut client, echo).await;
    let payload: Vec<u8> = (0..32_000).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = client.into_split();
    let write = writer.write_all(&payload);
    let read = async {
        let mut received = vec![0_u8; payload.len()];
        reader.read_exact(&mut received).await.expect("read");
        received
    };
    let (written, echoed) = tokio::join!(write, read);
    written.expect("write");
    assert_eq!(echoed, payload);

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_through_vless_udp() {
    let (echo, echo_task) = udp_echo().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {} ],
          "route": {{ "final": "vl" }}
        }}"#,
        vless_outbound(proxy_address)
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut control = TcpStream::connect(front_address).await.expect("connect");
    let (datagram, relay) = udp_associate(&mut control).await;
    let payload: Vec<u8> = (0..8_000).map(|index| (index % 251) as u8).collect();
    datagram
        .send_to(&udp_request(echo, &payload), relay)
        .await
        .expect("send");
    let mut reply = vec![0_u8; 65_535];
    let (length, _) = timeout(Duration::from_secs(5), datagram.recv_from(&mut reply))
        .await
        .expect("reply timeout")
        .expect("recv");
    assert!(length >= 10 + payload.len());
    let SocketAddr::V4(echo) = echo else {
        panic!("test echo must be IPv4");
    };
    assert_eq!(&reply[4..8], &echo.ip().octets());
    assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), echo.port());
    assert_eq!(&reply[10..length], &payload[..]);

    drop(control);
    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_through_vless_xudp() {
    let (echo, echo_task) = udp_echo().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {} ],
          "route": {{ "final": "vl" }}
        }}"#,
        vless_xudp_outbound(proxy_address)
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut control = TcpStream::connect(front_address).await.expect("connect");
    let (datagram, relay) = udp_associate(&mut control).await;
    let mut reply = vec![0_u8; 65_535];
    for round in 0..2 {
        let payload: Vec<u8> = (0..4_000)
            .map(|index| ((index + round) % 251) as u8)
            .collect();
        datagram
            .send_to(&udp_request(echo, &payload), relay)
            .await
            .expect("send");
        let (length, _) = timeout(Duration::from_secs(5), datagram.recv_from(&mut reply))
            .await
            .expect("reply timeout")
            .expect("recv");
        assert!(length >= 10 + payload.len());
        assert_eq!(&reply[10..length], &payload[..]);
    }

    let SocketAddr::V4(echo) = echo else {
        panic!("test echo must be IPv4");
    };
    assert_eq!(&reply[4..8], &echo.ip().octets());

    drop(control);
    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

async fn ws_chain<F>(
    inbound: String, outbound: F,
) -> (
    SocketAddr,
    InstanceHandle,
    JoinHandle<Result<(), ServeError>>,
    InstanceHandle,
    JoinHandle<Result<(), ServeError>>,
)
where
    F: FnOnce(SocketAddr) -> String,
{
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {inbound} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {} ],
          "route": {{ "final": "vl" }}
        }}"#,
        outbound(proxy_address)
    );
    let (front_address, front_handle, front_task) = start(&front).await;
    (
        front_address,
        front_handle,
        front_task,
        proxy_handle,
        proxy_task,
    )
}

#[tokio::test]
async fn relays_through_vless_websocket() {
    let (echo, echo_task) = echo_server().await;
    let (front, front_handle, front_task, proxy_handle, proxy_task) =
        ws_chain(vless_ws_inbound(), vless_ws_outbound).await;

    let mut client = TcpStream::connect(front).await.expect("connect");
    socks5_connect(&mut client, echo).await;
    let payload: Vec<u8> = (0..32_000).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = client.into_split();
    let write = writer.write_all(&payload);
    let read = async {
        let mut received = vec![0_u8; payload.len()];
        reader.read_exact(&mut received).await.expect("read");
        received
    };
    let (written, echoed) = tokio::join!(write, read);
    written.expect("write");
    assert_eq!(echoed, payload);

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_vless_uot_over_websocket() {
    let (echo, echo_task) = udp_echo().await;
    let (front, front_handle, front_task, proxy_handle, proxy_task) =
        ws_chain(vless_ws_inbound(), vless_ws_outbound).await;

    let mut control = TcpStream::connect(front).await.expect("connect");
    let (datagram, relay) = udp_associate(&mut control).await;
    let payload: Vec<u8> = (0..8_000).map(|index| (index % 251) as u8).collect();
    datagram
        .send_to(&udp_request(echo, &payload), relay)
        .await
        .expect("send");
    let mut reply = vec![0_u8; 65_535];
    let (length, _) = timeout(Duration::from_secs(5), datagram.recv_from(&mut reply))
        .await
        .expect("reply timeout")
        .expect("recv");
    assert!(length >= 10 + payload.len());
    assert_eq!(&reply[10..length], &payload[..]);

    drop(control);
    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_vless_over_compressed_websocket() {
    let (echo, echo_task) = echo_server().await;
    let (front, front_handle, front_task, proxy_handle, proxy_task) =
        ws_chain(vless_ws_compressed_inbound(), vless_ws_compressed_outbound).await;

    let mut client = TcpStream::connect(front).await.expect("connect");
    socks5_connect(&mut client, echo).await;
    let payload = vec![b'a'; 100_000];
    let (mut reader, mut writer) = client.into_split();
    let write = writer.write_all(&payload);
    let read = async {
        let mut received = vec![0_u8; payload.len()];
        reader.read_exact(&mut received).await.expect("read");
        received
    };
    let (written, echoed) = tokio::join!(write, read);
    written.expect("write");
    assert_eq!(echoed, payload);

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_through_vless_http2() {
    let (echo, echo_task) = echo_server().await;
    let (front, front_handle, front_task, proxy_handle, proxy_task) =
        ws_chain(vless_h2_inbound(), vless_h2_outbound).await;

    let mut client = TcpStream::connect(front).await.expect("connect");
    socks5_connect(&mut client, echo).await;
    let payload: Vec<u8> = (0..32_000).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = client.into_split();
    let write = writer.write_all(&payload);
    let read = async {
        let mut received = vec![0_u8; payload.len()];
        reader.read_exact(&mut received).await.expect("read");
        received
    };
    let (written, echoed) = tokio::join!(write, read);
    written.expect("write");
    assert_eq!(echoed, payload);

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_vless_uot_over_http2() {
    let (echo, echo_task) = udp_echo().await;
    let (front, front_handle, front_task, proxy_handle, proxy_task) =
        ws_chain(vless_h2_inbound(), vless_h2_outbound).await;

    let mut control = TcpStream::connect(front).await.expect("connect");
    let (datagram, relay) = udp_associate(&mut control).await;
    let payload: Vec<u8> = (0..8_000).map(|index| (index % 251) as u8).collect();
    datagram
        .send_to(&udp_request(echo, &payload), relay)
        .await
        .expect("send");
    let mut reply = vec![0_u8; 65_535];
    let (length, _) = timeout(Duration::from_secs(5), datagram.recv_from(&mut reply))
        .await
        .expect("reply timeout")
        .expect("recv");
    assert!(length >= 10 + payload.len());
    assert_eq!(&reply[10..length], &payload[..]);

    drop(control);
    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

/// Accumulates Mux.Cool frames from a byte stream.
#[derive(Default)]
struct MuxFrames {
    buffer: Vec<u8>,
}

impl MuxFrames {
    async fn next<R: tokio::io::AsyncRead + Unpin>(
        &mut self, stream: &mut R,
    ) -> (marmo_proto::mux::Meta, Vec<u8>) {
        loop {
            if let Some(frame) = self.take() {
                return frame;
            }
            let mut extra = [0_u8; 4096];
            let read = stream.read(&mut extra).await.expect("frame read");
            assert!(read > 0, "eof before mux frame");
            self.buffer.extend_from_slice(&extra[..read]);
        }
    }

    fn take(&mut self) -> Option<(marmo_proto::mux::Meta, Vec<u8>)> {
        if self.buffer.len() < 2 {
            return None;
        }
        let meta_len = usize::from(u16::from_be_bytes([self.buffer[0], self.buffer[1]]));
        if self.buffer.len() < 2 + meta_len {
            return None;
        }
        let meta = marmo_proto::mux::parse_meta(&self.buffer[2..2 + meta_len]).ok()?;
        let offset = 2 + meta_len;
        let data_len = if meta.option & marmo_proto::mux::OPTION_DATA != 0 {
            if self.buffer.len() < offset + 2 {
                return None;
            }
            let length = usize::from(u16::from_be_bytes([
                self.buffer[offset],
                self.buffer[offset + 1],
            ]));
            if self.buffer.len() < offset + 2 + length {
                return None;
            }
            length
        } else {
            0
        };
        let data = self.buffer[offset + 2..offset + 2 + data_len].to_vec();
        self.buffer.drain(..offset + 2 + data_len);
        Some((meta, data))
    }
}

fn mux_new(session: u16, target: &marmo_net::Endpoint, network: u8, data: &[u8]) -> Vec<u8> {
    let mut meta = [0_u8; 512];
    let length =
        marmo_proto::mux::encode_new_meta(session, target, network, &mut meta).expect("new meta");
    let mut header = [0_u8; 2 + 512 + 2];
    let length =
        marmo_proto::mux::encode_header(&meta[..length], data.len(), &mut header).expect("header");
    let mut frame = header[..length].to_vec();
    frame.extend_from_slice(data);
    frame
}

fn mux_end(session: u16) -> Vec<u8> {
    let mut meta = [0_u8; 512];
    let length = marmo_proto::mux::encode_end_meta(session, &mut meta).expect("end meta");
    let mut frame = (length as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&meta[..length]);
    frame
}

#[tokio::test]
async fn terminates_vless_mux_tcp_and_udp_sessions() {
    let (tcp_echo, tcp_task) = echo_server().await;
    let (udp_echo, udp_task) = udp_echo().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let uuid = marmo_proto::vless::Uuid::parse(UUID).expect("uuid");
    let tcp = TcpStream::connect(proxy_address).await.expect("connect");
    let tls = TlsClient::new(&TlsClientOptions {
        server_name: "localhost",
        alpn: &[],
        required_alpn: None,
        insecure: true,
        client_certificate: None,
        client_private_key: None,
        handshake_timeout: Some(Duration::from_secs(5)),
    })
    .expect("tls client");
    let mut client = tls.wrap(Box::new(tcp)).await.expect("tls handshake");
    let mut header = [0_u8; 64];
    let length = marmo_proto::vless::encode_mux_request(&uuid, &mut header).expect("mux");
    client.write_all(&header[..length]).await.expect("header");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).await.expect("response");
    assert_eq!(response, [0, 0]);

    let mut frames = MuxFrames::default();

    // TCP session on id 1.
    client
        .write_all(&mux_new(
            1,
            &marmo_net::Endpoint::from(tcp_echo),
            marmo_proto::mux::NETWORK_TCP,
            b"hello mux",
        ))
        .await
        .expect("tcp new");
    let (meta, data) = frames.next(&mut client).await;
    assert_eq!(meta.session, 1);
    assert_eq!(meta.status, marmo_proto::mux::STATUS_KEEP);
    assert_eq!(data, b"hello mux");
    client.write_all(&mux_end(1)).await.expect("tcp end");

    // UDP session on id 2 over the same physical connection.
    client
        .write_all(&mux_new(
            2,
            &marmo_net::Endpoint::from(udp_echo),
            marmo_proto::mux::NETWORK_UDP,
            b"datagram",
        ))
        .await
        .expect("udp new");
    let (meta, data) = frames.next(&mut client).await;
    assert_eq!(meta.session, 2);
    assert_eq!(meta.status, marmo_proto::mux::STATUS_KEEP);
    assert_eq!(data, b"datagram");
    client.write_all(&mux_end(2)).await.expect("udp end");

    drop(client);
    stop(proxy_handle, proxy_task).await;
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn mux_session_budget_is_separate_from_connections() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "max_connections": 1, "handshake_timeout_s": 5, "idle_timeout_s": 5 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let uuid = marmo_proto::vless::Uuid::parse(UUID).expect("uuid");
    let tcp = TcpStream::connect(proxy_address).await.expect("connect");
    let tls = TlsClient::new(&TlsClientOptions {
        server_name: "localhost",
        alpn: &[],
        required_alpn: None,
        insecure: true,
        client_certificate: None,
        client_private_key: None,
        handshake_timeout: Some(Duration::from_secs(5)),
    })
    .expect("tls client");
    let mut client = tls.wrap(Box::new(tcp)).await.expect("tls handshake");
    let mut header = [0_u8; 64];
    let length = marmo_proto::vless::encode_mux_request(&uuid, &mut header).expect("mux");
    client.write_all(&header[..length]).await.expect("header");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).await.expect("response");
    assert_eq!(response, [0, 0]);

    let target = marmo_net::Endpoint::from(echo);
    client
        .write_all(&mux_new(1, &target, marmo_proto::mux::NETWORK_TCP, b"one"))
        .await
        .expect("first new");
    client
        .write_all(&mux_new(2, &target, marmo_proto::mux::NETWORK_TCP, b"two"))
        .await
        .expect("second new");

    let mut frames = MuxFrames::default();
    let rejected = timeout(Duration::from_secs(2), async {
        loop {
            let (meta, data) = frames.next(&mut client).await;
            if meta.session == 2 && meta.status == marmo_proto::mux::STATUS_END {
                return data;
            }
        }
    })
    .await
    .expect("second session was not rejected");
    assert_eq!(rejected, b"session limit");

    drop(client);
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn mux_downlink_activity_resets_idle_timeout() {
    let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let target_addr = target.local_addr().expect("target addr");
    let target_task = tokio::spawn(async move {
        let Ok((mut stream, _)) = target.accept().await else {
            return;
        };
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(400)).await;
            if stream.write_all(b"x").await.is_err() {
                break;
            }
        }
    });

    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 1 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let uuid = marmo_proto::vless::Uuid::parse(UUID).expect("uuid");
    let tcp = TcpStream::connect(proxy_address).await.expect("connect");
    let tls = TlsClient::new(&TlsClientOptions {
        server_name: "localhost",
        alpn: &[],
        required_alpn: None,
        insecure: true,
        client_certificate: None,
        client_private_key: None,
        handshake_timeout: Some(Duration::from_secs(5)),
    })
    .expect("tls client");
    let mut client = tls.wrap(Box::new(tcp)).await.expect("tls handshake");
    let mut header = [0_u8; 64];
    let length = marmo_proto::vless::encode_mux_request(&uuid, &mut header).expect("mux");
    client.write_all(&header[..length]).await.expect("header");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).await.expect("response");
    assert_eq!(response, [0, 0]);

    client
        .write_all(&mux_new(
            1,
            &marmo_net::Endpoint::from(target_addr),
            marmo_proto::mux::NETWORK_TCP,
            b"open",
        ))
        .await
        .expect("tcp new");

    let mut frames = MuxFrames::default();
    let collect = async {
        let mut received = Vec::new();
        while received.len() < 5 {
            let (meta, data) = frames.next(&mut client).await;
            if meta.session == 1 && !data.is_empty() {
                received.extend_from_slice(&data);
            }
        }
        received
    };
    let received = timeout(Duration::from_secs(4), collect)
        .await
        .expect("downlink activity did not reset the idle timer");
    assert_eq!(received, b"xxxxx");

    drop(client);
    stop(proxy_handle, proxy_task).await;
    target_task.abort();
}

#[tokio::test]
async fn relays_through_vless_mux_tcp() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {} ],
          "route": {{ "final": "vl" }}
        }}"#,
        vless_mux_outbound(proxy_address)
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut clients = Vec::new();
    for _ in 0..8 {
        let mut client = TcpStream::connect(front_address).await.expect("connect");
        socks5_connect(&mut client, echo).await;
        clients.push(client);
    }
    for (index, client) in clients.into_iter().enumerate() {
        let payload: Vec<u8> = (0..8_000)
            .map(|offset| ((offset + index) % 251) as u8)
            .collect();
        let (mut reader, mut writer) = client.into_split();
        let write = writer.write_all(&payload);
        let read = async {
            let mut received = vec![0_u8; payload.len()];
            reader.read_exact(&mut received).await.expect("read");
            received
        };
        let (written, echoed) = tokio::join!(write, read);
        written.expect("write");
        assert_eq!(echoed, payload);
    }

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_through_vless_mux_udp() {
    let (echo, echo_task) = udp_echo().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {} ],
          "route": {{ "final": "vl" }}
        }}"#,
        vless_mux_outbound(proxy_address)
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut control = TcpStream::connect(front_address).await.expect("connect");
    let (datagram, relay) = udp_associate(&mut control).await;
    let payload: Vec<u8> = (0..8_000).map(|index| (index % 251) as u8).collect();
    datagram
        .send_to(&udp_request(echo, &payload), relay)
        .await
        .expect("send");
    let mut reply = vec![0_u8; 65_535];
    let (length, _) = timeout(Duration::from_secs(5), datagram.recv_from(&mut reply))
        .await
        .expect("reply timeout")
        .expect("recv");
    assert!(length >= 10 + payload.len());
    assert_eq!(&reply[10..length], &payload[..]);

    drop(control);
    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_through_vless_mux_over_websocket() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_ws_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let outbound =
        vless_ws_outbound(proxy_address).replace(r#""uuid": "#, r#""mux": true, "uuid": "#);
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {outbound} ],
          "route": {{ "final": "vl" }}
        }}"#
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut client = TcpStream::connect(front_address).await.expect("connect");
    socks5_connect(&mut client, echo).await;
    let payload: Vec<u8> = (0..16_000).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = client.into_split();
    let write = writer.write_all(&payload);
    let read = async {
        let mut received = vec![0_u8; payload.len()];
        reader.read_exact(&mut received).await.expect("read");
        received
    };
    let (written, echoed) = tokio::join!(write, read);
    written.expect("write");
    assert_eq!(echoed, payload);

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_through_vless_mux_over_http2() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_h2_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let outbound =
        vless_h2_outbound(proxy_address).replace(r#""uuid": "#, r#""mux": true, "uuid": "#);
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {outbound} ],
          "route": {{ "final": "vl" }}
        }}"#
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut client = TcpStream::connect(front_address).await.expect("connect");
    socks5_connect(&mut client, echo).await;
    let payload: Vec<u8> = (0..16_000).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = client.into_split();
    let write = writer.write_all(&payload);
    let read = async {
        let mut received = vec![0_u8; payload.len()];
        reader.read_exact(&mut received).await.expect("read");
        received
    };
    let (written, echoed) = tokio::join!(write, read);
    written.expect("write");
    assert_eq!(echoed, payload);
    assert_eq!(proxy_handle.metrics().connections_accepted, 1);

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

async fn h2_client(server: SocketAddr) -> marmo_transport::H2ClientConnection {
    let tcp = TcpStream::connect(server).await.expect("connect");
    let tls = TlsClient::new(&TlsClientOptions {
        server_name: "localhost",
        alpn: &["h2".to_owned()],
        required_alpn: Some("h2"),
        insecure: true,
        client_certificate: None,
        client_private_key: None,
        handshake_timeout: Some(Duration::from_secs(5)),
    })
    .expect("tls client");
    let stream = tls.wrap(Box::new(tcp)).await.expect("tls handshake");
    H2Client::new(H2ClientOptions {
        host: "localhost".into(),
        path: "/h2".into(),
    })
    .handshake(stream)
    .await
    .expect("h2 handshake")
}

fn vless_tcp_request(target: &marmo_net::Endpoint) -> Vec<u8> {
    let uuid = marmo_proto::vless::Uuid::parse(UUID).expect("uuid");
    let mut header = [0_u8; 256];
    let length = marmo_proto::vless::encode_request(
        &uuid,
        target,
        marmo_proto::vless::COMMAND_TCP,
        &mut header,
    )
    .expect("encode request");
    header[..length].to_vec()
}

#[tokio::test]
async fn serves_multiple_vless_streams_on_one_http2_connection() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_h2_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let connection = h2_client(proxy_address).await;
    let request = vless_tcp_request(&marmo_net::Endpoint::from(echo));

    let mut streams = Vec::new();
    for _ in 0..4 {
        streams.push(connection.open_stream().await.expect("open stream"));
    }

    for (index, stream) in streams.iter_mut().enumerate() {
        stream.write_all(&request).await.expect("request header");
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.expect("response");
        assert_eq!(response, [0, 0]);

        let payload = format!("stream-{index}");
        stream.write_all(payload.as_bytes()).await.expect("write");
        let mut echoed = vec![0_u8; payload.len()];
        stream.read_exact(&mut echoed).await.expect("read");
        assert_eq!(echoed, payload.as_bytes());
        stream.shutdown().await.expect("shutdown");
    }

    let metrics = proxy_handle.metrics();
    assert_eq!(metrics.connections_accepted, 1);
    assert_eq!(metrics.h2_streams_accepted, 4);
    assert_eq!(metrics.h2_streams_rejected, 0);

    drop(connection);
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn rejects_vless_http2_streams_over_the_stream_budget() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{
            "max_connections": 1,
            "handshake_timeout_s": 5,
            "idle_timeout_s": 10
          }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vless_h2_inbound()
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let connection = h2_client(proxy_address).await;
    let request = vless_tcp_request(&marmo_net::Endpoint::from(echo));

    // Hold the only stream permit open.
    let mut first = connection.open_stream().await.expect("first stream");
    first.write_all(&request).await.expect("first request");
    let mut response = [0_u8; 2];
    first
        .read_exact(&mut response)
        .await
        .expect("first response");
    first.write_all(b"first").await.expect("first write");
    let mut echoed = [0_u8; 5];
    first.read_exact(&mut echoed).await.expect("first read");

    // The second stream gets an HTTP/2 200 or a reset, but either way the
    // stream budget rejects it.
    let second = connection.open_stream().await;
    if let Ok(mut stream) = second {
        let _ = stream.write_all(&request).await;
        let mut response = [0_u8; 2];
        let _ = stream.read_exact(&mut response).await;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if proxy_handle.metrics().h2_streams_rejected == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "stream rejection was not recorded"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(proxy_handle.metrics().connections_accepted, 1);
    assert_eq!(proxy_handle.metrics().h2_streams_accepted, 1);

    drop(first);
    drop(connection);
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn pools_vless_http2_connections() {
    let (echo, echo_task) = echo_server().await;
    let (front, front_handle, front_task, proxy_handle, proxy_task) =
        ws_chain(vless_h2_inbound(), vless_h2_outbound).await;

    let mut clients = Vec::new();
    for _ in 0..4 {
        let mut client = TcpStream::connect(front).await.expect("connect");
        socks5_connect(&mut client, echo).await;
        clients.push(client);
    }

    for (index, client) in clients.iter_mut().enumerate() {
        let payload = format!("pooled-{index}");
        client.write_all(payload.as_bytes()).await.expect("write");
        let mut echoed = vec![0_u8; payload.len()];
        client.read_exact(&mut echoed).await.expect("read");
        assert_eq!(echoed, payload.as_bytes());
    }

    let metrics = proxy_handle.metrics();
    assert_eq!(metrics.connections_accepted, 1);
    assert!(metrics.h2_streams_accepted >= 4);

    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}
