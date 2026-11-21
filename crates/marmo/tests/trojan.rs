//! Trojan loopback tests through the public `Instance`.

use std::net::SocketAddr;
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, ServeError};
use marmo_transport::TlsClient;
use marmo_transport::tls::TlsClientOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const SERVER_CERT: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.pem");
const SERVER_KEY: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.key");

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

#[test]
fn json_escaping_handles_crlf() {
    assert_eq!(json_string("a\r\nb"), "\"a\\r\\nb\"");
}

fn trojan_inbound(fallback: Option<SocketAddr>) -> String {
    let fallback = fallback
        .map(|address| format!(r#","fallback":"{address}""#))
        .unwrap_or_default();
    format!(
        r#"{{ "tag": "tj", "protocol": "trojan", "listen": "127.0.0.1:0",
             "password": "s3cret"{fallback},
             "tls": {{ "certificate": {}, "private_key": {} }} }}"#,
        json_string(SERVER_CERT),
        json_string(SERVER_KEY)
    )
}

#[tokio::test]
async fn relays_through_trojan_tcp() {
    let (echo, echo_task) = echo_server().await;

    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "tj", "protocol": "trojan", "listen": "127.0.0.1:0",
               "password": "s3cret",
               "tls": {{ "certificate": {}, "private_key": {} }} }}
          ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        json_string(SERVER_CERT),
        json_string(SERVER_KEY)
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [
            {{ "tag": "tj", "protocol": "trojan", "server": "{proxy_address}",
               "password": "s3cret", "tls": {{ "insecure": true }} }}
          ],
          "route": {{ "final": "tj" }}
        }}"#
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
async fn trojan_fallback_relays_unknown_traffic() {
    let (fallback, fallback_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        trojan_inbound(Some(fallback))
    );
    let (address, handle, task) = start(&proxy).await;

    let client = TlsClient::new(&TlsClientOptions {
        server_name: "localhost",
        alpn: &[],
        required_alpn: None,
        insecure: true,
        client_certificate: None,
        client_private_key: None,
        handshake_timeout: None,
    })
    .expect("tls client");
    let stream = TcpStream::connect(address).await.expect("connect");
    let mut stream = client.connect(Box::new(stream)).await.expect("handshake");
    let request = b"GET / HTTP/1.1\r\nHost: fallback\r\n\r\n";
    stream.write_all(request).await.expect("write");
    let mut received = vec![0_u8; request.len()];
    timeout(Duration::from_secs(2), stream.read_exact(&mut received))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&received, request);

    stop(handle, task).await;
    fallback_task.abort();
}

#[tokio::test]
async fn trojan_rejects_wrong_password_without_fallback() {
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        trojan_inbound(None)
    );
    let (address, handle, task) = start(&proxy).await;

    let client = TlsClient::new(&TlsClientOptions {
        server_name: "localhost",
        alpn: &[],
        required_alpn: None,
        insecure: true,
        client_certificate: None,
        client_private_key: None,
        handshake_timeout: None,
    })
    .expect("tls client");
    let stream = TcpStream::connect(address).await.expect("connect");
    let mut stream = client.connect(Box::new(stream)).await.expect("handshake");
    stream
        .write_all(b"not-a-trojan-request")
        .await
        .expect("write");
    let mut buffer = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), stream.read(&mut buffer))
        .await
        .expect("read timeout");
    assert!(matches!(read, Ok(0) | Err(_)));

    stop(handle, task).await;
}

#[tokio::test]
async fn relays_through_trojan_udp() {
    let (echo, echo_task) = udp_echo().await;

    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        trojan_inbound(None)
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [
            {{ "tag": "tj", "protocol": "trojan", "server": "{proxy_address}",
               "password": "s3cret", "tls": {{ "insecure": true }} }}
          ],
          "route": {{ "final": "tj" }}
        }}"#
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
