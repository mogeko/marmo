//! VLESS Mux.Cool interop against a local Xray client.
//!
//! Ignored by default: CI has no reference binary. Run with
//! `cargo test -p marmo --test vless_interop -- --ignored --nocapture`.

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, ServeError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const SERVER_CERT: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.pem");
const SERVER_KEY: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.key");
const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

struct Xray {
    child: Child,
    config: std::path::PathBuf,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    listener.local_addr().expect("addr").port()
}

#[allow(clippy::zombie_processes)]
async fn start_xray(config: &str, port: u16) -> Xray {
    let path = std::env::temp_dir().join(format!("marmo-vless-xray-{port}.json"));
    let mut file = std::fs::File::create(&path).expect("config");
    file.write_all(config.as_bytes()).expect("write");
    drop(file);
    let child = Command::new("xray")
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn xray");
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() {
            return Xray {
                child,
                config: path,
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("xray did not start");
}

async fn start_marmo(
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

async fn stop_marmo(handle: InstanceHandle, task: JoinHandle<Result<(), ServeError>>) {
    handle.shutdown();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("serve timeout")
        .expect("join")
        .expect("serve");
}

async fn echo_tcp() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (address, task)
}

async fn echo_udp() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let address = socket.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 65_535];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..length], peer).await;
        }
    });
    (address, task)
}

async fn socks_connect(client: &mut TcpStream, target: SocketAddr) {
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);
    let SocketAddr::V4(target) = target else {
        panic!("ipv4 only");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.expect("request");
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0);
}

async fn socks_udp(client: &mut TcpStream) -> (UdpSocket, SocketAddr) {
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.expect("method");
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
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("udp");
    (socket, relay)
}

fn socks_udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(target) = target else {
        panic!("ipv4 only");
    };
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn tcp_through_socks(proxy: SocketAddr, target: SocketAddr) {
    let mut client = TcpStream::connect(proxy).await.expect("connect");
    socks_connect(&mut client, target).await;
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
}

async fn udp_through_socks(proxy: SocketAddr, target: SocketAddr) {
    let mut control = TcpStream::connect(proxy).await.expect("connect");
    let (datagram, relay) = socks_udp(&mut control).await;
    let payload: Vec<u8> = (0..4_000).map(|index| (index % 251) as u8).collect();
    datagram
        .send_to(&socks_udp_packet(target, &payload), relay)
        .await
        .expect("send");
    let mut reply = vec![0_u8; 65_535];
    let (length, _) = timeout(Duration::from_secs(5), datagram.recv_from(&mut reply))
        .await
        .expect("reply timeout")
        .expect("recv");
    assert_eq!(&reply[10..length], &payload[..]);
    drop(control);
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

fn marmo_inbound() -> String {
    format!(
        r#"{{
  "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
  "inbounds": [{{
    "tag": "vl", "protocol": "vless", "listen": "127.0.0.1:0", "uuid": "{UUID}",
    "tls": {{ "certificate": {}, "private_key": {} }}
  }}],
  "outbounds": [{{ "tag": "direct", "protocol": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        json_string(SERVER_CERT),
        json_string(SERVER_KEY)
    )
}

fn xray_client(socks_port: u16, server: SocketAddr) -> String {
    // SHA-256 of the DER leaf certificate in the TLS test fixture. Xray 26.11.9
    // removed `allowInsecure`, so interop pins the test certificate instead.
    let pin = "ed608c59dc77d50801ed0889fad68623277e400daec375869965a27e90b5ba6f";
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {socks_port}, "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": true }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{ "vnext": [{{ "address": "127.0.0.1", "port": {server_port},
      "users": [{{ "id": "{UUID}", "encryption": "none" }}] }}] }},
    "streamSettings": {{
      "network": "tcp", "security": "tls",
      "tlsSettings": {{ "serverName": "localhost",
        "pinnedPeerCertSha256": "{pin}" }}
    }},
    "mux": {{ "enabled": true }}
  }}]
}}"#,
        server_port = server.port(),
    )
}

#[test]
#[ignore = "requires a local xray binary"]
fn vless_mux_interop_with_xray() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let (tcp_echo, tcp_task) = echo_tcp().await;
        let (udp_echo, udp_task) = echo_udp().await;
        let (inbound, handle, task) = start_marmo(&marmo_inbound()).await;
        let socks_port = free_port();
        let xray = start_xray(&xray_client(socks_port, inbound), socks_port).await;
        let socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
        tcp_through_socks(socks, tcp_echo).await;
        udp_through_socks(socks, udp_echo).await;
        stop_marmo(handle, task).await;
        drop(xray);
        tcp_task.abort();
        udp_task.abort();
    });
}
