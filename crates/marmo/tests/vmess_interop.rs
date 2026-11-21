//! VMess reference interop against a local Xray server.
//!
//! Ignored by default: CI has no reference binary. Run with
//! `cargo test -p marmo --test vmess_interop -- --ignored --nocapture`
//! when `xray` (26.11.9 or compatible) is on `PATH`.

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use marmo_net::Endpoint;
use marmo_proto::vless::Uuid;
use marmo_proto::vmess::{
    CHUNK_WIRE_MAX, COMMAND_TCP, COMMAND_UDP, ChunkDecoder, ChunkEncoder, ChunkProgress, CmdKey,
    OPTION_MASKING, OPTION_PADDING, OPTION_STREAM, REQUEST_HEADER_MAX, Request, RequestProgress,
    RequestSecrets, RequestSpec, ResponseProgress, Security, encode_request, request_progress,
    response_keys, response_progress,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OPTION: u8 = OPTION_STREAM | OPTION_MASKING | OPTION_PADDING;

struct Xray {
    child: Child,
    address: SocketAddr,
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
async fn start_xray() -> Xray {
    let port = free_port();
    let config = std::env::temp_dir().join(format!("marmo-xray-{port}.json"));
    let text = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {port},
    "protocol": "vmess",
    "settings": {{ "clients": [{{ "id": "{UUID}", "alterId": 0 }}] }},
    "streamSettings": {{ "network": "tcp" }}
  }}],
  "outbounds": [{{ "protocol": "freedom", "settings": {{ "finalRules": [
    {{ "action": "allow", "ip": ["127.0.0.0/8"] }}
  ] }} }}]
}}"#
    );
    let mut file = std::fs::File::create(&config).expect("config");
    file.write_all(text.as_bytes()).expect("write");
    drop(file);
    let child = Command::new("xray")
        .arg("run")
        .arg("-c")
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn xray");
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() {
            return Xray {
                child,
                address,
                config,
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("xray did not start");
}

async fn tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

async fn udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

fn secrets() -> RequestSecrets {
    let mut value = RequestSecrets {
        body_iv: [0; 16],
        body_key: [0; 16],
        response_auth: 0,
        auth_rand: [0; 4],
        connection_nonce: [0; 8],
    };
    getrandom::fill(&mut value.body_iv).expect("random");
    getrandom::fill(&mut value.body_key).expect("random");
    getrandom::fill(&mut value.auth_rand).expect("random");
    getrandom::fill(&mut value.connection_nonce).expect("random");
    getrandom::fill(std::slice::from_mut(&mut value.response_auth)).expect("random");
    value
}

async fn exchange(
    xray: &Xray, target: SocketAddr, command: u8, security: Security, option: u8, payload: &[u8],
) -> Vec<u8> {
    let uuid = Uuid::parse(UUID).expect("uuid");
    let cmd_key = CmdKey::derive(&uuid);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let secrets = secrets();
    let target = Endpoint::from(target);
    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request(
        &cmd_key,
        &RequestSpec {
            target: &target,
            command,
            security,
            timestamp: now,
            padding: &[],
            secrets: &secrets,
        },
        &mut header,
    )
    .expect("encode");
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(xray.address))
        .await
        .expect("connect timeout")
        .expect("connect");
    stream.write_all(&header[..length]).await.expect("header");

    let mut encoder = ChunkEncoder::new(
        security,
        &secrets.body_key,
        &secrets.body_iv,
        option,
        [0x5a; 64],
    );
    let mut wire = Vec::new();
    encoder.encode(payload, &mut wire).expect("chunk");
    stream.write_all(&wire).await.expect("body");
    eprintln!(
        "sent request header {length} bytes, chunk {} bytes",
        wire.len()
    );

    let request = {
        let RequestProgress::Complete(request) = request_progress(&header[..length], &cmd_key, now)
        else {
            panic!("request did not decode");
        };
        request
    };
    drop(secrets);

    let mut response_header = ResponseReader::default();
    let leftover = timeout(
        Duration::from_secs(5),
        response_header.read(&mut stream, &request),
    )
    .await
    .expect("response header timeout");

    let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
    let mut decoder = ChunkDecoder::new(security, &response_key, &response_iv, option);
    let mut chunks = ChunkReader { buffer: leftover };
    timeout(
        Duration::from_secs(5),
        chunks.next(&mut stream, &mut decoder),
    )
    .await
    .expect("read timeout")
}

#[derive(Default)]
struct ResponseReader {
    buffer: Vec<u8>,
}

impl ResponseReader {
    async fn read(&mut self, stream: &mut TcpStream, request: &Request) -> Vec<u8> {
        loop {
            match response_progress(&self.buffer, request) {
                ResponseProgress::Complete { consumed } => {
                    self.buffer.drain(..consumed);
                    return std::mem::take(&mut self.buffer);
                }
                ResponseProgress::Invalid => panic!("invalid response header"),
                ResponseProgress::NeedMore { .. } => {
                    let mut extra = vec![0_u8; 128];
                    let read = stream.read(&mut extra).await.expect("read");
                    assert!(read > 0, "eof before response header");
                    self.buffer.extend_from_slice(&extra[..read]);
                    assert!(self.buffer.len() <= 4096);
                }
            }
        }
    }
}

#[derive(Default)]
struct ChunkReader {
    buffer: Vec<u8>,
}

impl ChunkReader {
    async fn next(&mut self, stream: &mut TcpStream, decoder: &mut ChunkDecoder) -> Vec<u8> {
        loop {
            match decoder.progress(&self.buffer) {
                Ok(ChunkProgress::Complete { consumed, data }) => {
                    self.buffer.drain(..consumed);
                    return data;
                }
                Ok(ChunkProgress::NeedMore { needed }) => {
                    assert!(needed <= CHUNK_WIRE_MAX);
                    let mut extra = vec![0_u8; 8192];
                    let read = stream.read(&mut extra).await.expect("read");
                    assert!(read > 0, "eof before chunk");
                    self.buffer.extend_from_slice(&extra[..read]);
                }
                Err(error) => panic!("chunk decode: {error}"),
            }
        }
    }
}

fn run_test() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let xray = start_xray().await;
        let (tcp, _tcp_task) = tcp_echo().await;
        let (udp, _udp_task) = udp_echo().await;
        for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            let echoed = exchange(&xray, tcp, COMMAND_TCP, security, OPTION, b"hello vmess").await;
            assert_eq!(echoed, b"hello vmess", "tcp {security:?}");
        }
        let echoed = exchange(
            &xray,
            udp,
            COMMAND_UDP,
            Security::Aes128Gcm,
            OPTION,
            b"ping",
        )
        .await;
        assert_eq!(echoed, b"ping", "udp");
    });
}

#[test]
#[ignore = "requires a local xray binary"]
fn interop_with_xray() {
    run_test();
}

#[allow(clippy::zombie_processes)]
async fn capture_xray_request() {
    let mock = TcpListener::bind(("127.0.0.1", 0)).await.expect("mock");
    let mock_port = mock.local_addr().expect("addr").port();
    let socks_port = free_port();
    let config = std::env::temp_dir().join(format!("marmo-xray-client-{socks_port}.json"));
    let text = format!(
        r#"{{
  "log": {{ "loglevel": "debug" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": false }}
  }}],
  "outbounds": [{{
    "protocol": "vmess",
    "settings": {{ "vnext": [{{
      "address": "127.0.0.1",
      "port": {mock_port},
      "users": [{{ "id": "{UUID}", "alterId": 0, "security": "aes-128-gcm" }}]
    }}] }},
    "streamSettings": {{ "network": "tcp", "security": "none" }}
  }}]
}}"#
    );
    let mut file = std::fs::File::create(&config).expect("config");
    file.write_all(text.as_bytes()).expect("write");
    drop(file);
    let mut child = Command::new("xray")
        .arg("run")
        .arg("-c")
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn xray");
    let socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
    for _ in 0..100 {
        if TcpStream::connect(socks).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let capture = tokio::spawn(async move {
        let (mut stream, _) = mock.accept().await.expect("accept");
        let mut buffer = vec![0_u8; 4096];
        let mut filled = 0;
        for _ in 0..20 {
            let read = timeout(
                Duration::from_millis(250),
                stream.read(&mut buffer[filled..]),
            )
            .await;
            match read {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => filled += n,
                _ => break,
            }
        }
        buffer.truncate(filled);
        buffer
    });

    let mut client = TcpStream::connect(socks).await.expect("socks");
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut reply = [0_u8; 2];
    client.read_exact(&mut reply).await.expect("greeting reply");
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 9])
        .await
        .expect("connect");
    let mut reply = [0_u8; 10];
    let _ = timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await;
    eprintln!("socks reply: {:02x?}", reply);
    client.write_all(b"hello").await.expect("payload");

    let bytes = capture.await.expect("capture");
    eprintln!("captured {} bytes: {:02x?}", bytes.len(), bytes);
    let uuid = Uuid::parse(UUID).expect("uuid");
    let cmd_key = CmdKey::derive(&uuid);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    match request_progress(&bytes, &cmd_key, now) {
        RequestProgress::Complete(request) => {
            eprintln!(
                "decoded: command {} target {} security {:?} option {:#x} consumed {}",
                request.command, request.target, request.security, request.option, request.consumed
            );
            eprintln!("iv {:02x?}", request.body_iv);
            eprintln!("key {:02x?}", request.body_key);
            eprintln!("chunk bytes {:02x?}", &bytes[request.consumed..]);
            let mut decoder = ChunkDecoder::new(
                request.security,
                &request.body_key,
                &request.body_iv,
                request.option,
            );
            match decoder.progress(&bytes[request.consumed..]) {
                Ok(ChunkProgress::Complete { consumed, data }) => {
                    eprintln!(
                        "chunk: {consumed} bytes, payload {:?}",
                        String::from_utf8_lossy(&data)
                    );
                }
                other => eprintln!("chunk decode failed: {other:?}"),
            }
        }
        other => eprintln!("decode failed: {other:?}"),
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&config);
}

#[test]
#[ignore = "requires a local xray binary"]
fn capture_request_from_xray() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(capture_xray_request());
}

// ---------------------------------------------------------------------------
// Instance-level interop: marmo outbound against Xray, Xray against marmo.
// ---------------------------------------------------------------------------

use marmo::{Config, Instance, InstanceHandle, ServeError};

async fn start_marmo(
    json: &str,
) -> (
    SocketAddr,
    InstanceHandle,
    tokio::task::JoinHandle<Result<(), ServeError>>,
) {
    let config = Config::from_json(json).expect("config");
    let instance = Instance::builder(config).build().expect("build");
    let bound = instance.bind().await.expect("bind");
    let address = bound.local_addrs().next().expect("inbound").addr;
    let handle = bound.handle();
    let task = tokio::spawn(bound.serve());
    (address, handle, task)
}

async fn stop_marmo(handle: InstanceHandle, task: tokio::task::JoinHandle<Result<(), ServeError>>) {
    handle.shutdown();
    timeout(Duration::from_secs(2), task)
        .await
        .expect("serve timeout")
        .expect("join")
        .expect("serve");
}

#[allow(clippy::zombie_processes)]
async fn start_xray_config(text: &str, port: u16, probe: bool) -> Xray {
    let config = std::env::temp_dir().join(format!("marmo-xray-{port}.json"));
    let mut file = std::fs::File::create(&config).expect("config");
    file.write_all(text.as_bytes()).expect("write");
    drop(file);
    let child = Command::new("xray")
        .arg("run")
        .arg("-c")
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn xray");
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    if probe {
        for _ in 0..100 {
            if TcpStream::connect(address).await.is_ok() {
                return Xray {
                    child,
                    address,
                    config,
                };
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("xray did not start");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    Xray {
        child,
        address,
        config,
    }
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

async fn echo_tcp() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

async fn echo_udp() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

fn vmess_server_config(port: u16, network: &str, path: &str) -> String {
    let ws = if network == "ws" {
        format!(r#", "wsSettings": {{ "path": "{path}" }}"#)
    } else {
        String::new()
    };
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {port}, "protocol": "vmess",
    "settings": {{ "clients": [{{ "id": "{UUID}", "alterId": 0 }}] }},
    "streamSettings": {{ "network": "{network}"{ws} }}
  }}],
  "outbounds": [{{ "protocol": "freedom", "settings": {{ "finalRules": [
    {{ "action": "allow", "ip": ["127.0.0.0/8"] }}
  ] }} }}]
}}"#
    )
}

fn marmo_outbound_config(server: SocketAddr, network: &str, path: &str) -> String {
    let ws = if network == "ws" {
        format!(r#", "transport": {{ "network": "ws", "path": "{path}" }}"#)
    } else {
        String::new()
    };
    format!(
        r#"{{
  "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
  "inbounds": [{{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}],
  "outbounds": [{{ "tag": "vm", "protocol": "vmess", "server": "{server}",
    "uuid": "{UUID}", "security": "aes-128-gcm"{ws} }}],
  "route": {{ "final": "vm" }}
}}"#
    )
}

fn marmo_vmess_inbound_config() -> String {
    format!(
        r#"{{
  "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
  "inbounds": [{{ "tag": "vm", "protocol": "vmess", "listen": "127.0.0.1:0",
    "uuid": "{UUID}" }}],
  "outbounds": [{{ "tag": "direct", "protocol": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#
    )
}

fn xray_client_config(socks_port: u16, server: SocketAddr, mux: bool) -> String {
    let mux = if mux {
        r#", "mux": { "enabled": true }"#
    } else {
        ""
    };
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {socks_port}, "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": true }}
  }}],
  "outbounds": [{{
    "protocol": "vmess",
    "settings": {{ "vnext": [{{ "address": "127.0.0.1", "port": {server_port},
      "users": [{{ "id": "{UUID}", "alterId": 0, "security": "aes-128-gcm" }}] }}] }},
    "streamSettings": {{ "network": "tcp", "security": "none" }}{mux}
  }}]
}}"#,
        server_port = server.port(),
    )
}

#[test]
#[ignore = "requires a local xray binary"]
fn instance_interop_with_xray() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let (echo, echo_task) = echo_tcp().await;
        let (udp_echo, udp_task) = echo_udp().await;

        // marmo outbound -> Xray inbound, plain TCP and WebSocket.
        for (network, path) in [("tcp", ""), ("ws", "/ws")] {
            let port = free_port();
            let xray =
                start_xray_config(&vmess_server_config(port, network, path), port, true).await;
            let (proxy, handle, task) = start_marmo(&marmo_outbound_config(
                SocketAddr::from(([127, 0, 0, 1], port)),
                network,
                path,
            ))
            .await;
            tcp_through_socks(proxy, echo).await;
            udp_through_socks(proxy, udp_echo).await;
            stop_marmo(handle, task).await;
            drop(xray);
        }

        // Xray outbound -> marmo inbound, with and without mux.
        for mux in [false, true] {
            let (inbound, handle, task) = start_marmo(&marmo_vmess_inbound_config()).await;
            let socks_port = free_port();
            let xray = start_xray_config(
                &xray_client_config(socks_port, inbound, mux),
                socks_port,
                true,
            )
            .await;
            let socks = SocketAddr::from(([127, 0, 0, 1], socks_port));
            tcp_through_socks(socks, echo).await;
            udp_through_socks(socks, udp_echo).await;
            stop_marmo(handle, task).await;
            drop(xray);
        }

        echo_task.abort();
        udp_task.abort();
    });
}
