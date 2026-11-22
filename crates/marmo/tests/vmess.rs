//! VMess loopback tests through the public `Instance`, plus Mux.Cool.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use marmo::{Config, Instance, InstanceHandle, ServeError};
use marmo_net::Endpoint;
use marmo_proto::mux::{
    KEEPALIVE_META, NETWORK_TCP, NETWORK_UDP, STATUS_END, STATUS_KEEP, encode_header,
    encode_new_meta, parse_meta,
};
use marmo_proto::vless::Uuid;
use marmo_proto::vmess::{
    CHUNK_WIRE_MAX, COMMAND_MUX, COMMAND_TCP, ChunkDecoder, ChunkEncoder, ChunkProgress, CmdKey,
    OPTION_MASKING, OPTION_PADDING, OPTION_STREAM, REQUEST_HEADER_MAX, Request, RequestProgress,
    RequestSecrets, RequestSpec, ResponseProgress, Security, encode_request, request_progress,
    response_keys, response_progress,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const SERVER_CERT: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.pem");
const SERVER_KEY: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.key");
const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const OPTION: u8 = OPTION_STREAM | OPTION_MASKING | OPTION_PADDING;

async fn echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
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
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
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

fn vmess_inbound(tls: bool, transport: &str) -> String {
    let tls = if tls {
        format!(
            r#", "tls": {{ "certificate": {}, "private_key": {} }}"#,
            json_string(SERVER_CERT),
            json_string(SERVER_KEY)
        )
    } else {
        String::new()
    };
    let transport = match transport {
        "ws" => r#", "transport": { "network": "ws", "path": "/ws", "subprotocols": ["marmo"] }"#,
        "h2" => r#", "transport": { "network": "h2", "path": "/h2" }"#,
        _ => "",
    };
    format!(
        r#"{{ "tag": "vm", "protocol": "vmess", "listen": "127.0.0.1:0",
             "uuid": "{UUID}"{tls}{transport} }}"#
    )
}

fn vmess_outbound(server: SocketAddr, tls: bool, transport: &str) -> String {
    let tls = if tls {
        r#", "tls": { "insecure": true }"#
    } else {
        ""
    };
    let transport = match transport {
        "ws" => r#", "transport": { "network": "ws", "path": "/ws", "subprotocols": ["marmo"] }"#,
        "h2" => r#", "transport": { "network": "h2", "path": "/h2" }"#,
        _ => "",
    };
    format!(
        r#"{{ "tag": "vm", "protocol": "vmess", "server": "{server}",
             "uuid": "{UUID}"{tls}{transport} }}"#
    )
}

async fn tcp_round_trip(tls: bool, transport: &str, security: &str, mux: bool) {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vmess_inbound(tls, transport)
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let outbound = vmess_outbound(proxy_address, tls, transport).replace(
        r#""uuid": "#,
        &format!(r#""security": "{security}", "mux": {mux}, "uuid": "#),
    );
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {outbound} ],
          "route": {{ "final": "vm" }}
        }}"#
    );
    let (front_address, front_handle, front_task) = start(&front).await;

    let mut client = TcpStream::connect(front_address).await.expect("connect");
    socks5_connect(&mut client, echo).await;
    let payload: Vec<u8> = (0..64_000).map(|index| (index % 251) as u8).collect();
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
async fn relays_through_vmess_tcp() {
    tcp_round_trip(false, "tcp", "aes-128-gcm", false).await;
}

#[tokio::test]
async fn relays_through_vmess_tcp_chacha() {
    tcp_round_trip(false, "tcp", "chacha20-poly1305", false).await;
}

#[tokio::test]
async fn relays_through_vmess_tls() {
    tcp_round_trip(true, "tcp", "aes-128-gcm", false).await;
}

#[tokio::test]
async fn relays_through_vmess_ws() {
    tcp_round_trip(true, "ws", "aes-128-gcm", false).await;
}

#[tokio::test]
async fn relays_through_vmess_h2() {
    tcp_round_trip(true, "h2", "aes-128-gcm", false).await;
}

#[tokio::test]
async fn relays_through_vmess_tcp_mux() {
    tcp_round_trip(false, "tcp", "aes-128-gcm", true).await;
}

#[tokio::test]
async fn relays_through_vmess_udp() {
    let (echo, echo_task) = udp_echo().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vmess_inbound(false, "tcp")
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {} ],
          "route": {{ "final": "vm" }}
        }}"#,
        vmess_outbound(proxy_address, false, "tcp")
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
async fn relays_through_vmess_udp_mux() {
    let (echo, echo_task) = udp_echo().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vmess_inbound(false, "tcp")
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let outbound = vmess_outbound(proxy_address, false, "tcp")
        .replace(r#""uuid": "#, r#""mux": true, "uuid": "#);
    let front = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [ {outbound} ],
          "route": {{ "final": "vm" }}
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
    assert_eq!(&reply[10..length], &payload[..]);

    drop(control);
    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
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
                    let mut extra = [0_u8; 256];
                    let read = stream.read(&mut extra).await.expect("read");
                    assert!(read > 0, "eof before response header");
                    self.buffer.extend_from_slice(&extra[..read]);
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
                Ok(ChunkProgress::NeedMore { .. }) => {
                    let mut extra = vec![0_u8; 8192];
                    let read = stream.read(&mut extra).await.expect("read");
                    assert!(read > 0, "eof before chunk");
                    self.buffer.extend_from_slice(&extra[..read]);
                    assert!(self.buffer.len() <= CHUNK_WIRE_MAX + 8192);
                }
                Err(error) => panic!("chunk decode: {error}"),
            }
        }
    }
}

struct VmessClient {
    stream: TcpStream,
    encoder: ChunkEncoder,
    decoder: ChunkDecoder,
    chunks: ChunkReader,
}

impl VmessClient {
    async fn connect(server: SocketAddr, target: &Endpoint, command: u8) -> Self {
        let uuid = Uuid::parse(UUID).expect("uuid");
        let key = CmdKey::derive(&uuid);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let mut secrets = RequestSecrets {
            body_iv: [0; 16],
            body_key: [0; 16],
            response_auth: 0,
            auth_rand: [0; 4],
            connection_nonce: [0; 8],
        };
        getrandom::fill(&mut secrets.body_iv).expect("random");
        getrandom::fill(&mut secrets.body_key).expect("random");
        getrandom::fill(&mut secrets.auth_rand).expect("random");
        getrandom::fill(&mut secrets.connection_nonce).expect("random");
        getrandom::fill(std::slice::from_mut(&mut secrets.response_auth)).expect("random");
        let mut header = [0_u8; REQUEST_HEADER_MAX];
        let length = encode_request(
            &key,
            &RequestSpec {
                target,
                command,
                security: Security::Aes128Gcm,
                timestamp: now,
                padding: &[],
                secrets: &secrets,
            },
            &mut header,
        )
        .expect("encode");
        let mut stream = TcpStream::connect(server).await.expect("connect");
        stream.write_all(&header[..length]).await.expect("header");
        let RequestProgress::Complete(request) = request_progress(&header[..length], &key, now)
        else {
            panic!("request");
        };
        let encoder = ChunkEncoder::new(
            Security::Aes128Gcm,
            &request.body_key,
            &request.body_iv,
            OPTION,
            [0x5a; 64],
        );
        let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
        let decoder = ChunkDecoder::new(Security::Aes128Gcm, &response_key, &response_iv, OPTION);
        let mut response = ResponseReader::default();
        let leftover = response.read(&mut stream, &request).await;
        Self {
            stream,
            encoder,
            decoder,
            chunks: ChunkReader { buffer: leftover },
        }
    }

    async fn send_chunk(&mut self, payload: &[u8]) {
        let mut wire = Vec::new();
        self.encoder.encode(payload, &mut wire).expect("chunk");
        self.stream.write_all(&wire).await.expect("write");
    }

    async fn recv_chunk(&mut self) -> Vec<u8> {
        self.chunks.next(&mut self.stream, &mut self.decoder).await
    }
}

fn mux_frame(meta: &[u8], data: &[u8]) -> Vec<u8> {
    if meta[3] & marmo_proto::mux::OPTION_DATA == 0 {
        let mut frame = (meta.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(meta);
        return frame;
    }
    let mut header = [0_u8; 2 + 512 + 2];
    let length = encode_header(meta, data.len(), &mut header).expect("header");
    let mut frame = header[..length].to_vec();
    frame.extend_from_slice(data);
    frame
}

fn mux_new(session: u16, target: &Endpoint, network: u8, data: &[u8]) -> Vec<u8> {
    let mut meta = [0_u8; 512];
    let length = encode_new_meta(session, target, network, &mut meta).expect("new");
    mux_frame(&meta[..length], data)
}

fn mux_end(session: u16) -> Vec<u8> {
    let meta = [
        session.to_be_bytes()[0],
        session.to_be_bytes()[1],
        STATUS_END,
        0,
    ];
    mux_frame(&meta, &[])
}

fn take_mux_frame(buffer: &mut Vec<u8>) -> Option<(marmo_proto::mux::Meta, Vec<u8>)> {
    if buffer.len() < 2 {
        return None;
    }
    let meta_len = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
    if buffer.len() < 2 + meta_len {
        return None;
    }
    let meta = parse_meta(&buffer[2..2 + meta_len]).ok()?;
    let offset = 2 + meta_len;
    let data_len = if meta.option & marmo_proto::mux::OPTION_DATA != 0 {
        if buffer.len() < offset + 2 {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([buffer[offset], buffer[offset + 1]]));
        if buffer.len() < offset + 2 + length {
            return None;
        }
        length
    } else {
        0
    };
    let data = if data_len == 0 {
        Vec::new()
    } else {
        buffer[offset + 2..offset + 2 + data_len].to_vec()
    };
    buffer.drain(..offset + 2 + data_len);
    Some((meta, data))
}

#[tokio::test]
async fn terminates_mux_tcp_and_udp_sessions() {
    let (tcp_echo, tcp_task) = echo_server().await;
    let (udp_echo, udp_task) = udp_echo().await;
    let proxy = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 5, "idle_timeout_s": 10 }},
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vmess_inbound(false, "tcp")
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let mux_target = Endpoint::from_domain("v1.mux.cool", 0).expect("mux target");
    let mut client = VmessClient::connect(proxy_address, &mux_target, COMMAND_MUX).await;
    let mut mux = Vec::new();

    // TCP session: New carries the payload, the echo reply comes back as Keep.
    let tcp_target = Endpoint::from(tcp_echo);
    let frame = mux_new(7, &tcp_target, NETWORK_TCP, b"hello mux");
    client.send_chunk(&frame).await;
    let (meta, data) = loop {
        mux.extend_from_slice(&client.recv_chunk().await);
        if let Some(frame) = take_mux_frame(&mut mux) {
            break frame;
        }
    };
    assert_eq!(meta.session, 7);
    assert_eq!(meta.status, STATUS_KEEP);
    assert_eq!(data, b"hello mux");
    client.send_chunk(&mux_end(7)).await;

    // UDP session: one datagram per Keep frame.
    let udp_target = Endpoint::from(udp_echo);
    let frame = mux_new(9, &udp_target, NETWORK_UDP, b"datagram");
    client.send_chunk(&frame).await;
    let (meta, data) = loop {
        mux.extend_from_slice(&client.recv_chunk().await);
        if let Some(frame) = take_mux_frame(&mut mux) {
            break frame;
        }
    };
    assert_eq!(meta.session, 9);
    assert_eq!(meta.status, STATUS_KEEP);
    assert_eq!(data, b"datagram");
    client.send_chunk(&mux_end(9)).await;

    // The physical connection stays usable after both sessions close.
    client.send_chunk(&mux_frame(&KEEPALIVE_META, &[])).await;

    drop(client);
    stop(proxy_handle, proxy_task).await;
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn rejects_an_invalid_uuid() {
    let proxy = format!(
        r#"{{
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vmess_inbound(false, "tcp")
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;
    let uuid = Uuid::parse("ffffffff-ffff-ffff-ffff-ffffffffffff").expect("uuid");
    let key = CmdKey::derive(&uuid);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let secrets = RequestSecrets {
        body_iv: [1; 16],
        body_key: [2; 16],
        response_auth: 3,
        auth_rand: [4; 4],
        connection_nonce: [5; 8],
    };
    let target = Endpoint::from_domain("example.com", 80).expect("target");
    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request(
        &key,
        &RequestSpec {
            target: &target,
            command: COMMAND_TCP,
            security: Security::Aes128Gcm,
            timestamp: now,
            padding: &[],
            secrets: &secrets,
        },
        &mut header,
    )
    .expect("encode");
    let mut stream = TcpStream::connect(proxy_address).await.expect("connect");
    stream.write_all(&header[..length]).await.expect("header");
    let mut buffer = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))));

    stop(proxy_handle, proxy_task).await;
}

#[tokio::test]
async fn rejects_a_replayed_auth_id() {
    let (echo, echo_task) = echo_server().await;
    let proxy = format!(
        r#"{{
          "inbounds": [ {} ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#,
        vmess_inbound(false, "tcp")
    );
    let (proxy_address, proxy_handle, proxy_task) = start(&proxy).await;

    let uuid = Uuid::parse(UUID).expect("uuid");
    let key = CmdKey::derive(&uuid);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let secrets = RequestSecrets {
        body_iv: [0x11; 16],
        body_key: [0x22; 16],
        response_auth: 0x33,
        auth_rand: [0x44; 4],
        connection_nonce: [0x55; 8],
    };
    let target = Endpoint::from(echo);
    let mut header = [0_u8; REQUEST_HEADER_MAX];
    let length = encode_request(
        &key,
        &RequestSpec {
            target: &target,
            command: COMMAND_TCP,
            security: Security::Aes128Gcm,
            timestamp: now,
            padding: &[],
            secrets: &secrets,
        },
        &mut header,
    )
    .expect("encode");
    let RequestProgress::Complete(request) = request_progress(&header[..length], &key, now) else {
        panic!("request");
    };

    let mut first = TcpStream::connect(proxy_address).await.expect("connect");
    first.write_all(&header[..length]).await.expect("header");
    let mut response = ResponseReader::default();
    response.read(&mut first, &request).await;
    drop(first);

    let mut replay = TcpStream::connect(proxy_address).await.expect("connect");
    replay.write_all(&header[..length]).await.expect("header");
    let mut buffer = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), replay.read(&mut buffer)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))));

    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}
