//! Sniffing tests: routing on the sniffed domain and byte-exact replay.

use std::net::SocketAddr;
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, ServeError};
use marmo_transport::Layer;
use marmo_transport::tls::{TlsClient, TlsClientOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

async fn socks5_connect(client: &mut TcpStream, target: SocketAddr) -> u8 {
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
    reply[1]
}

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::with_capacity(256);
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.expect("head byte");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return head;
        }
        assert!(head.len() < 8192, "head did not terminate");
    }
}

async fn expect_echo(client: &mut TcpStream, payload: &[u8]) {
    client.write_all(payload).await.expect("payload");
    let mut echoed = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(2), client.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .expect("echo");
    assert_eq!(echoed, payload);
}

async fn expect_closed(client: &mut TcpStream) {
    let mut buffer = [0_u8; 32];
    match timeout(Duration::from_secs(2), client.read(&mut buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(read)) => panic!("expected close, read {read} bytes"),
        Err(_) => panic!("connection did not close"),
    }
}

fn socks_config(sniffing: &str) -> String {
    format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          "inbounds": [
            {{
              "tag": "socks",
              "protocol": "socks5",
              "listen": "127.0.0.1:0",
              "sniffing": {sniffing}
            }}
          ],
          "route": {{
            "rules": [
              {{ "domain_suffix": ["blocked.test"], "outbound": "reject" }}
            ],
            "final": "direct"
          }}
        }}"#
    )
}

fn http_config(sniffing: &str) -> String {
    format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          "inbounds": [
            {{
              "tag": "http",
              "protocol": "http",
              "listen": "127.0.0.1:0",
              "sniffing": {sniffing}
            }}
          ],
          "route": {{
            "rules": [
              {{ "domain_suffix": ["blocked.test"], "outbound": "reject" }}
            ],
            "final": "direct"
          }}
        }}"#
    )
}

fn client_hello(server_name: &str) -> Vec<u8> {
    let name = server_name.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0_u16.to_be_bytes());
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(0);
    hello.extend_from_slice(&2_u16.to_be_bytes());
    hello.extend_from_slice(&[0x13, 0x01]);
    hello.push(1);
    hello.push(0);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn h2_frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0,
        0,
        u8::try_from(payload.len()).expect("small frame"),
        kind,
        flags,
    ];
    frame.extend_from_slice(&[0, 0, 0, 1]);
    frame.extend_from_slice(payload);
    frame
}

fn h2_request(authority: &str) -> Vec<u8> {
    let mut block = vec![0x82, 0x41];
    block.push(u8::try_from(authority.len()).expect("small authority"));
    block.extend_from_slice(authority.as_bytes());

    let mut input = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    input.extend_from_slice(&h2_frame(0x04, 0, &[]));
    input.extend_from_slice(&h2_frame(0x01, 0x04, &block));
    input
}

#[tokio::test]
async fn replays_unrecognised_bytes_unchanged() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(&socks_config(r#"{ "enabled": true }"#)).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    expect_echo(&mut client, b"hello").await;

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn routes_on_tls_server_name() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(&socks_config(r#"{ "enabled": true }"#)).await;

    let hello = client_hello("blocked.test");
    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(&hello).await.expect("hello");
    expect_closed(&mut client).await;

    let hello = client_hello("allowed.test");
    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    expect_echo(&mut client, &hello).await;

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn routes_on_http_host() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(&socks_config(r#"{ "enabled": true }"#)).await;

    let blocked = b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n";
    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(blocked).await.expect("request");
    expect_closed(&mut client).await;

    let allowed = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    expect_echo(&mut client, allowed).await;

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn routes_on_http2_authority() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(&socks_config(r#"{ "enabled": true }"#)).await;

    let blocked = h2_request("blocked.test");
    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(&blocked).await.expect("request");
    expect_closed(&mut client).await;

    let allowed = h2_request("allowed.test");
    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    expect_echo(&mut client, &allowed).await;

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn http_connect_sniffs_after_the_tunnel_reply() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(&http_config(r#"{ "enabled": true }"#)).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo.port(),
        echo.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("connect head");
    let head = read_head(&mut client).await;
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "unexpected head: {}",
        String::from_utf8_lossy(&head)
    );

    let blocked = b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n";
    client.write_all(blocked).await.expect("request");
    expect_closed(&mut client).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        echo.port(),
        echo.port()
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("connect head");
    let head = read_head(&mut client).await;
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let allowed = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
    expect_echo(&mut client, allowed).await;

    stop(handle, serve).await;
    echo_task.abort();
}

fn vless_config() -> String {
    let certificate = serde_json::to_string(SERVER_CERT).expect("certificate");
    let key = serde_json::to_string(SERVER_KEY).expect("key");
    format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          "inbounds": [
            {{
              "tag": "vless",
              "protocol": "vless",
              "listen": "127.0.0.1:0",
              "uuid": "{UUID}",
              "tls": {{ "certificate": {certificate}, "private_key": {key} }},
              "sniffing": {{ "enabled": true }}
            }}
          ],
          "route": {{
            "rules": [
              {{ "domain_suffix": ["blocked.test"], "outbound": "reject" }}
            ],
            "final": "direct"
          }}
        }}"#
    )
}

#[tokio::test]
async fn vless_pipelined_bytes_are_sniffed_and_replayed() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(&vless_config()).await;

    let uuid = marmo_proto::vless::Uuid::parse(UUID).expect("uuid");
    let target = marmo::Endpoint::from(echo);

    let blocked = b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n";
    let mut header = [0_u8; 64];
    let length = marmo_proto::vless::encode_request(
        &uuid,
        &target,
        marmo_proto::vless::COMMAND_TCP,
        &mut header,
    )
    .expect("request");
    let mut client = vless_client(address).await;
    client.write_all(&header[..length]).await.expect("header");
    client.write_all(blocked).await.expect("request");
    let mut buffer = [0_u8; 32];
    match timeout(Duration::from_secs(2), client.read(&mut buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(read)) => panic!("expected close, read {read} bytes"),
        Err(_) => panic!("connection did not close"),
    }

    let allowed = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
    let mut client = vless_client(address).await;
    client.write_all(&header[..length]).await.expect("header");
    client.write_all(allowed).await.expect("request");
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).await.expect("response");
    assert_eq!(response, [0, 0]);
    let mut echoed = vec![0_u8; allowed.len()];
    client.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(echoed, allowed);

    stop(handle, serve).await;
    echo_task.abort();
}

async fn vless_client(address: SocketAddr) -> marmo_transport::BoxStream {
    let stream = TcpStream::connect(address).await.expect("connect");
    let tls = TlsClient::new(&TlsClientOptions {
        server_name: "localhost",
        alpn: &[],
        required_alpn: None,
        insecure: true,
        client_certificate: None,
        client_private_key: None,
        handshake_timeout: Some(Duration::from_secs(2)),
    })
    .expect("tls client");
    tls.wrap(Box::new(stream)).await.expect("tls handshake")
}

#[tokio::test]
async fn inbound_domain_overrides_sniffing() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(
        r#"{
          "limits": { "handshake_timeout_s": 2 },
          "inbounds": [
            {
              "tag": "socks",
              "protocol": "socks5",
              "listen": "127.0.0.1:0",
              "sniffing": { "enabled": true }
            }
          ],
          "route": {
            "rules": [
              { "domain": ["localhost"], "outbound": "reject" }
            ],
            "final": "direct"
          }
        }"#,
    )
    .await;

    let target = marmo::Endpoint::from_domain("localhost", echo.port()).expect("endpoint");
    let mut client = TcpStream::connect(address).await.expect("connect");
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.expect("method");
    let mut request = Vec::new();
    request.extend_from_slice(&[5, 1, 0, 3]);
    request.push(u8::try_from("localhost".len()).expect("length"));
    request.extend_from_slice(target.domain().expect("domain").as_bytes());
    request.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&request).await.expect("request");
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.expect("reply");
    assert_ne!(reply[1], 0, "inbound domain should have been rejected");

    stop(handle, serve).await;
    echo_task.abort();
}
