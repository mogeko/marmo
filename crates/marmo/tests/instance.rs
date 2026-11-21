//! Public `Instance` lifecycle tests over loopback.

use std::net::SocketAddr;
use std::time::Duration;

use marmo::{BoundInstance, BuildError, Config, Instance, InstanceHandle, ServeError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const DIRECT: &str = r#"{
  "limits": { "handshake_timeout_s": 2, "idle_timeout_s": 5 },
  "inbounds": [
    { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
  ],
  "outbounds": [
    { "tag": "proxy", "protocol": "direct" }
  ],
  "route": { "final": "direct" }
}"#;

const REJECT: &str = r#"{
  "limits": { "handshake_timeout_s": 2 },
  "inbounds": [
    { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
  ],
  "route": { "final": "reject" }
}"#;

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

async fn start_bound(json: &str) -> BoundInstance {
    let config = Config::from_json(json).expect("config");
    Instance::builder(config)
        .build()
        .expect("build")
        .bind()
        .await
        .expect("bind")
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

#[tokio::test]
async fn relays_through_socks5_connect() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(DIRECT).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(b"hello").await.expect("write");
    let mut buffer = [0_u8; 5];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"hello");

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn routes_to_a_configured_outbound() {
    let (echo, echo_task) = echo_server().await;
    let json = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [{{ "tag": "proxy", "protocol": "direct" }}],
          "route": {{
            "rules": [{{ "port": [{}], "outbound": "proxy" }}],
            "final": "reject"
          }}
        }}"#,
        echo.port()
    );
    let (address, handle, serve) = start(&json).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(b"ok").await.expect("write");
    let mut buffer = [0_u8; 2];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"ok");

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn rejects_when_route_rejects() {
    let (address, handle, serve) = start(REJECT).await;
    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(
        socks5_connect(&mut client, "127.0.0.1:9".parse().expect("addr")).await,
        2
    );

    let mut buffer = [0_u8; 1];
    let result = timeout(Duration::from_secs(1), client.read(&mut buffer)).await;
    assert!(matches!(result, Ok(Ok(0)) | Ok(Err(_))));
    stop(handle, serve).await;
}

#[tokio::test]
async fn idle_timeout_closes_the_relay() {
    let (echo, echo_task) = echo_server().await;
    let json = r#"{
      "limits": { "handshake_timeout_s": 2, "idle_timeout_s": 1 },
      "inbounds": [
        { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
      ],
      "route": { "final": "direct" }
    }"#;
    let (address, handle, serve) = start(json).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    let mut buffer = [0_u8; 1];
    let result = timeout(Duration::from_secs(3), client.read(&mut buffer))
        .await
        .expect("idle close");
    assert!(matches!(result, Ok(0) | Err(_)));

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn connection_limit_rejects_extra_clients() {
    let (echo, echo_task) = echo_server().await;
    let json = r#"{
      "limits": { "max_connections": 1, "handshake_timeout_s": 2 },
      "inbounds": [
        { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
      ],
      "route": { "final": "direct" }
    }"#;
    let (address, handle, serve) = start(json).await;

    let mut first = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut first, echo).await, 0);
    first.write_all(b"x").await.expect("write");
    let mut echo_buffer = [0_u8; 1];
    first.read_exact(&mut echo_buffer).await.expect("echo");

    let mut second = TcpStream::connect(address).await.expect("connect");
    let mut method = [0_u8; 2];
    let result = timeout(Duration::from_secs(1), second.read_exact(&mut method)).await;
    assert!(matches!(result, Ok(Err(_)) | Err(_)));

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn external_shutdown_stops_serve() {
    let bound = start_bound(DIRECT).await;
    let serve = tokio::spawn(bound.serve_with_shutdown(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }));
    timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve timeout")
        .expect("join")
        .expect("serve");
}

#[tokio::test]
async fn shutdown_stops_the_listener() {
    let (address, handle, serve) = start(DIRECT).await;
    stop(handle, serve).await;
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn local_addrs_report_tags_and_network() {
    let bound = start_bound(DIRECT).await;
    let addrs: Vec<_> = bound.local_addrs().collect();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].tag, "socks");
    assert_eq!(addrs[0].network, marmo::Network::Tcp);
    assert_ne!(addrs[0].addr.port(), 0);
}

#[test]
fn build_without_a_runtime_fails() {
    let config = Config::from_json(DIRECT).expect("config");
    match Instance::builder(config).build() {
        Err(BuildError::NoRuntime) => {}
        Ok(_) => panic!("build unexpectedly succeeded"),
        Err(other) => panic!("unexpected build error: {other:?}"),
    }
}

#[tokio::test]
async fn builds_selector_outbounds() {
    let config = Config::from_json(
        r#"{
          "outbounds": [
            { "tag": "d", "protocol": "direct" },
            { "tag": "s", "protocol": "selector", "nodes": ["d"], "strategy": "manual" }
          ],
          "route": { "final": "d" }
        }"#,
    )
    .expect("config");
    assert!(Instance::builder(config).build().is_ok());
}

#[tokio::test]
async fn selector_falls_back_after_a_dead_node() {
    let (echo, echo_task) = echo_server().await;
    let dead = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let dead_address = dead.local_addr().expect("addr");
    let dead_task = tokio::spawn(async move {
        let _ = dead.accept().await;
    });
    let json = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [
            {{ "tag": "dead", "protocol": "http", "server": "127.0.0.1:{}" }},
            {{ "tag": "direct", "protocol": "direct" }},
            {{ "tag": "group", "protocol": "selector",
               "nodes": ["dead", "direct"], "strategy": "fallback" }}
          ],
          "route": {{ "final": "group" }}
        }}"#,
        dead_address.port()
    );
    let (address, handle, serve) = start(&json).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(b"fallback").await.expect("write");
    let mut buffer = [0_u8; 8];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"fallback");

    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let metrics = handle.clone();
    stop(handle, serve).await;
    let snapshot = metrics.metrics();
    assert!(snapshot.connections_accepted >= 1);
    assert_eq!(snapshot.connections_active, 0);
    assert_eq!(snapshot.connections_rejected, 0);
    assert!(snapshot.bytes_client_to_remote >= 8);
    assert!(snapshot.bytes_remote_to_client >= 8);
    dead_task.abort();
    echo_task.abort();
}
