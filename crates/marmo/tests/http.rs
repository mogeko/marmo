//! HTTP/1.1 inbound tests over loopback.

use std::net::SocketAddr;
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, ServeError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const DIRECT: &str = r#"{
  "limits": { "handshake_timeout_s": 2, "idle_timeout_s": 5 },
  "inbounds": [
    { "tag": "http", "protocol": "http", "listen": "127.0.0.1:0" }
  ],
  "outbounds": [ { "tag": "proxy", "protocol": "direct" } ],
  "route": { "final": "direct" }
}"#;

const REJECT: &str = r#"{
  "limits": { "handshake_timeout_s": 2 },
  "inbounds": [
    { "tag": "http", "protocol": "http", "listen": "127.0.0.1:0" }
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

#[tokio::test]
async fn connect_tunnels_and_forwards_leftover_bytes() {
    let (echo, echo_task) = echo_server().await;
    let (address, handle, serve) = start(DIRECT).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\nhello",
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
    let mut buffer = [0_u8; 5];
    client.read_exact(&mut buffer).await.expect("echo");
    assert_eq!(&buffer, b"hello");

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn forward_rewrites_absolute_form_and_strips_hop_headers() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let upstream = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let head = read_head(&mut stream).await;
        let text = String::from_utf8_lossy(&head);
        assert!(
            text.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
            "unexpected request line: {text}"
        );
        assert!(
            text.contains(&format!("Host: 127.0.0.1:{}", upstream.port())),
            "missing rewritten Host: {text}"
        );
        assert!(
            text.contains("Connection: close"),
            "missing Connection: close: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("proxy-connection"),
            "proxy-connection was forwarded: {text}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .expect("response");
        let _ = stream.shutdown().await;
    });

    let (address, handle, serve) = start(DIRECT).await;
    let mut client = TcpStream::connect(address).await.expect("connect");
    let request = format!(
        "GET http://127.0.0.1:{}/path?q=1 HTTP/1.1\r\nHost: ignored\r\nProxy-Connection: keep-alive\r\n\r\n",
        upstream.port()
    );
    client.write_all(request.as_bytes()).await.expect("request");

    let head = read_head(&mut client).await;
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "unexpected head: {}",
        String::from_utf8_lossy(&head)
    );
    let mut body = [0_u8; 2];
    client.read_exact(&mut body).await.expect("body");
    assert_eq!(&body, b"ok");

    stop(handle, serve).await;
    server.abort();
}

#[tokio::test]
async fn reject_returns_forbidden() {
    let (address, handle, serve) = start(REJECT).await;
    let mut client = TcpStream::connect(address).await.expect("connect");
    client
        .write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        .await
        .expect("request");

    let head = read_head(&mut client).await;
    assert!(
        head.starts_with(b"HTTP/1.1 403"),
        "unexpected head: {}",
        String::from_utf8_lossy(&head)
    );
    stop(handle, serve).await;
}

#[tokio::test]
async fn origin_form_forward_is_not_implemented() {
    let (address, handle, serve) = start(DIRECT).await;
    let mut client = TcpStream::connect(address).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("request");

    let head = read_head(&mut client).await;
    assert!(
        head.starts_with(b"HTTP/1.1 501"),
        "unexpected head: {}",
        String::from_utf8_lossy(&head)
    );
    stop(handle, serve).await;
}

#[tokio::test]
async fn http_connect_outbound_tunnels() {
    let (echo, echo_task) = echo_server().await;

    let proxy_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let proxy_address = proxy_listener.local_addr().expect("addr");
    let proxy = tokio::spawn(async move {
        let (mut client, _) = proxy_listener.accept().await.expect("accept");
        let head = read_head(&mut client).await;
        let text = String::from_utf8_lossy(&head);
        assert!(
            text.starts_with(&format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n", echo.port())),
            "unexpected CONNECT: {text}"
        );
        let mut upstream = TcpStream::connect(echo).await.expect("upstream");
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .expect("response");
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });

    let json = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [
            {{ "tag": "proxy", "protocol": "http", "server": "127.0.0.1:{}" }}
          ],
          "route": {{ "final": "proxy" }}
        }}"#,
        proxy_address.port()
    );
    let (address, handle, serve) = start(&json).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(b"hello").await.expect("write");
    let mut buffer = [0_u8; 5];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"hello");

    stop(handle, serve).await;
    echo_task.abort();
    proxy.abort();
}
