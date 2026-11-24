//! Shadowsocks 2022 TCP loopback tests through the public `Instance`.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use marmo::{Config, Endpoint, Instance, InstanceHandle, ServeError};
use marmo_proto::shadowsocks::{Key, Method, encode_client_request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const KEY_128: &str = "AAECAwQFBgcICQoLDA0ODw==";
const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const METHOD_128: &str = "2022-blake3-aes-128-gcm";
const METHOD_256: &str = "2022-blake3-aes-256-gcm";

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

async fn relay_round_trip(method: &str, key: &str) {
    let (echo, echo_task) = echo_server().await;

    let server = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          "inbounds": [
            {{ "tag": "ss", "protocol": "shadowsocks", "listen": "127.0.0.1:0",
               "method": "{method}", "password": "{key}" }}
          ],
          "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
          "route": {{ "final": "direct" }}
        }}"#
    );
    let (proxy, proxy_handle, proxy_task) = start(&server).await;

    let client = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [
            {{ "tag": "ss", "protocol": "shadowsocks", "server": "{proxy}",
               "method": "{method}", "password": "{key}" }}
          ],
          "route": {{ "final": "ss" }}
        }}"#
    );
    let (front, front_handle, front_task) = start(&client).await;

    let mut stream = TcpStream::connect(front).await.expect("connect");
    socks5_connect(&mut stream, echo).await;

    // Larger than one chunk in both directions.
    let payload: Vec<u8> = (0..100_000).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = stream.into_split();
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
async fn relays_through_shadowsocks_2022_tcp() {
    relay_round_trip(METHOD_128, KEY_128).await;
    relay_round_trip(METHOD_256, KEY_256).await;
}

#[tokio::test]
async fn rejects_a_replayed_tcp_request_salt() {
    let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let target_addr = target.local_addr().expect("target addr");
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
    let target_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = target.accept().await else {
                break;
            };
            let _ = accepted_tx.send(());
            drop(stream);
        }
    });

    let json = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          "inbounds": [
            {{ "tag": "ss", "protocol": "shadowsocks", "listen": "127.0.0.1:0",
               "method": "{METHOD_128}", "password": "{KEY_128}" }}
          ],
          "route": {{ "final": "direct" }}
        }}"#
    );
    let (proxy, handle, serve) = start(&json).await;

    let method = Method::Aes128Gcm;
    let key = Key::parse(method, KEY_128).expect("key");
    let destination = Endpoint::from(target_addr);
    let salt = [7_u8; 16];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let mut request = [0_u8; 512];
    let length = encode_client_request(
        method,
        key.as_bytes(),
        &salt,
        &destination,
        now,
        b"padding",
        b"",
        &mut request,
    )
    .expect("encode");

    let mut first = TcpStream::connect(proxy).await.expect("connect");
    first
        .write_all(&request[..length])
        .await
        .expect("first request");
    timeout(Duration::from_secs(2), accepted_rx.recv())
        .await
        .expect("first target timeout")
        .expect("first target");

    let mut replay = TcpStream::connect(proxy).await.expect("connect");
    replay
        .write_all(&request[..length])
        .await
        .expect("replay request");
    assert!(
        timeout(Duration::from_millis(300), accepted_rx.recv())
            .await
            .is_err(),
        "replayed request salt was accepted"
    );

    drop(first);
    drop(replay);
    stop(handle, serve).await;
    target_task.abort();
}
