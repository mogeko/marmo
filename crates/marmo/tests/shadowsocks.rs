//! Shadowsocks 2022 TCP loopback tests through the public `Instance`.

use std::net::SocketAddr;
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, ServeError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
