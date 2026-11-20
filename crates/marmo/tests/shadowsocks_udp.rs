//! Shadowsocks 2022 UDP loopback tests through the public `Instance`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, Network, ServeError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const KEY_128: &str = "AAECAwQFBgcICQoLDA0ODw==";
const KEY_256: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const METHOD_128: &str = "2022-blake3-aes-128-gcm";
const METHOD_256: &str = "2022-blake3-aes-256-gcm";

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
    assert_eq!(reply[0], 5);
    assert_eq!(reply[1], 0);

    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
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

#[tokio::test]
async fn binds_udp_beside_tcp_for_shadowsocks() {
    let config = Config::from_json(&format!(
        r#"{{
          "inbounds": [
            {{ "tag": "ss", "protocol": "shadowsocks", "listen": "127.0.0.1:0",
               "method": "{METHOD_128}", "password": "{KEY_128}" }}
          ],
          "route": {{ "final": "direct" }}
        }}"#
    ))
    .expect("config");
    let bound = Instance::builder(config)
        .build()
        .expect("build")
        .bind()
        .await
        .expect("bind");
    let addresses: Vec<_> = bound.local_addrs().collect();
    assert_eq!(addresses.len(), 2);
    let tcp = addresses
        .iter()
        .find(|address| address.network == Network::Tcp)
        .expect("tcp");
    let udp = addresses
        .iter()
        .find(|address| address.network == Network::Udp)
        .expect("udp");
    assert_eq!(tcp.addr.port(), udp.addr.port());
}

async fn relay_datagram(method: &str, key: &str) {
    let (echo, echo_task) = udp_echo().await;

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

    let client_config = format!(
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
    let (front, front_handle, front_task) = start(&client_config).await;

    let mut control = TcpStream::connect(front).await.expect("connect");
    let (datagram, relay) = udp_associate(&mut control).await;

    let payload: Vec<u8> = (0..8_000).map(|index| (index % 251) as u8).collect();
    let request = udp_request(echo, &payload);
    datagram.send_to(&request, relay).await.expect("send");
    let mut reply = vec![0_u8; 65_535];
    let (length, _) = timeout(Duration::from_secs(2), datagram.recv_from(&mut reply))
        .await
        .expect("reply timeout")
        .expect("recv");
    assert!(length >= 10 + payload.len());
    assert_eq!(&reply[3], &1);
    assert_eq!(
        &reply[4..8],
        &echo
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .expect("ip")
            .octets()
    );
    assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), echo.port());
    assert_eq!(&reply[10..length], &payload[..]);

    drop(control);
    stop(front_handle, front_task).await;
    stop(proxy_handle, proxy_task).await;
    echo_task.abort();
}

#[tokio::test]
async fn relays_shadowsocks_2022_udp() {
    relay_datagram(METHOD_128, KEY_128).await;
    relay_datagram(METHOD_256, KEY_256).await;
}
