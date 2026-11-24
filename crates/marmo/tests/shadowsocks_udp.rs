//! Shadowsocks 2022 UDP loopback tests through the public `Instance`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use marmo::{Config, Endpoint, Instance, InstanceHandle, Network, ServeError};
use marmo_proto::shadowsocks::{
    Direction, Key, Method, UdpPacket, decode_udp_packet, encode_udp_packet,
};
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

async fn start_shadowsocks(
    json: &str,
) -> (
    SocketAddr,
    SocketAddr,
    InstanceHandle,
    JoinHandle<Result<(), ServeError>>,
) {
    let config = Config::from_json(json).expect("config");
    let instance = Instance::builder(config).build().expect("build");
    let bound = instance.bind().await.expect("bind");
    let addresses: Vec<_> = bound.local_addrs().collect();
    let tcp = addresses
        .iter()
        .find(|address| address.network == Network::Tcp)
        .expect("tcp")
        .addr;
    let udp = addresses
        .iter()
        .find(|address| address.network == Network::Udp)
        .expect("udp")
        .addr;
    let handle = bound.handle();
    let task = tokio::spawn(bound.serve());
    (tcp, udp, handle, task)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
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

#[tokio::test]
async fn rejects_a_stale_udp_packet() {
    let (echo, echo_task) = udp_echo().await;
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
    let (_tcp, udp, handle, task) = start_shadowsocks(&json).await;

    let method = Method::Aes128Gcm;
    let key = Key::parse(method, KEY_128).expect("key");
    let destination = Endpoint::from(echo);
    let session_id = *b"stale-01";
    let mut encoded = vec![0_u8; 1024];
    let stale = UdpPacket {
        direction: Direction::ClientToServer,
        session_id,
        packet_id: 1,
        client_session_id: None,
        destination: &destination,
        payload: b"stale",
        padding_len: 0,
        timestamp: unix_now().saturating_sub(31),
    };
    let length = encode_udp_packet(method, key.as_bytes(), &stale, &mut encoded).expect("encode");
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    socket.send_to(&encoded[..length], udp).await.expect("send");

    let mut buffer = [0_u8; 256];
    assert!(
        timeout(Duration::from_millis(300), socket.recv_from(&mut buffer))
            .await
            .is_err(),
        "stale UDP packet was accepted"
    );

    // The same session with a fresh timestamp must still work.
    let fresh = UdpPacket {
        timestamp: unix_now(),
        packet_id: 2,
        ..stale
    };
    let length = encode_udp_packet(method, key.as_bytes(), &fresh, &mut encoded).expect("encode");
    socket.send_to(&encoded[..length], udp).await.expect("send");
    let (length, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("fresh timeout")
        .expect("fresh recv");
    let mut plain = [0_u8; 256];
    let decoded = decode_udp_packet(
        method,
        key.as_bytes(),
        &buffer[..length],
        Direction::ServerToClient,
        Some(session_id),
        &mut plain,
    )
    .expect("reply");
    assert_eq!(decoded.payload, b"stale");

    stop(handle, task).await;
    echo_task.abort();
}
