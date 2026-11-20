//! SOCKS5 UDP ASSOCIATE tests over loopback.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use marmo::{Config, Instance, InstanceHandle, ServeError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const DIRECT: &str = r#"{
  "limits": { "handshake_timeout_s": 2, "idle_timeout_s": 5 },
  "inbounds": [
    { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
  ],
  "outbounds": [ { "tag": "proxy", "protocol": "direct" } ],
  "route": { "final": "direct" }
}"#;

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

async fn read_reply(stream: &mut TcpStream) -> (u8, SocketAddr) {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[0], 5);
    assert_eq!(head[3], 1, "test expects an IPv4 bound address");
    let mut address = [0_u8; 6];
    stream
        .read_exact(&mut address)
        .await
        .expect("reply address");
    let ip = Ipv4Addr::new(address[0], address[1], address[2], address[3]);
    let port = u16::from_be_bytes([address[4], address[5]]);
    (head[1], SocketAddr::new(IpAddr::V4(ip), port))
}

fn udp_packet(target: SocketAddr, frag: u8, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(target) = target else {
        panic!("test target must be IPv4");
    };
    let mut packet = vec![0, 0, frag, 1];
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[tokio::test]
async fn udp_associate_relays_datagrams() {
    let echo = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let echo_address = echo.local_addr().expect("addr");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 65_535];
        loop {
            let Ok((length, source)) = echo.recv_from(&mut buffer).await else {
                break;
            };
            let _ = echo.send_to(&buffer[..length], source).await;
        }
    });

    let (address, handle, serve) = start(DIRECT).await;
    let mut control = TcpStream::connect(address).await.expect("control");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);

    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let (status, relay) = read_reply(&mut control).await;
    assert_eq!(status, 0);

    let client = UdpSocket::bind(("127.0.0.1", 0)).await.expect("client udp");
    let packet = udp_packet(echo_address, 0, b"hello");
    client.send_to(&packet, relay).await.expect("send");

    let mut buffer = [0_u8; 1024];
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("reply timeout")
        .expect("reply");
    assert!(length > 10);
    assert_eq!(&buffer[..3], &[0, 0, 0]);
    assert_eq!(buffer[3], 1);
    assert_eq!(&buffer[10..length], b"hello");

    let _ = control.shutdown().await;
    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn fragmented_datagrams_are_dropped() {
    let echo = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let echo_address = echo.local_addr().expect("addr");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 65_535];
        loop {
            let Ok((length, source)) = echo.recv_from(&mut buffer).await else {
                break;
            };
            let _ = echo.send_to(&buffer[..length], source).await;
        }
    });

    let (address, handle, serve) = start(DIRECT).await;
    let mut control = TcpStream::connect(address).await.expect("control");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await.expect("method");
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let (_, relay) = read_reply(&mut control).await;

    let client = UdpSocket::bind(("127.0.0.1", 0)).await.expect("client udp");
    let fragmented = udp_packet(echo_address, 1, b"drop");
    client.send_to(&fragmented, relay).await.expect("send");

    let mut buffer = [0_u8; 1024];
    let result = timeout(Duration::from_millis(200), client.recv_from(&mut buffer)).await;
    assert!(result.is_err(), "fragmented datagram was forwarded");

    let packet = udp_packet(echo_address, 0, b"ok");
    client.send_to(&packet, relay).await.expect("send");
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("reply timeout")
        .expect("reply");
    assert_eq!(&buffer[10..length], b"ok");

    let _ = control.shutdown().await;
    stop(handle, serve).await;
    echo_task.abort();
}
