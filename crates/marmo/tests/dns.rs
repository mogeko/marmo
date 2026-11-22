//! DNS resolver integration over loopback fixtures.
//!
//! Every upstream is a local UDP, DoT, or DoH server; no public resolver is
//! contacted.

#![cfg(feature = "dns")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use marmo::dns::{DnsAnswer, DnsError, DnsFuture, DnsResolver};
use marmo::{Config, Instance, InstanceHandle, ServeError};
use marmo_transport::tls::{ClientAuth, TlsServer, TlsServerOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const SERVER_CERT: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.pem");
const SERVER_KEY: &str = include_str!("../../marmo-transport/tests/fixtures/tls/server.key");
const CA_CERT: &str = include_str!("../../marmo-transport/tests/fixtures/tls/ca.pem");

#[derive(Clone, Copy)]
enum DnsBehavior {
    Answer(Ipv4Addr, u32),
    ServFail,
    NxDomain,
}

struct DnsFixture {
    address: SocketAddr,
    queries: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl DnsFixture {
    fn query_count(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_dns(behavior: DnsBehavior) -> DnsFixture {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("dns bind");
    let address = socket.local_addr().expect("dns addr");
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            if let Some(response) = dns_response(&buffer[..length], behavior) {
                let _ = socket.send_to(&response, peer).await;
            }
        }
    });
    DnsFixture {
        address,
        queries,
        task,
    }
}

fn dns_response(query: &[u8], behavior: DnsBehavior) -> Option<Vec<u8>> {
    let (end, qtype) = question(query)?;
    let id = query.get(..2)?;
    let (rcode, answer) = match behavior {
        DnsBehavior::Answer(address, ttl) if qtype == 1 => (0, Some((address, ttl))),
        DnsBehavior::Answer(..) => (0, None),
        DnsBehavior::ServFail => (2, None),
        DnsBehavior::NxDomain => (3, None),
    };
    let mut response = Vec::with_capacity(end + 16);
    response.extend_from_slice(id);
    response.extend_from_slice(&[0x81, 0x80 | rcode]);
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(query.get(12..end)?);
    if let Some((address, ttl)) = answer {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address.octets());
    }
    Some(response)
}

fn question(query: &[u8]) -> Option<(usize, u16)> {
    let mut index = 12;
    loop {
        let length = usize::from(*query.get(index)?);
        index = index.checked_add(1)?;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        index = index.checked_add(length)?;
    }
    let qtype = u16::from_be_bytes([*query.get(index)?, *query.get(index + 1)?]);
    Some((index + 4, qtype))
}

async fn start_dot(behavior: DnsBehavior) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("dot bind");
    let address = listener.local_addr().expect("dot addr");
    let alpn: Vec<String> = Vec::new();
    let tls = Arc::new(
        TlsServer::new(&TlsServerOptions {
            certificate: SERVER_CERT,
            private_key: SERVER_KEY,
            alpn: &alpn,
            client_ca: None,
            client_auth: ClientAuth::None,
            handshake_timeout: None,
        })
        .expect("dot tls"),
    );
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                let Ok(accepted) = tls.accept(Box::new(stream)).await else {
                    return;
                };
                let mut stream = accepted.stream;
                loop {
                    let mut length = [0_u8; 2];
                    if stream.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
                    if stream.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    let Some(response) = dns_response(&query, behavior) else {
                        return;
                    };
                    let Ok(size) = u16::try_from(response.len()) else {
                        return;
                    };
                    if stream.write_all(&size.to_be_bytes()).await.is_err() {
                        return;
                    }
                    if stream.write_all(&response).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, task)
}

async fn start_doh(behavior: DnsBehavior) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("doh bind");
    let address = listener.local_addr().expect("doh addr");
    let alpn = vec!["h2".to_owned()];
    let tls = Arc::new(
        TlsServer::new(&TlsServerOptions {
            certificate: SERVER_CERT,
            private_key: SERVER_KEY,
            alpn: &alpn,
            client_ca: None,
            client_auth: ClientAuth::None,
            handshake_timeout: None,
        })
        .expect("doh tls"),
    );
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                let Ok(accepted) = tls.accept(Box::new(stream)).await else {
                    return;
                };
                let Ok(mut connection) = h2::server::handshake(accepted.stream).await else {
                    return;
                };
                while let Some(request) = connection.accept().await {
                    let Ok((request, mut respond)) = request else {
                        return;
                    };
                    let mut body = request.into_body();
                    let mut query = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let Ok(chunk) = chunk else {
                            return;
                        };
                        let _ = body.flow_control().release_capacity(chunk.len());
                        query.extend_from_slice(&chunk);
                    }
                    let Some(response) = dns_response(&query, behavior) else {
                        return;
                    };
                    let head = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/dns-message")
                        .body(())
                        .expect("response");
                    let Ok(mut send) = respond.send_response(head, false) else {
                        return;
                    };
                    if send.send_data(Bytes::from(response), true).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, task)
}

async fn start_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("echo bind");
    let address = listener.local_addr().expect("echo addr");
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

async fn start_udp_echo() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("udp echo bind");
    let address = socket.local_addr().expect("udp echo addr");
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 65_535];
        loop {
            let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let _ = socket.send_to(&buffer[..length], source).await;
        }
    });
    (address, task)
}

async fn start_connect_proxy() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("proxy bind");
    let address = listener.local_addr().expect("proxy addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut stream = stream;
                let Some(target) = read_connect_target(&mut stream).await else {
                    return;
                };
                let Ok(mut remote) = TcpStream::connect(target.as_str()).await else {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                if stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
            });
        }
    });
    (address, task)
}

async fn read_connect_target(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        if stream.read_exact(&mut byte).await.is_err() {
            return None;
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 8192 {
            return None;
        }
    }
    let text = String::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "CONNECT" {
        return None;
    }
    parts.next().map(str::to_owned)
}

async fn start(
    json: &str,
) -> (
    SocketAddr,
    InstanceHandle,
    JoinHandle<Result<(), ServeError>>,
) {
    let config = Config::from_json(json).expect("config");
    let bound = Instance::builder(config)
        .build()
        .expect("build")
        .bind()
        .await
        .expect("bind");
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

async fn socks5_connect(client: &mut TcpStream, target: &str) -> u8 {
    client.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);

    let (domain, port) = target.rsplit_once(':').expect("target");
    let port: u16 = port.parse().expect("port");
    let mut request = Vec::with_capacity(7 + domain.len());
    request.extend_from_slice(&[5, 1, 0, 3]);
    request.push(u8::try_from(domain.len()).expect("domain length"));
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.expect("request");

    let mut head = [0_u8; 4];
    client.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[0], 5);
    let skip = match head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length).await.expect("reply length");
            usize::from(length[0]) + 2
        }
        other => panic!("unexpected address type {other}"),
    };
    let mut rest = vec![0_u8; skip];
    client.read_exact(&mut rest).await.expect("reply address");
    head[1]
}

fn udp_packet(domain: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 3, u8::try_from(domain.len()).expect("domain")];
    packet.extend_from_slice(domain.as_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn read_reply_address(control: &mut TcpStream) -> SocketAddr {
    let mut head = [0_u8; 4];
    control.read_exact(&mut head).await.expect("reply head");
    let mut address = [0_u8; 6];
    control
        .read_exact(&mut address)
        .await
        .expect("reply address");
    SocketAddr::from((
        [address[0], address[1], address[2], address[3]],
        u16::from_be_bytes([address[4], address[5]]),
    ))
}

fn dns_config(address: SocketAddr) -> String {
    format!(
        r#""dns": {{
          "servers": [{{ "protocol": "udp", "address": "{address}" }}],
          "timeout_ms": 1000,
          "cache_capacity": 8
        }}"#
    )
}

fn direct_config(dns: &str) -> String {
    format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          {dns},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "route": {{ "final": "direct" }}
        }}"#
    )
}

#[tokio::test]
async fn tcp_dials_use_the_cache_and_expire() {
    let dns = start_dns(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 2)).await;
    let (echo, echo_task) = start_echo().await;
    let config = direct_config(&dns_config(dns.address));
    let (address, handle, serve) = start(&config).await;

    let target = format!("cache.test:{}", echo.port());
    let mut client = TcpStream::connect(address).await.expect("socks");
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    client.write_all(b"one").await.expect("write");
    let mut buffer = [0_u8; 3];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"one");
    let first = dns.query_count();

    let mut client = TcpStream::connect(address).await.expect("socks");
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    client.write_all(b"two").await.expect("write");
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"two");
    assert_eq!(dns.query_count(), first, "second dial should hit the cache");

    tokio::time::sleep(Duration::from_millis(2200)).await;
    let mut client = TcpStream::connect(address).await.expect("socks");
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    client.write_all(b"three").await.expect("write");
    let mut buffer = [0_u8; 5];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"three");
    assert!(dns.query_count() > first, "expired entry should be queried");

    let metrics = handle.metrics();
    assert!(metrics.dns_queries >= 2);
    assert!(metrics.dns_cache_hits >= 1);
    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn udp_associate_resolves_domain_targets() {
    let dns = start_dns(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 60)).await;
    let (echo, echo_task) = start_udp_echo().await;
    let config = direct_config(&dns_config(dns.address));
    let (address, handle, serve) = start(&config).await;

    let mut control = TcpStream::connect(address).await.expect("control");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await.expect("method");
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let relay = read_reply_address(&mut control).await;

    let client = UdpSocket::bind(("127.0.0.1", 0)).await.expect("udp client");
    let packet = udp_packet("udp.test", echo.port(), b"hello");
    client.send_to(&packet, relay).await.expect("send");
    let mut buffer = [0_u8; 1024];
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
        .await
        .expect("reply timeout")
        .expect("reply");
    assert!(buffer[..length].ends_with(b"hello"));

    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn fallback_is_used_after_a_transport_failure() {
    let primary = start_dns(DnsBehavior::ServFail).await;
    let fallback = start_dns(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 60)).await;
    let (echo, echo_task) = start_echo().await;
    let dns = format!(
        r#""dns": {{
          "servers": [{{ "protocol": "udp", "address": "{}" }}],
          "fallback": [{{ "protocol": "udp", "address": "{}" }}],
          "timeout_ms": 1000
        }}"#,
        primary.address, fallback.address
    );
    let config = direct_config(&dns);
    let (address, handle, serve) = start(&config).await;

    let mut client = TcpStream::connect(address).await.expect("socks");
    let target = format!("fallback.test:{}", echo.port());
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    assert_eq!(handle.metrics().dns_fallbacks, 1);
    assert!(fallback.query_count() > 0);
    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn nxdomain_does_not_use_fallback() {
    let primary = start_dns(DnsBehavior::NxDomain).await;
    let fallback = start_dns(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 60)).await;
    let (echo, echo_task) = start_echo().await;
    let dns = format!(
        r#""dns": {{
          "servers": [{{ "protocol": "udp", "address": "{}" }}],
          "fallback": [{{ "protocol": "udp", "address": "{}" }}],
          "timeout_ms": 1000
        }}"#,
        primary.address, fallback.address
    );
    let config = direct_config(&dns);
    let (address, handle, serve) = start(&config).await;

    let mut client = TcpStream::connect(address).await.expect("socks");
    let target = format!("missing.test:{}", echo.port());
    assert_ne!(socks5_connect(&mut client, &target).await, 0);
    assert_eq!(fallback.query_count(), 0);
    assert_eq!(handle.metrics().dns_fallbacks, 0);
    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn dot_resolver_uses_the_private_ca() {
    let (dot, dot_task) = start_dot(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 60)).await;
    let (echo, echo_task) = start_echo().await;
    let dns = format!(
        r#""dns": {{
          "servers": [{{
            "protocol": "tls",
            "address": "{dot}",
            "server_name": "localhost"
          }}],
          "timeout_ms": 1000,
          "tls": {{ "ca": {CA_CERT:?} }}
        }}"#
    );
    let config = direct_config(&dns);
    let (address, handle, serve) = start(&config).await;

    let mut client = TcpStream::connect(address).await.expect("socks");
    let target = format!("dot.test:{}", echo.port());
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    stop(handle, serve).await;
    echo_task.abort();
    dot_task.abort();
}

#[tokio::test]
async fn doh_resolver_uses_the_private_ca() {
    let (doh, doh_task) = start_doh(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 60)).await;
    let (echo, echo_task) = start_echo().await;
    let dns = format!(
        r#""dns": {{
          "servers": [{{
            "protocol": "https",
            "address": "{doh}",
            "server_name": "localhost",
            "path": "/dns-query"
          }}],
          "timeout_ms": 1000,
          "tls": {{ "ca": {CA_CERT:?} }}
        }}"#
    );
    let config = direct_config(&dns);
    let (address, handle, serve) = start(&config).await;

    let mut client = TcpStream::connect(address).await.expect("socks");
    let target = format!("doh.test:{}", echo.port());
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    stop(handle, serve).await;
    echo_task.abort();
    doh_task.abort();
}

#[tokio::test]
async fn proxy_server_domain_uses_the_resolver() {
    let dns = start_dns(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 60)).await;
    let (echo, echo_task) = start_echo().await;
    let (proxy, proxy_task) = start_connect_proxy().await;
    let dns = dns_config(dns.address);
    let config = format!(
        r#"{{
          "limits": {{ "handshake_timeout_s": 2, "idle_timeout_s": 5 }},
          {dns},
          "inbounds": [
            {{ "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }}
          ],
          "outbounds": [
            {{ "tag": "proxy", "protocol": "http", "server": "proxy.test:{}" }}
          ],
          "route": {{ "final": "proxy" }}
        }}"#,
        proxy.port()
    );
    let (address, handle, serve) = start(&config).await;

    let mut client = TcpStream::connect(address).await.expect("socks");
    let target = format!("127.0.0.1:{}", echo.port());
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    client.write_all(b"via-proxy").await.expect("write");
    let mut buffer = [0_u8; 9];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"via-proxy");
    stop(handle, serve).await;
    echo_task.abort();
    proxy_task.abort();
}

struct FixedResolver {
    calls: Arc<AtomicUsize>,
}

impl DnsResolver for FixedResolver {
    fn resolve<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Result<DnsAnswer, DnsError>> {
        assert_eq!(name, "injected.test");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(DnsAnswer::new(
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                Duration::from_secs(60),
            ))
        })
    }
}

#[tokio::test]
async fn injected_resolver_uses_the_library_cache() {
    let (echo, echo_task) = start_echo().await;
    let config = direct_config(r#""dns": null"#);
    let config = Config::from_json(&config).expect("config");
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = Arc::new(FixedResolver {
        calls: Arc::clone(&calls),
    });
    let bound = Instance::builder(config)
        .dns_resolver(resolver)
        .build()
        .expect("build")
        .bind()
        .await
        .expect("bind");
    let address = bound.local_addrs().next().expect("inbound").addr;
    let handle = bound.handle();
    let serve = tokio::spawn(bound.serve());

    let target = format!("injected.test:{}", echo.port());
    let mut client = TcpStream::connect(address).await.expect("socks");
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    client.write_all(b"one").await.expect("write");
    let mut buffer = [0_u8; 3];
    client.read_exact(&mut buffer).await.expect("read");

    let mut client = TcpStream::connect(address).await.expect("socks");
    assert_eq!(socks5_connect(&mut client, &target).await, 0);
    client.write_all(b"two").await.expect("write");
    client.read_exact(&mut buffer).await.expect("read");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(handle.metrics().dns_cache_hits >= 1);
    stop(handle, serve).await;
    echo_task.abort();
}

#[tokio::test]
async fn injected_resolver_conflicts_with_builtin_servers() {
    let dns = start_dns(DnsBehavior::Answer(Ipv4Addr::LOCALHOST, 60)).await;
    let config = direct_config(&dns_config(dns.address));
    let config = Config::from_json(&config).expect("config");
    let calls = Arc::new(AtomicUsize::new(0));
    let result = Instance::builder(config)
        .dns_resolver(Arc::new(FixedResolver { calls }))
        .build();
    assert!(matches!(
        result,
        Err(marmo::BuildError::DnsResolverConflict)
    ));
}

#[test]
fn builds_with_an_explicit_runtime_handle() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    // Building a resolver must not perform I/O, so an unbound address is fine.
    let dns: SocketAddr = "127.0.0.1:9".parse().expect("address");
    let config = direct_config(&dns_config(dns));
    let config = Config::from_json(&config).expect("config");
    Instance::builder(config)
        .runtime(runtime.handle().clone())
        .build()
        .expect("build outside the runtime");
}

#[test]
fn invalid_trust_anchors_fail_the_build() {
    let config = r#"{
          "dns": {
            "servers": [{
              "protocol": "tls",
              "address": "127.0.0.1:9",
              "server_name": "localhost"
            }],
            "tls": { "ca": "not a certificate" }
          }
        }"#;
    let config = Config::from_json(config).expect("config");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let result = Instance::builder(config)
        .runtime(runtime.handle().clone())
        .build();
    assert!(matches!(result, Err(marmo::BuildError::Dns { .. })));
}

#[test]
fn empty_servers_without_an_injected_resolver_fail_the_build() {
    let config = Config::from_json(r#"{"dns":{}}"#).expect("config");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let result = Instance::builder(config)
        .runtime(runtime.handle().clone())
        .build();
    assert!(matches!(result, Err(marmo::BuildError::Dns { .. })));
}
