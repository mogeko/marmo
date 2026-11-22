//! Injected process-identity routing over loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use marmo::{
    BuildError, Config, Instance, InstanceHandle, ProcessInfo, ProcessRequest, ProcessResolver,
    ServeError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const PROCESS_ROUTE: &str = r#"{
  "limits": { "handshake_timeout_s": 2, "idle_timeout_s": 5 },
  "inbounds": [
    { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
  ],
  "outbounds": [{ "tag": "proxy", "protocol": "direct" }],
  "route": {
    "rules": [{ "process_name": ["curl"], "outbound": "reject" }],
    "final": "direct"
  }
}"#;

const DIRECT: &str = r#"{
  "limits": { "handshake_timeout_s": 2, "idle_timeout_s": 5 },
  "inbounds": [
    { "tag": "socks", "protocol": "socks5", "listen": "127.0.0.1:0" }
  ],
  "route": { "final": "direct" }
}"#;

struct FixedResolver {
    name: Option<&'static str>,
    calls: AtomicUsize,
}

impl FixedResolver {
    fn new(name: Option<&'static str>) -> Arc<Self> {
        Arc::new(Self {
            name,
            calls: AtomicUsize::new(0),
        })
    }
}

impl ProcessResolver for FixedResolver {
    fn resolve(&self, _request: &ProcessRequest) -> Option<ProcessInfo> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.name
            .map(|name| ProcessInfo::new(Some(Arc::from(name)), None))
    }
}

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
    json: &str, resolver: Option<Arc<dyn ProcessResolver>>,
) -> (
    SocketAddr,
    InstanceHandle,
    JoinHandle<Result<(), ServeError>>,
) {
    let config = Config::from_json(json).expect("config");
    let mut builder = Instance::builder(config);
    if let Some(resolver) = resolver {
        builder = builder.process_resolver(resolver);
    }
    let bound = builder.build().expect("build").bind().await.expect("bind");
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

#[tokio::test]
async fn matches_an_injected_process_name() {
    let (echo, echo_task) = echo_server().await;
    let resolver = FixedResolver::new(Some("curl"));
    let (address, handle, serve) = start(PROCESS_ROUTE, Some(resolver.clone())).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    let status = socks5_connect(&mut client, echo).await;
    assert_ne!(status, 0, "reject rule should not connect");

    stop(handle, serve).await;
    echo_task.abort();
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unknown_process_fails_open() {
    let (echo, echo_task) = echo_server().await;
    let resolver = FixedResolver::new(None);
    let (address, handle, serve) = start(PROCESS_ROUTE, Some(resolver.clone())).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);
    client.write_all(b"hello").await.expect("write");
    let mut buffer = [0_u8; 5];
    client.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"hello");

    stop(handle, serve).await;
    echo_task.abort();
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn resolver_is_not_called_without_process_rules() {
    let (echo, echo_task) = echo_server().await;
    let resolver = FixedResolver::new(Some("curl"));
    let (address, handle, serve) = start(DIRECT, Some(resolver.clone())).await;

    let mut client = TcpStream::connect(address).await.expect("connect");
    assert_eq!(socks5_connect(&mut client, echo).await, 0);

    stop(handle, serve).await;
    echo_task.abort();
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn process_rules_without_a_resolver_fail_build() {
    let config = Config::from_json(PROCESS_ROUTE).expect("config");
    match Instance::builder(config).build() {
        Err(BuildError::MissingProcessResolver) => {}
        Ok(_) => panic!("build unexpectedly succeeded"),
        Err(other) => panic!("unexpected build error: {other:?}"),
    }
}
