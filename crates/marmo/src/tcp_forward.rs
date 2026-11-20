//! R1 TCP forward engine: accept, admit, connect, relay.
//!
//! This is the internal composition root used by the integration tests. The
//! public `Instance` lifecycle lands with the R2 configuration schema.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use marmo_net::Endpoint;
use marmo_transport::{BoxStream, RelayOptions, relay};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::direct;
use crate::limits::Limits;
use crate::supervisor::Supervisor;

/// A fixed TCP forwarder used to exercise the supervisor and relay.
pub(crate) struct TcpForward {
    listen: Endpoint,
    target: Endpoint,
    limits: Limits,
}

impl TcpForward {
    pub(crate) fn new(listen: Endpoint, target: Endpoint, limits: Limits) -> Self {
        Self {
            listen,
            target,
            limits,
        }
    }

    /// Binds the listener. Partial state is dropped on failure.
    pub(crate) async fn bind(self) -> Result<BoundTcpForward, TcpForwardError> {
        let address = self
            .listen
            .to_socket_addr()
            .ok_or_else(|| TcpForwardError::DomainListen(self.listen.clone()))?;
        let listener = TcpListener::bind(address)
            .await
            .map_err(TcpForwardError::Bind)?;
        let local_addr = listener.local_addr().map_err(TcpForwardError::Bind)?;

        Ok(BoundTcpForward {
            listener,
            local_addr,
            target: self.target,
            limits: self.limits,
            supervisor: Arc::new(Supervisor::new(self.limits.max_connections)),
            counters: Arc::new(Counters::default()),
            connections: JoinSet::new(),
        })
    }
}

/// A bound forwarder that can be served and stopped.
pub(crate) struct BoundTcpForward {
    listener: TcpListener,
    local_addr: SocketAddr,
    target: Endpoint,
    limits: Limits,
    supervisor: Arc<Supervisor>,
    counters: Arc<Counters>,
    connections: JoinSet<()>,
}

impl BoundTcpForward {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn handle(&self) -> TcpForwardHandle {
        TcpForwardHandle {
            token: self.supervisor.token(),
            counters: Arc::clone(&self.counters),
        }
    }

    /// Accepts until shutdown, then drains within `shutdown_grace`.
    pub(crate) async fn serve(mut self) -> Result<(), TcpForwardError> {
        let token = self.supervisor.token();
        let mut reap = interval(Duration::from_secs(1));
        let mut fatal = None;

        loop {
            while self.connections.try_join_next().is_some() {}
            tokio::select! {
                _ = token.cancelled() => break,
                _ = reap.tick() => {
                    while self.connections.try_join_next().is_some() {}
                }
                accepted = self.listener.accept() => {
                    let (stream, _peer) = match accepted {
                        Ok(pair) => pair,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                            ) =>
                        {
                            continue;
                        }
                        Err(error) => {
                            fatal = Some(error);
                            break;
                        }
                    };

                    let Some(permit) = self.supervisor.try_acquire() else {
                        Counters::inc(&self.counters.rejected);
                        drop(stream);
                        continue;
                    };
                    Counters::inc(&self.counters.accepted);

                    let target = self.target.clone();
                    let limits = self.limits;
                    let token = token.clone();
                    let counters = Arc::clone(&self.counters);
                    let _ = self.connections.spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, &target, limits, token, counters).await;
                    });
                }
            }
        }

        self.shutdown().await;
        match fatal {
            Some(error) => Err(TcpForwardError::Accept(error)),
            None => Ok(()),
        }
    }

    async fn shutdown(&mut self) {
        self.supervisor.cancel();
        let grace = self.limits.shutdown_grace;
        let drain = async { while self.connections.join_next().await.is_some() {} };
        if timeout(grace, drain).await.is_err() {
            self.connections.abort_all();
            while self.connections.join_next().await.is_some() {}
        }
    }
}

impl Drop for BoundTcpForward {
    fn drop(&mut self) {
        self.supervisor.cancel();
        self.connections.abort_all();
    }
}

/// Cloneable control handle for a served forwarder.
#[derive(Clone)]
pub(crate) struct TcpForwardHandle {
    token: CancellationToken,
    counters: Arc<Counters>,
}

impl TcpForwardHandle {
    pub(crate) fn shutdown(&self) {
        self.token.cancel();
    }

    pub(crate) fn accepted(&self) -> u64 {
        self.counters.accepted.load(Ordering::Relaxed)
    }

    pub(crate) fn rejected(&self) -> u64 {
        self.counters.rejected.load(Ordering::Relaxed)
    }

    pub(crate) fn failed(&self) -> u64 {
        self.counters.failed.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    rejected: AtomicU64,
    failed: AtomicU64,
}

impl Counters {
    fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

async fn handle_connection(
    stream: TcpStream,
    target: &Endpoint,
    limits: Limits,
    token: CancellationToken,
    counters: Arc<Counters>,
) {
    let remote = tokio::select! {
        _ = token.cancelled() => return,
        result = timeout(limits.handshake_timeout, direct::connect(target)) => {
            match result {
                Ok(Ok(remote)) => remote,
                Ok(Err(_)) | Err(_) => {
                    Counters::inc(&counters.failed);
                    return;
                }
            }
        }
    };

    let options = RelayOptions {
        idle_timeout: limits.idle_timeout,
        uplink_grace: limits.uplink_grace,
        downlink_grace: limits.downlink_grace,
    };
    let relay = relay(
        Box::new(stream) as BoxStream,
        Box::new(remote) as BoxStream,
        options,
    );
    tokio::select! {
        _ = token.cancelled() => {}
        result = relay => {
            if result.is_err() {
                Counters::inc(&counters.failed);
            }
        }
    }
}

/// Why a forwarder could not bind or serve.
#[derive(Debug, Error)]
pub(crate) enum TcpForwardError {
    /// The listen endpoint is a domain; listeners must be IP literals.
    #[error("listen endpoint must be an IP: {0}")]
    DomainListen(Endpoint),
    /// Binding the listener failed.
    #[error("bind failed: {0}")]
    Bind(#[source] io::Error),
    /// A fatal accept error stopped the listener.
    #[error("accept failed: {0}")]
    Accept(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::sleep;

    async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

    async fn start_forward(
        target: SocketAddr,
        limits: Limits,
    ) -> (
        SocketAddr,
        TcpForwardHandle,
        tokio::task::JoinHandle<Result<(), TcpForwardError>>,
    ) {
        let listen = Endpoint::from(SocketAddr::from(([127, 0, 0, 1], 0)));
        let bound = TcpForward::new(listen, Endpoint::from(target), limits)
            .bind()
            .await
            .expect("bind");
        let address = bound.local_addr();
        let handle = bound.handle();
        let serve = tokio::spawn(bound.serve());
        (address, handle, serve)
    }

    async fn finish(
        handle: TcpForwardHandle,
        serve: tokio::task::JoinHandle<Result<(), TcpForwardError>>,
    ) {
        handle.shutdown();
        timeout(Duration::from_secs(2), serve)
            .await
            .expect("serve timeout")
            .expect("join")
            .expect("serve");
    }

    async fn wait_for(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !condition() {
            assert!(Instant::now() < deadline, "condition timed out");
            sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn relays_bytes() {
        let (echo, echo_task) = spawn_echo().await;
        let (address, handle, serve) = start_forward(echo, Limits::default()).await;

        let mut client = TcpStream::connect(address).await.expect("connect");
        client.write_all(b"hello").await.expect("write");
        let mut buffer = [0_u8; 5];
        client.read_exact(&mut buffer).await.expect("read");
        assert_eq!(&buffer, b"hello");

        finish(handle, serve).await;
        echo_task.abort();
    }

    #[tokio::test]
    async fn idle_timeout_closes() {
        let (echo, echo_task) = spawn_echo().await;
        let limits = Limits {
            idle_timeout: Some(Duration::from_millis(50)),
            ..Limits::default()
        };
        let (address, handle, serve) = start_forward(echo, limits).await;

        let mut client = TcpStream::connect(address).await.expect("connect");
        let mut buffer = [0_u8; 1];
        let result = timeout(Duration::from_secs(1), client.read(&mut buffer))
            .await
            .expect("client should close");
        assert!(matches!(result, Ok(0) | Err(_)));

        finish(handle, serve).await;
        echo_task.abort();
    }

    #[tokio::test]
    async fn connection_limit_rejects() {
        let (echo, echo_task) = spawn_echo().await;
        let limits = Limits {
            max_connections: 1,
            ..Limits::default()
        };
        let (address, handle, serve) = start_forward(echo, limits).await;

        let mut first = TcpStream::connect(address).await.expect("connect");
        first.write_all(b"x").await.expect("write");
        let mut buffer = [0_u8; 1];
        first.read_exact(&mut buffer).await.expect("echo");
        wait_for(|| handle.accepted() >= 1).await;

        let mut second = TcpStream::connect(address).await.expect("connect");
        let result = timeout(Duration::from_secs(1), second.read(&mut buffer))
            .await
            .expect("second should close");
        assert!(matches!(result, Ok(0) | Err(_)));
        assert_eq!(handle.rejected(), 1);
        assert_eq!(handle.failed(), 0);

        finish(handle, serve).await;
        echo_task.abort();
    }

    #[tokio::test]
    async fn propagates_half_close() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let server_address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (mut reader, mut writer) = stream.into_split();
            let mut data = Vec::new();
            reader.read_to_end(&mut data).await.expect("read");
            assert_eq!(data, b"bye");
            writer.write_all(b"ack").await.expect("write");
            writer.shutdown().await.expect("shutdown");
        });

        let (address, handle, serve) = start_forward(server_address, Limits::default()).await;
        let mut client = TcpStream::connect(address).await.expect("connect");
        client.write_all(b"bye").await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("read");
        assert_eq!(response, b"ack");

        finish(handle, serve).await;
        server.abort();
    }

    #[tokio::test]
    async fn shutdown_stops_listener() {
        let (echo, echo_task) = spawn_echo().await;
        let (address, handle, serve) = start_forward(echo, Limits::default()).await;
        finish(handle, serve).await;

        assert!(TcpStream::connect(address).await.is_err());
        echo_task.abort();
    }
}
