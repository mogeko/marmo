//! Bound listeners, per-connection supervision, and the accept loops.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use marmo_net::Network;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{interval, timeout};

use crate::deadline::Deadline;
use crate::inbound::{self, http, socks5};
use crate::metrics::{MetricEvent, Metrics, MetricsSnapshot};
use crate::sniff::Policy;

use super::context::{Context, InboundKind};
use super::{BoundAddr, BoundInstance, InstanceHandle, ServeError};

/// Records a closed connection even if the handler future is aborted.
struct ConnectionGuard(Arc<Metrics>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.record(MetricEvent::ConnectionClosed);
    }
}

/// Aborts outbound background tasks when serving ends or the future is dropped.
#[derive(Default)]
struct BackgroundTasks(Vec<tokio::task::JoinHandle<()>>);

impl BackgroundTasks {
    fn abort_all(&mut self) {
        for task in self.0.drain(..) {
            task.abort();
        }
    }

    /// Waits for pool supervisors to drain, aborting any that exceed `grace`.
    async fn shutdown(&mut self, grace: Duration) {
        let tasks = std::mem::take(&mut self.0);
        let deadline = tokio::time::Instant::now() + grace;
        for mut task in tasks {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if timeout(remaining, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

pub(crate) struct BoundInbound {
    pub(crate) tag: Arc<str>,
    pub(crate) kind: InboundKind,
    pub(crate) listener: TcpListener,
    pub(crate) local_addr: SocketAddr,
    pub(crate) udp: Option<UdpSocket>,
    pub(crate) sniffing: Option<Policy>,
}

impl BoundInstance {
    /// Returns the bound address of every listener: TCP per inbound, plus UDP
    /// for protocols that serve both.
    pub fn local_addrs(&self) -> impl Iterator<Item = BoundAddr<'_>> {
        self.inbounds.iter().flat_map(|inbound| {
            let tcp = BoundAddr {
                tag: inbound.tag.as_ref(),
                network: Network::Tcp,
                addr: inbound.local_addr,
            };
            let udp = inbound
                .udp
                .as_ref()
                .and_then(|socket| socket.local_addr().ok())
                .map(|addr| BoundAddr {
                    tag: inbound.tag.as_ref(),
                    network: Network::Udp,
                    addr,
                });
            std::iter::once(tcp).chain(udp)
        })
    }

    /// Returns a cloneable control handle.
    #[must_use]
    pub fn handle(&self) -> InstanceHandle {
        InstanceHandle {
            token: self.supervisor.token(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    /// Returns a point-in-time copy of the instance counters.
    #[must_use]
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Accepts until the handle shuts down or a listener fails.
    pub async fn serve(self) -> Result<(), ServeError> {
        let supervisor = Arc::clone(&self.supervisor);
        let runtime = self.runtime.clone();
        let limits = self.limits;
        let dialer = self.dialer;
        let context = Arc::new(Context {
            runtime: runtime.clone(),
            supervisor: Arc::clone(&supervisor),
            router: self.router,
            metrics: self.metrics,
            process: self.process,
            direct: Arc::new(crate::direct::DirectOutbound::new(dialer.clone())),
            dialer,
            outbounds: self.outbounds,
            limits,
        });
        let token = supervisor.token();
        let mut background = BackgroundTasks::default();
        for outbound in &context.outbounds {
            background
                .0
                .extend(outbound.start(&context.runtime, &token));
            if let Some(task) = outbound.start_health(&context.runtime, &token) {
                background.0.push(task);
            }
        }

        let mut tasks = JoinSet::new();
        for inbound in self.inbounds {
            let context = Arc::clone(&context);
            let _ = tasks.spawn_on(serve_inbound(inbound, context), &runtime);
        }

        let mut fatal = None;
        while !tasks.is_empty() {
            tokio::select! {
                _ = token.cancelled() => break,
                result = tasks.join_next() => match result {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => {
                        fatal = Some(error);
                        supervisor.cancel();
                        break;
                    }
                    Some(Err(error)) => {
                        fatal = Some(ServeError::Task(error.to_string()));
                        supervisor.cancel();
                        break;
                    }
                    None => break,
                }
            }
        }

        let grace = limits.shutdown_grace;
        supervisor.cancel();
        background.shutdown(grace).await;
        let drain = async { while tasks.join_next().await.is_some() {} };
        if timeout(grace, drain).await.is_err() {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        match fatal {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Like [`BoundInstance::serve`], but also stops when `shutdown` resolves.
    pub async fn serve_with_shutdown<F>(self, shutdown: F) -> Result<(), ServeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let token = self.supervisor.token();
        let serve = self.serve();
        tokio::pin!(serve);
        tokio::select! {
            result = &mut serve => result,
            _ = shutdown => {
                token.cancel();
                serve.await
            }
        }
    }
}

async fn serve_inbound(mut inbound: BoundInbound, context: Arc<Context>) -> Result<(), ServeError> {
    let token = context.supervisor.token();
    let mut connections = JoinSet::new();
    let mut shared = JoinSet::new();
    let mut reap = interval(Duration::from_secs(1));
    let mut fatal = None;
    let runtime = context.runtime.clone();

    if let Some(socket) = inbound.udp.take()
        && let InboundKind::Shadowsocks { method, key, .. } = &inbound.kind
    {
        let udp_context = Arc::clone(&context);
        let tag = Arc::clone(&inbound.tag);
        let (method, key) = (*method, Arc::clone(key));
        let _ = shared.spawn_on(
            inbound::shadowsocks_udp::serve(socket, udp_context, tag, method, key),
            &runtime,
        );
    }

    loop {
        reap_finished(&mut connections, &context.metrics);
        tokio::select! {
            _ = token.cancelled() => break,
            _ = reap.tick() => {
                reap_finished(&mut connections, &context.metrics);
            }
            Some(result) = shared.join_next(), if !shared.is_empty() => {
                if token.is_cancelled() {
                    break;
                }
                context.metrics.record(MetricEvent::TaskPanicked);
                fatal = Some(ServeError::Task(match result {
                    Ok(()) => "shared UDP listener stopped".into(),
                    Err(error) => error.to_string(),
                }));
                break;
            }
            accepted = inbound.listener.accept() => {
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
                    Err(source) => {
                        fatal = Some(ServeError::Accept {
                            inbound: inbound.tag.to_string(),
                            source,
                        });
                        break;
                    }
                };

                let Some(permit) = context.supervisor.try_acquire() else {
                    context.metrics.record(MetricEvent::ConnectionRejected);
                    drop(stream);
                    continue;
                };
                context.metrics.record(MetricEvent::ConnectionAccepted);
                let tag = Arc::clone(&inbound.tag);
                let kind = inbound.kind.clone();
                let sniffing = inbound.sniffing;
                let task_context = Arc::clone(&context);
                let deadline = Deadline::after(
                    context.limits.handshake_timeout,
                    Arc::clone(&context.metrics),
                );
                let guard = ConnectionGuard(Arc::clone(&context.metrics));
                let runtime = context.runtime.clone();
                let _ = connections.spawn_on(async move {
                    let _permit = permit;
                    let _guard = guard;
                    match kind {
                        InboundKind::Socks5 => {
                            socks5::handle(stream, task_context, tag, sniffing, deadline).await;
                        }
                        InboundKind::Http => {
                            http::handle(stream, task_context, tag, sniffing, deadline).await;
                        }
                        InboundKind::Shadowsocks {
                            method,
                            key,
                            replay,
                        } => {
                            inbound::shadowsocks::handle(
                                stream,
                                task_context,
                                tag,
                                method,
                                key,
                                replay,
                                sniffing,
                                deadline,
                            )
                            .await;
                        }
                        InboundKind::Trojan {
                            password,
                            tls,
                            fallback,
                        } => {
                            inbound::trojan::handle(
                                stream,
                                task_context,
                                tag,
                                tls,
                                password,
                                fallback,
                                sniffing,
                                deadline,
                            )
                            .await;
                        }
                        InboundKind::Vless { uuid, layers, h2 } => {
                            if let Some(options) = h2 {
                                inbound::vless::serve_h2(
                                    stream,
                                    task_context,
                                    tag,
                                    uuid,
                                    layers,
                                    options,
                                    sniffing,
                                    deadline,
                                )
                                .await;
                            } else {
                                inbound::vless::handle(
                                    stream,
                                    task_context,
                                    tag,
                                    uuid,
                                    layers,
                                    sniffing,
                                    deadline,
                                )
                                .await;
                            }
                        }
                        InboundKind::Vmess {
                            cmd_key,
                            replay,
                            layers,
                            h2,
                        } => {
                            if let Some(options) = h2 {
                                inbound::vmess::serve_h2(
                                    stream,
                                    task_context,
                                    tag,
                                    cmd_key,
                                    replay,
                                    layers,
                                    options,
                                    sniffing,
                                    deadline,
                                )
                                .await;
                            } else {
                                inbound::vmess::handle(
                                    stream,
                                    task_context,
                                    tag,
                                    cmd_key,
                                    replay,
                                    layers,
                                    sniffing,
                                    deadline,
                                )
                                .await;
                            }
                        }
                    }
                }, &runtime);
            }
        }
    }

    shared.abort_all();
    while let Some(result) = shared.join_next().await {
        if result.is_err() {
            context.metrics.record(MetricEvent::TaskPanicked);
        }
    }

    let grace = context.limits.shutdown_grace;
    let drain = async { while connections.join_next().await.is_some() {} };
    if timeout(grace, drain).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    match fatal {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn reap_finished(tasks: &mut JoinSet<()>, metrics: &Metrics) {
    while let Some(result) = tasks.try_join_next() {
        if result.is_err() {
            metrics.record(MetricEvent::TaskPanicked);
        }
    }
}
