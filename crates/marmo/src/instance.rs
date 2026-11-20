//! Public instance lifecycle: build, bind, serve, shutdown.
//!
//! `Config::from_json` validates the document; `build` compiles the router,
//! rejects protocols that are not implemented yet, and captures the tokio
//! handle. `bind` performs the only startup I/O; `serve` owns every accept
//! loop and drains connections on cancellation.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use marmo_net::{Endpoint, Network};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::config::{Config, ConfigError, InboundProtocol, OutboundProtocol};
use crate::direct;
use crate::inbound::{http, socks5};
use crate::limits::Limits;
use crate::outbound::http_connect;
use crate::routing::{Action, Router, RoutingError};
use crate::supervisor::Supervisor;

/// A built instance; no sockets are open yet.
pub struct Instance {
    runtime: Handle,
    limits: Limits,
    supervisor: Arc<Supervisor>,
    router: Arc<Router>,
    outbounds: Vec<OutboundKind>,
    inbounds: Vec<InboundSpec>,
}

impl Instance {
    /// Starts a builder. `build()` is pure: it performs no I/O.
    #[must_use]
    pub fn builder(config: Config) -> InstanceBuilder {
        InstanceBuilder {
            config,
            runtime: None,
            shutdown_grace: None,
        }
    }

    /// Returns a cloneable control handle.
    #[must_use]
    pub fn handle(&self) -> InstanceHandle {
        InstanceHandle {
            token: self.supervisor.token(),
        }
    }

    /// Binds every inbound and returns the running-bound state.
    pub async fn bind(self) -> Result<BoundInstance, BindError> {
        let Self {
            runtime,
            limits,
            supervisor,
            router,
            outbounds,
            inbounds,
        } = self;

        let mut bound = Vec::with_capacity(inbounds.len());
        for spec in inbounds {
            let listener =
                TcpListener::bind(spec.listen)
                    .await
                    .map_err(|source| BindError::Inbound {
                        inbound: spec.tag.to_string(),
                        address: spec.listen.to_string(),
                        source,
                    })?;
            let local_addr = listener.local_addr().map_err(|source| BindError::Inbound {
                inbound: spec.tag.to_string(),
                address: spec.listen.to_string(),
                source,
            })?;
            bound.push(BoundInbound {
                tag: spec.tag,
                kind: spec.kind,
                listener,
                local_addr,
            });
        }

        Ok(BoundInstance {
            runtime,
            limits,
            supervisor,
            router,
            outbounds,
            inbounds: bound,
        })
    }

    /// Binds and serves until [`InstanceHandle::shutdown`].
    pub async fn serve(self) -> Result<(), ServeError> {
        self.bind().await?.serve().await
    }

    /// Binds and serves until `shutdown` resolves or the handle is shut down.
    pub async fn serve_with_shutdown<F>(self, shutdown: F) -> Result<(), ServeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.bind().await?.serve_with_shutdown(shutdown).await
    }
}

/// Builder for [`Instance`].
pub struct InstanceBuilder {
    config: Config,
    runtime: Option<Handle>,
    shutdown_grace: Option<Duration>,
}

impl InstanceBuilder {
    /// Supplies the runtime handle explicitly. Without this, `build` uses
    /// `Handle::try_current()`.
    #[must_use]
    pub fn runtime(mut self, handle: Handle) -> Self {
        self.runtime = Some(handle);
        self
    }

    /// Overrides the drain deadline from `Config::limits`.
    #[must_use]
    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.shutdown_grace = Some(grace);
        self
    }

    /// Validates config, compiles rules, and rejects unsupported protocols.
    pub fn build(self) -> Result<Instance, BuildError> {
        self.config.validate()?;
        let runtime = match self.runtime {
            Some(handle) => handle,
            None => Handle::try_current().map_err(|_| BuildError::NoRuntime)?,
        };

        let mut limits = self.config.limits();
        if let Some(grace) = self.shutdown_grace {
            limits.shutdown_grace = grace;
        }
        let router = Router::compile(&self.config)?;

        let mut inbounds = Vec::with_capacity(self.config.inbounds.len());
        for inbound in &self.config.inbounds {
            let kind = match inbound.protocol {
                InboundProtocol::Socks5 => InboundKind::Socks5,
                InboundProtocol::Http => InboundKind::Http,
                protocol => {
                    return Err(BuildError::UnsupportedInbound {
                        tag: inbound.tag.clone(),
                        protocol,
                    });
                }
            };
            let endpoint =
                Endpoint::parse(&inbound.listen).map_err(|_| BuildError::InboundListen {
                    tag: inbound.tag.clone(),
                    listen: inbound.listen.clone(),
                })?;
            let Some(listen) = endpoint.to_socket_addr() else {
                return Err(BuildError::InboundListen {
                    tag: inbound.tag.clone(),
                    listen: inbound.listen.clone(),
                });
            };
            inbounds.push(InboundSpec {
                tag: Arc::from(inbound.tag.as_str()),
                kind,
                listen,
            });
        }

        let mut outbounds = Vec::with_capacity(self.config.outbounds.len());
        for outbound in &self.config.outbounds {
            match outbound.protocol {
                OutboundProtocol::Direct => outbounds.push(OutboundKind::Direct),
                OutboundProtocol::Http => {
                    let Some(server) = outbound.server.as_deref() else {
                        return Err(BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: String::new(),
                        });
                    };
                    let server =
                        Endpoint::parse(server).map_err(|_| BuildError::OutboundEndpoint {
                            tag: outbound.tag.clone(),
                            value: server.to_string(),
                        })?;
                    outbounds.push(OutboundKind::Http { server });
                }
                protocol => {
                    return Err(BuildError::UnsupportedOutbound {
                        tag: outbound.tag.clone(),
                        protocol,
                    });
                }
            }
        }

        let supervisor = Arc::new(Supervisor::new(limits.max_connections));
        Ok(Instance {
            runtime,
            limits,
            supervisor,
            router: Arc::new(router),
            outbounds,
            inbounds,
        })
    }
}

/// A bound instance: listeners are open, no accept loop has started.
pub struct BoundInstance {
    runtime: Handle,
    limits: Limits,
    supervisor: Arc<Supervisor>,
    router: Arc<Router>,
    outbounds: Vec<OutboundKind>,
    inbounds: Vec<BoundInbound>,
}

impl BoundInstance {
    /// Returns the bound address for each inbound.
    pub fn local_addrs(&self) -> impl Iterator<Item = BoundAddr<'_>> {
        self.inbounds.iter().map(|inbound| BoundAddr {
            tag: inbound.tag.as_ref(),
            network: Network::Tcp,
            addr: inbound.local_addr,
        })
    }

    /// Returns a cloneable control handle.
    #[must_use]
    pub fn handle(&self) -> InstanceHandle {
        InstanceHandle {
            token: self.supervisor.token(),
        }
    }

    /// Accepts until the handle shuts down or a listener fails.
    pub async fn serve(self) -> Result<(), ServeError> {
        let supervisor = Arc::clone(&self.supervisor);
        let runtime = self.runtime.clone();
        let limits = self.limits;
        let context = Arc::new(Context {
            runtime: runtime.clone(),
            supervisor: Arc::clone(&supervisor),
            router: self.router,
            outbounds: self.outbounds,
            limits,
        });
        let token = supervisor.token();

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

        supervisor.cancel();
        let grace = limits.shutdown_grace;
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

/// A cloneable shutdown handle.
#[derive(Clone)]
pub struct InstanceHandle {
    token: CancellationToken,
}

impl InstanceHandle {
    /// Requests shutdown. Non-blocking and idempotent.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns true after shutdown was requested.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// A bound listener address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundAddr<'a> {
    /// Inbound tag.
    pub tag: &'a str,
    /// Transport network.
    pub network: Network,
    /// Bound socket address.
    pub addr: SocketAddr,
}

pub(crate) struct Context {
    pub(crate) runtime: Handle,
    pub(crate) supervisor: Arc<Supervisor>,
    pub(crate) router: Arc<Router>,
    pub(crate) outbounds: Vec<OutboundKind>,
    pub(crate) limits: Limits,
}

impl Context {
    pub(crate) async fn connect(&self, action: Action, target: &Endpoint) -> io::Result<TcpStream> {
        match action {
            Action::Direct => direct::connect(target).await,
            Action::Route(id) => match self.outbounds.get(id.index() as usize) {
                Some(OutboundKind::Direct) => direct::connect(target).await,
                Some(OutboundKind::Http { server }) => http_connect::connect(server, target).await,
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "outbound id is out of range",
                )),
            },
            Action::Reject(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "route rejected the connection",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum OutboundKind {
    Direct,
    Http { server: Endpoint },
}

#[derive(Clone, Copy, Debug)]
enum InboundKind {
    Socks5,
    Http,
}

struct InboundSpec {
    tag: Arc<str>,
    kind: InboundKind,
    listen: SocketAddr,
}

struct BoundInbound {
    tag: Arc<str>,
    kind: InboundKind,
    listener: TcpListener,
    local_addr: SocketAddr,
}

async fn serve_inbound(inbound: BoundInbound, context: Arc<Context>) -> Result<(), ServeError> {
    let token = context.supervisor.token();
    let mut connections = JoinSet::new();
    let mut reap = interval(Duration::from_secs(1));
    let mut fatal = None;

    loop {
        while connections.try_join_next().is_some() {}
        tokio::select! {
            _ = token.cancelled() => break,
            _ = reap.tick() => {
                while connections.try_join_next().is_some() {}
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
                    drop(stream);
                    continue;
                };
                let tag = Arc::clone(&inbound.tag);
                let kind = inbound.kind;
                let task_context = Arc::clone(&context);
                let runtime = context.runtime.clone();
                let _ = connections.spawn_on(async move {
                    let _permit = permit;
                    match kind {
                        InboundKind::Socks5 => {
                            socks5::handle(stream, task_context, tag).await;
                        }
                        InboundKind::Http => {
                            http::handle(stream, task_context, tag).await;
                        }
                    }
                }, &runtime);
            }
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

/// Why an instance could not be built.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The configuration failed validation.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The routing rules could not be compiled.
    #[error(transparent)]
    Routing(#[from] RoutingError),
    /// No tokio runtime was supplied and none is current.
    #[error("no tokio runtime; call .runtime(handle) or build inside a runtime")]
    NoRuntime,
    /// The inbound protocol is not implemented yet.
    #[error("inbound '{tag}' protocol {protocol:?} is not implemented")]
    UnsupportedInbound {
        /// Inbound tag.
        tag: String,
        /// Configured protocol.
        protocol: InboundProtocol,
    },
    /// The outbound protocol is not implemented yet.
    #[error("outbound '{tag}' protocol {protocol:?} is not implemented")]
    UnsupportedOutbound {
        /// Outbound tag.
        tag: String,
        /// Configured protocol.
        protocol: OutboundProtocol,
    },
    /// The listen endpoint is not an IP literal.
    #[error("inbound '{tag}' listen is not an IP endpoint: {listen}")]
    InboundListen {
        /// Inbound tag.
        tag: String,
        /// Configured listen string.
        listen: String,
    },
    /// The outbound server endpoint is missing or invalid.
    #[error("outbound '{tag}' has an invalid server: {value}")]
    OutboundEndpoint {
        /// Outbound tag.
        tag: String,
        /// Configured server string.
        value: String,
    },
}

/// Why binding failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BindError {
    /// One inbound could not bind.
    #[error("inbound '{inbound}' failed to bind {address}: {source}")]
    Inbound {
        /// Inbound tag.
        inbound: String,
        /// Configured address.
        address: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },
}

/// Why serving stopped with an error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServeError {
    /// Binding failed before serving started.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// A listener could not accept.
    #[error("inbound '{inbound}' accept failed: {source}")]
    Accept {
        /// Inbound tag.
        inbound: String,
        /// Underlying socket error.
        #[source]
        source: io::Error,
    },
    /// An inbound task panicked.
    #[error("inbound task failed: {0}")]
    Task(String),
}
