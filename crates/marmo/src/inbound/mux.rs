//! Inbound Mux.Cool dispatcher for the VMess Mux command.
//!
//! One physical stream carries many logical TCP or UDP sessions. The session
//! table is bounded, each session owns one task and one bounded uplink queue,
//! and all downlink frames are serialized through one writer.

use std::collections::HashMap;
use std::sync::Arc;

use marmo_net::{Endpoint, Network};
use marmo_proto::mux::{
    NETWORK_TCP, NETWORK_UDP, STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE, STATUS_NEW,
};
use marmo_proto::vless::MAX_UDP_PAYLOAD;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::{AbortHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::deadline::wait_for_activity;
use crate::instance::Context;
use crate::mux::{Frame, MuxReader, MuxWriter};
use crate::routing::{Action, Metadata};
use crate::vmess::ChunkStream;

/// Maximum sessions on one physical connection.
const MAX_SESSIONS: usize = 128;
/// Bounded uplink frames per session.
const QUEUE: usize = 16;
/// Bytes read from one logical TCP stream per read.
const READ_BUFFER: usize = 32 * 1024;

type Writer = Arc<Mutex<MuxWriter<WriteHalf<ChunkStream>>>>;

struct Uplink {
    target: Option<Endpoint>,
    data: Vec<u8>,
}

struct Session {
    cancel: CancellationToken,
    abort: AbortHandle,
    uplink: mpsc::Sender<Uplink>,
}

/// Serves Mux.Cool frames until the physical stream closes or fails.
pub(crate) async fn serve(
    stream: ChunkStream, context: Arc<Context>, inbound: Arc<str>, source: Endpoint,
    token: CancellationToken,
) {
    let (reader, writer) = tokio::io::split(stream);
    let Ok(frames) = MuxReader::new(reader, &[]) else {
        return;
    };
    let writer: Writer = Arc::new(Mutex::new(MuxWriter::new(writer)));
    let (closed_tx, mut closed_rx) = mpsc::channel::<u16>(MAX_SESSIONS);
    let mut state = State {
        sessions: HashMap::new(),
        tasks: JoinSet::new(),
        closed: closed_tx,
        writer,
        context,
        inbound,
        source,
        token: token.clone(),
    };
    let activity = Arc::new(Notify::new());
    let mut frames = frames;
    loop {
        let has_tasks = !state.tasks.is_empty();
        tokio::select! {
            _ = token.cancelled() => break,
            idle = wait_for_activity(state.context.limits.idle_timeout, &activity) => {
                if idle {
                    break;
                }
            }
            Some(_) = state.tasks.join_next(), if has_tasks => {}
            closed = closed_rx.recv() => {
                if let Some(id) = closed {
                    state.sessions.remove(&id);
                }
            }
            result = frames.next() => {
                let Ok(Some(frame)) = result else {
                    break;
                };
                activity.notify_one();
                if !state.handle(frame).await {
                    break;
                }
            }
        }
    }
    for (_, session) in state.sessions.drain() {
        session.cancel.cancel();
        session.abort.abort();
    }
    while state.tasks.join_next().await.is_some() {}
}

struct State {
    sessions: HashMap<u16, Session>,
    tasks: JoinSet<()>,
    closed: mpsc::Sender<u16>,
    writer: Writer,
    context: Arc<Context>,
    inbound: Arc<str>,
    source: Endpoint,
    token: CancellationToken,
}

impl State {
    /// Handles one frame; false closes the physical connection.
    async fn handle(&mut self, frame: Frame) -> bool {
        match frame.meta.status {
            STATUS_NEW => self.new_session(&frame).await,
            STATUS_KEEP => self.keep(frame).await,
            STATUS_END => {
                if let Some(session) = self.sessions.remove(&frame.meta.session) {
                    session.cancel.cancel();
                    session.abort.abort();
                }
                true
            }
            STATUS_KEEPALIVE => true,
            _ => false,
        }
    }

    async fn new_session(&mut self, frame: &Frame) -> bool {
        let id = frame.meta.session;
        if self.sessions.contains_key(&id) {
            return false;
        }
        let Some(target) = frame.meta.target.clone() else {
            return false;
        };
        if self.sessions.len() >= MAX_SESSIONS {
            let _ = self
                .writer
                .lock()
                .await
                .end_error(id, b"session limit")
                .await;
            return true;
        }
        let (uplink, receiver) = mpsc::channel(QUEUE);
        let cancel = self.token.child_token();
        let writer = Arc::clone(&self.writer);
        let closed = self.closed.clone();
        let context = Arc::clone(&self.context);
        let inbound = Arc::clone(&self.inbound);
        let source = self.source.clone();
        let session_token = cancel.clone();
        let abort = match frame.meta.network {
            NETWORK_TCP => self.tasks.spawn(run_tcp(
                id,
                target,
                receiver,
                writer,
                context,
                inbound,
                source,
                session_token,
                closed,
            )),
            NETWORK_UDP => self.tasks.spawn(run_udp(
                id,
                target,
                receiver,
                writer,
                context,
                inbound,
                source,
                session_token,
                closed,
            )),
            _ => return false,
        };
        self.sessions.insert(
            id,
            Session {
                cancel,
                abort,
                uplink: uplink.clone(),
            },
        );
        if !frame.data.is_empty() {
            let _ = uplink.try_send(Uplink {
                target: None,
                data: frame.data.clone(),
            });
        }
        true
    }

    async fn keep(&mut self, frame: Frame) -> bool {
        let id = frame.meta.session;
        let Some(session) = self.sessions.get(&id) else {
            return true;
        };
        if frame.data.is_empty() {
            return true;
        }
        if session
            .uplink
            .try_send(Uplink {
                target: frame.meta.target,
                data: frame.data,
            })
            .is_err()
        {
            if let Some(session) = self.sessions.remove(&id) {
                session.cancel.cancel();
                session.abort.abort();
            }
            let _ = self.writer.lock().await.end(id).await;
        }
        true
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp(
    id: u16, target: Endpoint, mut receiver: mpsc::Receiver<Uplink>, writer: Writer,
    context: Arc<Context>, inbound: Arc<str>, source: Endpoint, token: CancellationToken,
    closed: mpsc::Sender<u16>,
) {
    tcp_session(
        id,
        &target,
        &mut receiver,
        &writer,
        &context,
        &inbound,
        &source,
        &token,
    )
    .await;
    let _ = closed.try_send(id);
}

#[allow(clippy::too_many_arguments)]
async fn tcp_session(
    id: u16, target: &Endpoint, receiver: &mut mpsc::Receiver<Uplink>, writer: &Writer,
    context: &Context, inbound: &str, source: &Endpoint, token: &CancellationToken,
) {
    let Some(action) = route(context, inbound, source, target, Network::Tcp) else {
        let _ = writer.lock().await.end_error(id, b"no route").await;
        return;
    };
    let connected = tokio::select! {
        _ = token.cancelled() => return,
        result = context.connect(action, target) => result,
    };
    let Ok(connected) = connected else {
        let _ = writer.lock().await.end_error(id, b"connect failed").await;
        return;
    };
    let (mut read, mut write) = tokio::io::split(connected.stream);
    let mut buffer = vec![0_u8; READ_BUFFER];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            message = receiver.recv() => {
                let Some(message) = message else {
                    break;
                };
                if write.write_all(&message.data).await.is_err() {
                    break;
                }
            }
            result = read.read(&mut buffer) => {
                match result {
                    Ok(0) => break,
                    Ok(count) => {
                        if writer
                            .lock()
                            .await
                            .keep(id, None, &buffer[..count])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    let _ = writer.lock().await.end(id).await;
}

#[allow(clippy::too_many_arguments)]
async fn run_udp(
    id: u16, target: Endpoint, mut receiver: mpsc::Receiver<Uplink>, writer: Writer,
    context: Arc<Context>, inbound: Arc<str>, source: Endpoint, token: CancellationToken,
    closed: mpsc::Sender<u16>,
) {
    udp_session(
        id,
        &target,
        &mut receiver,
        &writer,
        &context,
        &inbound,
        &source,
        &token,
    )
    .await;
    let _ = closed.try_send(id);
}

#[allow(clippy::too_many_arguments)]
async fn udp_session(
    id: u16, initial: &Endpoint, receiver: &mut mpsc::Receiver<Uplink>, writer: &Writer,
    context: &Context, inbound: &str, source: &Endpoint, token: &CancellationToken,
) {
    let Some(action) = route(context, inbound, source, initial, Network::Udp) else {
        let _ = writer.lock().await.end_error(id, b"no route").await;
        return;
    };
    let ipv4 = source.ip().is_none_or(|ip| ip.is_ipv4());
    let outbound = tokio::select! {
        _ = token.cancelled() => return,
        result = context.udp_outbound(action, ipv4, initial) => result,
    };
    let Ok(Some(mut outbound)) = outbound else {
        let _ = writer.lock().await.end_error(id, b"udp unavailable").await;
        return;
    };
    let mut buffer = vec![0_u8; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            message = receiver.recv() => {
                let Some(message) = message else {
                    break;
                };
                let destination = message.target.as_ref().unwrap_or(initial);
                if outbound.send_to(destination, &message.data).await.is_err() {
                    break;
                }
            }
            received = outbound.recv_from(&mut buffer) => {
                let Ok((length, from)) = received else {
                    break;
                };
                if writer
                    .lock()
                    .await
                    .keep(id, Some(&from), &buffer[..length])
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    let _ = writer.lock().await.end(id).await;
}

fn route(
    context: &Context, inbound: &str, source: &Endpoint, target: &Endpoint, network: Network,
) -> Option<Action> {
    let domain = target.domain().map(str::to_owned);
    let metadata = Metadata {
        network,
        source: source.clone(),
        destination: target.clone(),
        domain: domain.as_deref(),
        inbound: Some(inbound),
    };
    Some(context.router.route(&metadata))
}
