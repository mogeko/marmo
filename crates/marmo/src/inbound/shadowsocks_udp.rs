//! Shadowsocks 2022 UDP inbound: per-client-session relay sockets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use marmo_net::{Endpoint, Network};
use marmo_proto::shadowsocks::{
    Direction, Key, Method, UdpPacket, Window, decode_udp_packet, encode_udp_packet, next_counter,
};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::direct::Dialer;
use crate::instance::Context;
use crate::routing::Metadata;
use crate::shadowsocks::{random_bytes, unix_now};

/// Fixed session-table capacity.
const MAX_SESSIONS: usize = 128;
/// Largest plaintext payload carried by one packet.
const MAX_PAYLOAD: usize = 65_535;
/// Largest encoded packet: separate header, body header, address, payload, tag.
const MAX_ENCODED: usize = 16 + 1 + 8 + 8 + 2 + 259 + MAX_PAYLOAD + 16;

/// Runs the UDP listener until shutdown, aborting every session on exit.
pub(crate) async fn serve(
    listener: UdpSocket, context: Arc<Context>, inbound: Arc<str>, method: Method, key: Arc<Key>,
) {
    let listener = Arc::new(listener);
    let token = context.supervisor.token();
    let mut sessions: HashMap<[u8; 8], Session> = HashMap::new();
    let mut packet = vec![0_u8; MAX_PAYLOAD];
    let mut plain = vec![0_u8; MAX_PAYLOAD];
    let mut reap = interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = reap.tick() => reap_sessions(&mut sessions, context.limits.idle_timeout),
            received = listener.recv_from(&mut packet) => {
                let Ok((length, source)) = received else {
                    continue;
                };
                let Ok(decoded) = decode_udp_packet(
                    method,
                    key.as_bytes(),
                    &packet[..length],
                    Direction::ClientToServer,
                    None,
                    &mut plain,
                ) else {
                    continue;
                };

                let client_session = decoded.session_id;
                if sessions
                    .get(&client_session)
                    .is_some_and(|session| session.task.is_finished())
                    && let Some(session) = sessions.remove(&client_session) {
                        session.task.abort();
                    }
                if !sessions.contains_key(&client_session) {
                    reap_sessions(&mut sessions, context.limits.idle_timeout);
                    if sessions.len() >= MAX_SESSIONS {
                        continue;
                    }
                    let Some(session) = Session::create(
                        &listener,
                        method,
                        &key,
                        client_session,
                        source,
                        context.dialer.clone(),
                    )
                    .await
                    else {
                        continue;
                    };
                    sessions.insert(client_session, session);
                    context
                        .metrics
                        .record(crate::metrics::MetricEvent::UdpSessionOpened);
                }
                let Some(session) = sessions.get_mut(&client_session) else {
                    continue;
                };

                if !session.window.accept(decoded.packet_id) {
                    continue;
                }
                session.touch(source);

                let destination = decoded.destination.clone();
                let domain = destination.domain().map(str::to_owned);
                let metadata = Metadata {
                    network: Network::Udp,
                    source: Endpoint::from(source),
                    destination: destination.clone(),
                    domain: domain.as_deref(),
                    inbound: Some(inbound.as_ref()),
                    process: None,
                };
                let action = context.route(metadata).await;
                if !context.udp_direct(action) {
                    continue;
                }
                let Some(target) = session.resolve(&destination).await else {
                    continue;
                };
                let _ = session.socket.send_to(decoded.payload, target).await;
            }
        }
    }

    for (_, session) in sessions.drain() {
        session.task.abort();
    }
}

struct ClientState {
    address: SocketAddr,
    last_active: Instant,
}

struct Session {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<ClientState>>,
    window: Window,
    ipv4: bool,
    dialer: Dialer,
    task: JoinHandle<()>,
}

impl Session {
    async fn create(
        listener: &Arc<UdpSocket>, method: Method, key: &Arc<Key>, client_session_id: [u8; 8],
        source: SocketAddr, dialer: Dialer,
    ) -> Option<Self> {
        let ipv4 = source.is_ipv4();
        let bind = if ipv4 {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        let socket = Arc::new(UdpSocket::bind(bind).await.ok()?);
        let mut server_session_id = random_bytes::<8>().ok()?;
        if server_session_id == client_session_id {
            server_session_id[0] ^= 1;
        }
        let state = Arc::new(Mutex::new(ClientState {
            address: source,
            last_active: Instant::now(),
        }));
        let task_listener = Arc::clone(listener);
        let task_socket = Arc::clone(&socket);
        let task_key = Arc::clone(key);
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut counter = 0_u64;
            let mut received = vec![0_u8; MAX_PAYLOAD];
            let mut encoded = vec![0_u8; MAX_ENCODED];
            loop {
                let Ok((length, source)) = task_socket.recv_from(&mut received).await else {
                    return;
                };
                let address = match task_state.lock() {
                    Ok(mut state) => {
                        state.last_active = Instant::now();
                        state.address
                    }
                    Err(_) => return,
                };
                let Ok(packet_id) = next_counter(&mut counter) else {
                    return;
                };
                let destination = Endpoint::from(source);
                let packet = UdpPacket {
                    direction: Direction::ServerToClient,
                    session_id: server_session_id,
                    packet_id,
                    client_session_id: Some(client_session_id),
                    destination: &destination,
                    payload: &received[..length],
                    padding_len: 0,
                    timestamp: unix_now(),
                };
                let Ok(size) =
                    encode_udp_packet(method, task_key.as_bytes(), &packet, &mut encoded)
                else {
                    return;
                };
                if task_listener
                    .send_to(&encoded[..size], address)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        Some(Self {
            socket,
            state,
            window: Window::default(),
            ipv4,
            dialer,
            task,
        })
    }

    async fn resolve(&self, destination: &Endpoint) -> Option<SocketAddr> {
        self.dialer.resolve_udp(destination, self.ipv4).await.ok()
    }

    fn touch(&self, source: SocketAddr) {
        if let Ok(mut state) = self.state.lock() {
            state.address = source;
            state.last_active = Instant::now();
        }
    }

    fn last_active(&self) -> Instant {
        self.state
            .lock()
            .map(|state| state.last_active)
            .unwrap_or_else(|_| Instant::now())
    }
}

fn reap_sessions(sessions: &mut HashMap<[u8; 8], Session>, idle: Option<Duration>) {
    let finished: Vec<[u8; 8]> = sessions
        .iter()
        .filter(|(_, session)| session.task.is_finished())
        .map(|(id, _)| *id)
        .collect();
    for id in finished {
        if let Some(session) = sessions.remove(&id) {
            session.task.abort();
        }
    }
    let Some(idle) = idle else {
        return;
    };
    let now = Instant::now();
    let expired: Vec<[u8; 8]> = sessions
        .iter()
        .filter(|(_, session)| now.duration_since(session.last_active()) >= idle)
        .map(|(id, _)| *id)
        .collect();
    for id in expired {
        if let Some(session) = sessions.remove(&id) {
            session.task.abort();
        }
    }
}
