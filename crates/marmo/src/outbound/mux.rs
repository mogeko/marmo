//! Client-side Mux.Cool pool shared by the VMess and VLESS outbounds.
//!
//! A pool owns up to four physical connections. Each connection has one read
//! driver, one serialized writer, and a bounded session table. TCP sessions use
//! a duplex pipe plus one task; UDP sessions use a bounded datagram queue.
//! Downlink is bounded by a connection-wide memory permit budget.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use marmo_net::Endpoint;
use marmo_proto::mux::{
    NETWORK_TCP, NETWORK_UDP, STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE, STATUS_NEW,
};
use marmo_transport::{BoxFuture, BoxStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::AbortHandle;
use tokio::time::{Instant, MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::mux::{Frame, MuxReader, MuxWriter};

/// Physical connections per outbound.
const MAX_CONNECTIONS: usize = 4;
/// Concurrent sessions per physical connection.
const MAX_SESSIONS: usize = 128;
/// Queued frames per TCP or UDP session.
const QUEUE_FRAMES: usize = 16;
/// Queued write commands per connection.
const QUEUE_WRITES: usize = 64;
/// TCP pipe size in bytes.
const TCP_PIPE: usize = 32 * 1024;
/// Connection-wide in-flight downlink budget (64 KiB frames).
const MEMORY_PERMITS: usize = 64;
/// Keep-alive interval while the connection is idle.
const KEEPALIVE: Duration = Duration::from_secs(15);
/// Close an idle connection with no sessions.
const IDLE: Duration = Duration::from_secs(30);
/// Read buffer for one TCP session.
const READ_BUFFER: usize = 32 * 1024;

/// Opens one protocol-specific mux connection.
pub(crate) trait MuxDialer: Send + Sync + 'static {
    /// Dials the server and sends the protocol mux request.
    fn dial(&self) -> BoxFuture<'_, io::Result<BoxStream>>;

    /// Bytes the server sends before the first Mux.Cool frame.
    fn handshake_len(&self) -> usize {
        0
    }
}

enum WriteCommand {
    New {
        id: u16,
        target: Endpoint,
        network: u8,
    },
    Keep {
        id: u16,
        target: Option<Endpoint>,
        data: Vec<u8>,
    },
    End {
        id: u16,
    },
    KeepAlive,
}

struct FrameData {
    data: Vec<u8>,
    source: Option<Endpoint>,
    _permit: OwnedSemaphorePermit,
}

enum SessionEntry {
    Tcp {
        down: mpsc::Sender<FrameData>,
        abort: AbortHandle,
    },
    Udp {
        down: mpsc::Sender<FrameData>,
    },
}

type Sessions = Arc<StdMutex<HashMap<u16, SessionEntry>>>;

#[derive(Clone)]
struct ConnectionState {
    sessions: Sessions,
    count: Arc<AtomicUsize>,
    memory: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
}

/// A bounded pool of mux connections.
pub(crate) struct MuxPool {
    runtime: Handle,
    token: CancellationToken,
    dialer: Arc<dyn MuxDialer>,
    connections: tokio::sync::Mutex<Vec<Arc<MuxConnection>>>,
    tasks: TaskTracker,
}

impl Drop for MuxPool {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

impl MuxPool {
    /// Builds a pool; no connection is dialed until the first session.
    pub(crate) fn new(
        runtime: Handle, token: CancellationToken, dialer: Arc<dyn MuxDialer>,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            token: token.child_token(),
            dialer,
            connections: tokio::sync::Mutex::new(Vec::new()),
            tasks: TaskTracker::new(),
        })
    }

    /// Spawns the supervisor that closes connections and drains tasks on
    /// shutdown.
    pub(crate) fn supervisor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        self.runtime.spawn(async move {
            pool.token.cancelled().await;
            let connections = pool.connections.lock().await.clone();
            for connection in &connections {
                connection.close();
            }
            pool.tasks.close();
            pool.tasks.wait().await;
        })
    }

    /// Opens a TCP session over the pool.
    pub(crate) async fn open_tcp(&self, target: &Endpoint) -> io::Result<BoxStream> {
        for _ in 0..2 {
            if self.token.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "mux pool is shut down",
                ));
            }
            let connection = self.connection().await?;
            match connection.open_tcp(target).await {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "mux pool is full",
        ))
    }

    /// Opens a UDP session over the pool.
    pub(crate) async fn open_udp(&self, target: &Endpoint) -> io::Result<MuxDatagram> {
        for _ in 0..2 {
            if self.token.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "mux pool is shut down",
                ));
            }
            let connection = self.connection().await?;
            match connection.open_udp(target).await {
                Ok(datagram) => return Ok(datagram),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "mux pool is full",
        ))
    }

    async fn connection(&self) -> io::Result<Arc<MuxConnection>> {
        if self.token.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "mux pool is shut down",
            ));
        }
        let mut connections = self.connections.lock().await;
        connections.retain(|connection| !connection.is_closed());
        if let Some(connection) = connections.iter().find(|connection| connection.accepting()) {
            return Ok(Arc::clone(connection));
        }
        if connections.len() >= MAX_CONNECTIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "mux connection limit reached",
            ));
        }
        let stream = tokio::select! {
            _ = self.token.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "mux pool is shut down",
                ));
            }
            result = self.dialer.dial() => result?,
        };
        let connection = MuxConnection::start(
            stream,
            self.token.clone(),
            self.tasks.clone(),
            self.dialer.handshake_len(),
        )?;
        connections.push(Arc::clone(&connection));
        Ok(connection)
    }
}

struct MuxConnection {
    writer: mpsc::Sender<WriteCommand>,
    state: ConnectionState,
    next_id: AtomicU32,
    tracker: TaskTracker,
}

impl MuxConnection {
    fn start(
        stream: BoxStream, parent: CancellationToken, tracker: TaskTracker, handshake: usize,
    ) -> io::Result<Arc<Self>> {
        let (read, write) = tokio::io::split(stream);
        let token = parent.child_token();
        let state = ConnectionState {
            sessions: Arc::new(StdMutex::new(HashMap::new())),
            count: Arc::new(AtomicUsize::new(0)),
            memory: Arc::new(Semaphore::new(MEMORY_PERMITS)),
            closed: Arc::new(AtomicBool::new(false)),
        };
        let (writer, writer_rx) = mpsc::channel(QUEUE_WRITES);
        tracker.spawn(writer_loop(write, writer_rx, token.clone()));
        tracker.spawn(driver(
            read,
            handshake,
            writer.clone(),
            state.clone(),
            token,
        ));
        Ok(Arc::new(Self {
            writer,
            state,
            next_id: AtomicU32::new(1),
            tracker,
        }))
    }

    fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Acquire)
    }

    fn accepting(&self) -> bool {
        !self.is_closed()
            && self.state.count.load(Ordering::Acquire) < MAX_SESSIONS
            && self.next_id.load(Ordering::Acquire) <= u32::from(u16::MAX)
    }

    fn close(&self) {
        self.state.closed.store(true, Ordering::Release);
    }

    fn allocate(&self) -> io::Result<u16> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "mux connection is closed",
            ));
        }
        if self.state.count.fetch_add(1, Ordering::AcqRel) >= MAX_SESSIONS {
            self.state.count.fetch_sub(1, Ordering::AcqRel);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "mux connection is full",
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        if id > u32::from(u16::MAX) {
            self.state.count.fetch_sub(1, Ordering::AcqRel);
            self.state.closed.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "mux session ids are exhausted",
            ));
        }
        Ok(id as u16)
    }

    async fn open_tcp(&self, target: &Endpoint) -> io::Result<BoxStream> {
        let id = self.allocate()?;
        let (client, server) = tokio::io::duplex(TCP_PIPE);
        let (down, down_rx) = mpsc::channel(QUEUE_FRAMES);
        let task = self.tracker.spawn(tcp_session(
            id,
            server,
            down_rx,
            self.writer.clone(),
            Arc::clone(&self.state.sessions),
            Arc::clone(&self.state.count),
        ));
        let abort = task.abort_handle();
        self.insert(id, SessionEntry::Tcp { down, abort });
        if self
            .writer
            .send(WriteCommand::New {
                id,
                target: target.clone(),
                network: NETWORK_TCP,
            })
            .await
            .is_err()
        {
            self.remove(id);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux connection closed",
            ));
        }
        Ok(Box::new(client))
    }

    async fn open_udp(&self, target: &Endpoint) -> io::Result<MuxDatagram> {
        let id = self.allocate()?;
        let (down, down_rx) = mpsc::channel(QUEUE_FRAMES);
        self.insert(id, SessionEntry::Udp { down });
        if self
            .writer
            .send(WriteCommand::New {
                id,
                target: target.clone(),
                network: NETWORK_UDP,
            })
            .await
            .is_err()
        {
            self.remove(id);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux connection closed",
            ));
        }
        Ok(MuxDatagram {
            id,
            target: target.clone(),
            last_target: target.clone(),
            writer: self.writer.clone(),
            down: down_rx,
            sessions: Arc::clone(&self.state.sessions),
            count: Arc::clone(&self.state.count),
        })
    }

    fn insert(&self, id: u16, entry: SessionEntry) {
        if let Ok(mut sessions) = self.state.sessions.lock() {
            sessions.insert(id, entry);
        }
    }

    fn remove(&self, id: u16) {
        remove_session(&self.state.sessions, &self.state.count, id);
    }
}

/// A UDP session over a mux connection.
pub(crate) struct MuxDatagram {
    id: u16,
    target: Endpoint,
    last_target: Endpoint,
    writer: mpsc::Sender<WriteCommand>,
    down: mpsc::Receiver<FrameData>,
    sessions: Sessions,
    count: Arc<AtomicUsize>,
}

impl MuxDatagram {
    /// Sends one datagram; a changed destination is carried on the Keep frame.
    pub(crate) async fn send_to(&mut self, target: &Endpoint, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let changed = target != &self.last_target;
        self.writer
            .send(WriteCommand::Keep {
                id: self.id,
                target: changed.then(|| target.clone()),
                data: payload.to_vec(),
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux connection closed"))?;
        self.last_target = target.clone();
        Ok(())
    }

    /// Receives one datagram and its source.
    pub(crate) async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Endpoint)> {
        let Some(frame) = self.down.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mux association closed",
            ));
        };
        if frame.data.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mux datagram exceeds the output buffer",
            ));
        }
        buffer[..frame.data.len()].copy_from_slice(&frame.data);
        let source = frame.source.unwrap_or_else(|| self.target.clone());
        Ok((frame.data.len(), source))
    }
}

impl Drop for MuxDatagram {
    fn drop(&mut self) {
        let _ = self.writer.try_send(WriteCommand::End { id: self.id });
        remove_session(&self.sessions, &self.count, self.id);
    }
}

async fn driver(
    mut read: ReadHalf<BoxStream>, handshake: usize, writer: mpsc::Sender<WriteCommand>,
    state: ConnectionState, token: CancellationToken,
) {
    let ConnectionState {
        sessions,
        count,
        memory,
        closed,
    } = state;
    if handshake > 0 {
        let mut response = vec![0_u8; handshake];
        if read.read_exact(&mut response).await.is_err() || response.iter().any(|byte| *byte != 0) {
            closed.store(true, Ordering::Release);
            token.cancel();
            return;
        }
    }
    let Ok(mut frames) = MuxReader::new(read, &[]) else {
        closed.store(true, Ordering::Release);
        token.cancel();
        return;
    };
    let mut keepalive = interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last = Instant::now();
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = keepalive.tick() => {
                let idle = sessions
                    .lock()
                    .map(|sessions| sessions.is_empty())
                    .unwrap_or(false);
                if idle && last.elapsed() >= IDLE {
                    break;
                }
                if last.elapsed() >= KEEPALIVE
                    && writer.send(WriteCommand::KeepAlive).await.is_err()
                {
                    break;
                }
            }
            result = frames.next() => {
                let Ok(Some(frame)) = result else {
                    break;
                };
                last = Instant::now();
                if !dispatch(frame, &sessions, &count, &memory, &token).await {
                    break;
                }
            }
        }
    }
    closed.store(true, Ordering::Release);
    token.cancel();
    if let Ok(mut sessions) = sessions.lock() {
        for (_, entry) in sessions.drain() {
            if let SessionEntry::Tcp { abort, .. } = entry {
                abort.abort();
            }
        }
    }
    count.store(0, Ordering::Release);
}

async fn dispatch(
    frame: Frame, sessions: &Sessions, count: &AtomicUsize, memory: &Arc<Semaphore>,
    token: &CancellationToken,
) -> bool {
    let id = frame.meta.session;
    match frame.meta.status {
        STATUS_NEW | STATUS_KEEP => {
            if frame.data.is_empty() {
                return true;
            }
            let entry = match sessions.lock() {
                Ok(sessions) => sessions.get(&id).map(|entry| match entry {
                    SessionEntry::Tcp { down, .. } => Entry::Tcp(down.clone()),
                    SessionEntry::Udp { down } => Entry::Udp(down.clone()),
                }),
                Err(_) => None,
            };
            let Some(entry) = entry else {
                return true;
            };
            match entry {
                Entry::Tcp(down) => {
                    let permit = tokio::select! {
                        _ = token.cancelled() => return false,
                        permit = Arc::clone(memory).acquire_owned() => match permit {
                            Ok(permit) => permit,
                            Err(_) => return false,
                        },
                    };
                    let frame = FrameData {
                        data: frame.data,
                        source: None,
                        _permit: permit,
                    };
                    let sent = tokio::select! {
                        _ = token.cancelled() => return false,
                        result = down.send(frame) => result,
                    };
                    if sent.is_err() {
                        remove_session(sessions, count, id);
                    }
                }
                Entry::Udp(down) => {
                    if let Ok(permit) = Arc::clone(memory).try_acquire_owned() {
                        let frame = FrameData {
                            data: frame.data,
                            source: frame.meta.target,
                            _permit: permit,
                        };
                        let _ = down.try_send(frame);
                    }
                }
            }
        }
        STATUS_END => {
            remove_session(sessions, count, id);
        }
        STATUS_KEEPALIVE => {}
        _ => {
            return false;
        }
    }
    true
}

enum Entry {
    Tcp(mpsc::Sender<FrameData>),
    Udp(mpsc::Sender<FrameData>),
}

fn remove_session(sessions: &Sessions, count: &AtomicUsize, id: u16) {
    let removed = sessions
        .lock()
        .ok()
        .and_then(|mut sessions| sessions.remove(&id));
    if let Some(entry) = removed {
        count.fetch_sub(1, Ordering::AcqRel);
        if let SessionEntry::Tcp { abort, .. } = entry {
            abort.abort();
        }
    }
}

async fn writer_loop(
    write: WriteHalf<BoxStream>, mut commands: mpsc::Receiver<WriteCommand>,
    token: CancellationToken,
) {
    let mut writer = MuxWriter::new(write);
    loop {
        let command = tokio::select! {
            _ = token.cancelled() => break,
            command = commands.recv() => command,
        };
        let Some(command) = command else {
            break;
        };
        let result = match command {
            WriteCommand::New {
                id,
                target,
                network,
            } => writer.new_session(id, &target, network, &[]).await,
            WriteCommand::Keep { id, target, data } => {
                writer.keep(id, target.as_ref(), &data).await
            }
            WriteCommand::End { id } => writer.end(id).await,
            WriteCommand::KeepAlive => writer.keepalive().await,
        };
        if result.is_err() {
            break;
        }
    }
    token.cancel();
}

async fn tcp_session(
    id: u16, mut server: DuplexStream, mut down: mpsc::Receiver<FrameData>,
    writer: mpsc::Sender<WriteCommand>, sessions: Sessions, count: Arc<AtomicUsize>,
) {
    let mut buffer = vec![0_u8; READ_BUFFER];
    loop {
        tokio::select! {
            result = server.read(&mut buffer) => match result {
                Ok(0) => break,
                Ok(read) => {
                    let data = buffer[..read].to_vec();
                    if writer.send(WriteCommand::Keep {
                        id,
                        target: None,
                        data,
                    }).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            message = down.recv() => match message {
                Some(frame) => {
                    if server.write_all(&frame.data).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    let _ = writer.try_send(WriteCommand::End { id });
    remove_session(&sessions, &count, id);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoDialer {
        dials: Arc<AtomicUsize>,
    }

    impl MuxDialer for EchoDialer {
        fn dial(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let (read, write) = tokio::io::split(server);
                    let Ok(mut frames) = MuxReader::new(read, &[]) else {
                        return;
                    };
                    let mut writer = MuxWriter::new(write);
                    while let Ok(Some(frame)) = frames.next().await {
                        match frame.meta.status {
                            STATUS_NEW => {}
                            STATUS_KEEP => {
                                if !frame.data.is_empty()
                                    && writer
                                        .keep(frame.meta.session, None, &frame.data)
                                        .await
                                        .is_err()
                                {
                                    break;
                                }
                            }
                            STATUS_END => {
                                let _ = writer.end(frame.meta.session).await;
                            }
                            _ => {}
                        }
                    }
                });
                let stream: BoxStream = Box::new(client);
                Ok(stream)
            })
        }
    }

    fn pool(
        dials: Arc<AtomicUsize>,
    ) -> (Arc<MuxPool>, CancellationToken, tokio::task::JoinHandle<()>) {
        let token = CancellationToken::new();
        let pool = MuxPool::new(
            Handle::current(),
            token.clone(),
            Arc::new(EchoDialer { dials }),
        );
        let supervisor = pool.supervisor();
        (pool, token, supervisor)
    }

    #[tokio::test]
    async fn reuses_one_connection_for_tcp_sessions() {
        let dials = Arc::new(AtomicUsize::new(0));
        let (pool, token, supervisor) = pool(Arc::clone(&dials));
        let target = Endpoint::from_domain("example.com", 80).expect("target");
        let mut streams = Vec::new();
        for _ in 0..8 {
            streams.push(pool.open_tcp(&target).await.expect("open"));
        }
        for (index, mut stream) in streams.into_iter().enumerate() {
            let payload = format!("hello {index}");
            stream.write_all(payload.as_bytes()).await.expect("write");
            let mut buffer = [0_u8; 16];
            stream
                .read_exact(&mut buffer[..payload.len()])
                .await
                .expect("read");
            assert_eq!(&buffer[..payload.len()], payload.as_bytes());
        }
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        token.cancel();
        supervisor.await.expect("supervisor");
    }

    #[tokio::test]
    async fn opens_a_second_connection_when_full() {
        let dials = Arc::new(AtomicUsize::new(0));
        let (pool, token, supervisor) = pool(Arc::clone(&dials));
        let target = Endpoint::from_domain("example.com", 80).expect("target");
        let mut streams = Vec::new();
        for _ in 0..=MAX_SESSIONS {
            streams.push(pool.open_tcp(&target).await.expect("open"));
        }
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        drop(streams);
        token.cancel();
        supervisor.await.expect("supervisor");
    }

    #[tokio::test]
    async fn echoes_udp_datagrams() {
        let dials = Arc::new(AtomicUsize::new(0));
        let (pool, token, supervisor) = pool(Arc::clone(&dials));
        let target = Endpoint::from_domain("example.com", 53).expect("target");
        let mut datagram = pool.open_udp(&target).await.expect("open");
        datagram.send_to(&target, b"ping").await.expect("send");
        let mut buffer = [0_u8; 16];
        let (length, source) = datagram.recv_from(&mut buffer).await.expect("recv");
        assert_eq!(&buffer[..length], b"ping");
        assert_eq!(source, target);
        drop(datagram);
        token.cancel();
        supervisor.await.expect("supervisor");
    }
}
