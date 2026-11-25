//! Shared HTTP/2 inbound stream acceptor (ADR-0031).
//!
//! One accepted TCP connection carries up to 16 logical streams. TLS is
//! terminated once; each stream gets its own handshake deadline, stream
//! permit, and protocol handler. The connection driver owns the h2 connection
//! and keeps it polled even while the accept loop is busy.

use std::io;
use std::sync::Arc;

use marmo_net::Endpoint;
use marmo_transport::h2::{H2Error, H2Server, H2ServerConnection, H2ServerOptions};
use marmo_transport::{AcceptedStream, BoxFuture, BoxStream, Layer};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::deadline::Deadline;
use crate::instance::Context;
use crate::metrics::{MetricEvent, Metrics};

/// One protocol handler for an accepted HTTP/2 stream.
pub(crate) type StreamHandler = dyn Fn(BoxStream, Endpoint, Deadline, CancellationToken) -> BoxFuture<'static, ()>
    + Send
    + Sync;

/// Serves every stream on one HTTP/2 connection.
pub(crate) async fn serve(
    client: TcpStream, layers: Arc<[Arc<dyn Layer>]>, options: H2ServerOptions,
    context: Arc<Context>, deadline: Deadline, handler: Arc<StreamHandler>,
) {
    let token = context.supervisor.token();
    let Some(source) = client.peer_addr().ok().map(Endpoint::from) else {
        return;
    };
    let prepared = tokio::select! {
        _ = token.cancelled() => return,
        result = deadline.run(handshake(client, &layers, options)) => result,
    };
    let Ok(Ok(mut connection)) = prepared else {
        return;
    };

    let connection_token = token.child_token();
    let mut tasks = JoinSet::new();
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                context.metrics.record(MetricEvent::TaskPanicked);
            }
        }
        let next = tokio::select! {
            _ = token.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    context.metrics.record(MetricEvent::TaskPanicked);
                }
                continue;
            }
            next = connection.accept_stream() => next,
        };
        let Some(result) = next else {
            break;
        };
        let stream = match result {
            Ok(stream) => stream,
            Err(H2Error::Protocol) => continue,
            Err(_) => break,
        };
        let Some(permit) = context.supervisor.try_acquire_stream() else {
            context.metrics.record(MetricEvent::H2StreamRejected);
            drop(stream);
            continue;
        };
        context.metrics.record(MetricEvent::H2StreamAccepted);
        let stream_deadline = Deadline::after(
            context.limits.handshake_timeout,
            Arc::clone(&context.metrics),
        );
        let guard = StreamGuard(Arc::clone(&context.metrics));
        let handler = Arc::clone(&handler);
        let task_context = Arc::clone(&context);
        let source = source.clone();
        let stream_token = connection_token.child_token();
        let _ = tasks.spawn_on(
            async move {
                let _permit = permit;
                let _guard = guard;
                handler(stream, source, stream_deadline, stream_token).await;
            },
            &task_context.runtime,
        );
    }

    connection_token.cancel();
    while tasks.join_next().await.is_some() {}
}

async fn handshake(
    client: TcpStream, layers: &[Arc<dyn Layer>], options: H2ServerOptions,
) -> io::Result<H2ServerConnection> {
    let mut stream = AcceptedStream {
        stream: Box::new(client),
        alpn: None,
    };
    for layer in layers {
        stream = layer
            .accept_stream(stream)
            .await
            .map_err(io::Error::other)?;
    }
    if stream.alpn.as_deref() != Some(b"h2") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/2 inbound requires the h2 ALPN protocol",
        ));
    }
    H2Server::new(options)
        .accept_connection(stream.stream)
        .await
        .map_err(|error| io::Error::other(error.to_string()))
}

/// Records a closed HTTP/2 stream even if its handler future is aborted.
struct StreamGuard(Arc<Metrics>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.record(MetricEvent::H2StreamClosed);
    }
}
