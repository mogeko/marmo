//! TLS 1.3 client and server adapters on `rustls` (ADR-0012, ADR-0018).
//!
//! Only TLS 1.3 is configured. Certificates and keys are PEM or DER text from
//! config; test-only certificates live in `tests/fixtures/tls/`.
//!
//! The adapters operate on the erased [`BoxStream`] boundary so the same layer
//! composes with plain TCP, WebSocket, and HTTP/2 (ADR-0004, ADR-0016).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use thiserror::Error;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::BoxStream;

/// Upper bound on ALPN protocols; mirrors config validation.
const MAX_ALPN_PROTOCOLS: usize = 32;
/// Upper bound on a certificate chain parsed from one config value.
const MAX_CERTIFICATES: usize = 16;

/// Whether the server requests and verifies client certificates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ClientAuth {
    /// Do not request a client certificate.
    #[default]
    None,
    /// Request a certificate and verify it when present.
    Optional,
    /// Require a verified client certificate.
    Required,
}

/// Parameters for a TLS client.
#[derive(Clone, Copy, Default)]
pub struct TlsClientOptions<'a> {
    /// SNI name or IP address; must match the server certificate.
    pub server_name: &'a str,
    /// ALPN protocols in preference order.
    pub alpn: &'a [String],
    /// Fail the handshake unless the server selects this ALPN protocol.
    pub required_alpn: Option<&'a str>,
    /// Skip certificate verification for a loopback test server.
    ///
    /// `Instance` rejects this in config for a non-loopback server.
    pub insecure: bool,
    /// PEM or DER client certificate chain.
    pub client_certificate: Option<&'a str>,
    /// PEM or DER client private key.
    pub client_private_key: Option<&'a str>,
    /// Optional handshake deadline; `None` leaves it to the caller.
    pub handshake_timeout: Option<Duration>,
}

/// Parameters for a TLS server.
#[derive(Clone, Copy)]
pub struct TlsServerOptions<'a> {
    /// PEM or DER certificate chain, leaf first.
    pub certificate: &'a str,
    /// PEM or DER private key.
    pub private_key: &'a str,
    /// ALPN protocols in server preference order.
    pub alpn: &'a [String],
    /// PEM or DER client-certificate trust anchors.
    pub client_ca: Option<&'a str>,
    /// Client-certificate policy.
    pub client_auth: ClientAuth,
    /// Optional handshake deadline; `None` leaves it to the caller.
    pub handshake_timeout: Option<Duration>,
}

impl std::fmt::Debug for TlsClientOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientOptions")
            .field("server_name", &self.server_name)
            .field("alpn", &self.alpn)
            .field("required_alpn", &self.required_alpn)
            .field("insecure", &self.insecure)
            .field(
                "client_certificate",
                &self.client_certificate.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "client_private_key",
                &self.client_private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("handshake_timeout", &self.handshake_timeout)
            .finish()
    }
}

impl std::fmt::Debug for TlsServerOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerOptions")
            .field("certificate", &"<redacted>")
            .field("private_key", &"<redacted>")
            .field("alpn", &self.alpn)
            .field("client_ca", &self.client_ca.as_ref().map(|_| "<redacted>"))
            .field("client_auth", &self.client_auth)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish()
    }
}

/// Callback invoked when a TLS handshake exceeds its local timeout.
pub type TimeoutObserver = Arc<dyn Fn() + Send + Sync>;

/// A TLS client with a fixed configuration; clone the `Arc` to share it.
#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    required_alpn: Option<Vec<u8>>,
    handshake_timeout: Option<Duration>,
    timeout_observer: Option<TimeoutObserver>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient")
            .field("server_name", &self.server_name)
            .field("required_alpn", &self.required_alpn)
            .finish_non_exhaustive()
    }
}

impl TlsClient {
    /// Builds a TLS 1.3 client from config values.
    pub fn new(options: &TlsClientOptions<'_>) -> Result<Self, TlsError> {
        let alpn = parse_alpn(options.alpn)?;
        let required_alpn = options.required_alpn.map(|name| name.as_bytes().to_vec());
        if required_alpn.is_some() && alpn.is_empty() {
            return Err(TlsError::Alpn(
                options.required_alpn.unwrap_or_default().to_owned(),
            ));
        }

        let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
        let builder = if options.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification::default()))
        } else {
            use rustls_platform_verifier::BuilderVerifierExt;
            builder.with_platform_verifier()?
        };
        let mut config = match (options.client_certificate, options.client_private_key) {
            (Some(certificate), Some(private_key)) => {
                let chain = parse_certificates(certificate)?;
                let key = parse_private_key(private_key)?;
                builder.with_client_auth_cert(chain, key)?
            }
            (None, None) => builder.with_no_client_auth(),
            _ => return Err(TlsError::ClientAuth),
        };
        config.alpn_protocols = alpn;

        let server_name = ServerName::try_from(options.server_name.to_owned())
            .map_err(|_| TlsError::ServerName(options.server_name.to_owned()))?;

        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
            required_alpn,
            handshake_timeout: options.handshake_timeout,
            timeout_observer: None,
        })
    }

    /// Installs a callback for local handshake timeouts.
    #[must_use]
    pub fn with_timeout_observer(mut self, observer: TimeoutObserver) -> Self {
        self.timeout_observer = Some(observer);
        self
    }

    /// Wraps `inner` in TLS and enforces `required_alpn` when configured.
    pub async fn connect(&self, inner: BoxStream) -> Result<BoxStream, TlsError> {
        let stream = match self.handshake_timeout {
            Some(limit) => tokio::time::timeout(
                limit,
                self.connector.connect(self.server_name.clone(), inner),
            )
            .await
            .map_err(|_| {
                if let Some(observer) = self.timeout_observer.as_ref() {
                    observer();
                }
                TlsError::Timeout
            })??,
            None => {
                self.connector
                    .connect(self.server_name.clone(), inner)
                    .await?
            }
        };
        if let Some(required) = self.required_alpn.as_deref() {
            let negotiated = stream.get_ref().1.alpn_protocol();
            if negotiated != Some(required) {
                return Err(TlsError::Alpn(String::from_utf8_lossy(required).into()));
            }
        }
        Ok(Box::new(stream))
    }
}

/// A TLS server with a fixed certificate and client-auth policy.
#[derive(Clone)]
pub struct TlsServer {
    acceptor: TlsAcceptor,
    handshake_timeout: Option<Duration>,
    timeout_observer: Option<TimeoutObserver>,
}

impl std::fmt::Debug for TlsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer").finish_non_exhaustive()
    }
}

impl TlsServer {
    /// Builds a TLS 1.3 server from config values.
    pub fn new(options: &TlsServerOptions<'_>) -> Result<Self, TlsError> {
        let chain = parse_certificates(options.certificate)?;
        let key = parse_private_key(options.private_key)?;
        let verifier = client_verifier(options)?;

        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)?;
        config.alpn_protocols = parse_alpn(options.alpn)?;

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            handshake_timeout: options.handshake_timeout,
            timeout_observer: None,
        })
    }

    /// Installs a callback for local handshake timeouts.
    #[must_use]
    pub fn with_timeout_observer(mut self, observer: TimeoutObserver) -> Self {
        self.timeout_observer = Some(observer);
        self
    }

    /// Completes the handshake and reports the selected ALPN protocol.
    ///
    /// The caller owns the outer handshake deadline; the adapter timeout is an
    /// optional earlier cap.
    pub async fn accept(&self, inner: BoxStream) -> Result<AcceptedTls, TlsError> {
        let stream = match self.handshake_timeout {
            Some(limit) => tokio::time::timeout(limit, self.acceptor.clone().accept(inner))
                .await
                .map_err(|_| {
                    if let Some(observer) = self.timeout_observer.as_ref() {
                        observer();
                    }
                    TlsError::Timeout
                })??,
            None => self.acceptor.clone().accept(inner).await?,
        };
        let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        Ok(AcceptedTls {
            stream: Box::new(stream),
            alpn,
        })
    }
}

/// A TLS server stream plus the negotiated ALPN protocol.
pub struct AcceptedTls {
    /// The decrypted stream.
    pub stream: BoxStream,
    /// The protocol the server selected, if any.
    pub alpn: Option<Vec<u8>>,
}

impl std::fmt::Debug for AcceptedTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptedTls")
            .field("alpn", &self.alpn)
            .finish_non_exhaustive()
    }
}

/// Why TLS setup or the handshake failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The certificate chain was empty or not PEM/DER.
    #[error("invalid certificate")]
    Certificate,
    /// The private key was empty or not PEM/DER.
    #[error("invalid private key")]
    PrivateKey,
    /// Only one half of the client certificate/key pair was set.
    #[error("client certificate and private key must be set together")]
    ClientAuth,
    /// Client authentication was enabled without trust anchors.
    #[error("client_ca is required when client_auth is enabled")]
    ClientCaRequired,
    /// The SNI value is not a valid DNS name or IP address.
    #[error("invalid TLS server name '{0}'")]
    ServerName(String),
    /// An ALPN protocol name was empty or longer than 255 bytes.
    #[error("invalid ALPN protocol name")]
    AlpnName,
    /// The required ALPN protocol was not selected.
    #[error("required ALPN protocol '{0}' was not negotiated")]
    Alpn(String),
    /// The TLS configuration was rejected.
    #[error("TLS configuration failed: {0}")]
    Config(#[source] rustls::Error),
    /// The client trust anchors were rejected.
    #[error("invalid TLS client CA: {0}")]
    ClientCa(String),
    /// The handshake failed.
    #[error("TLS handshake failed: {0}")]
    Handshake(#[source] io::Error),
    /// The handshake exceeded its configured deadline.
    #[error("TLS handshake timed out")]
    Timeout,
}

impl From<rustls::Error> for TlsError {
    fn from(error: rustls::Error) -> Self {
        Self::Config(error)
    }
}

impl From<io::Error> for TlsError {
    fn from(error: io::Error) -> Self {
        Self::Handshake(error)
    }
}

fn client_verifier(
    options: &TlsServerOptions<'_>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, TlsError> {
    match (options.client_auth, options.client_ca) {
        (ClientAuth::None, _) => Ok(WebPkiClientVerifier::no_client_auth()),
        (_, Some(ca)) => {
            let mut roots = RootCertStore::empty();
            for certificate in parse_certificates(ca)? {
                roots
                    .add(certificate)
                    .map_err(|error| TlsError::ClientCa(error.to_string()))?;
            }
            let builder = WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = match options.client_auth {
                ClientAuth::Optional => builder.allow_unauthenticated().build(),
                ClientAuth::Required => builder.build(),
                ClientAuth::None => unreachable!("handled above"),
            };
            verifier.map_err(|error| TlsError::ClientCa(error.to_string()))
        }
        (_, None) => Err(TlsError::ClientCaRequired),
    }
}

fn parse_alpn(protocols: &[String]) -> Result<Vec<Vec<u8>>, TlsError> {
    if protocols.len() > MAX_ALPN_PROTOCOLS {
        return Err(TlsError::AlpnName);
    }
    protocols
        .iter()
        .map(|protocol| {
            if protocol.is_empty() || protocol.len() > 255 {
                return Err(TlsError::AlpnName);
            }
            Ok(protocol.as_bytes().to_vec())
        })
        .collect()
}

fn parse_certificates(input: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    if input.contains("-----BEGIN") {
        let certificates: Result<Vec<_>, _> =
            CertificateDer::pem_slice_iter(input.as_bytes()).collect();
        let certificates = certificates.map_err(|_| TlsError::Certificate)?;
        if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
            return Err(TlsError::Certificate);
        }
        Ok(certificates)
    } else if input.is_empty() {
        Err(TlsError::Certificate)
    } else {
        Ok(vec![CertificateDer::from(input.as_bytes().to_vec())])
    }
}

fn parse_private_key(input: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    if input.contains("-----BEGIN") {
        PrivateKeyDer::from_pem_slice(input.as_bytes()).map_err(|_| TlsError::PrivateKey)
    } else if input.is_empty() {
        Err(TlsError::PrivateKey)
    } else {
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            input.as_bytes().to_vec(),
        )))
    }
}

/// Accepts any certificate while still checking handshake signatures.
///
/// Used only for `insecure` clients, which config validation restricts to
/// tests. The signature check keeps the crypto path honest.
#[derive(Debug)]
struct NoVerification {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl Default for NoVerification {
    fn default() -> Self {
        Self {
            algorithms: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SERVER_CERT: &str = include_str!("../tests/fixtures/tls/server.pem");
    const SERVER_KEY: &str = include_str!("../tests/fixtures/tls/server.key");
    const CLIENT_CERT: &str = include_str!("../tests/fixtures/tls/client.pem");
    const CLIENT_KEY: &str = include_str!("../tests/fixtures/tls/client.key");
    const CA: &str = include_str!("../tests/fixtures/tls/ca.pem");

    fn server_with(alpn: &[String], auth: ClientAuth, ca: Option<&str>) -> TlsServer {
        TlsServer::new(&TlsServerOptions {
            certificate: SERVER_CERT,
            private_key: SERVER_KEY,
            alpn,
            client_ca: ca,
            client_auth: auth,
            handshake_timeout: None,
        })
        .expect("server")
    }

    fn insecure_client<'a>(alpn: &'a [String], required: Option<&'a str>) -> TlsClient {
        TlsClient::new(&TlsClientOptions {
            server_name: "localhost",
            alpn,
            required_alpn: required,
            insecure: true,
            client_certificate: None,
            client_private_key: None,
            handshake_timeout: None,
        })
        .expect("client")
    }

    async fn serve(server: TlsServer) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut accepted) = server.accept(Box::new(stream)).await else {
                return;
            };
            let mut buffer = [0_u8; 1024];
            loop {
                match accepted.stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(length) => {
                        if accepted.stream.write_all(&buffer[..length]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (address, task)
    }

    async fn echo(address: std::net::SocketAddr, client: &TlsClient) -> Vec<u8> {
        let stream = TcpStream::connect(address).await.expect("connect");
        let mut stream = client.connect(Box::new(stream)).await.expect("handshake");
        stream.write_all(b"ping").await.expect("write");
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).await.expect("read");
        buffer.to_vec()
    }

    #[tokio::test]
    async fn echoes_over_tls() {
        let (address, task) = serve(server_with(&[], ClientAuth::None, None)).await;
        assert_eq!(echo(address, &insecure_client(&[], None)).await, b"ping");
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn negotiates_alpn() {
        let alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
        let (address, task) = serve(server_with(&alpn, ClientAuth::None, None)).await;
        let offered = vec!["http/1.1".to_owned()];
        assert_eq!(
            echo(address, &insecure_client(&offered, Some("http/1.1"))).await,
            b"ping"
        );
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn rejects_unoffered_required_alpn() {
        let alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
        let (address, task) = serve(server_with(&alpn, ClientAuth::None, None)).await;
        let offered = vec!["http/1.1".to_owned()];
        let client = insecure_client(&offered, Some("h2"));
        let stream = TcpStream::connect(address).await.expect("connect");
        let result = client.connect(Box::new(stream)).await;
        assert!(matches!(result, Err(TlsError::Alpn(_))));
        task.abort();
    }

    #[tokio::test]
    async fn requires_a_client_certificate() {
        let server = server_with(&[], ClientAuth::Required, Some(CA));
        let (address, task) = serve(server).await;
        let client = insecure_client(&[], None);
        let stream = TcpStream::connect(address).await.expect("connect");
        // TLS 1.3 lets the client finish before the server checks the
        // certificate, so the rejection can surface at the first read.
        if let Ok(mut stream) = client.connect(Box::new(stream)).await {
            let _ = stream.write_all(b"ping").await;
            let mut buffer = [0_u8; 1];
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buffer))
                    .await;
            assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))));
        }
        task.abort();
    }

    #[tokio::test]
    async fn accepts_a_client_certificate() {
        let server = server_with(&[], ClientAuth::Required, Some(CA));
        let (address, task) = serve(server).await;
        let client = TlsClient::new(&TlsClientOptions {
            server_name: "localhost",
            alpn: &[],
            required_alpn: None,
            insecure: true,
            client_certificate: Some(CLIENT_CERT),
            client_private_key: Some(CLIENT_KEY),
            handshake_timeout: None,
        })
        .expect("client");
        assert_eq!(echo(address, &client).await, b"ping");
        task.await.expect("server task");
    }

    #[tokio::test]
    async fn verifies_the_server_against_configured_roots() {
        let (address, task) = serve(server_with(&[], ClientAuth::None, None)).await;
        let mut roots = RootCertStore::empty();
        for certificate in parse_certificates(CA).expect("ca") {
            roots.add(certificate).expect("add");
        }
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = TlsClient {
            connector: TlsConnector::from(Arc::new(config)),
            server_name: ServerName::try_from("localhost".to_owned()).expect("name"),
            required_alpn: None,
            handshake_timeout: None,
            timeout_observer: None,
        };
        assert_eq!(echo(address, &client).await, b"ping");
        task.await.expect("server task");
    }

    #[test]
    fn debug_redacts_private_key_material() {
        let client = TlsClientOptions {
            client_private_key: Some("SECRET-KEY"),
            client_certificate: Some("SECRET-CERT"),
            ..TlsClientOptions::default()
        };
        let text = format!("{client:?}");
        assert!(!text.contains("SECRET-KEY"));
        assert!(!text.contains("SECRET-CERT"));

        let server = TlsServerOptions {
            certificate: "SECRET-CERT",
            private_key: "SECRET-KEY",
            alpn: &[],
            client_ca: Some("SECRET-CA"),
            client_auth: ClientAuth::None,
            handshake_timeout: None,
        };
        let text = format!("{server:?}");
        assert!(!text.contains("SECRET-KEY"));
        assert!(!text.contains("SECRET-CERT"));
        assert!(!text.contains("SECRET-CA"));
    }

    #[tokio::test]
    async fn reports_a_local_handshake_timeout() {
        use std::sync::atomic::AtomicU32;

        let observed = Arc::new(AtomicU32::new(0));
        let observer = Arc::clone(&observed);
        let server = TlsServer::new(&TlsServerOptions {
            certificate: SERVER_CERT,
            private_key: SERVER_KEY,
            alpn: &[],
            client_ca: None,
            client_auth: ClientAuth::None,
            handshake_timeout: Some(Duration::from_millis(5)),
        })
        .expect("server")
        .with_timeout_observer(Arc::new(move || {
            observer.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        let (client, server_io) = tokio::io::duplex(64);
        let result = server.accept(Box::new(server_io)).await;
        assert!(matches!(result, Err(TlsError::Timeout)));
        assert_eq!(observed.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(client);
    }

    #[test]
    fn parses_pem_with_crlf_line_endings() {
        let certificate = SERVER_CERT.replace('\n', "\r\n");
        let key = SERVER_KEY.replace('\n', "\r\n");
        assert!(
            !parse_certificates(&certificate)
                .expect("certificates")
                .is_empty()
        );
        assert!(parse_private_key(&key).is_ok());
    }

    #[test]
    fn rejects_invalid_credentials() {
        assert!(matches!(
            TlsServer::new(&TlsServerOptions {
                certificate: "",
                private_key: SERVER_KEY,
                alpn: &[],
                client_ca: None,
                client_auth: ClientAuth::None,
                handshake_timeout: None,
            }),
            Err(TlsError::Certificate)
        ));
        assert!(matches!(
            TlsServer::new(&TlsServerOptions {
                certificate: SERVER_CERT,
                private_key: "not a key",
                alpn: &[],
                client_ca: None,
                client_auth: ClientAuth::None,
                handshake_timeout: None,
            }),
            Err(TlsError::Config(_))
        ));
        assert!(matches!(
            TlsServer::new(&TlsServerOptions {
                certificate: SERVER_CERT,
                private_key: SERVER_KEY,
                alpn: &[],
                client_ca: None,
                client_auth: ClientAuth::Required,
                handshake_timeout: None,
            }),
            Err(TlsError::ClientCaRequired)
        ));
    }
}
