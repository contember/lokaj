//! Server connections: connect over TLS, authenticate with SCRAM-SHA-256, and the cheap checks
//! run on idle connections.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use rustls_pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::cancel::ServerCancelKey;
use crate::dns::Resolver;
use crate::protocol::{self, Authentication, ErrorFields, TxStatus, tag};
use crate::scram::{self, ScramClient, ScramError, ScramKeys, Secret};
use crate::sql_guard;

/// Largest message accepted from the server outside the relay (startup, health checks).
const MAX_CONTROL_MESSAGE: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("DNS lookup failed: {0}")]
    Dns(io::Error),
    #[error("server I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("timed out connecting to the server")]
    Timeout,
    #[error("server does not accept TLS")]
    TlsRefused,
    #[error("TLS handshake with the server failed: {0}")]
    Tls(io::Error),
    #[error("server error {}: {}", .0.code, .0.message)]
    Server(ErrorFields),
    #[error("server refused the connection before authentication: {}", .0.message)]
    Refused(ErrorFields),
    #[error("SCRAM authentication failed: {0}")]
    Scram(#[from] ScramError),
    #[error("server requested unsupported authentication: {0}")]
    UnsupportedAuth(&'static str),
    #[error("server protocol violation: {0}")]
    Protocol(String),
    #[error("no verified credential for this user and database")]
    NoCredential,
}

impl From<protocol::ProtocolError> for ConnectError {
    fn from(error: protocol::ProtocolError) -> Self {
        ConnectError::Protocol(error.to_string())
    }
}

impl ConnectError {
    /// Whether the server refused these credentials, as opposed to being unavailable.
    pub fn is_auth_failure(&self) -> bool {
        match self {
            ConnectError::Server(fields) => fields.code == "28P01" || fields.code == "28000",
            ConnectError::Scram(ScramError::VerifierChanged | ScramError::ServerError(_)) => true,
            ConnectError::NoCredential => true,
            _ => false,
        }
    }

    /// Whether another attempt may soon succeed: the server is starting, full or unreachable.
    pub fn is_transient(&self) -> bool {
        match self {
            ConnectError::Dns(_) | ConnectError::Io(_) | ConnectError::Timeout => true,
            ConnectError::Server(fields) => matches!(fields.code.as_str(), "53300" | "57P03"),
            _ => false,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            ConnectError::Dns(_) => "dns",
            ConnectError::Io(_) => "io",
            ConnectError::Timeout => "timeout",
            ConnectError::TlsRefused | ConnectError::Tls(_) => "tls",
            ConnectError::Server(_) if self.is_auth_failure() => "auth",
            ConnectError::Server(_) => "server_error",
            ConnectError::Refused(_) => "refused",
            ConnectError::Scram(_) | ConnectError::NoCredential => "auth",
            ConnectError::UnsupportedAuth(_) => "unsupported_auth",
            ConnectError::Protocol(_) => "protocol",
        }
    }
}

/// TLS towards the server: the trusted CAs and the name its certificate must match.
pub struct ServerTls {
    pub connector: TlsConnector,
    pub name: ServerName<'static>,
}

pub struct ServerSettings {
    pub tls: ServerTls,
    pub application_name: String,
    pub connect_timeout: Duration,
    pub keepalive_time: Duration,
    pub lifetime: Duration,
    pub lifetime_jitter: Duration,
}

pub type ServerStream = TlsStream<TcpStream>;

pub struct ServerConn {
    pub stream: ServerStream,
    /// Bytes read from the server and not yet processed.
    pub buf: BytesMut,
    cancel_key: ServerCancelKey,
    pub params: Params,
    expires_at: Instant,
    /// Generation of the pool's parameter snapshot this connection matched.
    pub generation: u64,
}

/// Parameters the server reported with `ParameterStatus`.
#[derive(Debug, Default)]
pub struct Params {
    pub values: BTreeMap<String, String>,
    /// Set when the server reported a change after startup.
    pub changed: bool,
    /// Set once the server reported a parameter that `sql_guard` does not assume. Never cleared:
    /// the guard may have let session state through, even if the parameter was reverted since.
    pub unguarded: bool,
}

impl Params {
    pub fn set(&mut self, name: &str, value: &str) {
        if sql_guard::ASSUMED_PARAMETERS
            .iter()
            .any(|&(assumed, expected)| assumed == name && expected != value)
        {
            self.unguarded = true;
        }
        if self.values.get(name).map(String::as_str) != Some(value) {
            self.values.insert(name.to_owned(), value.to_owned());
            self.changed = true;
        }
    }
}

pub struct Connected {
    pub conn: ServerConn,
    pub keys: ScramKeys,
}

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_RETRIES: u32 = 3;

/// Keepalive, and the same bound on unacknowledged data: keepalive probes pause while data is
/// unacknowledged, so a peer that vanished mid-query would otherwise hold on for ~15 minutes.
pub fn keepalive(stream: &TcpStream, time: Duration) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = TcpKeepalive::new()
        .with_time(time)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    let socket = SockRef::from(stream);
    socket.set_tcp_keepalive(&keepalive)?;
    #[cfg(target_os = "linux")]
    socket.set_tcp_user_timeout(Some(time + KEEPALIVE_INTERVAL * KEEPALIVE_RETRIES))?;
    Ok(())
}

/// Negotiates TLS with `SSLRequest`. Only the one-byte answer is read before the handshake, so
/// bytes the server sent after it cannot pass as if they came through TLS.
async fn start_tls(mut tcp: TcpStream, tls: &ServerTls) -> Result<ServerStream, ConnectError> {
    tcp.write_all(&protocol::ssl_request()).await?;
    let mut answer = [0u8; 1];
    tcp.read_exact(&mut answer).await?;
    match answer[0] {
        b'S' => tls
            .connector
            .connect(tls.name.clone(), tcp)
            .await
            .map_err(ConnectError::Tls),
        b'N' => Err(ConnectError::TlsRefused),
        other => Err(ConnectError::Protocol(format!(
            "unexpected answer {:?} to SSLRequest",
            other as char
        ))),
    }
}

impl ServerConn {
    /// Opens and authenticates a connection for `user`/`database` with startup `options`.
    pub async fn connect(
        settings: &ServerSettings,
        dns: &Resolver,
        user: &str,
        database: &str,
        options: &[(String, String)],
        secret: Secret<'_>,
    ) -> Result<Connected, ConnectError> {
        timeout(
            settings.connect_timeout,
            Self::connect_inner(settings, dns, user, database, options, secret),
        )
        .await
        .map_err(|_| ConnectError::Timeout)?
    }

    async fn connect_inner(
        settings: &ServerSettings,
        dns: &Resolver,
        user: &str,
        database: &str,
        options: &[(String, String)],
        secret: Secret<'_>,
    ) -> Result<Connected, ConnectError> {
        let addrs = dns.resolve().await.map_err(ConnectError::Dns)?;
        let mut last_error = None;
        let mut connected = None;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    connected = Some((stream, addr));
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let Some((stream, peer)) = connected else {
            return Err(ConnectError::Io(
                last_error.unwrap_or_else(|| io::Error::other("no server address")),
            ));
        };
        keepalive(&stream, settings.keepalive_time)?;
        let stream = start_tls(stream, &settings.tls).await?;

        let mut params: Vec<(&str, &str)> = vec![
            ("user", user),
            ("database", database),
            ("application_name", &settings.application_name),
            ("client_encoding", "UTF8"),
            // A reader endpoint may fall back to the writer: keep sessions read-only there too,
            // or a write or a temporary table could outlive the client that made it.
            ("default_transaction_read_only", "on"),
        ];
        params.extend(options.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let mut out = BytesMut::new();
        protocol::startup_message(&mut out, &params);

        let mut conn = ServerConn {
            stream,
            buf: BytesMut::with_capacity(8192),
            cancel_key: ServerCancelKey {
                addr: peer,
                process_id: 0,
                secret: Vec::new(),
            },
            params: Params::default(),
            expires_at: Instant::now() + settings.lifetime + jitter(settings.lifetime_jitter),
            generation: 0,
        };
        conn.send(&out).await?;

        let mut scram: Option<ScramClient> = None;
        let mut keys: Option<ScramKeys> = None;
        let mut server_verified = false;
        let mut key_data = None;
        loop {
            let (msg_tag, body) = conn.read_message().await?;
            match msg_tag {
                tag::AUTHENTICATION => match protocol::parse_authentication(&body)? {
                    Authentication::Sasl { mechanisms } => {
                        if scram.is_some() || !mechanisms.contains(&scram::MECHANISM) {
                            return Err(ConnectError::UnsupportedAuth(
                                "SASL without SCRAM-SHA-256",
                            ));
                        }
                        let (client, first) = ScramClient::start();
                        out.clear();
                        protocol::sasl_initial_response(&mut out, scram::MECHANISM, &first);
                        conn.send(&out).await?;
                        scram = Some(client);
                    }
                    Authentication::SaslContinue(data) => {
                        let client = scram.as_mut().ok_or_else(|| {
                            ConnectError::Protocol("unexpected SASLContinue".into())
                        })?;
                        if keys.is_some() {
                            return Err(ConnectError::Protocol("repeated SASLContinue".into()));
                        }
                        let first = client.read_server_first(data)?;
                        let derived = match secret {
                            Secret::Keys(keys) => keys.clone(),
                            // PBKDF2 takes milliseconds of CPU; keep it off the runtime threads.
                            Secret::Password(password) => {
                                let password = Zeroizing::new(password.to_owned());
                                let (salt, iterations) = (first.salt.clone(), first.iterations);
                                tokio::task::spawn_blocking(move || {
                                    ScramKeys::derive(&password, &salt, iterations)
                                })
                                .await
                                .map_err(io::Error::other)?
                            }
                        };
                        let message = client.respond(&first, &derived)?;
                        out.clear();
                        protocol::sasl_response(&mut out, &message);
                        conn.send(&out).await?;
                        keys = Some(derived);
                    }
                    Authentication::SaslFinal(data) => {
                        let client = scram.as_ref().filter(|_| keys.is_some());
                        let client = client
                            .ok_or_else(|| ConnectError::Protocol("unexpected SASLFinal".into()))?;
                        client.finish(data)?;
                        server_verified = true;
                    }
                    Authentication::Ok => {
                        // A server that skips SCRAM would accept any password, so a login there
                        // proves nothing about the client's credentials.
                        if !server_verified {
                            return Err(ConnectError::UnsupportedAuth(
                                "server did not authenticate the client",
                            ));
                        }
                    }
                    Authentication::CleartextPassword => {
                        return Err(ConnectError::UnsupportedAuth("cleartext password"));
                    }
                    Authentication::Md5Password => {
                        return Err(ConnectError::UnsupportedAuth("MD5 password"));
                    }
                    Authentication::Other(_) => {
                        return Err(ConnectError::UnsupportedAuth("unknown method"));
                    }
                },
                tag::ERROR_RESPONSE => {
                    let fields = protocol::parse_error_response(&body)?;
                    // pg_hba.conf refuses before any password exchange, so it says nothing
                    // about the password.
                    if scram.is_none() && fields.code == "28000" {
                        return Err(ConnectError::Refused(fields));
                    }
                    return Err(ConnectError::Server(fields));
                }
                tag::PARAMETER_STATUS => {
                    let (name, value) = protocol::parse_parameter_status(&body)?;
                    conn.params.values.insert(name.to_owned(), value.to_owned());
                }
                tag::BACKEND_KEY_DATA => key_data = Some(protocol::parse_backend_key_data(&body)?),
                tag::NOTICE_RESPONSE => {}
                tag::READY_FOR_QUERY => {
                    if protocol::parse_ready_for_query(&body)? != TxStatus::Idle || !server_verified
                    {
                        return Err(ConnectError::Protocol(
                            "unexpected ReadyForQuery during startup".into(),
                        ));
                    }
                    let (process_id, secret) = key_data
                        .ok_or_else(|| ConnectError::Protocol("no BackendKeyData".into()))?;
                    conn.cancel_key.process_id = process_id;
                    conn.cancel_key.secret = secret;
                    let keys =
                        keys.ok_or_else(|| ConnectError::Protocol("no SCRAM exchange".into()))?;
                    return Ok(Connected { conn, keys });
                }
                other => {
                    return Err(ConnectError::Protocol(format!(
                        "unexpected message {:?} during startup",
                        other as char
                    )));
                }
            }
        }
    }

    /// Writes `out` and flushes it: a TLS write may keep bytes back until a flush.
    async fn send(&mut self, out: &[u8]) -> io::Result<()> {
        self.stream.write_all(out).await?;
        self.stream.flush().await
    }

    /// Reads one whole message outside the relay.
    async fn read_message(&mut self) -> Result<(u8, BytesMut), ConnectError> {
        loop {
            if let Some((msg_tag, len)) = protocol::frame_at(&self.buf, MAX_CONTROL_MESSAGE)? {
                let mut frame = self.buf.split_to(len);
                frame.advance(5);
                return Ok((msg_tag, frame));
            }
            if self.stream.read_buf(&mut self.buf).await? == 0 {
                return Err(ConnectError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    }

    pub fn cancel_key(&self) -> &ServerCancelKey {
        &self.cancel_key
    }

    pub fn peer(&self) -> SocketAddr {
        self.cancel_key.addr
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Whether the server sent anything (an error, a shutdown notice) or closed the connection
    /// while it sat idle. An idle connection must be silent.
    pub fn idle_disturbed(&mut self) -> bool {
        if !self.buf.is_empty() {
            return true;
        }
        let mut probe = [0u8; 64];
        let mut probe = ReadBuf::new(&mut probe);
        // A TLS record without data, such as a session ticket, leaves the read pending; data,
        // an alert, the end of the stream or an error completes it.
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(&mut self.stream)
            .poll_read(&mut cx, &mut probe)
            .is_ready()
    }

    /// Sends `Terminate` and closes TLS if the socket takes them right away, so the server sees
    /// a clean end instead of an unexpected EOF. Only for a connection at a message boundary.
    pub fn terminate(&mut self) {
        let mut out = BytesMut::new();
        protocol::terminate(&mut out);
        let mut cx = Context::from_waker(Waker::noop());
        let mut stream = Pin::new(&mut self.stream);
        if let Poll::Ready(Ok(n)) = stream.as_mut().poll_write(&mut cx, &out)
            && n == out.len()
        {
            let _ = stream.poll_shutdown(&mut cx);
        }
    }

    /// One round trip: a `Sync` outside a pipeline makes the server answer `ReadyForQuery`.
    pub async fn health_check(&mut self, limit: Duration) -> bool {
        let check = async {
            let mut out = BytesMut::new();
            protocol::sync(&mut out);
            self.send(&out).await?;
            let (msg_tag, body) = self.read_message().await?;
            Ok::<_, ConnectError>(
                msg_tag == tag::READY_FOR_QUERY
                    && protocol::parse_ready_for_query(&body)? == TxStatus::Idle,
            )
        };
        matches!(timeout(limit, check).await, Ok(Ok(true))) && self.buf.is_empty()
    }
}

fn jitter(max: Duration) -> Duration {
    use rand::RngExt;
    if max.is_zero() {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::rng().random_range(0..=max.as_millis() as u64))
}

/// Sends a `CancelRequest` for a server connection, over TLS like the connection itself, and
/// waits until the server closed the cancel connection, which it does once the cancel signal
/// has been delivered.
pub async fn send_cancel(
    key: &ServerCancelKey,
    tls: &ServerTls,
    limit: Duration,
) -> Result<(), ConnectError> {
    let send = async {
        let mut stream = start_tls(TcpStream::connect(key.addr).await?, tls).await?;
        stream
            .write_all(&protocol::cancel_request(key.process_id, &key.secret))
            .await?;
        stream.flush().await?;
        let mut sink = [0u8; 16];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                // The server may close the cancel connection without a TLS close_notify.
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    };
    timeout(limit, send)
        .await
        .map_err(|_| ConnectError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn a_parameter_the_guard_does_not_assume_marks_the_connection_for_good() {
        let mut params = Params::default();
        params.set("client_encoding", "UTF8");
        params.set("standard_conforming_strings", "on");
        params.set("TimeZone", "UTC");
        assert!(!params.unguarded);
        params.set("standard_conforming_strings", "off");
        params.set("standard_conforming_strings", "on");
        assert!(params.unguarded);
    }

    /// A server connection over TLS on loopback, and the server's end of it.
    async fn tls_conn() -> (ServerConn, tokio_rustls::server::TlsStream<TcpStream>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted, connected) = tokio::join!(
            async {
                let (tcp, _) = listener.accept().await.unwrap();
                TlsAcceptor::from(Arc::new(server))
                    .accept(tcp)
                    .await
                    .unwrap()
            },
            async {
                let tcp = TcpStream::connect(addr).await.unwrap();
                TlsConnector::from(Arc::new(client))
                    .connect(ServerName::try_from("localhost").unwrap(), tcp)
                    .await
                    .unwrap()
            },
        );
        let conn = ServerConn {
            stream: connected,
            buf: BytesMut::new(),
            cancel_key: ServerCancelKey {
                addr,
                process_id: 1,
                secret: vec![0; 4],
            },
            params: Params::default(),
            expires_at: Instant::now() + Duration::from_secs(60),
            generation: 0,
        };
        (conn, accepted)
    }

    #[tokio::test]
    async fn terminate_ends_the_session_cleanly() {
        let (mut conn, mut server) = tls_conn().await;
        assert!(!conn.idle_disturbed());
        conn.terminate();
        let mut received = Vec::new();
        // A clean TLS close ends the stream; an EOF without close_notify would be an error.
        timeout(Duration::from_secs(5), server.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, [b'X', 0, 0, 0, 4]);
    }

    #[tokio::test]
    async fn an_idle_connection_the_server_closed_is_disturbed() {
        let (mut conn, mut server) = tls_conn().await;
        server.shutdown().await.unwrap();
        timeout(Duration::from_secs(5), async {
            while !conn.idle_disturbed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unacknowledged_data_is_bounded_like_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        keepalive(&stream, Duration::from_secs(30)).unwrap();
        assert_eq!(
            SockRef::from(&stream).tcp_user_timeout().unwrap(),
            Some(Duration::from_secs(60))
        );
    }
}
