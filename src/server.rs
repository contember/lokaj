//! Server connections: connect, authenticate with SCRAM-SHA-256, and the cheap checks run on
//! idle connections.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use zeroize::Zeroizing;

use crate::cancel::ServerCancelKey;
use crate::dns::Resolver;
use crate::protocol::{self, Authentication, ErrorFields, TxStatus, tag};
use crate::scram::{self, ScramClient, ScramError, ScramKeys, Secret};

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
    #[error("server error {}: {}", .0.code, .0.message)]
    Server(ErrorFields),
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

    pub fn reason(&self) -> &'static str {
        match self {
            ConnectError::Dns(_) => "dns",
            ConnectError::Io(_) => "io",
            ConnectError::Timeout => "timeout",
            ConnectError::Server(_) if self.is_auth_failure() => "auth",
            ConnectError::Server(_) => "server_error",
            ConnectError::Scram(_) | ConnectError::NoCredential => "auth",
            ConnectError::UnsupportedAuth(_) => "unsupported_auth",
            ConnectError::Protocol(_) => "protocol",
        }
    }
}

pub struct ServerSettings {
    pub application_name: String,
    pub connect_timeout: Duration,
    pub keepalive_time: Duration,
    pub lifetime: Duration,
    pub lifetime_jitter: Duration,
}

pub struct ServerConn {
    pub stream: TcpStream,
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
}

impl Params {
    pub fn set(&mut self, name: &str, value: &str) {
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

pub fn keepalive(stream: &TcpStream, time: Duration) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = TcpKeepalive::new()
        .with_time(time)
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    SockRef::from(stream).set_tcp_keepalive(&keepalive)
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

        let mut params: Vec<(&str, &str)> = vec![
            ("user", user),
            ("database", database),
            ("application_name", &settings.application_name),
            ("client_encoding", "UTF8"),
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
        conn.stream.write_all(&out).await?;

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
                        conn.stream.write_all(&out).await?;
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
                        conn.stream.write_all(&out).await?;
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
                    return Err(ConnectError::Server(protocol::parse_error_response(&body)?));
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
        match self.stream.try_read(&mut probe) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
            Err(_) => true,
        }
    }

    /// One round trip: a `Sync` outside a pipeline makes the server answer `ReadyForQuery`.
    pub async fn health_check(&mut self, limit: Duration) -> bool {
        let check = async {
            let mut out = BytesMut::new();
            protocol::sync(&mut out);
            self.stream.write_all(&out).await?;
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

/// Sends a `CancelRequest` for a server connection and waits until the server closed the
/// cancel connection, which it does once the cancel signal has been delivered.
pub async fn send_cancel(key: &ServerCancelKey, limit: Duration) -> io::Result<()> {
    let send = async {
        let mut stream = TcpStream::connect(key.addr).await?;
        stream
            .write_all(&protocol::cancel_request(key.process_id, &key.secret))
            .await?;
        let mut sink = [0u8; 16];
        while stream.read(&mut sink).await? != 0 {}
        Ok(())
    };
    timeout(limit, send)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}
