//! One client connection: TLS, startup, password authentication, then the relay loop.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Instant, timeout};
use tokio_rustls::server::TlsStream;
use zeroize::Zeroizing;

use crate::app::App;
use crate::auth::{AuthError, CredKey, Login, Verification};
use crate::cancel::CancelHandle;
use crate::metrics::{PoolLabels, WaitSource};
use crate::pool::{AcquireError, Lease, PoolHandle, PoolKey, TooManyVariants};
use crate::protocol::{self, FrontendMessage, Severity, StartupPacket, TxStatus};
use crate::relay::{BackendStream, Flow, FrontendAction, Rejected, Relay, ServerViolation};
use crate::scram::Secret;
use crate::server::{self, ConnectError, Connected, ServerConn};
use crate::upstream::Upstream;

/// Output and server-bound data buffered beyond this pause reading from the other side.
const HIGH_WATER: usize = 256 << 10;
/// Largest `PasswordMessage` accepted.
const MAX_PASSWORD_MESSAGE: usize = 4096;
/// PostgreSQL's `NAMEDATALEN - 1`.
const MAX_NAME: usize = 63;
/// Session options a client may set at startup; they become part of the pool key.
const SESSION_OPTIONS: [&str; 3] = [
    "statement_timeout",
    "lock_timeout",
    "idle_in_transaction_session_timeout",
];

type Client = TlsStream<TcpStream>;

#[derive(Debug, thiserror::Error)]
enum LoginError {
    #[error("client I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS handshake failed: {0}")]
    Tls(std::io::Error),
    #[error("{0}")]
    Protocol(#[from] protocol::ProtocolError),
}

/// A FATAL error for the client.
struct Fatal {
    code: String,
    message: String,
}

fn fatal(code: &str, message: impl Into<String>) -> Fatal {
    Fatal {
        code: code.to_owned(),
        message: message.into(),
    }
}

fn connect_failure(error: &ConnectError) -> Fatal {
    match error {
        // The server's own startup errors (starting up, too many connections, unknown
        // database, …) are what the client would have seen without lokaj.
        ConnectError::Server(fields) | ConnectError::Refused(fields) => {
            fatal(&fields.code, fields.message.clone())
        }
        error if error.is_auth_failure() => fatal("28P01", "lokaj: password authentication failed"),
        ConnectError::UnsupportedAuth(method) => fatal(
            "28000",
            format!("lokaj: the server asked for {method}; lokaj needs SCRAM-SHA-256"),
        ),
        _ => fatal("08006", "lokaj: could not connect to the server"),
    }
}

fn acquire_reason(error: &AcquireError<ConnectError>) -> &'static str {
    match error {
        AcquireError::TimedOut => "wait_timeout",
        AcquireError::TooManyWaiters => "too_many_waiters",
        AcquireError::Open(_) => "connect_failed",
    }
}

fn acquire_failure(error: &AcquireError<ConnectError>) -> Fatal {
    match error {
        AcquireError::TimedOut => {
            fatal("53300", "lokaj: timed out waiting for a server connection")
        }
        AcquireError::TooManyWaiters => fatal(
            "53300",
            "lokaj: too many clients waiting for a server connection",
        ),
        AcquireError::Open(error) => connect_failure(error),
    }
}

async fn send_fatal<S: AsyncWrite + Unpin>(stream: &mut S, error: &Fatal) {
    let mut out = BytesMut::new();
    protocol::error_response(&mut out, Severity::Fatal, &error.code, &error.message);
    let _ = stream.write_all(&out).await;
    let _ = stream.shutdown().await;
}

async fn read_startup_packet<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<StartupPacket, LoginError> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await?;
    let len = protocol::startup_packet_len(prefix)?;
    let mut body = vec![0u8; len - 4];
    stream.read_exact(&mut body).await?;
    Ok(protocol::parse_startup_packet(&body)?)
}

struct StartupParams {
    user: String,
    database: String,
    application_name: String,
    options: Vec<(String, String)>,
    /// `_pq_.` protocol options, reported back as unrecognized.
    unrecognized: Vec<String>,
}

impl StartupParams {
    fn parse(params: Vec<(String, String)>) -> Result<Self, Fatal> {
        let mut user = None;
        let mut database = None;
        let mut application_name = String::new();
        let mut options = Vec::new();
        let mut unrecognized = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (name, value) in params {
            if !seen.insert(name.clone()) {
                return Err(fatal(
                    "08P01",
                    format!("lokaj: duplicate startup parameter \"{name}\""),
                ));
            }
            match name.as_str() {
                "user" => user = Some(value),
                "database" => database = Some(value),
                "application_name" => application_name = value,
                "client_encoding" => {
                    if !value.eq_ignore_ascii_case("utf8") && !value.eq_ignore_ascii_case("utf-8") {
                        return Err(fatal("0A000", "lokaj: client_encoding must be UTF8"));
                    }
                }
                name if SESSION_OPTIONS.contains(&name) => {
                    if value.is_empty()
                        || value.len() > 10
                        || !value.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(fatal(
                            "22023",
                            format!("lokaj: {name} must be an integer number of milliseconds"),
                        ));
                    }
                    options.push((name.to_owned(), value));
                }
                name if name.starts_with("_pq_.") => unrecognized.push(name.to_owned()),
                name => {
                    return Err(fatal(
                        "0A000",
                        format!("lokaj: startup parameter \"{name}\" is not supported"),
                    ));
                }
            }
        }
        let user = user
            .filter(|u| !u.is_empty())
            .ok_or_else(|| fatal("28000", "lokaj: no user name specified"))?;
        let database = database
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| user.clone());
        // PostgreSQL truncates longer names; refusing them keeps lokaj's identity for rate
        // limits and pools the same as the server's.
        if user.len() > MAX_NAME || database.len() > MAX_NAME {
            return Err(fatal(
                "42622",
                format!("lokaj: user and database names must be at most {MAX_NAME} bytes"),
            ));
        }
        options.sort();
        Ok(Self {
            user,
            database,
            application_name,
            options,
            unrecognized,
        })
    }
}

/// Serves one accepted connection until it closes.
pub async fn handle(app: Arc<App>, tcp: TcpStream, peer: SocketAddr) {
    if let Err(error) = server::keepalive(&tcp, app.config.server.keepalive_time) {
        tracing::debug!(%peer, %error, "cannot configure client socket");
    }
    let login = login(&app, tcp, peer.ip());
    let session = match timeout(app.config.client.login_timeout, login).await {
        Err(_) => {
            app.metrics.client_reject("login_timeout");
            return;
        }
        Ok(Err(error)) => {
            match error {
                // Often an expired or untrusted lokaj certificate, which every client then hits.
                LoginError::Tls(_) => {
                    app.metrics.client_reject("tls_handshake");
                    tracing::info!(%peer, %error, "client TLS handshake failed");
                }
                LoginError::Protocol(_) => {
                    app.metrics.client_reject("protocol");
                    tracing::debug!(%peer, %error, "client login failed");
                }
                LoginError::Io(_) => {
                    app.metrics.client_reject("disconnected");
                    tracing::debug!(%peer, %error, "client login failed");
                }
            }
            return;
        }
        Ok(Ok(None)) => return,
        Ok(Ok(Some(session))) => session,
    };
    session.run().await;
}

async fn login(
    app: &Arc<App>,
    mut tcp: TcpStream,
    source: IpAddr,
) -> Result<Option<Session>, LoginError> {
    let mut client = loop {
        match read_startup_packet(&mut tcp).await? {
            StartupPacket::SslRequest => {
                tcp.write_all(b"S").await?;
                break app.tls.accept(tcp).await.map_err(LoginError::Tls)?;
            }
            StartupPacket::GssEncRequest => tcp.write_all(b"N").await?,
            StartupPacket::Cancel { process_id, secret } => {
                app.cancel(process_id, &secret);
                return Ok(None);
            }
            StartupPacket::Startup { .. } => {
                // The password would follow in cleartext.
                app.metrics.client_reject("tls_required");
                send_fatal(&mut tcp, &fatal("28000", "lokaj: TLS is required")).await;
                return Ok(None);
            }
        }
    };

    let (minor, params) = match read_startup_packet(&mut client).await? {
        StartupPacket::Startup { minor, params } => (minor, params),
        StartupPacket::Cancel { process_id, secret } => {
            app.cancel(process_id, &secret);
            return Ok(None);
        }
        StartupPacket::SslRequest | StartupPacket::GssEncRequest => {
            send_fatal(
                &mut client,
                &fatal("08P01", "lokaj: encryption request inside TLS"),
            )
            .await;
            return Ok(None);
        }
    };
    if app.draining() {
        app.metrics.client_reject("draining");
        send_fatal(
            &mut client,
            &fatal("57P03", "lokaj: the pooler is shutting down"),
        )
        .await;
        return Ok(None);
    }
    let startup = match StartupParams::parse(params) {
        Ok(startup) => startup,
        Err(error) => {
            app.metrics.client_reject("startup_parameters");
            send_fatal(&mut client, &error).await;
            return Ok(None);
        }
    };

    let mut out = BytesMut::new();
    if minor > 0 || !startup.unrecognized.is_empty() {
        let unrecognized: Vec<&str> = startup.unrecognized.iter().map(String::as_str).collect();
        protocol::negotiate_protocol_version(&mut out, 0, &unrecognized);
    }
    protocol::authentication_cleartext_password(&mut out);
    client.write_all(&out).await?;
    client.flush().await?;
    out.clear();

    let (password, pipelined) = match read_password(&mut client).await? {
        Some(read) => read,
        None => {
            send_fatal(
                &mut client,
                &fatal("08P01", "lokaj: expected a password message"),
            )
            .await;
            return Ok(None);
        }
    };

    let upstream = app.pools.connector();
    let wait_timeout = app.config.pool.wait_timeout;
    let cred_key = CredKey {
        user: startup.user.clone(),
        database: startup.database.clone(),
    };
    let verify = || async {
        // Outside the pools: the client is not authenticated yet.
        let Ok(Ok(_permit)) = timeout(wait_timeout, app.verifications.acquire()).await else {
            let error = fatal("53300", "lokaj: too many logins are being verified");
            return Verification::Unavailable((error, "verification_busy"));
        };
        let secret = Secret::Password(password.as_str());
        match ServerConn::connect(
            &upstream.settings,
            &upstream.dns,
            &startup.user,
            &startup.database,
            &startup.options,
            secret,
        )
        .await
        {
            Ok(Connected { conn, keys }) => Verification::Accepted(keys, conn),
            Err(error) => {
                app.metrics.connect_error(error.reason());
                if error.is_auth_failure() {
                    Verification::Rejected((connect_failure(&error), "rejected"))
                } else {
                    tracing::warn!(user = %startup.user, database = %startup.database, %error, "cannot verify a password with the server");
                    Verification::Unavailable((connect_failure(&error), "unavailable"))
                }
            }
        }
    };
    let verified = match app
        .auth
        .authenticate(&cred_key, source, &password, verify)
        .await
    {
        Ok(Login::Cached) => {
            app.metrics.credential_cache("hit");
            None
        }
        Ok(Login::Verified(conn)) => {
            app.metrics.credential_cache("miss");
            app.metrics.server_connects.inc();
            Some(conn)
        }
        Err(error) => {
            let error = match error {
                AuthError::Rejected((error, reason)) => {
                    app.metrics.auth_failure(reason);
                    tracing::info!(user = %startup.user, database = %startup.database, "password rejected");
                    error
                }
                AuthError::RateLimited => {
                    app.metrics.auth_failure("rate_limited");
                    tracing::warn!(user = %startup.user, database = %startup.database, %source, "login rate limited");
                    fatal(
                        "28P01",
                        format!(
                            "password authentication failed for user \"{}\"",
                            startup.user
                        ),
                    )
                }
                AuthError::Unavailable((error, reason)) => {
                    app.metrics.auth_failure(reason);
                    error
                }
            };
            send_fatal(&mut client, &error).await;
            return Ok(None);
        }
    };
    drop(password);

    let pool_key = PoolKey {
        user: startup.user.clone(),
        database: startup.database.clone(),
        options: startup.options.clone(),
    };
    let pool = match app.pools.register(pool_key) {
        Ok(pool) => pool,
        Err(TooManyVariants) => {
            app.metrics.client_reject("option_variants");
            send_fatal(
                &mut client,
                &fatal(
                    "0A000",
                    "lokaj: too many different session options for this database",
                ),
            )
            .await;
            return Ok(None);
        }
    };
    if let Some(mut conn) = verified {
        pool.data.observe(&mut conn);
        // Without a free slot the verification connection is simply closed.
        match pool.try_adopt(conn) {
            Some(lease) => lease.release(),
            None => app.metrics.recycle("not_adopted"),
        }
    }
    let deadline = Instant::now() + wait_timeout;

    let params = match pool.data.current() {
        Some(params) => params,
        None => {
            // The pool was collected since the credential was verified: take a fresh snapshot.
            match pool.acquire(deadline).await {
                Ok(lease) => lease.release(),
                Err(error) => {
                    app.metrics.session_error(acquire_reason(&error));
                    send_fatal(&mut client, &acquire_failure(&error)).await;
                    return Ok(None);
                }
            }
            match pool.data.current() {
                Some(params) => params,
                None => {
                    send_fatal(
                        &mut client,
                        &fatal("08006", "lokaj: could not connect to the server"),
                    )
                    .await;
                    return Ok(None);
                }
            }
        }
    };

    let cancel = app.cancels.register();
    for (name, value) in params.iter() {
        if name != "application_name" {
            protocol::parameter_status(&mut out, name, value);
        }
    }
    protocol::parameter_status(&mut out, "application_name", &startup.application_name);
    protocol::backend_key_data(&mut out, cancel.process_id(), cancel.secret());
    protocol::ready_for_query(&mut out, TxStatus::Idle);
    client.write_all(&out).await?;
    client.flush().await?;

    let (reader, writer) = tokio::io::split(client);
    Ok(Some(Session {
        app: app.clone(),
        labels: pool.labels().clone(),
        pool,
        cancel,
        reader,
        writer,
        cli_in: pipelined,
        to_client: BytesMut::new(),
        client_unflushed: false,
        active_at: Instant::now(),
        close_idle: app.close_idle_receiver(),
    }))
}

/// Reads the `PasswordMessage`; also returns whatever the client sent after it.
async fn read_password(
    client: &mut Client,
) -> Result<Option<(Zeroizing<String>, BytesMut)>, LoginError> {
    // Sized so it never reallocates and leaves a copy of the password behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_MESSAGE + 512));
    loop {
        if let Some((tag, len)) = protocol::frame_at(&buf, MAX_PASSWORD_MESSAGE)? {
            if tag != b'p' {
                return Ok(None);
            }
            return match protocol::parse_frontend(tag, &buf[5..len])? {
                FrontendMessage::Password { password } => {
                    let mut pipelined = BytesMut::with_capacity(8192);
                    pipelined.extend_from_slice(&buf[len..]);
                    Ok(Some((Zeroizing::new(password.0.to_owned()), pipelined)))
                }
                _ => Ok(None),
            };
        }
        let mut chunk = Zeroizing::new([0u8; 512]);
        let n = client.read(chunk.as_mut()).await?;
        if n == 0 {
            return Err(LoginError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

struct Session {
    app: Arc<App>,
    pool: PoolHandle<Upstream>,
    labels: PoolLabels,
    cancel: CancelHandle,
    reader: ReadHalf<Client>,
    writer: WriteHalf<Client>,
    /// Client bytes not yet processed.
    cli_in: BytesMut,
    to_client: BytesMut,
    /// A TLS write may accept bytes it could not send yet; they leave only with a flush.
    client_unflushed: bool,
    /// Last time anything moved; bounds how long an assigned client may keep the server waiting.
    active_at: Instant,
    close_idle: watch::Receiver<bool>,
}

/// A server connection assigned to the client.
struct Assigned {
    lease: Lease<Upstream>,
    relay: Relay,
    stream: BackendStream,
    to_server: BytesMut,
    /// Like `client_unflushed`, for the TLS stream to the server.
    server_unflushed: bool,
}

enum Event {
    ClientRead(std::io::Result<usize>),
    ClientSent(std::io::Result<Sent>),
    ServerRead(std::io::Result<usize>),
    ServerSent(std::io::Result<Sent>),
    Drain,
    IdleTimeout,
    ClientStalled,
}

enum Sent {
    Wrote(usize),
    Flushed,
}

/// Writes queued output, or with nothing queued, flushes what the TLS stream still holds.
async fn send_queued<W: AsyncWrite + Unpin>(
    writer: &mut W,
    queued: &[u8],
) -> std::io::Result<Sent> {
    if queued.is_empty() {
        writer.flush().await?;
        Ok(Sent::Flushed)
    } else {
        writer.write(queued).await.map(Sent::Wrote)
    }
}

enum End {
    /// The client closed the connection or sent `Terminate`.
    Closed,
    /// lokaj ends the session; a FATAL error is queued for the client.
    Fatal,
}

impl Session {
    fn queue_fatal(&mut self, error: &Fatal) {
        protocol::error_response(
            &mut self.to_client,
            Severity::Fatal,
            &error.code,
            &error.message,
        );
    }

    /// Ends the session with `error`, counted under `reason`.
    fn fail(&mut self, reason: &'static str, error: &Fatal) -> End {
        self.app.metrics.session_error(reason);
        self.queue_fatal(error);
        End::Fatal
    }

    /// Ends the session over a message lokaj refuses, logged with the tenant: it points at the
    /// application that sent it.
    fn refuse(&mut self, rejected: Rejected) -> End {
        tracing::info!(user = %self.labels.user, database = %self.labels.database, code = rejected.code, message = %rejected.message, "client message refused");
        let reason = if rejected.code == "0A000" {
            "unsupported"
        } else {
            "protocol"
        };
        self.fail(reason, &fatal(rejected.code, rejected.message))
    }

    fn read_limit(&self) -> usize {
        self.app.config.client.max_message_size + 5
    }

    async fn run(mut self) {
        let mut assigned = None;
        let end = self.relay_loop(&mut assigned).await;
        if let Some(assigned) = assigned {
            self.abort(assigned, "client_aborted");
        }
        if let End::Fatal = end {
            let flush = async {
                self.writer.write_all(&self.to_client).await?;
                self.writer.shutdown().await
            };
            let _ = timeout(Duration::from_secs(5), flush).await;
        }
    }

    /// Gives up a connection whose client is gone or misbehaved: cancels any running query and
    /// closes the connection, so the server rolls back.
    fn abort(&mut self, assigned: Assigned, reason: &'static str) {
        let cancelled = self.cancel.detach();
        if assigned.relay.in_flight() && !cancelled {
            let key = assigned.lease.conn().cancel_key().clone();
            let limit = self.app.config.server.cancel_timeout;
            let metrics = self.app.metrics.clone();
            let pools = self.app.pools.clone();
            tokio::spawn(async move {
                match server::send_cancel(&key, &pools.connector().settings.tls, limit).await {
                    Ok(()) => metrics.cancel("abandoned"),
                    Err(error) => {
                        metrics.cancel("failed");
                        tracing::debug!(%error, "cancel of an abandoned query failed");
                    }
                }
            });
        }
        self.app.metrics.recycle(reason);
        drop(assigned);
    }

    fn release(&mut self, assigned: Assigned) {
        let cancelled = self.cancel.detach();
        let Assigned {
            mut lease,
            stream,
            to_server,
            ..
        } = assigned;
        let clean = lease.conn().buf.is_empty() && to_server.is_empty() && stream.at_boundary();
        let reason = if cancelled {
            Some("cancelled")
        } else if !clean {
            Some("protocol")
        } else {
            let pool = lease.pool().clone();
            self.app
                .pools
                .connector()
                .release_check(&pool.data, lease.conn_mut())
        };
        self.app
            .metrics
            .pool_transactions
            .get_or_create(&self.labels)
            .inc();
        match reason {
            Some(reason) => {
                self.app.metrics.recycle(reason);
                if clean {
                    lease.conn_mut().terminate();
                }
                drop(lease);
            }
            None => lease.release(),
        }
        if self.to_client.is_empty() && self.to_client.capacity() > HIGH_WATER {
            self.to_client = BytesMut::new();
        }
    }

    /// Waits for a server connection; returns `None` if the client disconnected meanwhile.
    async fn assign(&mut self, relay: Relay) -> Result<Option<Assigned>, Fatal> {
        if !self.to_client.is_empty() || self.client_unflushed {
            let sent = async {
                self.writer.write_all(&self.to_client).await?;
                self.writer.flush().await
            };
            if sent.await.is_err() {
                return Ok(None);
            }
            self.to_client.clear();
            self.client_unflushed = false;
        }
        let started = Instant::now();
        let deadline = started + self.app.config.pool.wait_timeout;
        let limit = self.read_limit();
        let acquire = self.pool.acquire(deadline);
        tokio::pin!(acquire);
        let result = loop {
            tokio::select! {
                result = &mut acquire => break result,
                read = self.reader.read_buf(&mut self.cli_in), if self.cli_in.len() < limit => match read {
                    Ok(0) | Err(_) => return Ok(None),
                    Ok(_) => {}
                },
            }
        };
        let lease = result.map_err(|error| {
            self.app.metrics.session_error(acquire_reason(&error));
            acquire_failure(&error)
        })?;
        self.app
            .metrics
            .pool_wait
            .get_or_create(&WaitSource {
                source: lease.source.as_str(),
            })
            .observe(started.elapsed().as_secs_f64());
        self.cancel.attach(lease.conn().cancel_key().clone());
        Ok(Some(Assigned {
            lease,
            relay,
            stream: BackendStream::new(),
            to_server: BytesMut::new(),
            server_unflushed: false,
        }))
    }

    async fn relay_loop(&mut self, assigned: &mut Option<Assigned>) -> End {
        let max_message = self.read_limit();
        let idle_timeout = self.app.config.client.idle_transaction_timeout;
        loop {
            while let Some((msg_tag, len)) = match protocol::frame_at(&self.cli_in, max_message) {
                Ok(frame) => frame,
                Err(error) => {
                    return self.fail("protocol", &fatal("08P01", format!("lokaj: {error}")));
                }
            } {
                let frame = self.cli_in.split_to(len);
                let msg = match protocol::parse_frontend(msg_tag, &frame[5..]) {
                    Ok(msg) => msg,
                    Err(error) => {
                        return self.fail("protocol", &fatal("08P01", format!("lokaj: {error}")));
                    }
                };
                let a = match assigned {
                    Some(a) => a,
                    None => {
                        let mut relay = Relay::new();
                        match relay.on_frontend(&msg) {
                            Ok(FrontendAction::Forward) => {}
                            Ok(FrontendAction::Terminate) => return End::Closed,
                            Err(rejected) => return self.refuse(rejected),
                        }
                        match self.assign(relay).await {
                            Ok(Some(a)) => {
                                let a = assigned.insert(a);
                                a.to_server.extend_from_slice(&frame);
                                continue;
                            }
                            Ok(None) => return End::Closed,
                            Err(error) => {
                                self.queue_fatal(&error);
                                return End::Fatal;
                            }
                        }
                    }
                };
                match a.relay.on_frontend(&msg) {
                    Ok(FrontendAction::Forward) => a.to_server.extend_from_slice(&frame),
                    Ok(FrontendAction::Terminate) => return End::Closed,
                    Err(rejected) => return self.refuse(rejected),
                }
            }

            self.cli_in.reserve(8192);
            let event = match assigned.as_mut() {
                Some(a) => {
                    let awaits_client =
                        a.relay.awaits_client() && a.to_server.is_empty() && !a.server_unflushed;
                    // Output the client does not read holds the server connection just as well.
                    let client_stalled = !self.to_client.is_empty() || self.client_unflushed;
                    let conn = a.lease.conn_mut();
                    conn.buf.reserve(32 << 10);
                    let (mut server_rd, mut server_wr) = tokio::io::split(&mut conn.stream);
                    tokio::select! {
                        read = server_rd.read_buf(&mut conn.buf), if self.to_client.len() < HIGH_WATER => Event::ServerRead(read),
                        sent = send_queued(&mut self.writer, &self.to_client), if !self.to_client.is_empty() || self.client_unflushed => Event::ClientSent(sent),
                        sent = send_queued(&mut server_wr, &a.to_server), if !a.to_server.is_empty() || a.server_unflushed => Event::ServerSent(sent),
                        read = self.reader.read_buf(&mut self.cli_in), if a.to_server.len() < HIGH_WATER && self.cli_in.len() < max_message => Event::ClientRead(read),
                        () = tokio::time::sleep_until(self.active_at + idle_timeout), if awaits_client || client_stalled => {
                            if client_stalled { Event::ClientStalled } else { Event::IdleTimeout }
                        }
                    }
                }
                None => {
                    let close = *self.close_idle.borrow_and_update();
                    if close {
                        Event::Drain
                    } else {
                        tokio::select! {
                            read = self.reader.read_buf(&mut self.cli_in), if self.cli_in.len() < max_message => Event::ClientRead(read),
                            sent = send_queued(&mut self.writer, &self.to_client), if !self.to_client.is_empty() || self.client_unflushed => Event::ClientSent(sent),
                            _ = self.close_idle.changed() => continue,
                        }
                    }
                }
            };

            if !matches!(event, Event::IdleTimeout | Event::ClientStalled) {
                self.active_at = Instant::now();
            }
            match event {
                Event::ClientRead(Ok(0) | Err(_))
                | Event::ClientSent(Ok(Sent::Wrote(0)) | Err(_)) => {
                    return End::Closed;
                }
                Event::ClientRead(Ok(_)) => {}
                Event::ClientSent(Ok(Sent::Wrote(n))) => {
                    self.to_client.advance(n);
                    self.client_unflushed = true;
                }
                Event::ClientSent(Ok(Sent::Flushed)) => self.client_unflushed = false,
                Event::ServerRead(Ok(0) | Err(_))
                | Event::ServerSent(Ok(Sent::Wrote(0)) | Err(_)) => {
                    if let Some(lost) = assigned.take() {
                        self.cancel.detach();
                        self.app.metrics.recycle("server_lost");
                        drop(lost);
                    }
                    return self.fail(
                        "server_lost",
                        &fatal("08006", "lokaj: server connection lost"),
                    );
                }
                Event::ServerRead(Ok(_)) => {
                    let Some(a) = assigned.as_mut() else { continue };
                    let conn = a.lease.conn_mut();
                    match a.stream.feed(
                        &mut conn.buf,
                        &mut self.to_client,
                        &mut a.relay,
                        &mut conn.params,
                    ) {
                        Ok(Flow::Continue) => {}
                        Ok(Flow::Release) => {
                            let done = assigned.take().expect("assigned");
                            self.release(done);
                            if *self.close_idle.borrow() {
                                self.queue_fatal(&fatal(
                                    "57P01",
                                    "lokaj: the pooler is shutting down",
                                ));
                                return End::Fatal;
                            }
                        }
                        Ok(Flow::Fatal) => {
                            // The server ends this session; the client already has its error.
                            if let Some(gone) = assigned.take() {
                                self.cancel.detach();
                                self.app.metrics.recycle("server_fatal");
                                drop(gone);
                            }
                            self.app.metrics.session_error("server_fatal");
                            return End::Fatal;
                        }
                        Err(ServerViolation::Copy) => {
                            return self.refuse(Rejected {
                                code: "0A000",
                                message: "lokaj: COPY is not supported".into(),
                            });
                        }
                        Err(error @ ServerViolation::Protocol(_)) => {
                            tracing::warn!(user = %self.labels.user, database = %self.labels.database, %error, "closing server connection");
                            return self.fail(
                                "server_protocol",
                                &fatal("08P01", "lokaj: server protocol violation"),
                            );
                        }
                    }
                }
                Event::ServerSent(Ok(Sent::Wrote(n))) => {
                    if let Some(a) = assigned.as_mut() {
                        a.to_server.advance(n);
                        a.server_unflushed = true;
                    }
                }
                Event::ServerSent(Ok(Sent::Flushed)) => {
                    if let Some(a) = assigned.as_mut() {
                        a.server_unflushed = false;
                    }
                }
                Event::Drain => {
                    self.queue_fatal(&fatal("57P01", "lokaj: the pooler is shutting down"));
                    return End::Fatal;
                }
                Event::IdleTimeout => {
                    if let Some(idle) = assigned.take() {
                        self.abort(idle, "idle_in_transaction");
                    }
                    return self.fail(
                        "idle_in_transaction",
                        &fatal(
                            "25P03",
                            "lokaj: terminating connection due to idle-in-transaction timeout",
                        ),
                    );
                }
                Event::ClientStalled => {
                    if let Some(stalled) = assigned.take() {
                        self.abort(stalled, "client_stalled");
                    }
                    return self.fail(
                        "client_stalled",
                        &fatal(
                            "08006",
                            "lokaj: terminating connection because the client stopped reading",
                        ),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::DuplexStream;
    use tokio_rustls::{TlsAcceptor, TlsConnector, client};

    const PIPE: usize = 1024;

    /// TLS over a pipe much smaller than one write, so writes fill it.
    async fn tls_pipe() -> (TlsStream<DuplexStream>, client::TlsStream<DuplexStream>) {
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
        let (server_io, client_io) = tokio::io::duplex(PIPE);
        let (server, client) = tokio::join!(
            TlsAcceptor::from(Arc::new(server)).accept(server_io),
            TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from("localhost").unwrap(), client_io),
        );
        (server.unwrap(), client.unwrap())
    }

    #[tokio::test]
    async fn a_flush_delivers_what_a_full_pipe_left_behind() {
        let (mut server, mut client) = tls_pipe().await;
        let data: Vec<u8> = (0..32 << 10).map(|i| (i % 251) as u8).collect();
        let Sent::Wrote(n) = send_queued(&mut server, &data).await.unwrap() else {
            panic!("expected a write");
        };
        // The write accepted far more than the pipe holds; the rest is only in the TLS stream.
        assert!(n > 4 * PIPE, "accepted {n} bytes");
        let reader = tokio::spawn(async move {
            let mut received = vec![0; n];
            client.read_exact(&mut received).await.map(|_| received)
        });
        assert!(matches!(
            send_queued(&mut server, &[]).await.unwrap(),
            Sent::Flushed
        ));
        let received = timeout(Duration::from_secs(5), reader)
            .await
            .expect("the client never received the accepted bytes")
            .unwrap()
            .unwrap();
        assert_eq!(received, data[..n]);
    }
}
