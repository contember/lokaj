//! Harness for tests against a real PostgreSQL: a raw protocol client, an in-process lokaj and
//! per-test roles and databases. Requires `LOKAJ_TEST_PG` (`host:port` of a PostgreSQL 18 with
//! SCRAM authentication and superuser `postgres`); see `scripts/integration.sh`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use lokaj::app::{self, App};
use lokaj::config::Config;
use lokaj::protocol::{self, Authentication, ErrorFields};
use lokaj::scram::{ScramClient, ScramKeys};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

pub const TIMEOUT: Duration = Duration::from_secs(15);

/// Address of the test PostgreSQL, or `None` to skip.
pub fn pg_addr() -> Option<String> {
    std::env::var("LOKAJ_TEST_PG").ok()
}

/// Skips the test when no PostgreSQL is configured.
#[macro_export]
macro_rules! require_pg {
    () => {
        if common::pg_addr().is_none() {
            eprintln!("skipped: LOKAJ_TEST_PG is not set");
            return;
        }
    };
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn cstr(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

pub fn query(sql: &str) -> Vec<u8> {
    let mut body = Vec::new();
    cstr(&mut body, sql);
    msg(b'Q', &body)
}

pub fn parse(name: &str, sql: &str) -> Vec<u8> {
    let mut body = Vec::new();
    cstr(&mut body, name);
    cstr(&mut body, sql);
    body.extend_from_slice(&0i16.to_be_bytes());
    msg(b'P', &body)
}

pub fn bind(portal: &str, statement: &str, params: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    cstr(&mut body, portal);
    cstr(&mut body, statement);
    body.extend_from_slice(&0i16.to_be_bytes());
    body.extend_from_slice(&(params.len() as i16).to_be_bytes());
    for param in params {
        body.extend_from_slice(&(param.len() as i32).to_be_bytes());
        body.extend_from_slice(param.as_bytes());
    }
    body.extend_from_slice(&0i16.to_be_bytes());
    msg(b'B', &body)
}

pub fn describe_portal() -> Vec<u8> {
    msg(b'D', b"P\0")
}

pub fn execute() -> Vec<u8> {
    let mut body = b"\0".to_vec();
    body.extend_from_slice(&0i32.to_be_bytes());
    msg(b'E', &body)
}

pub fn sync() -> Vec<u8> {
    msg(b'S', &[])
}

pub fn terminate() -> Vec<u8> {
    msg(b'X', &[])
}

pub type Row = Vec<Option<String>>;

pub struct Client {
    stream: Box<dyn Io>,
    buf: BytesMut,
    pub params: HashMap<String, String>,
    pub key: Option<(i32, Vec<u8>)>,
}

impl Client {
    pub fn new(stream: impl Io + 'static) -> Self {
        Self {
            stream: Box::new(stream),
            buf: BytesMut::new(),
            params: HashMap::new(),
            key: None,
        }
    }

    pub async fn plain(addr: SocketAddr) -> Self {
        Self::new(TcpStream::connect(addr).await.expect("connect"))
    }

    pub async fn tls(addr: SocketAddr) -> Self {
        Self::tls_over(TcpStream::connect(addr).await.expect("connect")).await
    }

    /// Connects from `source`, another loopback address, as if from another host.
    pub async fn tls_from(addr: SocketAddr, source: IpAddr) -> Self {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(source, 0)).unwrap();
        Self::tls_over(socket.connect(addr).await.expect("connect")).await
    }

    async fn tls_over(mut tcp: TcpStream) -> Self {
        let mut request = Vec::new();
        request.extend_from_slice(&8i32.to_be_bytes());
        request.extend_from_slice(&protocol::SSL_REQUEST_CODE.to_be_bytes());
        tcp.write_all(&request).await.unwrap();
        let mut answer = [0u8; 1];
        tcp.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[0], b'S', "SSLRequest was declined");
        let tls = pki()
            .connector()
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .expect("TLS handshake");
        Self::new(tls)
    }

    pub async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write");
    }

    /// The next message, or `None` once the peer closed the connection.
    pub async fn recv_opt(&mut self) -> Option<(u8, BytesMut)> {
        loop {
            if let Some((tag, len)) = protocol::frame_at(&self.buf, 1 << 30).unwrap() {
                let mut frame = self.buf.split_to(len);
                frame.advance(5);
                return Some((tag, frame));
            }
            let n = timeout(TIMEOUT, self.stream.read_buf(&mut self.buf))
                .await
                .expect("read timed out")
                .unwrap_or(0);
            if n == 0 {
                return None;
            }
        }
    }

    pub async fn recv(&mut self) -> (u8, BytesMut) {
        self.recv_opt().await.expect("connection closed")
    }

    pub async fn send_startup(&mut self, params: &[(&str, &str)]) {
        let mut out = BytesMut::new();
        protocol::startup_message(&mut out, params);
        self.send(&out).await;
    }

    /// Completes startup, answering cleartext or SCRAM authentication with `password`.
    pub async fn authenticate(&mut self, password: &str) -> Result<(), ErrorFields> {
        let mut scram = None;
        loop {
            let (tag, body) = self.recv().await;
            match tag {
                b'R' => match protocol::parse_authentication(&body).unwrap() {
                    Authentication::Ok => {}
                    Authentication::CleartextPassword => {
                        let mut body = Vec::new();
                        cstr(&mut body, password);
                        self.send(&msg(b'p', &body)).await;
                    }
                    Authentication::Sasl { .. } => {
                        let (client, first) = ScramClient::start();
                        let mut out = BytesMut::new();
                        protocol::sasl_initial_response(&mut out, "SCRAM-SHA-256", &first);
                        self.send(&out).await;
                        scram = Some(client);
                    }
                    Authentication::SaslContinue(data) => {
                        let scram = scram.as_mut().unwrap();
                        let first = scram.read_server_first(data).unwrap();
                        let keys = ScramKeys::derive(password, &first.salt, first.iterations);
                        let reply = scram.respond(&first, &keys).unwrap();
                        let mut out = BytesMut::new();
                        protocol::sasl_response(&mut out, &reply);
                        self.send(&out).await;
                    }
                    Authentication::SaslFinal(data) => {
                        scram.as_ref().unwrap().finish(data).unwrap()
                    }
                    other => panic!("unexpected authentication request {other:?}"),
                },
                b'S' => {
                    let (name, value) = protocol::parse_parameter_status(&body).unwrap();
                    self.params.insert(name.into(), value.into());
                }
                b'K' => self.key = Some(protocol::parse_backend_key_data(&body).unwrap()),
                b'E' => return Err(protocol::parse_error_response(&body).unwrap()),
                b'Z' => return Ok(()),
                b'N' | b'v' => {}
                other => panic!("unexpected message {:?} during startup", other as char),
            }
        }
    }

    pub async fn login(
        &mut self,
        params: &[(&str, &str)],
        password: &str,
    ) -> Result<(), ErrorFields> {
        self.send_startup(params).await;
        self.authenticate(password).await
    }

    /// Reads until `ReadyForQuery`; returns the rows and the first error.
    pub async fn results(&mut self) -> (Vec<Row>, Option<ErrorFields>, u8) {
        let mut rows = Vec::new();
        let mut error = None;
        loop {
            let (tag, body) = self.recv().await;
            match tag {
                b'D' => rows.push(data_row(&body)),
                b'E' => {
                    error.get_or_insert(protocol::parse_error_response(&body).unwrap());
                }
                b'S' => {
                    let (name, value) = protocol::parse_parameter_status(&body).unwrap();
                    self.params.insert(name.into(), value.into());
                }
                b'Z' => return (rows, error, body[0]),
                _ => {}
            }
        }
    }

    pub async fn query(&mut self, sql: &str) -> Result<Vec<Row>, ErrorFields> {
        self.send(&query(sql)).await;
        match self.results().await {
            (rows, None, _) => Ok(rows),
            (_, Some(error), _) => Err(error),
        }
    }

    pub async fn query_one(&mut self, sql: &str) -> String {
        let rows = self
            .query(sql)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        rows[0][0].clone().unwrap()
    }

    pub async fn extended(&mut self, sql: &str, params: &[&str]) -> Result<Vec<Row>, ErrorFields> {
        let mut out = parse("", sql);
        out.extend(bind("", "", params));
        out.extend(describe_portal());
        out.extend(execute());
        out.extend(sync());
        self.send(&out).await;
        match self.results().await {
            (rows, None, _) => Ok(rows),
            (_, Some(error), _) => Err(error),
        }
    }

    /// Expects a FATAL error followed by the end of the connection.
    pub async fn expect_fatal(&mut self) -> ErrorFields {
        let error = loop {
            match self.recv_opt().await {
                Some((b'E', body)) => break protocol::parse_error_response(&body).unwrap(),
                Some(_) => continue,
                None => panic!("connection closed without an error"),
            }
        };
        assert!(error.is_fatal(), "expected FATAL, got {error:?}");
        assert!(
            self.recv_opt().await.is_none(),
            "connection stayed open after FATAL"
        );
        error
    }

    pub async fn expect_closed(&mut self) {
        while let Some((tag, _)) = self.recv_opt().await {
            assert_ne!(tag, b'Z', "connection is still usable");
        }
    }
}

fn data_row(body: &[u8]) -> Row {
    let mut body = body;
    let count = body.get_i16();
    (0..count)
        .map(|_| {
            let len = body.get_i32();
            if len < 0 {
                return None;
            }
            let value = String::from_utf8(body[..len as usize].to_vec()).unwrap();
            body.advance(len as usize);
            Some(value)
        })
        .collect()
}

pub struct Pki {
    pub dir: PathBuf,
    ca: CertificateDer<'static>,
}

impl Pki {
    pub fn connector(&self) -> tokio_rustls::TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}

/// A test CA and a server certificate for `localhost`, written to a temporary directory.
pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        let dir = std::env::temp_dir().join(format!("lokaj-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("server.crt"), cert.pem()).unwrap();
        std::fs::write(dir.join("server.key"), key.serialize_pem()).unwrap();
        std::fs::write(dir.join("ca.crt"), ca_cert.pem()).unwrap();
        Pki {
            dir,
            ca: ca_cert.der().clone(),
        }
    })
}

pub fn base_config() -> Config {
    let pg = pg_addr().expect("LOKAJ_TEST_PG");
    let (host, port) = pg.rsplit_once(':').expect("LOKAJ_TEST_PG is host:port");
    let dir = &pki().dir;
    let text = format!(
        r#"
        listen = "127.0.0.1:0"
        admin_listen = "127.0.0.1:0"
        shutdown_timeout = "10s"
        [tls]
        cert = "{cert}"
        key = "{key}"
        [server]
        host = "{host}"
        port = {port}
        [pool]
        wait_timeout = "3s"
        "#,
        cert = dir.join("server.crt").display(),
        key = dir.join("server.key").display(),
    );
    Config::parse(&text).unwrap()
}

pub struct Lokaj {
    pub addr: SocketAddr,
    pub admin: SocketAddr,
    pub app: Arc<App>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Lokaj {
    pub async fn start() -> Self {
        Self::with(|_| {}).await
    }

    pub async fn with(customize: impl FnOnce(&mut Config)) -> Self {
        let mut config = base_config();
        customize(&mut config);
        let app = App::new(config).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let admin = admin_listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(app::serve(app.clone(), listener, admin_listener, async {
            let _ = rx.await;
        }));
        Self {
            addr,
            admin,
            app,
            shutdown: Some(tx),
            task: Some(task),
        }
    }

    pub async fn client(&self) -> Client {
        Client::tls(self.addr).await
    }

    pub async fn client_from(&self, source: IpAddr) -> Client {
        Client::tls_from(self.addr, source).await
    }

    pub async fn login(&self, tenant: &Tenant) -> Client {
        let mut client = self.client().await;
        client
            .login(&tenant.params(), &tenant.password)
            .await
            .expect("login");
        client
    }

    /// Starts the drain; returns the task that ends when lokaj stopped.
    pub fn shutdown(&mut self) -> tokio::task::JoinHandle<()> {
        let _ = self.shutdown.take().unwrap().send(());
        self.task.take().unwrap()
    }

    pub async fn http(&self, path: &str) -> (u16, String) {
        let mut tcp = TcpStream::connect(self.admin).await.unwrap();
        tcp.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: lokaj\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut response = String::new();
        tcp.read_to_string(&mut response).await.unwrap();
        let status = response[9..12].parse().unwrap();
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_owned())
            .unwrap_or_default();
        (status, body)
    }

    /// The value of a metric sample, by its full name with labels as exposed.
    pub async fn metric(&self, sample: &str) -> f64 {
        let (_, body) = self.http("/metrics").await;
        body.lines()
            .filter_map(|line| line.strip_prefix(sample)?.strip_prefix(' '))
            .map(|value| value.parse::<f64>().unwrap())
            .sum()
    }
}

/// A superuser connection straight to PostgreSQL.
pub async fn admin() -> Client {
    let addr = pg_addr().expect("LOKAJ_TEST_PG");
    let mut client = Client::new(
        TcpStream::connect(addr)
            .await
            .expect("connect to PostgreSQL"),
    );
    let password = std::env::var("LOKAJ_TEST_PG_PASSWORD").unwrap_or_else(|_| "postgres".into());
    client
        .login(&[("user", "postgres"), ("database", "postgres")], &password)
        .await
        .expect("admin login");
    client
}

pub struct Tenant {
    pub user: String,
    pub database: String,
    pub password: String,
}

impl Tenant {
    pub fn params(&self) -> Vec<(&str, &str)> {
        vec![
            ("user", &self.user),
            ("database", &self.database),
            ("client_encoding", "UTF8"),
            ("application_name", "test"),
        ]
    }
}

/// A fresh role with its own database, as each tenant has in production.
pub async fn tenant() -> Tenant {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let suffix: u32 = rand::random();
    let user = format!("t_{}_{n}_{suffix:08x}", std::process::id());
    let password = format!("pw-{suffix:08x}-{n}");
    let mut admin = admin().await;
    admin
        .query(&format!(
            "CREATE ROLE \"{user}\" LOGIN PASSWORD '{password}'"
        ))
        .await
        .unwrap();
    admin
        .query(&format!("CREATE DATABASE \"{user}\" OWNER \"{user}\""))
        .await
        .unwrap();
    admin
        .query(&format!(
            "REVOKE CONNECT ON DATABASE \"{user}\" FROM PUBLIC"
        ))
        .await
        .unwrap();
    Tenant {
        database: user.clone(),
        user,
        password,
    }
}
