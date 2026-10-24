//! Process wiring: listeners, background tasks and the graceful drain.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use prometheus_client::registry::Registry;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::{Instant, sleep, sleep_until};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::auth::AuthCache;
use crate::cancel::CancelRegistry;
use crate::config::Config;
use crate::dns::Resolver;
use crate::metrics::{Metrics, PoolCollector};
use crate::pool::{Limits, Pools};
use crate::server::{self, ServerSettings, ServerTls};
use crate::upstream::Upstream;
use crate::{admin, session, tls};

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    #[error("cannot listen: {0}")]
    Listen(#[from] io::Error),
}

pub struct App {
    pub config: Config,
    pub tls: TlsAcceptor,
    pub pools: Pools<Upstream>,
    pub auth: Arc<AuthCache>,
    pub dns: Arc<Resolver>,
    pub cancels: Arc<CancelRegistry>,
    pub metrics: Arc<Metrics>,
    pub registry: Registry,
    /// Budget for password verifications against the server.
    pub verifications: Semaphore,
    drain: watch::Sender<bool>,
    clients: AtomicUsize,
}

/// Counts a client connection for the drain and the client limit.
struct ClientGuard(Arc<App>);

impl ClientGuard {
    fn new(app: Arc<App>) -> Self {
        app.clients.fetch_add(1, Ordering::SeqCst);
        app.metrics.clients.inc();
        Self(app)
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.0.clients.fetch_sub(1, Ordering::SeqCst);
        self.0.metrics.clients.dec();
    }
}

impl App {
    pub fn new(config: Config) -> Result<Arc<Self>, StartError> {
        let tls = TlsAcceptor::from(tls::server_config(&config.tls.cert, &config.tls.key)?);
        let metrics = Arc::new(Metrics::new());
        let server = &config.server;
        let dns = Arc::new(Resolver::new(
            &server.host,
            server.port,
            server.dns_cache_ttl,
            server.dns_forget_after,
            metrics.clone(),
        ));
        let auth = Arc::new(AuthCache::new(
            config.auth.verify_ttl,
            config.auth.max_failures,
            config.auth.failure_window,
        ));
        let upstream = Upstream {
            settings: ServerSettings {
                tls: ServerTls {
                    connector: TlsConnector::from(tls::client_config(&server.ca)?),
                    name: tls::server_name(&server.host)?,
                },
                application_name: server.application_name.clone(),
                connect_timeout: server.connect_timeout,
                keepalive_time: server.keepalive_time,
                lifetime: server.lifetime,
                lifetime_jitter: server.lifetime_jitter,
            },
            dns: dns.clone(),
            auth: auth.clone(),
            metrics: metrics.clone(),
            idle_timeout: server.idle_timeout,
            check_after: server.check_after,
            check_timeout: server.check_timeout,
        };
        let limits = Limits {
            max_size: config.pool.max_size,
            max_total: config.pool.max_total,
            max_waiters: config.pool.max_waiters,
            gc_after: config.pool.gc_after,
        };
        let pools = Pools::new(upstream, limits, metrics.clone());
        let mut registry = Registry::with_prefix("lokaj");
        metrics.register(&mut registry);
        registry.register_collector(Box::new(PoolCollector(pools.clone())));
        let verifications = Semaphore::new(config.auth.max_verifications);
        Ok(Arc::new(Self {
            config,
            tls,
            pools,
            auth,
            dns,
            cancels: Arc::new(CancelRegistry::default()),
            metrics,
            registry,
            verifications,
            drain: watch::channel(false).0,
            clients: AtomicUsize::new(0),
        }))
    }

    pub fn draining(&self) -> bool {
        *self.drain.borrow()
    }

    pub fn drain_receiver(&self) -> watch::Receiver<bool> {
        self.drain.subscribe()
    }

    /// Forwards a client's cancel request to the server connection it currently holds.
    pub fn cancel(&self, process_id: i32, secret: &[u8]) {
        let Some(key) = self.cancels.cancel(process_id, secret) else {
            // Unknown keys include those of clients on another replica.
            self.metrics.cancel("unknown");
            return;
        };
        let limit = self.config.server.cancel_timeout;
        let metrics = self.metrics.clone();
        let pools = self.pools.clone();
        tokio::spawn(async move {
            match server::send_cancel(&key, &pools.connector().settings.tls, limit).await {
                Ok(()) => metrics.cancel("forwarded"),
                Err(error) => {
                    metrics.cancel("failed");
                    tracing::debug!(%error, "forwarding a cancel request failed");
                }
            }
        });
    }

    fn accept(self: &Arc<Self>, tcp: TcpStream, peer: SocketAddr) {
        if self.clients.load(Ordering::SeqCst) >= self.config.client.max_clients {
            self.metrics.client_reject("too_many_clients");
            tracing::warn!(%peer, "client limit reached, refusing connection");
            return;
        }
        let guard = ClientGuard::new(self.clone());
        let app = self.clone();
        tokio::spawn(async move {
            let _guard = guard;
            session::handle(app, tcp, peer).await;
        });
    }

    async fn accept_one(self: &Arc<Self>, listener: &TcpListener) {
        match listener.accept().await {
            Ok((tcp, peer)) => self.accept(tcp, peer),
            Err(error) => {
                // Usually file descriptor exhaustion; back off instead of spinning.
                tracing::warn!(%error, "accept failed");
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn shutdown_signal() {
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM");
                return std::future::pending().await;
            }
        };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

async fn reaper(app: Arc<App>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        app.pools.reap();
        app.auth.prune();
    }
}

/// Serves until SIGTERM or SIGINT, then drains.
pub async fn run(config: Config) -> Result<(), StartError> {
    let app = App::new(config)?;
    let listener = TcpListener::bind(app.config.listen).await?;
    let admin_listener = TcpListener::bind(app.config.admin_listen).await?;
    serve(app, listener, admin_listener, shutdown_signal()).await;
    Ok(())
}

/// Serves on bound listeners until `shutdown` completes, then drains: new clients get `57P03`,
/// idle clients `57P01`, and clients inside a transaction are closed when it ends.
pub async fn serve(
    app: Arc<App>,
    listener: TcpListener,
    admin_listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) {
    tracing::info!(
        listen = ?listener.local_addr().ok(),
        admin = ?admin_listener.local_addr().ok(),
        server = %app.config.server.host,
        "lokaj started"
    );
    let background = [
        tokio::spawn(
            app.dns
                .clone()
                .refresh_loop(app.config.server.dns_refresh_interval),
        ),
        tokio::spawn(reaper(app.clone())),
        tokio::spawn(admin::serve(app.clone(), admin_listener)),
    ];

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = app.accept_one(&listener) => {}
            () = &mut shutdown => break,
        }
    }

    tracing::info!(clients = app.clients.load(Ordering::SeqCst), "draining");
    app.drain.send_replace(true);
    let deadline = Instant::now() + app.config.shutdown_timeout;
    while app.clients.load(Ordering::SeqCst) > 0 {
        tokio::select! {
            () = app.accept_one(&listener) => {}
            () = sleep(Duration::from_millis(100)) => {}
            () = sleep_until(deadline) => {
                tracing::warn!(clients = app.clients.load(Ordering::SeqCst), "drain timed out, closing remaining clients");
                break;
            }
        }
    }
    for task in background {
        task.abort();
    }
    tracing::info!("stopped");
}
