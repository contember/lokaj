//! Simulates one lokaj process under a multi-tenant read workload, in virtual time.
//!
//! The lokaj pools are the real ones; only the server is fake. Each tenant sends requests, and a
//! request runs stages of parallel single-query transactions, the way an application server
//! resolves a query. The application servers reach lokaj through their own client pools, modelled
//! on node-postgres pools with a queue: a client connection that is released while another one
//! is still being opened serves the next query. The default profile mirrors one production
//! process: 85 tenants with their measured transaction rates, ~840 transactions per second.
//!
//! ```text
//! cargo run --release --example pool_sim -- [--minutes 15] [--seed 1] [--scale 1.0]
//!     [--connect-ms 55] [--hold-ms 1.0] [--fanout 1.0] [--mid 0.025] [--wide 0.005]
//!     [--engines 2] [--max-total 400] [--max-size 25]
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lokaj::metrics::{Metrics, Reason};
use lokaj::pool::{Connector, Limits, PoolKey, Pools, Source};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, sleep_until};

/// Transactions per second of each tenant, as measured on one process.
const RATES: [f64; 85] = [
    270.89, 155.53, 55.64, 43.92, 34.77, 29.31, 24.24, 23.92, 23.39, 21.93, 16.62, 14.39, 14.39,
    13.74, 13.58, 10.26, 8.83, 7.36, 6.01, 4.31, 4.03, 3.87, 3.69, 3.06, 2.56, 2.56, 2.45, 2.44,
    2.17, 2.12, 1.98, 1.85, 1.82, 1.8, 1.4, 1.09, 0.75, 0.67, 0.67, 0.56, 0.49, 0.48, 0.46, 0.42,
    0.35, 0.31, 0.31, 0.28, 0.27, 0.25, 0.23, 0.22, 0.2, 0.17, 0.17, 0.11, 0.11, 0.09, 0.08, 0.07,
    0.07, 0.07, 0.05, 0.05, 0.04, 0.04, 0.04, 0.03, 0.02, 0.02, 0.02, 0.01, 0.01, 0.01, 0.005,
    0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005,
];

/// Measurements start after this much virtual time, once idle connections reached steady state.
const WARMUP: Duration = Duration::from_secs(120);

#[derive(Clone)]
struct Params {
    minutes: u64,
    seed: u64,
    scale: f64,
    connect_ms: f64,
    hold_ms: f64,
    fanout: f64,
    /// Share of stages with 5-12 and with 13-30 parallel queries; the rest have 1-4.
    mid: f64,
    wide: f64,
    /// Application server processes per tenant, each with its own client pool.
    engines: usize,
    max_total: usize,
    max_size: usize,
}

impl Params {
    fn parse() -> Self {
        let mut params = Params {
            minutes: 15,
            seed: 1,
            scale: 1.0,
            connect_ms: 55.0,
            hold_ms: 1.0,
            fanout: 1.0,
            mid: 0.025,
            wide: 0.005,
            engines: 2,
            max_total: 400,
            max_size: 25,
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        for pair in args.chunks(2) {
            let [name, value] = pair else {
                panic!("expected --name value pairs, got {args:?}");
            };
            match name.as_str() {
                "--minutes" => params.minutes = value.parse().expect("--minutes"),
                "--seed" => params.seed = value.parse().expect("--seed"),
                "--scale" => params.scale = value.parse().expect("--scale"),
                "--connect-ms" => params.connect_ms = value.parse().expect("--connect-ms"),
                "--hold-ms" => params.hold_ms = value.parse().expect("--hold-ms"),
                "--fanout" => params.fanout = value.parse().expect("--fanout"),
                "--mid" => params.mid = value.parse().expect("--mid"),
                "--wide" => params.wide = value.parse().expect("--wide"),
                "--engines" => params.engines = value.parse().expect("--engines"),
                "--max-total" => params.max_total = value.parse().expect("--max-total"),
                "--max-size" => params.max_size = value.parse().expect("--max-size"),
                _ => panic!("unknown argument {name}"),
            }
        }
        params
    }
}

fn lognormal(rng: &mut StdRng, median: f64, sigma: f64) -> f64 {
    // Box-Muller
    let u1: f64 = rng.random_range(f64::EPSILON..1.0);
    let u2: f64 = rng.random();
    let normal = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    median * (sigma * normal).exp()
}

/// Parallel queries in one stage of a request: mostly one, sometimes a wide fan-out.
fn stage_width(rng: &mut StdRng, params: &Params) -> usize {
    let roll: f64 = rng.random();
    let width = if roll < params.wide {
        rng.random_range(13.0..31.0)
    } else if roll < params.wide + params.mid {
        rng.random_range(5.0..13.0)
    } else if roll < 0.5 {
        rng.random_range(2.0..5.0)
    } else {
        1.0
    };
    ((width * params.fanout).round() as usize).max(1)
}

/// Mean transactions per request, for turning a tenant's rate into a request rate.
fn mean_transactions(params: &Params) -> f64 {
    let mut rng = StdRng::seed_from_u64(0);
    let n = 100_000;
    let stages = 2.5;
    let total: usize = (0..n).map(|_| stage_width(&mut rng, params)).sum();
    stages * total as f64 / n as f64
}

struct SimConn {
    expires_at: Instant,
}

struct SimConnector {
    rng: Mutex<StdRng>,
    connect_ms: f64,
    opened: AtomicUsize,
    closed: AtomicUsize,
}

impl Connector for SimConnector {
    type Conn = SimConn;
    type PoolData = ();
    type Error = &'static str;

    async fn open(&self, _: &PoolKey, _: &()) -> Result<SimConn, &'static str> {
        let (connect, lifetime) = {
            let mut rng = self.rng.lock().unwrap();
            let connect = lognormal(&mut rng, self.connect_ms, 0.8);
            let lifetime = 1800.0 + rng.random_range(0.0..1800.0);
            (connect, lifetime)
        };
        sleep(Duration::from_secs_f64(connect / 1000.0)).await;
        self.opened.fetch_add(1, Ordering::Relaxed);
        Ok(SimConn {
            expires_at: Instant::now() + Duration::from_secs_f64(lifetime),
        })
    }

    async fn revalidate(
        &self,
        _: &(),
        conn: &mut SimConn,
        _: Duration,
    ) -> Result<(), &'static str> {
        if Instant::now() >= conn.expires_at {
            Err("lifetime")
        } else {
            Ok(())
        }
    }

    fn expired(&self, _: &(), conn: &mut SimConn, idle_for: Duration) -> Option<&'static str> {
        if idle_for >= Duration::from_secs(60) {
            Some("idle_timeout")
        } else if Instant::now() >= conn.expires_at {
            Some("lifetime")
        } else {
            None
        }
    }

    fn close(&self, _: &mut SimConn) {
        self.closed.fetch_add(1, Ordering::Relaxed);
    }

    fn transient(&self, _: &&'static str) -> bool {
        false
    }
}

/// An application server's pool of client connections to lokaj: a queue served by whichever
/// connection is available first, released or newly opened.
struct ClientPool {
    state: Mutex<ClientState>,
    rng: Mutex<StdRng>,
    opened: Arc<AtomicUsize>,
}

#[derive(Default)]
struct ClientState {
    /// Idle since; the most recently used last.
    idle: Vec<Instant>,
    total: usize,
    connecting: usize,
    queue: VecDeque<oneshot::Sender<()>>,
}

impl ClientPool {
    const MAX_CONNECTIONS: usize = 100;
    const MAX_CONNECTING: usize = 10;
    const MAX_IDLE: usize = 50;
    const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

    async fn acquire(self: &Arc<Self>) {
        let rx = {
            let mut state = self.state.lock().unwrap();
            if state.idle.pop().is_some() {
                return;
            }
            let (tx, rx) = oneshot::channel();
            state.queue.push_back(tx);
            rx
        };
        self.maybe_connect();
        rx.await.expect("client pool never drops a waiter");
    }

    fn release(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        Self::available(&mut state);
    }

    fn available(state: &mut ClientState) {
        match state.queue.pop_front() {
            Some(waiter) => waiter.send(()).expect("waiter is alive"),
            None if state.idle.len() >= Self::MAX_IDLE => state.total -= 1,
            None => state.idle.push(Instant::now()),
        }
    }

    fn maybe_connect(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        if state.queue.len() <= state.connecting
            || state.total >= Self::MAX_CONNECTIONS
            || state.connecting >= Self::MAX_CONNECTING
        {
            return;
        }
        state.connecting += 1;
        state.total += 1;
        drop(state);
        // TLS and a login answered from lokaj's credential cache.
        let connect = lognormal(&mut self.rng.lock().unwrap(), 5.0, 0.5);
        let pool = self.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs_f64(connect / 1000.0)).await;
            pool.opened.fetch_add(1, Ordering::Relaxed);
            {
                let mut state = pool.state.lock().unwrap();
                state.connecting -= 1;
                Self::available(&mut state);
            }
            pool.maybe_connect();
        });
    }

    fn reap(&self) {
        let mut state = self.state.lock().unwrap();
        let before = state.idle.len();
        state
            .idle
            .retain(|since| since.elapsed() < Self::IDLE_TIMEOUT);
        state.total -= before - state.idle.len();
    }

    fn connections(&self) -> usize {
        self.state.lock().unwrap().total
    }
}

#[derive(Default)]
struct Recorder {
    /// lokaj's wait for a server connection, by where it came from.
    waits: [Vec<f64>; 3],
    /// What a query waited in total: for a client connection, then for a server connection.
    query_waits: Vec<f64>,
    /// Summed over a request's stages, the slowest query's wait of each.
    request_waits: Vec<f64>,
    errors: usize,
    servers: Vec<f64>,
    leased: Vec<f64>,
    clients: Vec<f64>,
}

impl Recorder {
    fn wait(&mut self, source: Source, ms: f64) {
        let i = match source {
            Source::Idle => 0,
            Source::Released => 1,
            Source::New => 2,
        };
        self.waits[i].push(ms);
    }
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

fn summary(values: &mut [f64]) -> String {
    values.sort_by(f64::total_cmp);
    let mean = values.iter().sum::<f64>() / values.len().max(1) as f64;
    format!(
        "n {:>7}  mean {:>7.2}  p50 {:>6.1}  p90 {:>6.1}  p99 {:>6.1}  p99.9 {:>6.1}  max {:>7.1}",
        values.len(),
        mean,
        quantile(values, 0.5),
        quantile(values, 0.9),
        quantile(values, 0.99),
        quantile(values, 0.999),
        values.last().copied().unwrap_or(0.0)
    )
}

struct Tenant {
    pool: lokaj::pool::PoolHandle<SimConnector>,
    clients: Vec<Arc<ClientPool>>,
}

/// One query: a client connection from the application's pool, then a server connection.
async fn query(
    tenant: Arc<Tenant>,
    engine: usize,
    hold: f64,
) -> (Instant, f64, Option<(Source, f64)>) {
    let asked = Instant::now();
    let client = &tenant.clients[engine];
    client.acquire().await;
    let assigned = Instant::now();
    let lease = tenant.pool.acquire(assigned + Duration::from_secs(5)).await;
    let total = asked.elapsed().as_secs_f64() * 1000.0;
    let lokaj = assigned.elapsed().as_secs_f64() * 1000.0;
    let source = lease.as_ref().ok().map(|lease| (lease.source, lokaj));
    if let Ok(lease) = lease {
        sleep(Duration::from_secs_f64(hold / 1000.0)).await;
        lease.release();
    }
    client.release();
    (asked, total, source)
}

#[tokio::main(flavor = "current_thread", start_paused = true)]
async fn main() {
    let params = Params::parse();
    let connector = SimConnector {
        rng: Mutex::new(StdRng::seed_from_u64(params.seed ^ 0x5eed)),
        connect_ms: params.connect_ms,
        opened: AtomicUsize::new(0),
        closed: AtomicUsize::new(0),
    };
    let limits = Limits {
        max_size: params.max_size,
        max_idle: params.max_size,
        max_total: params.max_total,
        max_waiters: 100,
        max_connecting: 16,
        gc_after: Duration::from_secs(300),
    };
    let metrics = Arc::new(Metrics::new());
    let pools = Pools::new(connector, limits, metrics.clone());
    let recorder = Arc::new(Mutex::new(Recorder::default()));
    let client_opens = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let measure_from = start + WARMUP;
    let end = start + Duration::from_secs(params.minutes * 60);
    let per_request = mean_transactions(&params);

    let tenants: Vec<Arc<Tenant>> = (0..RATES.len())
        .map(|index| {
            let pool = pools
                .register(PoolKey {
                    user: format!("u{index}"),
                    database: format!("d{index}"),
                    options: Vec::new(),
                })
                .expect("one variant per tenant");
            let clients = (0..params.engines)
                .map(|engine| {
                    Arc::new(ClientPool {
                        state: Mutex::default(),
                        rng: Mutex::new(StdRng::seed_from_u64(
                            params.seed ^ ((index * 64 + engine) as u64) << 8,
                        )),
                        opened: client_opens.clone(),
                    })
                })
                .collect();
            Arc::new(Tenant { pool, clients })
        })
        .collect();

    {
        let pools = pools.clone();
        let tenants = tenants.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                pools.reap();
                tenants
                    .iter()
                    .flat_map(|tenant| &tenant.clients)
                    .for_each(|client| client.reap());
            }
        });
    }
    {
        let pools = pools.clone();
        let tenants = tenants.clone();
        let recorder = recorder.clone();
        tokio::spawn(async move {
            sleep_until(measure_from).await;
            let mut ticker = tokio::time::interval(Duration::from_millis(50));
            while Instant::now() < end {
                ticker.tick().await;
                let leased: usize = pools
                    .list()
                    .iter()
                    .map(|pool| pool.stats().clients_active)
                    .sum();
                let clients: usize = tenants
                    .iter()
                    .flat_map(|tenant| &tenant.clients)
                    .map(|client| client.connections())
                    .sum();
                let mut recorder = recorder.lock().unwrap();
                recorder.servers.push(pools.open_total() as f64);
                recorder.leased.push(leased as f64);
                recorder.clients.push(clients as f64);
            }
        });
    }

    let mut generators = JoinSet::new();
    for (index, tenant) in tenants.iter().enumerate() {
        let request_rate = RATES[index] * params.scale / per_request;
        let tenant = tenant.clone();
        let recorder = recorder.clone();
        let params = params.clone();
        generators.spawn(async move {
            let mut rng =
                StdRng::seed_from_u64(params.seed.wrapping_mul(1000).wrapping_add(index as u64));
            let mut requests = JoinSet::new();
            loop {
                let gap = -rng.random_range(f64::EPSILON..1.0f64).ln() / request_rate;
                let next = Instant::now() + Duration::from_secs_f64(gap.min(3600.0));
                if next >= end {
                    break;
                }
                sleep_until(next).await;
                let engine = rng.random_range(0..params.engines);
                let stages: Vec<Vec<f64>> = (0..rng.random_range(1..=4))
                    .map(|_| {
                        (0..stage_width(&mut rng, &params))
                            .map(|_| {
                                if rng.random::<f64>() < 0.0005 {
                                    rng.random_range(50.0..1000.0)
                                } else {
                                    lognormal(&mut rng, params.hold_ms, 1.1)
                                }
                            })
                            .collect()
                    })
                    .collect();
                let tenant = tenant.clone();
                let recorder = recorder.clone();
                requests.spawn(async move {
                    let started = Instant::now();
                    let mut waited = 0.0f64;
                    for stage in stages {
                        let mut queries = JoinSet::new();
                        for hold in stage {
                            queries.spawn(query(tenant.clone(), engine, hold));
                        }
                        let mut slowest = 0.0f64;
                        while let Some(result) = queries.join_next().await {
                            let (asked, total, source) = result.expect("query task");
                            slowest = slowest.max(total);
                            if asked < measure_from {
                                continue;
                            }
                            let mut recorder = recorder.lock().unwrap();
                            recorder.query_waits.push(total);
                            match source {
                                Some((source, lokaj)) => recorder.wait(source, lokaj),
                                None => recorder.errors += 1,
                            }
                        }
                        waited += slowest;
                        // The application works on the results before the next stage.
                        sleep(Duration::from_micros(500)).await;
                    }
                    if started >= measure_from {
                        recorder.lock().unwrap().request_waits.push(waited);
                    }
                });
                while requests.try_join_next().is_some() {}
            }
            while requests.join_next().await.is_some() {}
        });
    }

    sleep_until(measure_from).await;
    let opened_before = pools.connector().opened.load(Ordering::Relaxed);
    let client_opens_before = client_opens.load(Ordering::Relaxed);
    let recycled = |reason: &'static str| {
        metrics
            .server_recycles
            .get_or_create(&Reason { reason })
            .get()
    };
    let evicted_before = recycled("evicted");
    while generators.join_next().await.is_some() {}
    let seconds = (end - measure_from).as_secs_f64();
    let opened = pools.connector().opened.load(Ordering::Relaxed) - opened_before;
    let client_opened = client_opens.load(Ordering::Relaxed) - client_opens_before;
    let evicted = recycled("evicted") - evicted_before;

    let mut recorder = recorder.lock().unwrap();
    let transactions: usize = recorder.waits.iter().map(Vec::len).sum();
    println!(
        "{} tenants x {} engines, {:.0} tx/s, {:.1} tx per request, {seconds:.0} s measured",
        RATES.len(),
        params.engines,
        transactions as f64 / seconds,
        per_request
    );
    println!(
        "server opens/s {:.2}  evictions/s {:.2}  client opens/s {:.2}  errors {}",
        opened as f64 / seconds,
        evicted as f64 / seconds,
        client_opened as f64 / seconds,
        recorder.errors
    );
    for (i, name) in ["idle", "released", "new"].iter().enumerate() {
        let share = recorder.waits[i].len() as f64 * 100.0 / transactions.max(1) as f64;
        println!(
            "lokaj wait {name:>8} ms {share:6.2} %  {}",
            summary(&mut recorder.waits[i])
        );
    }
    let mut all: Vec<f64> = recorder.waits.iter().flatten().copied().collect();
    println!("lokaj wait      all ms           {}", summary(&mut all));
    println!(
        "query wait          ms           {}",
        summary(&mut recorder.query_waits)
    );
    println!(
        "request wait        ms           {}",
        summary(&mut recorder.request_waits)
    );
    println!(
        "servers open                     {}",
        summary(&mut recorder.servers)
    );
    println!(
        "servers leased                   {}",
        summary(&mut recorder.leased)
    );
    println!(
        "client connections               {}",
        summary(&mut recorder.clients)
    );
}
