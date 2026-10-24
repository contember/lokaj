//! Prometheus metrics. Event counters live here; per-pool gauges are read from the pools at
//! scrape time so they cannot drift.

use std::collections::HashMap;

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::{ConstGauge, Gauge};
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Reason {
    pub reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Outcome {
    pub result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct WaitSource {
    pub source: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PoolLabels {
    pub user: String,
    pub database: String,
}

const WAIT_BUCKETS: [f64; 12] = [
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0,
];

fn wait_histogram() -> Histogram {
    Histogram::new(WAIT_BUCKETS)
}

pub struct Metrics {
    pub clients: Gauge,
    pub client_rejects: Family<Reason, Counter>,
    pub server_connects: Counter,
    pub server_connect_errors: Family<Reason, Counter>,
    pub server_recycles: Family<Reason, Counter>,
    pub auth_failures: Family<Reason, Counter>,
    pub credential_cache: Family<Outcome, Counter>,
    pub dns_changes: Counter,
    pub cancels: Family<Outcome, Counter>,
    pub session_errors: Family<Reason, Counter>,
    /// Across pools: per tenant it would be a dozen series for each of ~a thousand pools.
    pub pool_wait: Family<WaitSource, Histogram, fn() -> Histogram>,
    pub pool_transactions: Family<PoolLabels, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            clients: Gauge::default(),
            client_rejects: Family::default(),
            server_connects: Counter::default(),
            server_connect_errors: Family::default(),
            server_recycles: Family::default(),
            auth_failures: Family::default(),
            credential_cache: Family::default(),
            dns_changes: Counter::default(),
            cancels: Family::default(),
            session_errors: Family::default(),
            pool_wait: Family::new_with_constructor(wait_histogram),
            pool_transactions: Family::default(),
        }
    }

    pub fn client_reject(&self, reason: &'static str) {
        self.client_rejects.get_or_create(&Reason { reason }).inc();
    }

    pub fn recycle(&self, reason: &'static str) {
        self.server_recycles.get_or_create(&Reason { reason }).inc();
    }

    pub fn auth_failure(&self, reason: &'static str) {
        self.auth_failures.get_or_create(&Reason { reason }).inc();
    }

    pub fn connect_error(&self, reason: &'static str) {
        self.server_connect_errors
            .get_or_create(&Reason { reason })
            .inc();
    }

    pub fn cancel(&self, result: &'static str) {
        self.cancels.get_or_create(&Outcome { result }).inc();
    }

    pub fn session_error(&self, reason: &'static str) {
        self.session_errors.get_or_create(&Reason { reason }).inc();
    }

    pub fn credential_cache(&self, result: &'static str) {
        self.credential_cache
            .get_or_create(&Outcome { result })
            .inc();
    }

    /// Drops the series of a tenant that no longer has pools.
    pub fn forget_pool(&self, labels: &PoolLabels) {
        self.pool_transactions.remove(labels);
    }

    pub fn register(&self, registry: &mut Registry) {
        registry.register("clients", "Connected client sessions", self.clients.clone());
        registry.register(
            "client_rejects",
            "Client connections refused before login",
            self.client_rejects.clone(),
        );
        registry.register(
            "server_connects",
            "Server connections established",
            self.server_connects.clone(),
        );
        registry.register(
            "server_connect_errors",
            "Failed server connection attempts",
            self.server_connect_errors.clone(),
        );
        registry.register(
            "server_recycles",
            "Server connections closed by lokaj",
            self.server_recycles.clone(),
        );
        registry.register(
            "auth_failures",
            "Rejected client logins",
            self.auth_failures.clone(),
        );
        registry.register(
            "credential_cache",
            "Client logins by credential cache result",
            self.credential_cache.clone(),
        );
        registry.register(
            "dns_changes",
            "Changes of the server address set",
            self.dns_changes.clone(),
        );
        registry.register("cancels", "Cancel requests", self.cancels.clone());
        registry.register(
            "session_errors",
            "Client sessions lokaj ended with an error after login",
            self.session_errors.clone(),
        );
        registry.register(
            "pool_wait_seconds",
            "Time clients waited for a server connection, by where it came from",
            self.pool_wait.clone(),
        );
        registry.register(
            "pool_transactions",
            "Server connection assignments completed",
            self.pool_transactions.clone(),
        );
    }
}

#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    pub clients: usize,
    pub clients_active: usize,
    pub clients_waiting: usize,
    pub servers_active: usize,
    pub servers_idle: usize,
}

impl std::ops::AddAssign<&PoolStats> for PoolStats {
    fn add_assign(&mut self, other: &PoolStats) {
        self.clients += other.clients;
        self.clients_active += other.clients_active;
        self.clients_waiting += other.clients_waiting;
        self.servers_active += other.servers_active;
        self.servers_idle += other.servers_idle;
    }
}

#[derive(Debug, Clone, Default)]
pub struct GlobalStats {
    pub servers_max: usize,
    /// Clients waiting for a connection because `max_total` is reached.
    pub clients_waiting_permit: usize,
}

/// Source of pool gauges, read on every scrape.
pub trait PoolStatsSource: std::fmt::Debug + Send + Sync + 'static {
    fn pool_stats(&self) -> Vec<(PoolLabels, PoolStats)>;
    fn global_stats(&self) -> GlobalStats;
}

#[derive(Debug)]
pub struct PoolCollector<S>(pub S);

impl<S: PoolStatsSource> Collector for PoolCollector<S> {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        // Pools that differ only in startup options share labels; their gauges are summed.
        let mut pools: HashMap<PoolLabels, PoolStats> = HashMap::new();
        for (labels, stats) in self.0.pool_stats() {
            *pools.entry(labels).or_default() += &stats;
        }
        let total: usize = pools
            .values()
            .map(|s| s.servers_active + s.servers_idle)
            .sum();
        // Pools with nothing in them are most of them; their zeros are left out.
        pools.retain(|_, s| {
            s.clients + s.clients_active + s.clients_waiting + s.servers_active + s.servers_idle > 0
        });
        type Gauge = (&'static str, &'static str, fn(&PoolStats) -> usize);
        let gauges: [Gauge; 5] = [
            ("pool_clients", "Clients logged in to the pool", |s| {
                s.clients
            }),
            (
                "pool_clients_active",
                "Clients holding a server connection",
                |s| s.clients_active,
            ),
            (
                "pool_clients_waiting",
                "Clients waiting for a server connection",
                |s| s.clients_waiting,
            ),
            (
                "pool_servers_active",
                "Server connections in use or being opened",
                |s| s.servers_active,
            ),
            ("pool_servers_idle", "Idle server connections", |s| {
                s.servers_idle
            }),
        ];
        for (name, help, value) in gauges {
            let gauge = ConstGauge::new(0i64);
            let mut family = encoder.encode_descriptor(name, help, None, gauge.metric_type())?;
            for (labels, stats) in &pools {
                ConstGauge::new(value(stats) as i64).encode(family.encode_family(labels)?)?;
            }
        }
        let global = self.0.global_stats();
        let globals = [
            ("servers", "Open server connections", total),
            (
                "servers_max",
                "Server connections allowed across pools (pool.max_total)",
                global.servers_max,
            ),
            (
                "clients_waiting_permit",
                "Clients waiting because pool.max_total is reached",
                global.clients_waiting_permit,
            ),
        ];
        for (name, help, value) in globals {
            let gauge = ConstGauge::new(value as i64);
            gauge.encode(encoder.encode_descriptor(name, help, None, gauge.metric_type())?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Pools;

    impl PoolStatsSource for Pools {
        fn pool_stats(&self) -> Vec<(PoolLabels, PoolStats)> {
            (0..1000)
                .map(|i| {
                    let labels = PoolLabels {
                        user: format!("u{i}"),
                        database: "d".into(),
                    };
                    let stats = PoolStats {
                        servers_idle: usize::from(i < 50),
                        ..PoolStats::default()
                    };
                    (labels, stats)
                })
                .collect()
        }

        fn global_stats(&self) -> GlobalStats {
            GlobalStats {
                servers_max: 300,
                clients_waiting_permit: 2,
            }
        }
    }

    #[test]
    fn empty_pools_are_left_out_of_the_gauges() {
        let mut registry = Registry::default();
        registry.register_collector(Box::new(PoolCollector(Pools)));
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
        let samples = |name: &str| {
            text.lines()
                .filter(|line| line.starts_with(&format!("{name}{{")))
                .count()
        };
        assert_eq!(samples("pool_servers_idle"), 50);
        assert_eq!(samples("pool_clients"), 50);
        for sample in ["servers 50", "servers_max 300", "clients_waiting_permit 2"] {
            assert!(text.lines().any(|line| line == sample), "{sample} missing");
        }
    }
}
