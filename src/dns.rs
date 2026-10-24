//! Resolution of the server host: a short-lived cache for new connections, and the set of
//! addresses still present in recent answers, used to recycle connections to addresses that
//! dropped out (failover, reader reboot, the reader endpoint falling back to the writer).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use crate::metrics::Metrics;

pub struct Resolver {
    host: String,
    port: u16,
    literal: Option<IpAddr>,
    cache_ttl: Duration,
    forget_after: Duration,
    state: Mutex<State>,
    metrics: Arc<Metrics>,
}

#[derive(Default)]
struct State {
    cached: Option<(Instant, Vec<SocketAddr>)>,
    /// When each address was last part of a successful answer.
    seen: HashMap<IpAddr, Instant>,
    last_success: Option<Instant>,
}

impl Resolver {
    pub fn new(
        host: &str,
        port: u16,
        cache_ttl: Duration,
        forget_after: Duration,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            host: host.to_owned(),
            port,
            literal: host.parse().ok(),
            cache_ttl,
            forget_after,
            state: Mutex::new(State::default()),
            metrics,
        }
    }

    /// Addresses for a new server connection.
    pub async fn resolve(&self) -> io::Result<Vec<SocketAddr>> {
        if let Some(ip) = self.literal {
            return Ok(vec![SocketAddr::new(ip, self.port)]);
        }
        let stale = {
            let state = self.state.lock().expect("dns state poisoned");
            match &state.cached {
                Some((at, addrs)) if at.elapsed() < self.cache_ttl => return Ok(addrs.clone()),
                Some((_, addrs)) => Some(addrs.clone()),
                None => None,
            }
        };
        match self.lookup().await {
            Ok(addrs) => Ok(addrs),
            Err(error) => match stale {
                Some(addrs) => {
                    tracing::warn!(host = %self.host, %error, "DNS lookup failed, using the previous answer");
                    Ok(addrs)
                }
                None => Err(error),
            },
        }
    }

    /// Whether `ip` appeared in a successful answer within `forget_after` of the latest one.
    /// Measured against the latest success, so a DNS outage does not age out every address.
    pub fn is_current(&self, ip: IpAddr) -> bool {
        if let Some(literal) = self.literal {
            return literal == ip;
        }
        let state = self.state.lock().expect("dns state poisoned");
        match (state.seen.get(&ip), state.last_success) {
            (Some(seen), Some(last)) => last.duration_since(*seen) < self.forget_after,
            // Nothing resolved yet: connections only exist after a successful lookup.
            _ => false,
        }
    }

    async fn lookup(&self) -> io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await?
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "DNS answer is empty",
            ));
        }
        let now = Instant::now();
        let mut state = self.state.lock().expect("dns state poisoned");
        let mut changed = false;
        for addr in &addrs {
            changed |= state.seen.insert(addr.ip(), now).is_none();
        }
        let forget_after = self.forget_after;
        let before = state.seen.len();
        state
            .seen
            .retain(|_, seen| now.duration_since(*seen) < forget_after);
        changed |= state.seen.len() != before;
        state.last_success = Some(now);
        state.cached = Some((now, addrs.clone()));
        drop(state);
        if changed {
            self.metrics.dns_changes.inc();
            tracing::info!(host = %self.host, addresses = ?addrs, "server addresses changed");
        }
        Ok(addrs)
    }

    /// Refreshes the answer periodically so dropped addresses are noticed without new connections.
    pub async fn refresh_loop(self: Arc<Self>, interval: Duration) {
        if self.literal.is_some() {
            return;
        }
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = self.lookup().await {
                tracing::warn!(host = %self.host, %error, "DNS refresh failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(host: &str) -> Resolver {
        Resolver::new(
            host,
            5432,
            Duration::from_secs(1),
            Duration::from_secs(15),
            Arc::new(Metrics::new()),
        )
    }

    #[tokio::test]
    async fn literal_addresses_skip_dns() {
        let resolver = resolver("127.0.0.1");
        assert_eq!(
            resolver.resolve().await.unwrap(),
            vec!["127.0.0.1:5432".parse().unwrap()]
        );
        assert!(resolver.is_current("127.0.0.1".parse().unwrap()));
        assert!(!resolver.is_current("127.0.0.2".parse().unwrap()));
    }

    #[tokio::test(start_paused = true)]
    async fn addresses_age_out_relative_to_the_latest_answer() {
        let resolver = resolver("localhost");
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let start = Instant::now();
        {
            let mut state = resolver.state.lock().unwrap();
            state.seen.insert(a, start);
            state.seen.insert(b, start + Duration::from_secs(20));
            state.last_success = Some(start + Duration::from_secs(20));
        }
        assert!(!resolver.is_current(a));
        assert!(resolver.is_current(b));
    }
}
