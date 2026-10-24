//! Configuration, parsed and validated once at startup from a TOML file.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address for PostgreSQL clients.
    pub listen: SocketAddr,
    /// Address for `/metrics`, `/healthz`, `/readyz` and `/pools`.
    pub admin_listen: SocketAddr,
    pub tls: TlsConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub pool: PoolConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub client: ClientConfig,
    /// How long a drain may take before remaining clients are dropped.
    #[serde(default = "defaults::shutdown_timeout", with = "humantime_serde")]
    pub shutdown_timeout: Duration,
}

/// Client-facing TLS. Clients send the password in cleartext, so TLS is mandatory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Host name of the server (a reader endpoint), resolved for every new connection. Server
    /// certificates are verified against this name.
    pub host: String,
    /// CA certificates (PEM) that server certificates must chain to. Server connections always
    /// use TLS: they carry the SCRAM exchange, and an unverified server could plant credentials.
    pub ca: PathBuf,
    #[serde(default = "defaults::port")]
    pub port: u16,
    /// `application_name` of server connections.
    #[serde(default = "defaults::application_name")]
    pub application_name: String,
    #[serde(default = "defaults::connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Idle server connections are closed after this long.
    #[serde(default = "defaults::idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Server connections are recycled after `lifetime` plus a random part of `lifetime_jitter`.
    #[serde(default = "defaults::lifetime", with = "humantime_serde")]
    pub lifetime: Duration,
    #[serde(default = "defaults::lifetime_jitter", with = "humantime_serde")]
    pub lifetime_jitter: Duration,
    /// An idle connection is health-checked with a round trip before reuse after this long.
    #[serde(default = "defaults::check_after", with = "humantime_serde")]
    pub check_after: Duration,
    #[serde(default = "defaults::check_timeout", with = "humantime_serde")]
    pub check_timeout: Duration,
    #[serde(default = "defaults::cancel_timeout", with = "humantime_serde")]
    pub cancel_timeout: Duration,
    /// TCP keepalive starts after this long idle. Sent data unacknowledged for this plus 30 s
    /// closes the connection too. Applies to client connections as well.
    #[serde(default = "defaults::keepalive_time", with = "humantime_serde")]
    pub keepalive_time: Duration,
    /// How long a DNS answer is reused for new connections.
    #[serde(default = "defaults::dns_cache_ttl", with = "humantime_serde")]
    pub dns_cache_ttl: Duration,
    #[serde(default = "defaults::dns_refresh_interval", with = "humantime_serde")]
    pub dns_refresh_interval: Duration,
    /// An address absent from every DNS answer for this long is treated as gone and its server
    /// connections are recycled. It spans several answers because a reader endpoint returns
    /// one reader per lookup.
    #[serde(default = "defaults::dns_forget_after", with = "humantime_serde")]
    pub dns_forget_after: Duration,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// Maximum server connections per pool. A pool serves one `(user, database)` and set of
    /// startup options; one database can have at most two such pools at a time.
    #[serde(default = "defaults::max_size")]
    pub max_size: usize,
    /// Maximum server connections across all pools.
    #[serde(default = "defaults::max_total")]
    pub max_total: usize,
    /// Maximum clients waiting for a server connection per pool.
    #[serde(default = "defaults::max_waiters")]
    pub max_waiters: usize,
    #[serde(default = "defaults::wait_timeout", with = "humantime_serde")]
    pub wait_timeout: Duration,
    /// An empty pool without clients is dropped after this long.
    #[serde(default = "defaults::gc_after", with = "humantime_serde")]
    pub gc_after: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: defaults::max_size(),
            max_total: defaults::max_total(),
            max_waiters: defaults::max_waiters(),
            wait_timeout: defaults::wait_timeout(),
            gc_after: defaults::gc_after(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// A cached credential is verified against the server again after this long without a
    /// successful server login.
    #[serde(default = "defaults::verify_ttl", with = "humantime_serde")]
    pub verify_ttl: Duration,
    /// Failed logins allowed per user and client address within `failure_window`, and failed
    /// server verifications per user across all addresses.
    #[serde(default = "defaults::max_failures")]
    pub max_failures: usize,
    #[serde(default = "defaults::failure_window", with = "humantime_serde")]
    pub failure_window: Duration,
    /// Password verifications against the server at once. They happen before the client is
    /// known, so they have their own budget outside the pools.
    #[serde(default = "defaults::max_verifications")]
    pub max_verifications: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            verify_ttl: defaults::verify_ttl(),
            max_failures: defaults::max_failures(),
            failure_window: defaults::failure_window(),
            max_verifications: defaults::max_verifications(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default = "defaults::max_clients")]
    pub max_clients: usize,
    /// Time allowed from accept until the client is authenticated.
    #[serde(default = "defaults::login_timeout", with = "humantime_serde")]
    pub login_timeout: Duration,
    /// Largest frontend message accepted, in bytes.
    #[serde(default = "defaults::max_message_size")]
    pub max_message_size: usize,
    /// How long a client may hold a server connection while the server waits for it: idle in
    /// a transaction or in an unfinished extended-protocol batch.
    #[serde(
        default = "defaults::idle_transaction_timeout",
        with = "humantime_serde"
    )]
    pub idle_transaction_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_clients: defaults::max_clients(),
            login_timeout: defaults::login_timeout(),
            max_message_size: defaults::max_message_size(),
            idle_transaction_timeout: defaults::idle_transaction_timeout(),
        }
    }
}

mod defaults {
    use std::time::Duration;

    pub fn shutdown_timeout() -> Duration {
        Duration::from_secs(55)
    }
    pub fn port() -> u16 {
        5432
    }
    pub fn application_name() -> String {
        "lokaj".into()
    }
    pub fn connect_timeout() -> Duration {
        Duration::from_secs(5)
    }
    pub fn idle_timeout() -> Duration {
        Duration::from_secs(60)
    }
    pub fn lifetime() -> Duration {
        Duration::from_secs(30 * 60)
    }
    pub fn lifetime_jitter() -> Duration {
        Duration::from_secs(30 * 60)
    }
    pub fn check_after() -> Duration {
        Duration::from_secs(30)
    }
    pub fn check_timeout() -> Duration {
        Duration::from_secs(2)
    }
    pub fn cancel_timeout() -> Duration {
        Duration::from_secs(5)
    }
    pub fn keepalive_time() -> Duration {
        Duration::from_secs(30)
    }
    pub fn dns_cache_ttl() -> Duration {
        Duration::from_secs(1)
    }
    pub fn dns_refresh_interval() -> Duration {
        Duration::from_secs(1)
    }
    pub fn dns_forget_after() -> Duration {
        Duration::from_secs(15)
    }
    pub fn max_size() -> usize {
        10
    }
    pub fn max_total() -> usize {
        300
    }
    pub fn max_waiters() -> usize {
        100
    }
    pub fn wait_timeout() -> Duration {
        Duration::from_secs(5)
    }
    pub fn gc_after() -> Duration {
        Duration::from_secs(5 * 60)
    }
    pub fn verify_ttl() -> Duration {
        Duration::from_secs(10 * 60)
    }
    pub fn max_failures() -> usize {
        5
    }
    pub fn failure_window() -> Duration {
        Duration::from_secs(60)
    }
    pub fn max_verifications() -> usize {
        16
    }
    pub fn max_clients() -> usize {
        5000
    }
    pub fn login_timeout() -> Duration {
        Duration::from_secs(15)
    }
    pub fn max_message_size() -> usize {
        64 << 20
    }
    pub fn idle_transaction_timeout() -> Duration {
        Duration::from_secs(60)
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: &str| Err(ConfigError::Invalid(msg.to_owned()));
        if self.server.host.is_empty() {
            return invalid("server.host must not be empty");
        }
        if self.pool.max_size == 0 || self.pool.max_total == 0 {
            return invalid("pool.max_size and pool.max_total must be positive");
        }
        if self.pool.max_size > self.pool.max_total {
            return invalid("pool.max_size must not exceed pool.max_total");
        }
        if self.pool.wait_timeout.is_zero() || self.server.connect_timeout.is_zero() {
            return invalid("pool.wait_timeout and server.connect_timeout must be positive");
        }
        if self.server.lifetime.is_zero() || self.server.idle_timeout.is_zero() {
            return invalid("server.lifetime and server.idle_timeout must be positive");
        }
        if self.server.dns_refresh_interval.is_zero()
            || self.server.dns_forget_after < self.server.dns_refresh_interval
        {
            return invalid(
                "server.dns_forget_after must be at least server.dns_refresh_interval, which must be positive",
            );
        }
        if self.auth.max_failures == 0 || self.auth.max_verifications == 0 {
            return invalid("auth.max_failures and auth.max_verifications must be positive");
        }
        if self.client.idle_transaction_timeout.is_zero() {
            return invalid("client.idle_transaction_timeout must be positive");
        }
        if self.client.max_clients == 0 || self.client.max_message_size < 1024 {
            return invalid(
                "client.max_clients must be positive and client.max_message_size at least 1024",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        listen = "127.0.0.1:6432"
        admin_listen = "127.0.0.1:9930"
        [tls]
        cert = "cert.pem"
        key = "key.pem"
        [server]
        host = "db.internal"
        ca = "ca.pem"
    "#;

    #[test]
    fn minimal_config_uses_defaults() {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!(config.server.port, 5432);
        assert_eq!(config.pool.max_size, 10);
        assert_eq!(config.pool.wait_timeout, Duration::from_secs(5));
    }

    #[test]
    fn durations_are_human_readable() {
        let config =
            Config::parse(&MINIMAL.replace("host = ", "idle_timeout = \"90s\"\n        host = "))
                .unwrap();
        assert_eq!(config.server.idle_timeout, Duration::from_secs(90));
    }

    #[test]
    fn example_config_is_valid() {
        let config = Config::parse(include_str!("../lokaj.example.toml")).unwrap();
        assert_eq!(config.server.dns_forget_after, Duration::from_secs(15));
        assert_eq!(config.client.max_message_size, defaults::max_message_size());
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_limits() {
        assert!(Config::parse(&format!("{MINIMAL}\n[pool]\nmax_size = 0\n")).is_err());
        assert!(Config::parse(&format!("{MINIMAL}\n[pool]\nmax_sise = 5\n")).is_err());
    }
}
