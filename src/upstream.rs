//! The production [`Connector`]: server connections opened with the SCRAM keys of a verified
//! credential, and the checks that decide whether a connection may be reused.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::auth::{AuthCache, CredKey};
use crate::dns::Resolver;
use crate::metrics::Metrics;
use crate::pool::{Connector, PoolKey};
use crate::scram::Secret;
use crate::server::{ConnectError, Connected, ServerConn, ServerSettings};

pub struct Upstream {
    pub settings: ServerSettings,
    pub dns: Arc<Resolver>,
    pub auth: Arc<AuthCache>,
    pub metrics: Arc<Metrics>,
    pub idle_timeout: Duration,
    pub check_after: Duration,
    pub check_timeout: Duration,
}

/// The server parameters a pool's clients are told at login. A connection reporting different
/// ones starts a new generation, which retires all older connections of the pool.
#[derive(Default)]
pub struct Snapshot {
    /// Generation and parameters.
    inner: Mutex<(u64, Option<ServerParams>)>,
}

pub type ServerParams = Arc<BTreeMap<String, String>>;

impl Snapshot {
    pub fn current(&self) -> Option<ServerParams> {
        self.inner.lock().expect("snapshot poisoned").1.clone()
    }

    /// Records the parameters of a newly opened connection.
    pub fn observe(&self, conn: &mut ServerConn) {
        let mut inner = self.inner.lock().expect("snapshot poisoned");
        if inner.1.as_deref() != Some(&conn.params.values) {
            inner.0 += 1;
            inner.1 = Some(Arc::new(conn.params.values.clone()));
        }
        conn.generation = inner.0;
        conn.params.changed = false;
    }

    fn is_current(&self, conn: &ServerConn) -> bool {
        conn.generation == self.inner.lock().expect("snapshot poisoned").0
    }

    /// Whether a connection still reports exactly the snapshot, after parameter changes the
    /// server announced while a client held it.
    fn check(&self, conn: &mut ServerConn) -> Result<(), &'static str> {
        let inner = self.inner.lock().expect("snapshot poisoned");
        if conn.generation != inner.0 {
            return Err("snapshot");
        }
        if conn.params.changed {
            if inner.1.as_deref() != Some(&conn.params.values) {
                return Err("dirty");
            }
            conn.params.changed = false;
        }
        Ok(())
    }
}

impl Upstream {
    /// Why a connection a client gives back must be closed instead of pooled, if it must.
    pub fn release_check(
        &self,
        snapshot: &Snapshot,
        conn: &mut ServerConn,
    ) -> Option<&'static str> {
        if conn.expired() {
            return Some("lifetime");
        }
        if !self.dns.is_current(conn.peer().ip()) {
            return Some("dns");
        }
        snapshot.check(conn).err()
    }
}

impl Connector for Upstream {
    type Conn = ServerConn;
    type PoolData = Snapshot;
    type Error = ConnectError;

    async fn open(&self, key: &PoolKey, snapshot: &Snapshot) -> Result<ServerConn, ConnectError> {
        let cred_key = CredKey {
            user: key.user.clone(),
            database: key.database.clone(),
        };
        let Some(credential) = self.auth.get(&cred_key) else {
            self.metrics.connect_error("no_credential");
            return Err(ConnectError::NoCredential);
        };
        let secret = Secret::Keys(&credential.keys);
        match ServerConn::connect(
            &self.settings,
            &self.dns,
            &key.user,
            &key.database,
            &key.options,
            secret,
        )
        .await
        {
            Ok(Connected { mut conn, .. }) => {
                self.auth.confirm(&cred_key, &credential);
                self.metrics.server_connects.inc();
                snapshot.observe(&mut conn);
                Ok(conn)
            }
            Err(error) => {
                self.metrics.connect_error(error.reason());
                if error.is_auth_failure() {
                    tracing::warn!(user = %key.user, database = %key.database, %error, "server rejected a cached credential");
                    self.auth.invalidate(&cred_key, &credential);
                }
                Err(error)
            }
        }
    }

    async fn revalidate(
        &self,
        snapshot: &Snapshot,
        conn: &mut ServerConn,
        idle_for: Duration,
    ) -> Result<(), &'static str> {
        if let Some(reason) = self.expired(snapshot, conn, idle_for) {
            return Err(reason);
        }
        if conn.idle_disturbed() {
            return Err("server_closed");
        }
        if idle_for >= self.check_after && !conn.health_check(self.check_timeout).await {
            return Err("health_check");
        }
        Ok(())
    }

    fn expired(
        &self,
        snapshot: &Snapshot,
        conn: &ServerConn,
        idle_for: Duration,
    ) -> Option<&'static str> {
        if idle_for >= self.idle_timeout {
            Some("idle_timeout")
        } else if conn.expired() {
            Some("lifetime")
        } else if !self.dns.is_current(conn.peer().ip()) {
            Some("dns")
        } else if !snapshot.is_current(conn) {
            Some("snapshot")
        } else {
            None
        }
    }
}
