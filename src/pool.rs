//! Pools of server connections, one per `(user, database, startup options)`.
//!
//! Every server connection is tied to the pool that opened it through its [`Slot`]: it can only
//! ever be handed to clients of that pool, and dropping it frees the slot for the pool's next
//! waiter. Connections are only opened for a waiting client, never in the background.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, sleep_until};

use crate::metrics::{Metrics, PoolLabels, PoolStats, PoolStatsSource};

pub trait Connector: Send + Sync + 'static {
    type Conn: Send + 'static;
    /// Per-pool state the connector keeps, such as the server parameter snapshot.
    type PoolData: Default + Send + Sync + 'static;
    type Error: Send + 'static;

    fn open(
        &self,
        key: &PoolKey,
        data: &Self::PoolData,
    ) -> impl Future<Output = Result<Self::Conn, Self::Error>> + Send;

    /// Prepares an idle connection for reuse; an `Err` names why it must be closed instead.
    fn revalidate(
        &self,
        data: &Self::PoolData,
        conn: &mut Self::Conn,
        idle_for: Duration,
    ) -> impl Future<Output = Result<(), &'static str>> + Send;

    /// Cheap check of an idle connection, run every second by the reaper; it must not block.
    fn expired(
        &self,
        data: &Self::PoolData,
        conn: &mut Self::Conn,
        idle_for: Duration,
    ) -> Option<&'static str>;

    /// Ends an idle connection the pool is about to drop, without waiting.
    fn close(&self, conn: &mut Self::Conn);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub user: String,
    pub database: String,
    /// Session options from the client's startup packet, sorted by name. Server connections are
    /// opened with them, so clients that differ in them cannot share connections.
    pub options: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_size: usize,
    pub max_total: usize,
    pub max_waiters: usize,
    pub gc_after: Duration,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AcquireError<E> {
    #[error("timed out waiting for a server connection")]
    TimedOut,
    #[error("too many clients waiting for a server connection")]
    TooManyWaiters,
    #[error("{0}")]
    Open(E),
}

pub struct Pools<C: Connector> {
    shared: Arc<Shared<C>>,
}

impl<C: Connector> Clone for Pools<C> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<C: Connector> std::fmt::Debug for Pools<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pools").finish_non_exhaustive()
    }
}

struct Shared<C: Connector> {
    connector: C,
    limits: Limits,
    global: Arc<Semaphore>,
    pools: Mutex<PoolMap<C>>,
    metrics: Arc<Metrics>,
}

struct PoolMap<C: Connector> {
    by_key: HashMap<PoolKey, Arc<Pool<C>>>,
    /// Pools per `(user, database)`: one per set of startup options.
    variants: HashMap<(String, String), usize>,
}

impl<C: Connector> Default for PoolMap<C> {
    fn default() -> Self {
        Self {
            by_key: HashMap::new(),
            variants: HashMap::new(),
        }
    }
}

/// Pools one `(user, database)` may have at once. Each gets `max_size` connections, so this
/// bounds what one tenant can hold while still allowing a change of options during a rollout.
pub const MAX_VARIANTS: usize = 2;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("too many different startup options for one database")]
pub struct TooManyVariants;

pub struct Pool<C: Connector> {
    key: PoolKey,
    labels: PoolLabels,
    shared: Arc<Shared<C>>,
    pub data: C::PoolData,
    state: Mutex<State<C>>,
    leased: AtomicUsize,
}

struct State<C: Connector> {
    /// Most recently used last; the oldest is at index 0.
    idle: Vec<Idle<C>>,
    /// Connections holding a slot: idle, leased or being opened.
    open: usize,
    waiters: VecDeque<oneshot::Sender<Grant<C>>>,
    clients: usize,
    last_active: Instant,
}

struct Idle<C: Connector> {
    conn: C::Conn,
    slot: Slot<C>,
    since: Instant,
}

enum Grant<C: Connector> {
    Conn(C::Conn, Slot<C>),
    Slot(Slot<C>),
}

/// The right to hold one server connection in a pool, backed by a global permit. Dropping it
/// passes it to the pool's next waiter or gives the permit back.
pub struct Slot<C: Connector> {
    pool: Arc<Pool<C>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl<C: Connector> Drop for Slot<C> {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.pool.slot_freed(permit);
        }
    }
}

/// A server connection handed to one client. Dropping the lease closes the connection;
/// [`Lease::release`] returns it to its pool.
pub struct Lease<C: Connector> {
    pool: Arc<Pool<C>>,
    inner: Option<(C::Conn, Slot<C>)>,
    /// Whether the connection was opened for this lease.
    pub fresh: bool,
}

impl<C: Connector> Lease<C> {
    pub fn conn(&self) -> &C::Conn {
        &self.inner.as_ref().expect("lease is live").0
    }

    pub fn conn_mut(&mut self) -> &mut C::Conn {
        &mut self.inner.as_mut().expect("lease is live").0
    }

    pub fn pool(&self) -> &Arc<Pool<C>> {
        &self.pool
    }

    pub fn release(mut self) {
        let (conn, slot) = self.inner.take().expect("lease is live");
        // A connection only ever returns to the pool its slot belongs to.
        slot.pool.clone().put_back(conn, slot);
    }
}

impl<C: Connector> Drop for Lease<C> {
    fn drop(&mut self) {
        self.pool.leased.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A client's membership in a pool. A pool with members is never garbage-collected.
pub struct PoolHandle<C: Connector> {
    pool: Arc<Pool<C>>,
}

impl<C: Connector> std::ops::Deref for PoolHandle<C> {
    type Target = Arc<Pool<C>>;
    fn deref(&self) -> &Arc<Pool<C>> {
        &self.pool
    }
}

impl<C: Connector> Drop for PoolHandle<C> {
    fn drop(&mut self) {
        let mut state = self.pool.lock();
        state.clients -= 1;
        state.last_active = Instant::now();
    }
}

enum Obtained<C: Connector> {
    Idle(Idle<C>),
    Slot(Slot<C>),
    Granted(C::Conn, Slot<C>),
}

enum Step<C: Connector> {
    Got(Obtained<C>),
    NeedPermit(oneshot::Receiver<Grant<C>>),
    Wait(oneshot::Receiver<Grant<C>>),
}

// Locking: the pool map before a pool's state; a pool's state is never held while another
// pool's state is locked, while awaiting, or while a `Slot` is dropped (its drop locks it).
impl<C: Connector> Pool<C> {
    fn lock(&self) -> MutexGuard<'_, State<C>> {
        self.state.lock().expect("pool state poisoned")
    }

    pub fn key(&self) -> &PoolKey {
        &self.key
    }

    pub fn labels(&self) -> &PoolLabels {
        &self.labels
    }

    fn lease(self: &Arc<Self>, conn: C::Conn, slot: Slot<C>, fresh: bool) -> Lease<C> {
        self.leased.fetch_add(1, Ordering::Relaxed);
        Lease {
            pool: self.clone(),
            inner: Some((conn, slot)),
            fresh,
        }
    }

    /// Takes over `conn`, opened outside the pool, if a slot is free right now. It never waits
    /// and never closes another connection to make room.
    pub fn try_adopt(self: &Arc<Self>, conn: C::Conn) -> Option<Lease<C>> {
        let slot = {
            let mut state = self.lock();
            if state.open >= self.shared.limits.max_size {
                return None;
            }
            let permit = self.shared.global.clone().try_acquire_owned().ok()?;
            state.open += 1;
            Slot {
                pool: self.clone(),
                permit: Some(permit),
            }
        };
        Some(self.lease(conn, slot, true))
    }

    fn slot_freed(self: &Arc<Self>, mut permit: OwnedSemaphorePermit) {
        loop {
            let waiter = {
                let mut state = self.lock();
                match state.waiters.pop_front() {
                    Some(waiter) => waiter,
                    None => {
                        state.open -= 1;
                        return;
                    }
                }
            };
            let slot = Slot {
                pool: self.clone(),
                permit: Some(permit),
            };
            match waiter.send(Grant::Slot(slot)) {
                Ok(()) => return,
                Err(grant) => {
                    permit = grant
                        .into_slot()
                        .permit
                        .take()
                        .expect("unsent slot keeps its permit")
                }
            }
        }
    }

    fn put_back(self: &Arc<Self>, mut conn: C::Conn, mut slot: Slot<C>) {
        loop {
            let waiter = {
                let mut state = self.lock();
                state.last_active = Instant::now();
                match state.waiters.pop_front() {
                    Some(waiter) => waiter,
                    None => {
                        state.idle.push(Idle {
                            conn,
                            slot,
                            since: Instant::now(),
                        });
                        return;
                    }
                }
            };
            match waiter.send(Grant::Conn(conn, slot)) {
                Ok(()) => return,
                Err(grant) => (conn, slot) = grant.into_conn(),
            }
        }
    }

    fn enqueue(
        &self,
        state: &mut State<C>,
    ) -> Result<oneshot::Receiver<Grant<C>>, AcquireError<C::Error>> {
        state.waiters.retain(|waiter| !waiter.is_closed());
        if state.waiters.len() >= self.shared.limits.max_waiters {
            return Err(AcquireError::TooManyWaiters);
        }
        let (tx, rx) = oneshot::channel();
        state.waiters.push_back(tx);
        Ok(rx)
    }

    async fn obtain(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<Obtained<C>, AcquireError<C::Error>> {
        let max_size = self.shared.limits.max_size;
        loop {
            let step = {
                let mut state = self.lock();
                state.last_active = Instant::now();
                if let Some(idle) = state.idle.pop() {
                    Step::Got(Obtained::Idle(idle))
                } else if state.open < max_size
                    && let Ok(permit) = self.shared.global.clone().try_acquire_owned()
                {
                    state.open += 1;
                    Step::Got(Obtained::Slot(Slot {
                        pool: self.clone(),
                        permit: Some(permit),
                    }))
                } else if state.open < max_size {
                    Step::NeedPermit(self.enqueue(&mut state)?)
                } else {
                    Step::Wait(self.enqueue(&mut state)?)
                }
            };
            let rx = match step {
                Step::Got(obtained) => return Ok(obtained),
                Step::Wait(rx) => rx,
                Step::NeedPermit(mut rx) => {
                    // The global limit is reached: close the oldest idle connection of another
                    // pool, or wait for a permit while staying first in line for our own pool.
                    if self.shared.evict_idle(&self.key) {
                        continue;
                    }
                    tokio::select! {
                        biased;
                        grant = &mut rx => match grant {
                            Ok(grant) => return Ok(grant.into_obtained()),
                            Err(_) => continue,
                        },
                        permit = self.shared.global.clone().acquire_owned() => {
                            let permit = permit.expect("global semaphore is never closed");
                            let mut state = self.lock();
                            if state.open < max_size {
                                state.open += 1;
                                drop(state);
                                return Ok(Obtained::Slot(Slot { pool: self.clone(), permit: Some(permit) }));
                            }
                            continue;
                        }
                        () = sleep_until(deadline) => return Err(AcquireError::TimedOut),
                    }
                }
            };
            tokio::select! {
                grant = rx => match grant {
                    Ok(grant) => return Ok(grant.into_obtained()),
                    Err(_) => continue,
                },
                () = sleep_until(deadline) => return Err(AcquireError::TimedOut),
            }
        }
    }

    /// A connection for one client: an idle one that passes revalidation, one released by
    /// another client, or a new one.
    pub async fn acquire(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<Lease<C>, AcquireError<C::Error>> {
        loop {
            match self.obtain(deadline).await? {
                Obtained::Idle(Idle {
                    mut conn,
                    slot,
                    since,
                }) => {
                    match self
                        .shared
                        .connector
                        .revalidate(&self.data, &mut conn, since.elapsed())
                        .await
                    {
                        Ok(()) => return Ok(self.lease(conn, slot, false)),
                        Err(reason) => {
                            self.shared.metrics.recycle(reason);
                            self.shared.connector.close(&mut conn);
                            drop((conn, slot));
                        }
                    }
                }
                Obtained::Granted(conn, slot) => return Ok(self.lease(conn, slot, false)),
                Obtained::Slot(slot) => {
                    let conn = self
                        .shared
                        .connector
                        .open(&self.key, &self.data)
                        .await
                        .map_err(AcquireError::Open)?;
                    return Ok(self.lease(conn, slot, true));
                }
            }
        }
    }

    pub fn stats(&self) -> PoolStats {
        let state = self.lock();
        PoolStats {
            clients: state.clients,
            clients_active: self.leased.load(Ordering::Relaxed),
            clients_waiting: state.waiters.iter().filter(|w| !w.is_closed()).count(),
            servers_active: state.open - state.idle.len(),
            servers_idle: state.idle.len(),
        }
    }
}

impl<C: Connector> Grant<C> {
    fn into_slot(self) -> Slot<C> {
        match self {
            Grant::Slot(slot) => slot,
            Grant::Conn(..) => unreachable!("a failed send returns what was sent"),
        }
    }

    fn into_conn(self) -> (C::Conn, Slot<C>) {
        match self {
            Grant::Conn(conn, slot) => (conn, slot),
            Grant::Slot(_) => unreachable!("a failed send returns what was sent"),
        }
    }

    fn into_obtained(self) -> Obtained<C> {
        match self {
            Grant::Conn(conn, slot) => Obtained::Granted(conn, slot),
            Grant::Slot(slot) => Obtained::Slot(slot),
        }
    }
}

impl<C: Connector> Shared<C> {
    fn list(&self) -> Vec<Arc<Pool<C>>> {
        self.pools
            .lock()
            .expect("pool map poisoned")
            .by_key
            .values()
            .cloned()
            .collect()
    }

    fn evict_idle(&self, except: &PoolKey) -> bool {
        let mut oldest: Option<(Arc<Pool<C>>, Instant)> = None;
        for pool in self.list() {
            if pool.key == *except {
                continue;
            }
            let since = pool.lock().idle.first().map(|idle| idle.since);
            if let Some(since) = since
                && oldest.as_ref().is_none_or(|(_, t)| since < *t)
            {
                oldest = Some((pool, since));
            }
        }
        let Some((pool, _)) = oldest else {
            return false;
        };
        let victim = {
            let mut state = pool.lock();
            (!state.idle.is_empty()).then(|| state.idle.remove(0))
        };
        match victim {
            Some(mut victim) => {
                self.metrics.recycle("evicted");
                self.connector.close(&mut victim.conn);
                drop(victim);
                true
            }
            None => false,
        }
    }
}

impl<C: Connector> Pools<C> {
    pub fn new(connector: C, limits: Limits, metrics: Arc<Metrics>) -> Self {
        let global = Arc::new(Semaphore::new(limits.max_total));
        Self {
            shared: Arc::new(Shared {
                connector,
                limits,
                global,
                pools: Mutex::default(),
                metrics,
            }),
        }
    }

    pub fn connector(&self) -> &C {
        &self.shared.connector
    }

    /// Joins a client to the pool for `key`, creating the pool on first use, unless its
    /// `(user, database)` already has [`MAX_VARIANTS`] pools with other options.
    pub fn register(&self, key: PoolKey) -> Result<PoolHandle<C>, TooManyVariants> {
        let mut guard = self.shared.pools.lock().expect("pool map poisoned");
        let map = &mut *guard;
        if !map.by_key.contains_key(&key) {
            let variants = map
                .variants
                .entry((key.user.clone(), key.database.clone()))
                .or_default();
            if *variants >= MAX_VARIANTS {
                return Err(TooManyVariants);
            }
            *variants += 1;
        }
        let pool = map
            .by_key
            .entry(key)
            .or_insert_with_key(|key| {
                Arc::new(Pool {
                    key: key.clone(),
                    labels: PoolLabels {
                        user: key.user.clone(),
                        database: key.database.clone(),
                    },
                    shared: self.shared.clone(),
                    data: C::PoolData::default(),
                    state: Mutex::new(State {
                        idle: Vec::new(),
                        open: 0,
                        waiters: VecDeque::new(),
                        clients: 0,
                        last_active: Instant::now(),
                    }),
                    leased: AtomicUsize::new(0),
                })
            })
            .clone();
        pool.lock().clients += 1;
        Ok(PoolHandle { pool })
    }

    pub fn list(&self) -> Vec<Arc<Pool<C>>> {
        self.shared.list()
    }

    /// Closes idle connections that expired and drops unused empty pools.
    pub fn reap(&self) {
        for pool in self.shared.list() {
            let expired: Vec<(Idle<C>, &'static str)> = {
                let mut state = pool.lock();
                let mut expired = Vec::new();
                let mut i = 0;
                while i < state.idle.len() {
                    let idle = &mut state.idle[i];
                    match self.shared.connector.expired(
                        &pool.data,
                        &mut idle.conn,
                        idle.since.elapsed(),
                    ) {
                        Some(reason) => expired.push((state.idle.remove(i), reason)),
                        None => i += 1,
                    }
                }
                expired
            };
            for (mut idle, reason) in expired {
                self.shared.metrics.recycle(reason);
                self.shared.connector.close(&mut idle.conn);
                drop(idle);
            }
        }
        let gc_after = self.shared.limits.gc_after;
        let removed: Vec<Arc<Pool<C>>> = {
            let mut guard = self.shared.pools.lock().expect("pool map poisoned");
            let map = &mut *guard;
            let mut removed = Vec::new();
            map.by_key.retain(|_, pool| {
                let state = pool.lock();
                let unused = state.clients == 0
                    && state.open == 0
                    && state.waiters.is_empty()
                    && state.last_active.elapsed() >= gc_after;
                if unused {
                    removed.push(pool.clone());
                }
                !unused
            });
            for pool in &removed {
                let tenant = (pool.key.user.clone(), pool.key.database.clone());
                if let Some(variants) = map.variants.get_mut(&tenant) {
                    *variants -= 1;
                    if *variants == 0 {
                        map.variants.remove(&tenant);
                    }
                }
            }
            removed
        };
        for pool in removed {
            self.shared.metrics.forget_pool(&pool.labels);
        }
    }

    /// Server connections currently open across all pools.
    pub fn open_total(&self) -> usize {
        self.shared.limits.max_total - self.shared.global.available_permits()
    }
}

impl<C: Connector> PoolStatsSource for Pools<C> {
    fn pool_stats(&self) -> Vec<(PoolLabels, PoolStats)> {
        self.list()
            .iter()
            .map(|pool| (pool.labels.clone(), pool.stats()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::atomic::AtomicU64;

    #[derive(Debug)]
    struct FakeConn {
        id: u64,
        key: PoolKey,
        broken: bool,
        closed: bool,
    }

    #[derive(Default)]
    struct FakeConnector {
        next_id: AtomicU64,
        opened: AtomicUsize,
        closed: AtomicUsize,
    }

    impl Connector for FakeConnector {
        type Conn = FakeConn;
        type PoolData = ();
        type Error = &'static str;

        async fn open(&self, key: &PoolKey, _: &()) -> Result<FakeConn, &'static str> {
            tokio::task::yield_now().await;
            if key.user == "down" {
                return Err("server down");
            }
            self.opened.fetch_add(1, Ordering::SeqCst);
            Ok(FakeConn {
                id: self.next_id.fetch_add(1, Ordering::SeqCst),
                key: key.clone(),
                broken: false,
                closed: false,
            })
        }

        async fn revalidate(
            &self,
            _: &(),
            conn: &mut FakeConn,
            _: Duration,
        ) -> Result<(), &'static str> {
            if conn.broken { Err("broken") } else { Ok(()) }
        }

        fn expired(&self, _: &(), conn: &mut FakeConn, idle_for: Duration) -> Option<&'static str> {
            if conn.broken {
                Some("broken")
            } else {
                (idle_for >= Duration::from_secs(60)).then_some("idle_timeout")
            }
        }

        fn close(&self, conn: &mut FakeConn) {
            conn.closed = true;
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn key(user: &str) -> PoolKey {
        PoolKey {
            user: user.into(),
            database: "db".into(),
            options: Vec::new(),
        }
    }

    fn pools(max_size: usize, max_total: usize) -> Pools<FakeConnector> {
        let limits = Limits {
            max_size,
            max_total,
            max_waiters: 4,
            gc_after: Duration::from_secs(300),
        };
        Pools::new(FakeConnector::default(), limits, Arc::new(Metrics::new()))
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[tokio::test(start_paused = true)]
    async fn reuses_released_connections() {
        let pools = pools(2, 10);
        let pool = pools.register(key("a")).unwrap();
        let lease = pool.acquire(deadline()).await.unwrap();
        let id = lease.conn().id;
        assert!(lease.fresh);
        lease.release();
        let lease = pool.acquire(deadline()).await.unwrap();
        assert_eq!(lease.conn().id, id);
        assert!(!lease.fresh);
        assert_eq!(pools.connector().opened.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn waiter_gets_the_released_connection_and_times_out_otherwise() {
        let pools = pools(1, 10);
        let pool = pools.register(key("a")).unwrap();
        let held = pool.acquire(deadline()).await.unwrap();
        let held_id = held.conn().id;
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire(deadline()).await.map(|l| l.conn().id) })
        };
        tokio::task::yield_now().await;
        held.release();
        assert_eq!(waiter.await.unwrap(), Ok(held_id));

        let _held = pool.acquire(deadline()).await.unwrap();
        assert!(matches!(
            pool.acquire(deadline()).await,
            Err(AcquireError::TimedOut)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn discarding_a_lease_lets_a_waiter_open_a_new_connection() {
        let pools = pools(1, 10);
        let pool = pools.register(key("a")).unwrap();
        let held = pool.acquire(deadline()).await.unwrap();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire(deadline()).await.map(|l| l.fresh) })
        };
        tokio::task::yield_now().await;
        drop(held);
        assert_eq!(waiter.await.unwrap(), Ok(true));
    }

    #[tokio::test(start_paused = true)]
    async fn global_limit_evicts_idle_connections_of_other_pools() {
        let pools = pools(2, 2);
        let a = pools.register(key("a")).unwrap();
        let b = pools.register(key("b")).unwrap();
        a.acquire(deadline()).await.unwrap().release();
        a.acquire(deadline()).await.unwrap().release();
        assert_eq!(pools.open_total(), 1);
        let held = a.acquire(deadline()).await.unwrap();
        let second = a.acquire(deadline()).await.unwrap();
        second.release();
        assert_eq!(pools.open_total(), 2);
        let lease = b.acquire(deadline()).await.unwrap();
        assert_eq!(lease.conn().key, key("b"));
        assert_eq!(a.stats().servers_idle, 0);
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_over_the_limit_are_refused() {
        let pools = pools(1, 10);
        let pool = pools.register(key("a")).unwrap();
        let _held = pool.acquire(deadline()).await.unwrap();
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { pool.acquire(deadline()).await.is_ok() })
            })
            .collect();
        tokio::task::yield_now().await;
        assert!(matches!(
            pool.acquire(deadline()).await,
            Err(AcquireError::TooManyWaiters)
        ));
        drop(waiters);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_open_frees_the_slot() {
        let pools = pools(1, 1);
        let pool = pools.register(key("down")).unwrap();
        assert!(matches!(
            pool.acquire(deadline()).await,
            Err(AcquireError::Open("server down"))
        ));
        assert_eq!(pools.open_total(), 0);
        assert_eq!(pool.stats().servers_active, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_closes_idle_connections_and_collects_unused_pools() {
        let pools = pools(2, 10);
        let pool = pools.register(key("a")).unwrap();
        pool.acquire(deadline()).await.unwrap().release();
        tokio::time::advance(Duration::from_secs(61)).await;
        pools.reap();
        assert_eq!(pool.stats().servers_idle, 0);
        assert_eq!(pools.connector().closed.load(Ordering::SeqCst), 1);
        drop(pool);
        tokio::time::advance(Duration::from_secs(301)).await;
        pools.reap();
        assert!(pools.list().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_closes_idle_connections_the_server_closed() {
        let pools = pools(2, 10);
        let pool = pools.register(key("a")).unwrap();
        let mut lease = pool.acquire(deadline()).await.unwrap();
        lease.conn_mut().broken = true;
        lease.release();
        pools.reap();
        assert_eq!(pool.stats().servers_idle, 0);
        assert_eq!(pools.open_total(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_outside_connection_joins_only_a_free_slot() {
        let pools = pools(1, 10);
        let pool = pools.register(key("a")).unwrap();
        let outside = |id| FakeConn {
            id,
            key: key("a"),
            broken: false,
            closed: false,
        };
        pool.try_adopt(outside(999)).unwrap().release();
        let lease = pool.acquire(deadline()).await.unwrap();
        assert_eq!(lease.conn().id, 999);
        lease.release();
        // The pool is full, and the idle connection is not closed to make room.
        assert!(pool.try_adopt(outside(1000)).is_none());
        assert_eq!(pool.stats().servers_idle, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn one_database_gets_a_bounded_number_of_option_variants() {
        let pools = pools(2, 10);
        let variant = |timeout: &str| PoolKey {
            options: vec![("statement_timeout".into(), timeout.into())],
            ..key("a")
        };
        let first = pools.register(variant("1")).unwrap();
        let _second = pools.register(variant("2")).unwrap();
        assert_eq!(pools.register(variant("3")).err(), Some(TooManyVariants));
        // Existing variants and other databases are unaffected.
        pools.register(variant("1")).unwrap();
        pools.register(key("b")).unwrap();
        drop(first);
        tokio::time::advance(Duration::from_secs(301)).await;
        pools.reap();
        pools.register(variant("3")).unwrap();
    }

    #[derive(Debug, Clone)]
    enum Op {
        Acquire { client: usize, pool: usize },
        Release { client: usize },
        Discard { client: usize },
        Break { client: usize },
        Advance { millis: u64 },
        Reap,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0..8usize, 0..3usize).prop_map(|(client, pool)| Op::Acquire { client, pool }),
            3 => (0..8usize).prop_map(|client| Op::Release { client }),
            1 => (0..8usize).prop_map(|client| Op::Discard { client }),
            1 => (0..8usize).prop_map(|client| Op::Break { client }),
            1 => (0..70_000u64).prop_map(|millis| Op::Advance { millis }),
            1 => Just(Op::Reap),
        ]
    }

    proptest! {
        /// Connections never cross pools, a connection is held by at most one client, and the
        /// per-pool and global limits always hold.
        #[test]
        fn isolation_and_limits(ops in proptest::collection::vec(op(), 1..120)) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
            rt.block_on(async {
                let (max_size, max_total) = (2, 4);
                let pools = pools(max_size, max_total);
                let keys = [key("a"), key("b"), key("c")];
                let handles: Vec<_> = keys.iter().map(|k| pools.register(k.clone()).unwrap()).collect();
                type Pending = tokio::task::JoinHandle<Result<Lease<FakeConnector>, AcquireError<&'static str>>>;
                let mut clients: Vec<Option<(usize, Lease<FakeConnector>)>> = (0..8).map(|_| None).collect();
                let mut pending: Vec<Option<(usize, Pending)>> = (0..8).map(|_| None).collect();
                for op in ops {
                    match op {
                        Op::Acquire { client, pool } if clients[client].is_none() && pending[client].is_none() => {
                            let handle = handles[pool].pool.clone();
                            pending[client] = Some((pool, tokio::spawn(async move { handle.acquire(deadline()).await })));
                        }
                        Op::Release { client } => if let Some((_, lease)) = clients[client].take() { lease.release() },
                        Op::Discard { client } => drop(clients[client].take()),
                        Op::Break { client } => if let Some((_, lease)) = &mut clients[client] { lease.conn_mut().broken = true },
                        Op::Advance { millis } => tokio::time::advance(Duration::from_millis(millis)).await,
                        Op::Reap => pools.reap(),
                        _ => {}
                    }
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                    }
                    for client in 0..8 {
                        if pending[client].as_ref().is_some_and(|(_, task)| task.is_finished()) {
                            let (pool, task) = pending[client].take().unwrap();
                            if let Ok(lease) = task.await.unwrap() {
                                clients[client] = Some((pool, lease));
                            }
                        }
                    }
                    let mut ids = std::collections::HashSet::new();
                    for (pool, lease) in clients.iter().flatten() {
                        prop_assert_eq!(&lease.conn().key, &keys[*pool]);
                        prop_assert!(ids.insert(lease.conn().id), "connection held by two clients");
                    }
                    let mut total = 0;
                    for handle in &handles {
                        let stats = handle.stats();
                        let open = stats.servers_active + stats.servers_idle;
                        prop_assert!(open <= max_size);
                        prop_assert!(stats.servers_idle == 0 || stats.clients_waiting == 0);
                        total += open;
                    }
                    prop_assert!(total <= max_total);
                    prop_assert_eq!(total, pools.open_total());
                }
                Ok(())
            })?;
        }
    }
}
