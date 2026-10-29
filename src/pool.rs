//! Pools of server connections, one per `(user, database, startup options)`.
//!
//! Every server connection is tied to the pool that opened it through its [`Slot`]: it can only
//! ever be handed to clients of that pool, and dropping it frees the slot for the pool to reuse.
//!
//! A client without an idle connection joins the pool's queue; it never opens a connection
//! itself. Whichever comes first, a connection another client releases or a new one, goes to
//! the oldest waiter. The pool opens only as many connections as the waiters cannot be served
//! without, judged by how long its clients hold a connection and how long a new one takes to
//! open (see [`crate::demand`]): a burst of short queries waits a few milliseconds for
//! releases rather than ~50 ms for a new connection each. Connections are opened only while
//! clients wait, never ahead of demand.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, sleep, sleep_until};

use crate::demand::{self, ConnectTime, Holds, Peaks};
use crate::metrics::{GlobalStats, Metrics, PoolLabels, PoolStats, PoolStatsSource};

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

    /// Whether another attempt may soon succeed: the server is starting, full or unreachable.
    fn transient(&self, error: &Self::Error) -> bool;
}

/// Pause between attempts to open a connection after a transient error.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);
/// How often an open waiting for a global permit checks that clients still wait for it.
const PERMIT_RECHECK: Duration = Duration::from_millis(50);
/// An idle connection beyond the pool's recent peak is closed once idle this long.
const SURPLUS_AFTER: Duration = Duration::from_secs(5);

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
    /// Idle connections kept per pool; one released beyond that is closed.
    pub max_idle: usize,
    pub max_total: usize,
    pub max_waiters: usize,
    /// Connections being opened at once across all pools.
    pub max_connecting: usize,
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
    connecting: Semaphore,
    pools: Mutex<PoolMap<C>>,
    metrics: Arc<Metrics>,
    /// Clients waiting for a global permit.
    permit_waiters: AtomicUsize,
    /// Holds across all pools, for pools that have not recorded enough of their own.
    holds: Mutex<Holds>,
    connect_time: Mutex<ConnectTime>,
    /// Origin of the [`Peaks`] windows.
    epoch: Instant,
}

/// Counts a client as waiting for a global permit while it lives.
struct PermitWait<'a>(&'a AtomicUsize);

impl Drop for PermitWait<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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
    /// Opens in progress, including those still waiting for a global permit.
    opening: usize,
    /// Of `opening`, those without a permit yet; they count against `max_size` too.
    reserved: usize,
    waiters: VecDeque<Waiter<C>>,
    /// When each current lease started, by lease id.
    leases: HashMap<u64, Instant>,
    next_lease: u64,
    holds: Holds,
    peaks: Peaks,
    /// A deferred look at the queue is scheduled.
    replan_scheduled: bool,
    clients: usize,
    last_active: Instant,
}

struct Waiter<C: Connector> {
    tx: oneshot::Sender<Grant<C>>,
    deadline: Instant,
}

struct Idle<C: Connector> {
    conn: C::Conn,
    slot: Slot<C>,
    since: Instant,
}

enum Grant<C: Connector> {
    Conn(C::Conn, Slot<C>, Source),
    /// Opening a connection failed for good, and this waiter is the one to hear why.
    Failed(C::Error),
}

/// The right to hold one server connection in a pool, backed by a global permit. Dropping it
/// gives the permit back and lets the pool reconsider its waiters.
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
    pub source: Source,
    id: u64,
}

/// Where a lease's connection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The pool's idle list.
    Idle,
    /// Another client released it while this one waited.
    Released,
    /// Opened while this client waited.
    New,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Idle => "idle",
            Source::Released => "released",
            Source::New => "new",
        }
    }
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
        self.pool.lease_ended(self.id);
        // A connection only ever returns to the pool its slot belongs to.
        slot.pool.clone().put_back(conn, slot, Source::Released);
    }
}

impl<C: Connector> Drop for Lease<C> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            self.pool.lease_ended(self.id);
        }
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

// Locking: the pool map before a pool's state, and a pool's state before the shared statistics;
// a pool's state is never held while another pool's state is locked, while awaiting, or while
// a `Slot` is dropped (its drop locks it).
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

    fn lease(self: &Arc<Self>, conn: C::Conn, slot: Slot<C>, source: Source) -> Lease<C> {
        self.leased.fetch_add(1, Ordering::Relaxed);
        let window = self.shared.window();
        let id = {
            let mut state = self.lock();
            let id = state.next_lease;
            state.next_lease += 1;
            state.leases.insert(id, Instant::now());
            let leased = state.leases.len();
            state.peaks.record(window, leased);
            id
        };
        Lease {
            pool: self.clone(),
            inner: Some((conn, slot)),
            source,
            id,
        }
    }

    fn lease_ended(&self, id: u64) {
        let hold = {
            let mut state = self.lock();
            let hold = state.leases.remove(&id).map(|started| started.elapsed());
            if let Some(hold) = hold {
                state.holds.record(hold);
            }
            hold
        };
        if let Some(hold) = hold {
            self.shared
                .holds
                .lock()
                .expect("holds poisoned")
                .record(hold);
        }
    }

    /// Takes over `conn`, opened outside the pool, if a slot is free right now. It never waits
    /// and never closes another connection to make room.
    pub fn try_adopt(self: &Arc<Self>, conn: C::Conn) -> Option<Lease<C>> {
        let slot = {
            let mut state = self.lock();
            if state.open + state.reserved >= self.shared.limits.max_size {
                return None;
            }
            let permit = self.shared.global.clone().try_acquire_owned().ok()?;
            state.open += 1;
            Slot {
                pool: self.clone(),
                permit: Some(permit),
            }
        };
        Some(self.lease(conn, slot, Source::New))
    }

    fn slot_freed(self: &Arc<Self>, permit: OwnedSemaphorePermit) {
        self.lock().open -= 1;
        drop(permit);
        // A waiter may have counted on the connection this slot held.
        self.plan();
    }

    /// Hands a connection to the oldest waiter, or keeps it idle.
    fn put_back(self: &Arc<Self>, mut conn: C::Conn, mut slot: Slot<C>, source: Source) {
        loop {
            let waiter = {
                let mut state = self.lock();
                state.last_active = Instant::now();
                match state.waiters.pop_front() {
                    Some(waiter) => waiter,
                    None if state.idle.len() >= self.shared.limits.max_idle => {
                        drop(state);
                        self.shared.metrics.recycle("max_idle");
                        self.shared.connector.close(&mut conn);
                        drop((conn, slot));
                        return;
                    }
                    None => {
                        state.idle.push(Idle {
                            conn,
                            slot,
                            since: Instant::now(),
                        });
                        drop(state);
                        // A client of another pool waits for a global permit: an idle
                        // connection now exists, so close the oldest one for it.
                        if self.shared.permit_waiters.load(Ordering::SeqCst) > 0 {
                            self.shared.evict_idle(None);
                        }
                        return;
                    }
                }
            };
            match waiter.tx.send(Grant::Conn(conn, slot, source)) {
                Ok(()) => return,
                Err(grant) => (conn, slot) = grant.into_conn(),
            }
        }
    }

    fn enqueue(
        &self,
        state: &mut State<C>,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<Grant<C>>, AcquireError<C::Error>> {
        state.waiters.retain(|waiter| !waiter.tx.is_closed());
        if state.waiters.len() >= self.shared.limits.max_waiters {
            return Err(AcquireError::TooManyWaiters);
        }
        let (tx, rx) = oneshot::channel();
        state.waiters.push_back(Waiter { tx, deadline });
        Ok(rx)
    }

    /// A connection for one client: an idle one that passes revalidation, or the first one
    /// available to the pool's queue, released by another client or newly opened.
    pub async fn acquire(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<Lease<C>, AcquireError<C::Error>> {
        loop {
            let taken = {
                let mut state = self.lock();
                state.last_active = Instant::now();
                match state.idle.pop() {
                    Some(idle) => Ok(idle),
                    None => Err(self.enqueue(&mut state, deadline)?),
                }
            };
            match taken {
                Ok(Idle {
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
                        Ok(()) => return Ok(self.lease(conn, slot, Source::Idle)),
                        Err(reason) => {
                            self.shared.metrics.recycle(reason);
                            self.shared.connector.close(&mut conn);
                            drop((conn, slot));
                        }
                    }
                }
                Err(rx) => {
                    self.plan();
                    tokio::select! {
                        biased;
                        grant = rx => match grant {
                            Ok(Grant::Conn(conn, slot, source)) => return Ok(self.lease(conn, slot, source)),
                            Ok(Grant::Failed(error)) => return Err(AcquireError::Open(error)),
                            Err(_) => continue,
                        },
                        () = sleep_until(deadline) => return Err(AcquireError::TimedOut),
                    }
                }
            }
        }
    }

    /// Opens the connections the queue needs now, and looks again shortly while clients wait.
    fn plan(self: &Arc<Self>) {
        let connect = self
            .shared
            .connect_time
            .lock()
            .expect("connect time poisoned")
            .estimate();
        let (opens, replan) = {
            let mut state = self.lock();
            state.waiters.retain(|waiter| !waiter.tx.is_closed());
            let waiting = state.waiters.len();
            if waiting == 0 {
                return;
            }
            let holds = if state.holds.weight() >= demand::MIN_WEIGHT {
                state.holds.clone()
            } else {
                self.shared.holds.lock().expect("holds poisoned").clone()
            };
            let now = Instant::now();
            let patience = demand::patience(connect);
            let ending: f64 = state
                .leases
                .values()
                .map(|started| holds.ends_within(now - *started, patience))
                .sum();
            let hold = Duration::from_secs_f64(holds.mean());
            let room = self.shared.limits.max_size - (state.open + state.reserved);
            let opens =
                demand::opens_needed(waiting, state.opening, ending, hold, connect, patience)
                    .min(room);
            state.opening += opens;
            state.reserved += opens;
            let replan = waiting > state.opening && !state.replan_scheduled;
            state.replan_scheduled |= replan;
            (opens, replan)
        };
        for _ in 0..opens {
            tokio::spawn(self.clone().open_for_queue());
        }
        if replan {
            let pool = self.clone();
            let after = (connect / 8).clamp(Duration::from_millis(1), Duration::from_millis(20));
            tokio::spawn(async move {
                sleep(after).await;
                pool.lock().replan_scheduled = false;
                pool.plan();
            });
        }
    }

    /// One planned open: a global permit, then a connection for whoever waits when it is ready.
    async fn open_for_queue(self: Arc<Self>) {
        let Some(permit) = self.permit().await else {
            let mut state = self.lock();
            state.reserved -= 1;
            state.opening -= 1;
            return;
        };
        {
            let mut state = self.lock();
            state.reserved -= 1;
            state.open += 1;
        }
        let slot = Slot {
            pool: self.clone(),
            permit: Some(permit),
        };
        let started = Instant::now();
        let opened = self.open().await;
        self.lock().opening -= 1;
        match opened {
            Ok(conn) => {
                self.shared
                    .connect_time
                    .lock()
                    .expect("connect time poisoned")
                    .record(started.elapsed());
                self.put_back(conn, slot, Source::New);
                self.plan();
            }
            Err(error) => {
                // The waiter hears first, so the freed slot does not open again on its behalf.
                self.fail_oldest(error);
                drop(slot);
            }
        }
    }

    /// A global permit, closing another pool's idle connection for it if needed; `None` once
    /// no client waits for this pool any more.
    async fn permit(&self) -> Option<OwnedSemaphorePermit> {
        loop {
            if let Ok(permit) = self.shared.global.clone().try_acquire_owned() {
                return Some(permit);
            }
            if !self.has_waiters() {
                return None;
            }
            // Counted before looking, so a connection that goes idle after the look is closed
            // by whoever released it.
            self.shared.permit_waiters.fetch_add(1, Ordering::SeqCst);
            let _waiting = PermitWait(&self.shared.permit_waiters);
            if self.shared.evict_idle(Some(&self.key)) {
                continue;
            }
            tokio::select! {
                permit = self.shared.global.clone().acquire_owned() => {
                    return Some(permit.expect("global semaphore is never closed"));
                }
                () = sleep(PERMIT_RECHECK) => {}
            }
        }
    }

    fn has_waiters(&self) -> bool {
        let mut state = self.lock();
        state.waiters.retain(|waiter| !waiter.tx.is_closed());
        !state.waiters.is_empty()
    }

    /// Opens a connection. Transient errors are retried while a waiter's deadline allows; the
    /// oldest waiter then gets the last one, which says more than a timeout.
    async fn open(&self) -> Result<C::Conn, C::Error> {
        loop {
            let _connecting = self
                .shared
                .connecting
                .acquire()
                .await
                .expect("connect semaphore is never closed");
            match self.shared.connector.open(&self.key, &self.data).await {
                Ok(conn) => return Ok(conn),
                Err(error) if self.shared.connector.transient(&error) && self.can_retry() => {}
                Err(error) => return Err(error),
            }
            drop(_connecting);
            sleep(RETRY_INTERVAL).await;
        }
    }

    fn can_retry(&self) -> bool {
        let retry_at = Instant::now() + RETRY_INTERVAL;
        self.lock()
            .waiters
            .iter()
            .any(|waiter| !waiter.tx.is_closed() && waiter.deadline > retry_at)
    }

    fn fail_oldest(&self, mut error: C::Error) {
        loop {
            let Some(waiter) = self.lock().waiters.pop_front() else {
                return;
            };
            match waiter.tx.send(Grant::Failed(error)) {
                Ok(()) => return,
                Err(grant) => error = grant.into_error(),
            }
        }
    }

    /// Closes idle connections beyond what the pool needed at once lately.
    fn close_surplus(&self, window: u64) -> Vec<Idle<C>> {
        let mut state = self.lock();
        let keep = state.peaks.recent(window).max(1);
        let mut surplus = Vec::new();
        while state.open - surplus.len() > keep
            && state
                .idle
                .first()
                .is_some_and(|idle| idle.since.elapsed() >= SURPLUS_AFTER)
        {
            surplus.push(state.idle.remove(0));
        }
        surplus
    }

    pub fn stats(&self) -> PoolStats {
        let state = self.lock();
        PoolStats {
            clients: state.clients,
            clients_active: self.leased.load(Ordering::Relaxed),
            clients_waiting: state.waiters.iter().filter(|w| !w.tx.is_closed()).count(),
            servers_active: state.open - state.idle.len(),
            servers_idle: state.idle.len(),
        }
    }
}

impl<C: Connector> Grant<C> {
    fn into_conn(self) -> (C::Conn, Slot<C>) {
        match self {
            Grant::Conn(conn, slot, _) => (conn, slot),
            Grant::Failed(_) => unreachable!("a failed send returns what was sent"),
        }
    }

    fn into_error(self) -> C::Error {
        match self {
            Grant::Failed(error) => error,
            Grant::Conn(..) => unreachable!("a failed send returns what was sent"),
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

    fn window(&self) -> u64 {
        self.epoch.elapsed().as_secs() / Peaks::WINDOW.as_secs()
    }

    /// Closes the oldest idle connection, of any pool other than `except`.
    fn evict_idle(&self, except: Option<&PoolKey>) -> bool {
        let mut oldest: Option<(Arc<Pool<C>>, Instant)> = None;
        for pool in self.list() {
            if Some(&pool.key) == except {
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
        let connecting = Semaphore::new(limits.max_connecting);
        Self {
            shared: Arc::new(Shared {
                connector,
                limits,
                global,
                connecting,
                pools: Mutex::default(),
                metrics,
                permit_waiters: AtomicUsize::new(0),
                holds: Mutex::default(),
                connect_time: Mutex::default(),
                epoch: Instant::now(),
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
                        opening: 0,
                        reserved: 0,
                        waiters: VecDeque::new(),
                        leases: HashMap::new(),
                        next_lease: 0,
                        holds: Holds::default(),
                        peaks: Peaks::default(),
                        replan_scheduled: false,
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

    /// Closes idle connections that expired or that the pool has not needed lately, ages the
    /// hold statistics and drops unused empty pools. Run once a second.
    pub fn reap(&self) {
        let window = self.shared.window();
        self.shared
            .holds
            .lock()
            .expect("holds poisoned")
            .decay(demand::DECAY_PER_SECOND);
        for pool in self.shared.list() {
            pool.lock().holds.decay(demand::DECAY_PER_SECOND);
            for mut idle in pool.close_surplus(window) {
                self.shared.metrics.recycle("surplus");
                self.shared.connector.close(&mut idle.conn);
                drop(idle);
            }
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
                let mut state = pool.lock();
                // A waiter that timed out leaves its sender behind until the next enqueue.
                state.waiters.retain(|waiter| !waiter.tx.is_closed());
                let unused = state.clients == 0
                    && state.open == 0
                    && state.opening == 0
                    && state.waiters.is_empty()
                    && state.last_active.elapsed() >= gc_after;
                if unused {
                    removed.push(pool.clone());
                }
                !unused
            });
            let mut forgotten = Vec::new();
            for pool in removed {
                let tenant = (pool.key.user.clone(), pool.key.database.clone());
                if let Some(variants) = map.variants.get_mut(&tenant) {
                    *variants -= 1;
                    // Variants share metric labels, so the series go with the last one.
                    if *variants == 0 {
                        map.variants.remove(&tenant);
                        forgotten.push(pool);
                    }
                }
            }
            forgotten
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

    fn global_stats(&self) -> GlobalStats {
        GlobalStats {
            servers_max: self.shared.limits.max_total,
            clients_waiting_permit: self.shared.permit_waiters.load(Ordering::Relaxed),
        }
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
        /// Opens for the user `flaky` that fail with a transient error first.
        flaky: AtomicUsize,
        connecting: AtomicUsize,
        max_connecting: AtomicUsize,
    }

    impl Connector for FakeConnector {
        type Conn = FakeConn;
        type PoolData = ();
        type Error = &'static str;

        async fn open(&self, key: &PoolKey, _: &()) -> Result<FakeConn, &'static str> {
            let connecting = self.connecting.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_connecting.fetch_max(connecting, Ordering::SeqCst);
            if key.user.starts_with("slow") {
                tokio::time::sleep(Duration::from_millis(50)).await;
            } else {
                tokio::task::yield_now().await;
            }
            self.connecting.fetch_sub(1, Ordering::SeqCst);
            if key.user == "down" {
                return Err("server down");
            }
            if key.user == "flaky"
                && self
                    .flaky
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
            {
                return Err("starting up");
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

        fn transient(&self, error: &&'static str) -> bool {
            *error == "starting up"
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
            max_idle: max_size,
            max_total,
            max_waiters: 4,
            max_connecting: 2,
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
        assert_eq!(lease.source, Source::New);
        lease.release();
        let lease = pool.acquire(deadline()).await.unwrap();
        assert_eq!(lease.conn().id, id);
        assert_eq!(lease.source, Source::Idle);
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
            tokio::spawn(async move { pool.acquire(deadline()).await.map(|l| l.source) })
        };
        tokio::task::yield_now().await;
        drop(held);
        assert_eq!(waiter.await.unwrap(), Ok(Source::New));
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
    async fn a_client_waiting_for_a_global_permit_gets_the_next_idle_connection_closed() {
        let pools = pools(1, 1);
        let a = pools.register(key("a")).unwrap();
        let b = pools.register(key("b")).unwrap();
        let held = a.acquire(deadline()).await.unwrap();
        let waiter = {
            let b = b.clone();
            tokio::spawn(async move { b.acquire(deadline()).await.map(|l| l.conn().key.clone()) })
        };
        tokio::task::yield_now().await;
        let started = Instant::now();
        held.release();
        assert_eq!(waiter.await.unwrap(), Ok(key("b")));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(a.stats().servers_idle, 0);
        let evicted = pools
            .shared
            .metrics
            .server_recycles
            .get_or_create(&crate::metrics::Reason { reason: "evicted" })
            .get();
        assert_eq!(evicted, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connections_beyond_max_idle_are_closed() {
        let mut pools = pools(3, 10);
        Arc::get_mut(&mut pools.shared).unwrap().limits.max_idle = 1;
        let pool = pools.register(key("a")).unwrap();
        let leases = [
            pool.acquire(deadline()).await.unwrap(),
            pool.acquire(deadline()).await.unwrap(),
            pool.acquire(deadline()).await.unwrap(),
        ];
        for lease in leases {
            lease.release();
        }
        assert_eq!(pool.stats().servers_idle, 1);
        assert_eq!(pools.open_total(), 1);
        assert_eq!(pools.connector().closed.load(Ordering::SeqCst), 2);
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
    async fn transient_errors_are_retried_until_the_deadline() {
        let pools = pools(1, 10);
        let pool = pools.register(key("flaky")).unwrap();
        pools.connector().flaky.store(3, Ordering::SeqCst);
        let started = Instant::now();
        pool.acquire(deadline()).await.unwrap();
        assert_eq!(started.elapsed(), 3 * RETRY_INTERVAL);

        drop(pool.acquire(deadline()).await.unwrap());
        pools.connector().flaky.store(usize::MAX, Ordering::SeqCst);
        let started = Instant::now();
        assert!(matches!(
            pool.acquire(deadline()).await,
            Err(AcquireError::Open("starting up"))
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(pools.open_total(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn connections_are_opened_a_few_at_a_time() {
        let pools = pools(2, 10);
        let tasks: Vec<_> = (0..6)
            .map(|i| {
                let pool = pools.register(key(&format!("slow{i}"))).unwrap();
                tokio::spawn(async move { pool.acquire(deadline()).await.is_ok() })
            })
            .collect();
        for task in tasks {
            assert!(task.await.unwrap());
        }
        assert_eq!(pools.connector().max_connecting.load(Ordering::SeqCst), 2);
    }

    /// Leases of `millis` each, one after another, so the pool learns how long its clients hold.
    async fn teach_holds(pool: &Arc<Pool<FakeConnector>>, millis: u64) {
        for _ in 0..30 {
            let lease = pool.acquire(deadline()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(millis)).await;
            lease.release();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_short_queries_is_served_by_released_connections() {
        let mut pools = pools(10, 10);
        Arc::get_mut(&mut pools.shared).unwrap().limits.max_waiters = 16;
        let pool = pools.register(key("slow")).unwrap();
        teach_holds(&pool, 1).await;
        let started = Instant::now();
        let queries: Vec<_> = (0..8)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    let lease = pool.acquire(deadline()).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    lease.release();
                })
            })
            .collect();
        for query in queries {
            query.await.unwrap();
        }
        // One connection serves all eight sooner than a second one opens (50 ms).
        assert_eq!(pools.connector().opened.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < Duration::from_millis(20));
    }

    #[tokio::test(start_paused = true)]
    async fn a_lease_held_longer_than_usual_does_not_hold_up_the_queue() {
        let pools = pools(2, 10);
        let pool = pools.register(key("slow")).unwrap();
        teach_holds(&pool, 1).await;
        let _held = pool.acquire(deadline()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        let lease = pool.acquire(deadline()).await.unwrap();
        assert_eq!(lease.source, Source::New);
        assert!(started.elapsed() < Duration::from_millis(60));
    }

    #[tokio::test(start_paused = true)]
    async fn the_reaper_closes_idle_connections_beyond_the_recent_peak() {
        let pools = pools(3, 10);
        let pool = pools.register(key("a")).unwrap();
        let burst = [
            pool.acquire(deadline()).await.unwrap(),
            pool.acquire(deadline()).await.unwrap(),
            pool.acquire(deadline()).await.unwrap(),
        ];
        for lease in burst {
            lease.release();
        }
        tokio::time::advance(Duration::from_secs(10)).await;
        pools.reap();
        // The burst is recent: its connections stay.
        assert_eq!(pool.stats().servers_idle, 3);
        tokio::time::advance(Duration::from_secs(25)).await;
        pool.acquire(deadline()).await.unwrap().release();
        pools.reap();
        assert_eq!(pool.stats().servers_idle, 1);
        let surplus = pools
            .shared
            .metrics
            .server_recycles
            .get_or_create(&crate::metrics::Reason { reason: "surplus" })
            .get();
        assert_eq!(surplus, 2);
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
    async fn reaper_collects_a_pool_whose_waiter_timed_out() {
        let pools = pools(1, 1);
        let a = pools.register(key("a")).unwrap();
        let b = pools.register(key("b")).unwrap();
        let _held = a.acquire(deadline()).await.unwrap();
        assert!(matches!(
            b.acquire(deadline()).await,
            Err(AcquireError::TimedOut)
        ));
        drop(b);
        tokio::time::advance(Duration::from_secs(301)).await;
        pools.reap();
        let keys: Vec<PoolKey> = pools.list().iter().map(|pool| pool.key.clone()).collect();
        assert_eq!(keys, [key("a")]);
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

    #[tokio::test(start_paused = true)]
    async fn collecting_one_option_variant_keeps_the_tenant_metrics() {
        let pools = pools(2, 10);
        let variant = |timeout: &str| PoolKey {
            options: vec![("statement_timeout".into(), timeout.into())],
            ..key("a")
        };
        let first = pools.register(variant("1")).unwrap();
        let second = pools.register(variant("2")).unwrap();
        let transactions = || {
            pools
                .shared
                .metrics
                .pool_transactions
                .get_or_create(first.labels())
                .get()
        };
        pools
            .shared
            .metrics
            .pool_transactions
            .get_or_create(first.labels())
            .inc();
        drop(second);
        tokio::time::advance(Duration::from_secs(301)).await;
        pools.reap();
        assert_eq!(pools.list().len(), 1);
        assert_eq!(transactions(), 1);
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
                    let mut idle = 0;
                    for handle in &handles {
                        let stats = handle.stats();
                        let open = stats.servers_active + stats.servers_idle;
                        prop_assert!(open <= max_size);
                        prop_assert!(stats.servers_idle == 0 || stats.clients_waiting == 0);
                        total += open;
                        idle += stats.servers_idle;
                    }
                    // No client waits for a global permit while an idle connection could make room.
                    prop_assert!(idle == 0 || pools.shared.permit_waiters.load(Ordering::SeqCst) == 0);
                    prop_assert!(total <= max_total);
                    prop_assert_eq!(total, pools.open_total());
                }
                Ok(())
            })?;
        }
    }
}
