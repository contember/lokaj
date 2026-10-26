//! Client credentials: cleartext passwords received over TLS and verified against the server.
//!
//! A password is accepted only after the server accepted it in a SCRAM login for exactly that
//! `(user, database)`. lokaj then keeps the SCRAM keys derived from it, to open further server
//! connections, and a keyed HMAC of it, to recognise later logins. The plaintext is never kept.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::time::Instant;

use crate::scram::ScramKeys;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredKey {
    pub user: String,
    pub database: String,
}

pub struct Credential {
    mac: [u8; 32],
    pub keys: ScramKeys,
    verified_at: Mutex<Instant>,
}

/// Outcome of logging in to the server with a client's password.
pub enum Verification<T, E> {
    /// The server accepted the password; `T` is what the login produced (a server connection).
    Accepted(ScramKeys, T),
    /// The server rejected the password.
    Rejected(E),
    /// The server could not be asked; nothing is learned about the password.
    Unavailable(E),
}

#[derive(Debug)]
pub enum Login<T> {
    /// The password matches a credential the server accepted within the verification TTL.
    Cached,
    /// The server accepted the password just now.
    Verified(T),
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError<E> {
    Rejected(E),
    /// The server rejected this password for this user and database within the failure window.
    RejectedBefore,
    RateLimited,
    Unavailable(E),
}

pub struct AuthCache {
    mac_key: [u8; 32],
    verify_ttl: Duration,
    max_failures: usize,
    failure_window: Duration,
    entries: Mutex<HashMap<CredKey, Arc<Credential>>>,
    inflight: Mutex<HashMap<CredKey, Arc<tokio::sync::Mutex<()>>>>,
    limits: Mutex<Limits>,
}

/// Failed logins in the current window.
#[derive(Default)]
struct Limits {
    /// Per user and client address: rejected or refused attempts. A source over the limit is
    /// refused even with the right password, so it cannot probe the cache.
    sources: HashMap<(String, IpAddr), VecDeque<Instant>>,
    /// Per user across sources: server verifications that failed, plus those in flight, so no
    /// number of sources or databases gets more guesses checked by the server.
    users: HashMap<String, UserLimit>,
    /// Per user and database: MACs of passwords the server rejected, so clients retrying one,
    /// such as pods still on a rotated password, do not spend the user's verifications.
    rejected: HashMap<CredKey, VecDeque<([u8; 32], Instant)>>,
}

#[derive(Default)]
struct UserLimit {
    failures: VecDeque<Instant>,
    verifying: usize,
}

fn prune(times: &mut VecDeque<Instant>, window: Duration) {
    while times.front().is_some_and(|t| t.elapsed() >= window) {
        times.pop_front();
    }
}

impl AuthCache {
    pub fn new(verify_ttl: Duration, max_failures: usize, failure_window: Duration) -> Self {
        let mut mac_key = [0u8; 32];
        rand::rng().fill_bytes(&mut mac_key);
        Self {
            mac_key,
            verify_ttl,
            max_failures,
            failure_window,
            entries: Mutex::default(),
            inflight: Mutex::default(),
            limits: Mutex::default(),
        }
    }

    fn mac(&self, key: &CredKey, password: &str) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.mac_key).expect("HMAC accepts any key length");
        for part in [
            key.user.as_bytes(),
            key.database.as_bytes(),
            password.as_bytes(),
        ] {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    /// When the server last accepted the cached credential `mac` matches, fresh or not.
    fn cached_at(&self, key: &CredKey, mac: &[u8; 32]) -> Option<Instant> {
        let entries = self.entries.lock().expect("auth entries poisoned");
        let entry = entries.get(key)?;
        bool::from(entry.mac.ct_eq(mac))
            .then(|| *entry.verified_at.lock().expect("auth entry poisoned"))
    }

    fn matches_fresh(&self, key: &CredKey, mac: &[u8; 32]) -> bool {
        self.cached_at(key, mac)
            .is_some_and(|at| at.elapsed() < self.verify_ttl)
    }

    fn rejected_before(&self, key: &CredKey, mac: &[u8; 32]) -> bool {
        let mut limits = self.limits();
        let Some(macs) = limits.rejected.get_mut(key) else {
            return false;
        };
        while macs
            .front()
            .is_some_and(|(_, at)| at.elapsed() >= self.failure_window)
        {
            macs.pop_front();
        }
        macs.iter().fold(false, |found, (rejected, _)| {
            found | bool::from(rejected.ct_eq(mac))
        })
    }

    fn record_rejection(&self, key: &CredKey, mac: [u8; 32]) {
        let mut limits = self.limits();
        let macs = limits.rejected.entry(key.clone()).or_default();
        macs.push_back((mac, Instant::now()));
        // Each one cost a verification, of which the user gets max_failures per window.
        while macs.len() > self.max_failures {
            macs.pop_front();
        }
    }

    fn limits(&self) -> std::sync::MutexGuard<'_, Limits> {
        self.limits.lock().expect("auth limits poisoned")
    }

    fn source_locked(&self, user: &str, source: IpAddr) -> bool {
        let mut limits = self.limits();
        let Some(times) = limits.sources.get_mut(&(user.to_owned(), source)) else {
            return false;
        };
        prune(times, self.failure_window);
        times.len() >= self.max_failures
    }

    fn record_source_failure(&self, user: &str, source: IpAddr) {
        let mut limits = self.limits();
        let times = limits.sources.entry((user.to_owned(), source)).or_default();
        times.push_back(Instant::now());
        while times.len() > self.max_failures {
            times.pop_front();
        }
    }

    /// Reserves one server verification for `user`, if its budget allows one.
    fn begin_verification<'a>(&'a self, user: &'a str) -> Option<Verifying<'a>> {
        let mut limits = self.limits();
        let limit = limits.users.entry(user.to_owned()).or_default();
        prune(&mut limit.failures, self.failure_window);
        if limit.failures.len() + limit.verifying >= self.max_failures {
            return None;
        }
        limit.verifying += 1;
        Some(Verifying {
            cache: self,
            user,
            failed: false,
        })
    }

    /// Authenticates `password` for `key` from the client address `source`. `verify` logs in
    /// to the server with it and is only called when no fresh cached credential matches;
    /// concurrent logins for one key verify one at a time so a burst of new clients costs a
    /// single server login.
    pub async fn authenticate<T, E, F, Fut>(
        &self,
        key: &CredKey,
        source: IpAddr,
        password: &str,
        verify: F,
    ) -> Result<Login<T>, AuthError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Verification<T, E>>,
    {
        // Not counted again, so the lock ends one window after the last counted attempt even
        // while the client keeps retrying.
        if self.source_locked(&key.user, source) {
            return Err(AuthError::RateLimited);
        }
        let mac = self.mac(key, password);
        if self.matches_fresh(key, &mac) {
            return Ok(Login::Cached);
        }
        if self.rejected_before(key, &mac) {
            self.record_source_failure(&key.user, source);
            return Err(AuthError::RejectedBefore);
        }
        let single_flight = SingleFlight::join(self, key);
        let _turn = single_flight.lock.lock().await;
        if self.matches_fresh(key, &mac) {
            return Ok(Login::Cached);
        }
        if self.rejected_before(key, &mac) {
            self.record_source_failure(&key.user, source);
            return Err(AuthError::RejectedBefore);
        }
        let Some(mut verifying) = self.begin_verification(&key.user) else {
            // A guess is counted, or a source could test guesses against the cache for free.
            // The password of a credential that only went stale is not a guess.
            if self.cached_at(key, &mac).is_none() {
                self.record_source_failure(&key.user, source);
            }
            return Err(AuthError::RateLimited);
        };
        match verify().await {
            Verification::Accepted(keys, value) => {
                let credential = Credential {
                    mac,
                    keys,
                    verified_at: Mutex::new(Instant::now()),
                };
                self.entries
                    .lock()
                    .expect("auth entries poisoned")
                    .insert(key.clone(), Arc::new(credential));
                Ok(Login::Verified(value))
            }
            Verification::Rejected(error) => {
                verifying.failed = true;
                self.record_source_failure(&key.user, source);
                self.record_rejection(key, mac);
                // The server no longer accepts this password, so a cached copy is stale.
                let mut entries = self.entries.lock().expect("auth entries poisoned");
                if entries
                    .get(key)
                    .is_some_and(|entry| bool::from(entry.mac.ct_eq(&mac)))
                {
                    entries.remove(key);
                }
                Err(AuthError::Rejected(error))
            }
            Verification::Unavailable(error) => Err(AuthError::Unavailable(error)),
        }
    }

    /// The credential used to open server connections for `key`.
    pub fn get(&self, key: &CredKey) -> Option<Arc<Credential>> {
        self.entries
            .lock()
            .expect("auth entries poisoned")
            .get(key)
            .cloned()
    }

    /// Records that the server accepted `credential` again.
    pub fn confirm(&self, key: &CredKey, credential: &Arc<Credential>) {
        let entries = self.entries.lock().expect("auth entries poisoned");
        if entries
            .get(key)
            .is_some_and(|entry| Arc::ptr_eq(entry, credential))
        {
            *credential.verified_at.lock().expect("auth entry poisoned") = Instant::now();
        }
    }

    /// Drops `credential` after the server rejected it, unless a newer one replaced it.
    pub fn invalidate(&self, key: &CredKey, credential: &Arc<Credential>) {
        let mut entries = self.entries.lock().expect("auth entries poisoned");
        if entries
            .get(key)
            .is_some_and(|entry| Arc::ptr_eq(entry, credential))
        {
            entries.remove(key);
        }
    }

    /// Forgets failure records that left the window.
    pub fn prune(&self) {
        let window = self.failure_window;
        let recent = |times: &VecDeque<Instant>| times.back().is_some_and(|t| t.elapsed() < window);
        let mut limits = self.limits();
        limits.sources.retain(|_, times| recent(times));
        limits
            .users
            .retain(|_, limit| limit.verifying > 0 || recent(&limit.failures));
        limits
            .rejected
            .retain(|_, macs| macs.back().is_some_and(|(_, at)| at.elapsed() < window));
    }
}

/// A reserved server verification. Released when dropped, also when the login is abandoned
/// mid-verification, which teaches the client nothing and so is not counted as a failure.
struct Verifying<'a> {
    cache: &'a AuthCache,
    user: &'a str,
    failed: bool,
}

impl Drop for Verifying<'_> {
    fn drop(&mut self) {
        let mut limits = self.cache.limits();
        let Some(limit) = limits.users.get_mut(self.user) else {
            return;
        };
        limit.verifying -= 1;
        if self.failed {
            limit.failures.push_back(Instant::now());
            while limit.failures.len() > self.cache.max_failures {
                limit.failures.pop_front();
            }
        }
    }
}

/// The per-key lock that serialises verifications; its map entry goes with the last user.
struct SingleFlight<'a> {
    cache: &'a AuthCache,
    key: &'a CredKey,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl<'a> SingleFlight<'a> {
    fn join(cache: &'a AuthCache, key: &'a CredKey) -> Self {
        let mut inflight = cache.inflight.lock().expect("auth inflight poisoned");
        let lock = inflight.entry(key.clone()).or_default().clone();
        Self { cache, key, lock }
    }
}

impl Drop for SingleFlight<'_> {
    fn drop(&mut self) {
        let mut inflight = self.cache.inflight.lock().expect("auth inflight poisoned");
        // The map holds one reference and this guard another.
        if Arc::strong_count(&self.lock) == 2 {
            inflight.remove(self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn keys() -> ScramKeys {
        ScramKeys {
            salt: vec![1],
            iterations: 1,
            client_key: [0; 32],
            server_key: [0; 32],
        }
    }

    fn key(user: &str) -> CredKey {
        CredKey {
            user: user.into(),
            database: "db".into(),
        }
    }

    fn cache() -> AuthCache {
        AuthCache::new(Duration::from_secs(600), 3, Duration::from_secs(60))
    }

    const POD: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const OTHER_POD: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    async fn login(
        cache: &AuthCache,
        key: &CredKey,
        password: &str,
        server_password: &str,
    ) -> Result<Login<()>, AuthError<()>> {
        login_from(cache, POD, key, password, server_password).await
    }

    async fn login_from(
        cache: &AuthCache,
        source: IpAddr,
        key: &CredKey,
        password: &str,
        server_password: &str,
    ) -> Result<Login<()>, AuthError<()>> {
        let accepted = password == server_password;
        cache
            .authenticate(key, source, password, || async move {
                if accepted {
                    Verification::Accepted(keys(), ())
                } else {
                    Verification::Rejected(())
                }
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn caches_verified_password_until_ttl() {
        let cache = cache();
        let alice = key("alice");
        assert!(matches!(
            login(&cache, &alice, "pw", "pw").await,
            Ok(Login::Verified(()))
        ));
        assert!(matches!(
            login(&cache, &alice, "pw", "pw").await,
            Ok(Login::Cached)
        ));
        tokio::time::advance(Duration::from_secs(601)).await;
        assert!(matches!(
            login(&cache, &alice, "pw", "pw").await,
            Ok(Login::Verified(()))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_source_is_refused_and_cannot_probe_the_cache() {
        let cache = cache();
        let alice = key("alice");
        login_from(&cache, OTHER_POD, &alice, "pw", "pw")
            .await
            .unwrap();
        for i in 0..3 {
            assert_eq!(
                login(&cache, &alice, &format!("guess{i}"), "pw")
                    .await
                    .unwrap_err(),
                AuthError::Rejected(())
            );
        }
        for _ in 0..100 {
            assert_eq!(
                login(&cache, &alice, "guess", "pw").await.unwrap_err(),
                AuthError::RateLimited
            );
        }
        // Even the right password: a cache match would otherwise answer every guess.
        assert_eq!(
            login(&cache, &alice, "pw", "pw").await.unwrap_err(),
            AuthError::RateLimited
        );
        // Other sources keep logging in from the cache.
        assert!(matches!(
            login_from(&cache, OTHER_POD, &alice, "pw", "pw").await,
            Ok(Login::Cached)
        ));
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(matches!(
            login(&cache, &alice, "pw", "pw").await,
            Ok(Login::Cached)
        ));
    }

    /// Logs in with `password` every 5 s, as a reconnecting driver does, until the server
    /// verifies it; returns how long that took.
    async fn retry_until_verified(cache: &AuthCache, source: IpAddr, password: &str) -> Duration {
        let alice = key("alice");
        let started = Instant::now();
        loop {
            match login_from(cache, source, &alice, password, password).await {
                Ok(Login::Verified(())) => return started.elapsed(),
                Err(AuthError::RateLimited) => {}
                other => panic!("unexpected {other:?}"),
            }
            assert!(
                started.elapsed() < Duration::from_secs(300),
                "never verified"
            );
            tokio::time::advance(Duration::from_secs(5)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_lock_ends_one_window_after_the_last_rejection_while_the_client_retries() {
        let cache = cache();
        for expected in [
            AuthError::Rejected(()),
            AuthError::RejectedBefore,
            AuthError::RejectedBefore,
        ] {
            assert_eq!(
                login(&cache, &key("alice"), "old", "new")
                    .await
                    .unwrap_err(),
                expected
            );
        }
        assert_eq!(
            retry_until_verified(&cache, POD, "new").await,
            Duration::from_secs(60)
        );
        assert!(matches!(
            login(&cache, &key("alice"), "new", "new").await,
            Ok(Login::Cached)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_spent_user_budget_holds_off_another_source_for_one_window() {
        let cache = cache();
        for i in 0..3 {
            login_from(&cache, OTHER_POD, &key("alice"), &format!("old{i}"), "new")
                .await
                .unwrap_err();
        }
        // Refused for the spent budget until locked, and through when the window has passed.
        assert_eq!(
            retry_until_verified(&cache, POD, "new").await,
            Duration::from_secs(60)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejected_password_is_answered_without_the_server() {
        let cache = cache();
        let alice = key("alice");
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let attempt = |source, password: &'static str| {
            let calls = &calls;
            let cache = &cache;
            let alice = &alice;
            async move {
                cache
                    .authenticate(alice, source, password, || async move {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if password == "new" {
                            Verification::Accepted(keys(), ())
                        } else {
                            Verification::<(), ()>::Rejected(())
                        }
                    })
                    .await
            }
        };
        assert_eq!(
            attempt(POD, "old").await.unwrap_err(),
            AuthError::Rejected(())
        );
        // Pods still on a rotated password keep retrying it from many addresses.
        for i in 0..20u8 {
            let source = IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, i));
            assert_eq!(
                attempt(source, "old").await.unwrap_err(),
                AuthError::RejectedBefore
            );
        }
        assert!(matches!(
            attempt(OTHER_POD, "new").await,
            Ok(Login::Verified(()))
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        // A rejection is remembered for one window.
        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(
            attempt(OTHER_POD, "old").await.unwrap_err(),
            AuthError::Rejected(())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stale_credential_refused_for_a_spent_budget_does_not_lock_its_source() {
        let cache = cache();
        let alice = key("alice");
        login(&cache, &alice, "pw", "pw").await.unwrap();
        tokio::time::advance(Duration::from_secs(601)).await;
        for i in 0..3 {
            login_from(&cache, OTHER_POD, &alice, &format!("guess{i}"), "pw")
                .await
                .unwrap_err();
        }
        for _ in 0..5 {
            assert_eq!(
                login(&cache, &alice, "pw", "pw").await.unwrap_err(),
                AuthError::RateLimited
            );
        }
        assert!(!cache.source_locked("alice", POD));
        // A guess is still counted.
        for _ in 0..3 {
            login(&cache, &alice, "guess", "pw").await.unwrap_err();
        }
        assert!(cache.source_locked("alice", POD));
    }

    #[tokio::test(start_paused = true)]
    async fn server_verifications_per_user_are_bounded_across_sources_and_databases() {
        let cache = Arc::new(cache());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tasks: Vec<_> = (0..50u8)
            .map(|i| {
                let cache = cache.clone();
                let calls = calls.clone();
                tokio::spawn(async move {
                    let key = CredKey {
                        user: "alice".into(),
                        database: format!("db{i}"),
                    };
                    let source = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 0, i));
                    cache
                        .authenticate(&key, source, &format!("guess{i}"), || async move {
                            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            Verification::<(), ()>::Rejected(())
                        })
                        .await
                })
            })
            .collect();
        for task in tasks {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_login_releases_its_reservations() {
        let cache = cache();
        let alice = key("alice");
        for _ in 0..5 {
            let pending = cache.authenticate(&alice, POD, "pw", || async {
                std::future::pending::<Verification<(), ()>>().await
            });
            assert!(
                tokio::time::timeout(Duration::from_secs(1), pending)
                    .await
                    .is_err()
            );
        }
        assert!(cache.inflight.lock().unwrap().is_empty());
        assert!(matches!(
            login(&cache, &alice, "pw", "pw").await,
            Ok(Login::Verified(()))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn credentials_are_per_user_and_database() {
        let cache = cache();
        login(&cache, &key("alice"), "pw", "pw").await.unwrap();
        let mallory = key("mallory");
        assert_eq!(
            login(&cache, &mallory, "pw", "other").await.unwrap_err(),
            AuthError::Rejected(())
        );
        let other_db = CredKey {
            user: "alice".into(),
            database: "other".into(),
        };
        assert!(matches!(
            login(&cache, &other_db, "pw", "pw").await,
            Ok(Login::Verified(()))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn unavailable_server_learns_nothing() {
        let cache = cache();
        let alice = key("alice");
        for _ in 0..5 {
            let result: Result<Login<()>, _> = cache
                .authenticate(&alice, POD, "pw", || async {
                    Verification::Unavailable(())
                })
                .await;
            assert_eq!(result.unwrap_err(), AuthError::Unavailable(()));
        }
        assert!(cache.get(&alice).is_none());
        assert!(matches!(
            login(&cache, &alice, "pw", "pw").await,
            Ok(Login::Verified(()))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn rejection_of_the_cached_password_drops_it() {
        let cache = cache();
        let alice = key("alice");
        login(&cache, &alice, "old", "old").await.unwrap();
        tokio::time::advance(Duration::from_secs(601)).await;
        assert!(login(&cache, &alice, "old", "new").await.is_err());
        assert!(cache.get(&alice).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_logins_verify_once() {
        let cache = Arc::new(cache());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let cache = cache.clone();
                let calls = calls.clone();
                tokio::spawn(async move {
                    cache
                        .authenticate(&key("alice"), POD, "pw", || async move {
                            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            Verification::<(), ()>::Accepted(keys(), ())
                        })
                        .await
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(cache.inflight.lock().unwrap().is_empty());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Login { user: u8, password: u8 },
        ChangePassword { user: u8, password: u8 },
        Advance { secs: u16 },
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0..3u8, 0..3u8).prop_map(|(user, password)| Op::Login { user, password }),
            1 => (0..3u8, 0..3u8).prop_map(|(user, password)| Op::ChangePassword { user, password }),
            1 => (0..700u16).prop_map(|secs| Op::Advance { secs }),
        ]
    }

    proptest! {
        /// A login succeeds only with the password the server holds for exactly that user, or
        /// with the one it accepted for that user within the TTL.
        #[test]
        fn accepted_passwords_were_accepted_by_the_server(ops in proptest::collection::vec(op(), 1..60)) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
            rt.block_on(async {
                let ttl = Duration::from_secs(600);
                let window = Duration::from_secs(60);
                let cache = AuthCache::new(ttl, 1000, window);
                let mut server = [0u8, 1, 2];
                // Per user: the last password the server accepted, and when.
                let mut accepted: [Option<(u8, Instant)>; 3] = [None; 3];
                // Per user: passwords the server rejected, and when.
                let mut rejected: [Vec<(u8, Instant)>; 3] = Default::default();
                for op in ops {
                    match op {
                        Op::Login { user, password } => {
                            let u = user as usize;
                            let result = login(&cache, &key(&user.to_string()), &password.to_string(), &server[u].to_string()).await;
                            match result {
                                Ok(Login::Verified(())) => {
                                    prop_assert_eq!(password, server[u]);
                                    accepted[u] = Some((password, Instant::now()));
                                }
                                Ok(Login::Cached) => {
                                    let (p, at) = accepted[u].expect("cached login without a verification");
                                    prop_assert_eq!(p, password);
                                    prop_assert!(at.elapsed() < ttl);
                                }
                                Err(AuthError::RejectedBefore) => {
                                    prop_assert!(rejected[u].iter().any(|&(p, at)| p == password && at.elapsed() < window));
                                }
                                Err(_) => {
                                    prop_assert_ne!(password, server[u]);
                                    rejected[u].push((password, Instant::now()));
                                    if accepted[u].is_some_and(|(p, _)| p == password) {
                                        accepted[u] = None;
                                    }
                                }
                            }
                        }
                        Op::ChangePassword { user, password } => server[user as usize] = password,
                        Op::Advance { secs } => tokio::time::advance(Duration::from_secs(secs.into())).await,
                    }
                }
                Ok(())
            })?;
        }
    }
}
