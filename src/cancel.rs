//! Cancel keys. Each client gets a synthetic `BackendKeyData`; a `CancelRequest` carrying it is
//! forwarded to the server connection the client holds at that moment, and to nothing else.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rand::{Rng, RngExt};
use subtle::ConstantTimeEq;

/// The real cancel key of a server connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCancelKey {
    pub addr: SocketAddr,
    pub process_id: i32,
    pub secret: Vec<u8>,
}

struct Attached {
    key: ServerCancelKey,
    cancelled: bool,
}

#[derive(Default)]
struct Target {
    attached: Mutex<Option<Attached>>,
}

struct Entry {
    secret: [u8; 4],
    target: Arc<Target>,
}

#[derive(Default)]
pub struct CancelRegistry {
    entries: Mutex<HashMap<i32, Entry>>,
}

/// A client's registration; dropping it unregisters the key.
pub struct CancelHandle {
    registry: Arc<CancelRegistry>,
    process_id: i32,
    secret: [u8; 4],
    target: Arc<Target>,
}

impl CancelRegistry {
    pub fn register(self: &Arc<Self>) -> CancelHandle {
        let mut rng = rand::rng();
        let mut entries = self.entries.lock().expect("cancel registry poisoned");
        let process_id = loop {
            let candidate = rng.random_range(1..=i32::MAX);
            if !entries.contains_key(&candidate) {
                break candidate;
            }
        };
        let mut secret = [0u8; 4];
        rng.fill_bytes(&mut secret);
        let target = Arc::new(Target::default());
        entries.insert(
            process_id,
            Entry {
                secret,
                target: target.clone(),
            },
        );
        CancelHandle {
            registry: self.clone(),
            process_id,
            secret,
            target,
        }
    }

    /// Resolves a client's cancel request to the server connection it holds right now, and
    /// marks that connection so it is closed rather than returned to its pool: the cancel
    /// signal may otherwise reach the server after another client took the connection over.
    pub fn cancel(&self, process_id: i32, secret: &[u8]) -> Option<ServerCancelKey> {
        let entries = self.entries.lock().expect("cancel registry poisoned");
        let entry = entries.get(&process_id)?;
        if !bool::from(entry.secret.as_slice().ct_eq(secret)) {
            return None;
        }
        let mut attached = entry
            .target
            .attached
            .lock()
            .expect("cancel target poisoned");
        let attached = attached.as_mut()?;
        attached.cancelled = true;
        Some(attached.key.clone())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("cancel registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CancelHandle {
    pub fn process_id(&self) -> i32 {
        self.process_id
    }

    pub fn secret(&self) -> &[u8; 4] {
        &self.secret
    }

    /// The client now holds the server connection with `key`.
    pub fn attach(&self, key: ServerCancelKey) {
        *self.target.attached.lock().expect("cancel target poisoned") = Some(Attached {
            key,
            cancelled: false,
        });
    }

    /// The client gives its server connection back. Returns whether a cancel was sent to it,
    /// in which case the connection must not be reused.
    pub fn detach(&self) -> bool {
        self.target
            .attached
            .lock()
            .expect("cancel target poisoned")
            .take()
            .is_some_and(|attached| attached.cancelled)
    }
}

impl Drop for CancelHandle {
    fn drop(&mut self) {
        self.registry
            .entries
            .lock()
            .expect("cancel registry poisoned")
            .remove(&self.process_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn server_key(n: i32) -> ServerCancelKey {
        ServerCancelKey {
            addr: "127.0.0.1:5432".parse().unwrap(),
            process_id: n,
            secret: vec![n as u8; 4],
        }
    }

    #[test]
    fn cancel_reaches_only_the_attached_connection() {
        let registry = Arc::new(CancelRegistry::default());
        let client = registry.register();
        assert_eq!(registry.cancel(client.process_id(), client.secret()), None);
        client.attach(server_key(7));
        let mut wrong = *client.secret();
        wrong[0] ^= 1;
        assert_eq!(registry.cancel(client.process_id(), &wrong), None);
        assert_eq!(
            registry.cancel(client.process_id(), client.secret()),
            Some(server_key(7))
        );
        assert!(client.detach());
        assert_eq!(registry.cancel(client.process_id(), client.secret()), None);
        client.attach(server_key(8));
        assert!(!client.detach());
    }

    #[test]
    fn dropped_handles_unregister() {
        let registry = Arc::new(CancelRegistry::default());
        let client = registry.register();
        let (process_id, secret) = (client.process_id(), *client.secret());
        client.attach(server_key(1));
        drop(client);
        assert_eq!(registry.cancel(process_id, &secret), None);
        assert!(registry.is_empty());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Register,
        Drop(usize),
        Attach(usize, i32),
        Detach(usize),
        Cancel {
            client: usize,
            forge_pid: bool,
            forge_secret: bool,
        },
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            Just(Op::Register),
            any::<usize>().prop_map(Op::Drop),
            (any::<usize>(), 1..1000i32).prop_map(|(c, k)| Op::Attach(c, k)),
            any::<usize>().prop_map(Op::Detach),
            (any::<usize>(), any::<bool>(), any::<bool>()).prop_map(
                |(client, forge_pid, forge_secret)| Op::Cancel {
                    client,
                    forge_pid,
                    forge_secret
                }
            ),
        ]
    }

    proptest! {
        /// A cancel resolves only for the exact key of a live client, only to the connection that
        /// client holds, and that connection is then never reported reusable.
        #[test]
        fn cancel_keys_map_only_to_their_own_client(ops in proptest::collection::vec(op(), 1..80)) {
            let registry = Arc::new(CancelRegistry::default());
            let mut clients: Vec<(CancelHandle, Option<(i32, bool)>)> = Vec::new();
            for op in ops {
                match op {
                    Op::Register => clients.push((registry.register(), None)),
                    Op::Drop(i) if !clients.is_empty() => { clients.remove(i % clients.len()); }
                    Op::Attach(i, k) if !clients.is_empty() => {
                        let n = clients.len();
                        let (handle, attached) = &mut clients[i % n];
                        handle.attach(server_key(k));
                        *attached = Some((k, false));
                    }
                    Op::Detach(i) if !clients.is_empty() => {
                        let n = clients.len();
                        let (handle, attached) = &mut clients[i % n];
                        let cancelled = attached.take().is_some_and(|(_, c)| c);
                        prop_assert_eq!(handle.detach(), cancelled);
                    }
                    Op::Cancel { client, forge_pid, forge_secret } if !clients.is_empty() => {
                        let n = clients.len();
                        let (handle, attached) = &mut clients[client % n];
                        let pid = if forge_pid { handle.process_id().wrapping_add(1).max(1) } else { handle.process_id() };
                        let mut secret = *handle.secret();
                        if forge_secret { secret[3] ^= 0x80; }
                        let result = registry.cancel(pid, &secret);
                        if forge_secret {
                            // A forged secret matches no live client, whichever pid it names.
                            prop_assert_eq!(result, None);
                        } else if !forge_pid {
                            prop_assert_eq!(result.clone(), attached.map(|(k, _)| server_key(k)));
                            if let Some((_, cancelled)) = attached { *cancelled = true; }
                        } else if let Some(key) = result {
                            // A pid that happens to belong to another client needs that client's secret.
                            let owner = clients.iter().find(|(h, _)| h.process_id() == pid);
                            prop_assert!(owner.is_some_and(|(h, a)| *h.secret() == secret && a.map(|(k, _)| server_key(k)) == Some(key)));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
