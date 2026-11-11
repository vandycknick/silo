use std::{collections::HashMap, fmt, future::Future, sync::Arc};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::identity::{Peer, Principal};
use crate::lobby::metrics::Metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OperationState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl OperationState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for OperationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Operation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) completion: Option<Completion>,
    pub(crate) id: String,
    pub(crate) kind: String,
    pub(crate) vm: String,
    pub(crate) principal: Principal,
    pub(crate) state: OperationState,
    pub(crate) started: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finished: Option<DateTime<Utc>>,
    pub(crate) progress: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<Failure>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Completion {
    pub(crate) vm_id: String,
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) user: String,
    pub(crate) running: bool,
    pub(crate) node_state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) node: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) approval_url: String,
}

pub(crate) type Progress = Arc<dyn Fn(String) + Send + Sync>;

struct Entry {
    operation: Operation,
    changed: watch::Sender<()>,
}

struct VmLock {
    mutex: Arc<AsyncMutex<()>>,
    refs: usize,
}

#[derive(Default)]
struct State {
    closing: bool,
    active: usize,
    entries: HashMap<String, Entry>,
    locks: HashMap<String, VmLock>,
}

struct Inner {
    cancel: CancellationToken,
    limit: usize,
    metrics: Arc<Metrics>,
    state: Mutex<State>,
    active: watch::Sender<usize>,
}

#[derive(Clone)]
pub(crate) struct Registry {
    inner: Arc<Inner>,
}

struct LockReservation {
    inner: Arc<Inner>,
    key: String,
    mutex: Arc<AsyncMutex<()>>,
}

impl LockReservation {
    fn acquire(inner: &Arc<Inner>, state: &mut State, key: String) -> Self {
        let lock = state.locks.entry(key.clone()).or_insert_with(|| VmLock {
            mutex: Arc::new(AsyncMutex::new(())),
            refs: 0,
        });
        lock.refs += 1;
        Self {
            inner: inner.clone(),
            key,
            mutex: lock.mutex.clone(),
        }
    }
}

impl Drop for LockReservation {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock();
        if let Some(lock) = state.locks.get_mut(&self.key) {
            lock.refs -= 1;
            if lock.refs == 0 {
                state.locks.remove(&self.key);
            }
        }
    }
}

struct Finalize<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Finalize<F> {
    fn run(&mut self) {
        if let Some(finalize) = self.0.take() {
            finalize();
        }
    }
}
impl<F: FnOnce()> Drop for Finalize<F> {
    fn drop(&mut self) {
        self.run();
    }
}

impl Registry {
    pub(crate) fn new(cancel: CancellationToken, limit: usize, metrics: Arc<Metrics>) -> Self {
        let (active, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                cancel,
                limit,
                metrics,
                state: Mutex::new(State::default()),
                active,
            }),
        }
    }

    pub(crate) fn metrics(&self) -> &Arc<Metrics> {
        &self.inner.metrics
    }

    pub(crate) fn submit_result<R, Fut, F>(
        &self,
        kind: impl Into<String>,
        vm: impl Into<String>,
        owner: Principal,
        run: R,
        finalize: F,
    ) -> Outcome<Operation>
    where
        R: FnOnce(CancellationToken, Progress) -> Fut + Send + 'static,
        Fut: Future<Output = Outcome<Option<Completion>>> + Send + 'static,
        F: FnOnce() + Send + 'static,
    {
        let mut finalize = Finalize(Some(finalize));
        let kind = kind.into();
        let vm = vm.into();
        let (operation, reservation) = {
            let mut state = self.inner.state.lock();
            if state.closing || self.inner.cancel.is_cancelled() {
                return Err(Failure::new(Code::Unavailable, "daemon is shutting down"));
            }
            if state.active >= self.inner.limit {
                return Err(Failure::new(
                    Code::Limit,
                    "operation admission limit reached",
                ));
            }
            let now = Utc::now();
            let id = new_id(now)?;
            prune(&mut state, now);
            let operation = Operation {
                completion: None,
                id: id.clone(),
                kind,
                vm,
                principal: owner,
                state: OperationState::Queued,
                started: now,
                finished: None,
                progress: Vec::new(),
                error: None,
            };
            let key = if operation.kind == "create" {
                id.clone()
            } else {
                operation.vm.clone()
            };
            let reservation = LockReservation::acquire(&self.inner, &mut state, key);
            let (changed, _) = watch::channel(());
            state.entries.insert(
                id,
                Entry {
                    operation: operation.clone(),
                    changed,
                },
            );
            state.active += 1;
            self.inner.metrics.job(1);
            self.inner.active.send_replace(state.active);
            (operation, reservation)
        };
        let inner = self.inner.clone();
        let id = operation.id.clone();
        let started = std::time::Instant::now();
        tokio::spawn(async move {
            let cancel = inner.cancel.child_token();
            let result = {
                let locked = tokio::select! {
                    biased;
                    () = cancel.cancelled() => None,
                    guard = reservation.mutex.lock() => Some(guard),
                };
                if let Some(guard) = locked {
                    let result = if cancel.is_cancelled() {
                        Err(interrupted())
                    } else {
                        update(&inner, &id, |op| op.state = OperationState::Running);
                        let progress_inner = inner.clone();
                        let progress_id = id.clone();
                        let progress: Progress = Arc::new(move |mut line| {
                            if line.len() > 1024 {
                                let mut end = 1024;
                                while !line.is_char_boundary(end) {
                                    end -= 1;
                                }
                                line.truncate(end);
                            }
                            update(&progress_inner, &progress_id, |op| {
                                if op.progress.len() == 128 {
                                    op.progress.remove(0);
                                }
                                op.progress.push(line);
                            });
                        });
                        let result = run(cancel.clone(), progress).await;
                        if cancel.is_cancelled() {
                            Err(interrupted())
                        } else {
                            result
                        }
                    };
                    drop(guard);
                    result
                } else {
                    Err(interrupted())
                }
            };
            finalize.run();
            drop(reservation);
            let mut state = inner.state.lock();
            if let Some(entry) = state.entries.get_mut(&id) {
                match result {
                    Ok(completion) => {
                        entry.operation.state = OperationState::Succeeded;
                        entry.operation.completion = completion;
                    }
                    Err(error) => {
                        entry.operation.state = OperationState::Failed;
                        entry.operation.error = Some(error);
                    }
                }
                entry.operation.finished = Some(Utc::now());
                inner.metrics.operation(
                    &entry.operation.kind,
                    entry.operation.state.as_str(),
                    started.elapsed(),
                );
                entry.changed.send_replace(());
            }
            state.active -= 1;
            inner.metrics.job(-1);
            inner.active.send_replace(state.active);
        });
        Ok(operation)
    }

    pub(crate) async fn with_vm<R, Fut, T>(
        &self,
        cancel: &CancellationToken,
        id: &str,
        run: R,
    ) -> Outcome<T>
    where
        R: FnOnce() -> Fut,
        Fut: Future<Output = Outcome<T>>,
    {
        let reservation = {
            let mut state = self.inner.state.lock();
            LockReservation::acquire(&self.inner, &mut state, id.to_owned())
        };
        let _guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Failure::new(Code::Cancelled, "operation cancelled")),
            guard = reservation.mutex.lock() => guard,
        };
        run().await
    }

    pub(crate) fn list(&self, peer: &Peer) -> Vec<Operation> {
        let mut state = self.inner.state.lock();
        prune(&mut state, Utc::now());
        let mut operations: Vec<_> = state
            .entries
            .values()
            .filter(|entry| peer.owns(&entry.operation.principal))
            .map(|entry| entry.operation.clone())
            .collect();
        operations.sort_by_key(|op| op.started);
        operations
    }

    pub(crate) fn observe(
        &self,
        peer: &Peer,
        id: &str,
    ) -> Outcome<(Operation, watch::Receiver<()>)> {
        let mut state = self.inner.state.lock();
        prune(&mut state, Utc::now());
        let entry = state
            .entries
            .get(id)
            .filter(|entry| peer.owns(&entry.operation.principal))
            .ok_or_else(|| Failure::new(Code::NotFound, "operation not found"))?;
        Ok((entry.operation.clone(), entry.changed.subscribe()))
    }

    pub(crate) async fn drained(&self) {
        let mut active = self.inner.active.subscribe();
        loop {
            if *active.borrow_and_update() == 0 {
                return;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }

    pub(crate) async fn wait(&self, cancel: &CancellationToken) -> Outcome<()> {
        self.inner.state.lock().closing = true;
        tokio::select! {
            biased;
            () = self.drained() => Ok(()),
            () = cancel.cancelled() => Err(Failure::new(Code::Cancelled, "operation drain cancelled")),
        }
    }
}

fn update(inner: &Inner, id: &str, change: impl FnOnce(&mut Operation)) {
    let mut state = inner.state.lock();
    if let Some(entry) = state.entries.get_mut(id) {
        change(&mut entry.operation);
        entry.changed.send_replace(());
    }
}

fn prune(state: &mut State, now: DateTime<Utc>) {
    state.entries.retain(|_, entry| {
        entry.operation.finished.is_none_or(|finished| {
            now.signed_duration_since(finished) < chrono::Duration::hours(24)
        })
    });
}

fn interrupted() -> Failure {
    Failure::new(
        Code::Unavailable,
        "daemon operation interrupted; inspect VM state",
    )
}

fn new_id(now: DateTime<Utc>) -> Outcome<String> {
    let milliseconds = now.timestamp_millis();
    if !(0..1_i64 << 48).contains(&milliseconds) {
        return Err(Failure::new(
            Code::Unavailable,
            "ULID timestamp out of range",
        ));
    }
    let entropy = uuid::Uuid::new_v4();
    let mut raw = [0_u8; 16];
    raw[..6].copy_from_slice(&milliseconds.to_be_bytes()[2..]);
    // The first six UUID bytes precede its version/variant bits; its last four
    // bytes are also entirely random, preserving all 80 entropy bits.
    raw[6..12].copy_from_slice(&entropy.as_bytes()[..6]);
    raw[12..].copy_from_slice(&entropy.as_bytes()[12..]);
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut id = String::with_capacity(29);
    id.push_str("op_");
    let value = u128::from_be_bytes(raw);
    for index in (0..26).rev() {
        id.push(char::from(ALPHABET[((value >> (index * 5)) & 31) as usize]));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use crate::lobby::failure::Code;
    use crate::lobby::identity::{Peer, Principal};
    use crate::lobby::jobs::{new_id, Completion, Operation, OperationState, Registry};
    use std::{
        collections::HashSet,
        future::Future,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    fn submit<R, Fut>(
        registry: &Registry,
        kind: &str,
        vm: &str,
        owner: Principal,
        run: R,
    ) -> crate::lobby::failure::Outcome<Operation>
    where
        R: FnOnce(CancellationToken, crate::lobby::jobs::Progress) -> Fut + Send + 'static,
        Fut: Future<Output = crate::lobby::failure::Outcome<()>> + Send + 'static,
    {
        registry.submit_result(
            kind,
            vm,
            owner,
            move |cancel, progress| async move {
                run(cancel, progress).await?;
                Ok(None)
            },
            || {},
        )
    }

    fn owner() -> Principal {
        Principal::parse("user:1").unwrap()
    }
    fn peer() -> Peer {
        Peer {
            principals: vec![owner()],
            ..Peer::default()
        }
    }
    async fn finished(registry: &Registry, id: &str) -> Operation {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (operation, mut changed) = registry.observe(&peer(), id).unwrap();
                if operation.finished.is_some() {
                    return operation;
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }

    #[test]
    fn canonical_crypto_ulid() {
        let now = chrono::DateTime::from_timestamp_millis(1_770_000_000_123).unwrap();
        let mut seen = HashSet::new();
        let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        for _ in 0..1000 {
            let id = new_id(now).unwrap();
            assert_eq!(id.len(), 29);
            assert!(id.starts_with("op_"));
            assert!(id.as_bytes()[3] <= b'7');
            assert!(seen.insert(id.clone()));
            let mut value = 0_u128;
            for c in id[3..].chars() {
                let digit = alphabet.find(c).unwrap() as u128;
                assert!(value <= u128::MAX >> 5);
                value = (value << 5) | digit;
            }
            assert_eq!(value >> 80, now.timestamp_millis() as u128);
        }
        assert!(new_id(chrono::DateTime::from_timestamp_millis(-1).unwrap()).is_err());
        assert!(new_id(chrono::DateTime::from_timestamp_millis(1_i64 << 48).unwrap()).is_err());
    }

    #[tokio::test]
    async fn empty_registry_wait_closes_admission() {
        let registry = Registry::new(
            CancellationToken::new(),
            1,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        );
        assert!(registry.list(&peer()).is_empty());
        registry.wait(&CancellationToken::new()).await.unwrap();
        assert!(registry.inner.state.lock().closing);
        assert_eq!(
            submit(&registry, "start", "vm", owner(), |_, _| async { Ok(()) })
                .unwrap_err()
                .code,
            Code::Unavailable
        );
    }

    #[tokio::test]
    async fn detached_serialization_admission_visibility_and_expiry() {
        let registry = Registry::new(
            CancellationToken::new(),
            2,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        );
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let a = submit(
            &registry,
            "start",
            "vm",
            owner(),
            move |_, progress| async move {
                entered_tx.send(()).unwrap();
                release_rx.await.unwrap();
                for _ in 0..150 {
                    progress("real milestone".into());
                }
                progress("é".repeat(1024));
                Ok(())
            },
        )
        .unwrap();
        entered_rx.await.unwrap();
        let (second_tx, mut second_rx) = oneshot::channel();
        let b = submit(&registry, "stop", "vm", owner(), move |_, _| async move {
            second_tx.send(()).unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(
            submit(&registry, "overflow", "other", owner(), |_, _| async {
                Ok(())
            })
            .unwrap_err()
            .code,
            Code::Limit
        );
        assert!(matches!(
            second_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(registry
            .metrics()
            .render()
            .contains("lobby_active_operations 2\n"));
        let other = Peer {
            principals: vec![Principal::parse("user:2").unwrap()],
            ..Peer::default()
        };
        assert_eq!(
            registry.observe(&other, &a.id).unwrap_err().code,
            Code::NotFound
        );
        assert!(registry.list(&other).is_empty());
        drop(registry.observe(&peer(), &a.id).unwrap());
        release_tx.send(()).unwrap();
        let completed = finished(&registry, &a.id).await;
        assert_eq!(completed.state, OperationState::Succeeded);
        assert_eq!(completed.progress.len(), 128);
        assert_eq!(completed.progress.last().unwrap().len(), 1024);
        assert_eq!(
            finished(&registry, &b.id).await.state,
            OperationState::Succeeded
        );
        registry
            .inner
            .state
            .lock()
            .entries
            .get_mut(&a.id)
            .unwrap()
            .operation
            .finished = Some(chrono::Utc::now() - chrono::Duration::hours(25));
        assert_eq!(
            registry.observe(&peer(), &a.id).unwrap_err().code,
            Code::NotFound
        );
        registry.wait(&CancellationToken::new()).await.unwrap();
        assert!(registry.inner.state.lock().locks.is_empty());
        let metrics = registry.metrics().render();
        assert!(metrics.contains("lobby_active_operations 0\n"));
        for kind in ["start", "stop"] {
            assert!(metrics.contains(&format!(
                "lobby_operations_total{{kind=\"{kind}\",outcome=\"succeeded\"}} 1\n"
            )));
            assert!(metrics.contains(&format!("lobby_operation_duration_seconds_count{{kind=\"{kind}\",outcome=\"succeeded\"}} 1\n")));
        }
    }

    #[tokio::test]
    async fn daemon_cancellation_releases_queued_lock_and_runs_finalizer() {
        let cancel = CancellationToken::new();
        let registry = Registry::new(
            cancel.clone(),
            2,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        );
        let (entered_tx, entered_rx) = oneshot::channel();
        let (hold_tx, hold_rx) = oneshot::channel();
        let a = submit(&registry, "start", "vm", owner(), move |_, _| async move {
            entered_tx.send(()).unwrap();
            hold_rx.await.unwrap();
            Ok(())
        })
        .unwrap();
        entered_rx.await.unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = called.clone();
        let (finalized_tx, finalized_rx) = oneshot::channel();
        let b = registry
            .submit_result(
                "set",
                "vm",
                owner(),
                move |_, _| async move {
                    callback_called.store(true, Ordering::SeqCst);
                    Ok(None)
                },
                move || {
                    finalized_tx.send(()).unwrap();
                },
            )
            .unwrap();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), finalized_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(
            finished(&registry, &b.id).await.state,
            OperationState::Failed
        );
        hold_tx.send(()).unwrap();
        assert_eq!(finished(&registry, &a.id).await.error.unwrap().exit, 9);
        registry.wait(&CancellationToken::new()).await.unwrap();
        let metrics = registry.metrics().render();
        assert!(metrics.contains("lobby_active_operations 0\n"));
        for kind in ["start", "set"] {
            assert!(metrics.contains(&format!(
                "lobby_operations_total{{kind=\"{kind}\",outcome=\"failed\"}} 1\n"
            )));
        }
        let state = registry.inner.state.lock();
        assert_eq!(state.active, 0);
        assert!(state.locks.is_empty());
    }

    #[tokio::test]
    async fn completion_is_an_immutable_snapshot_and_finalizer_precedes_publication() {
        let registry = Registry::new(
            CancellationToken::new(),
            1,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        );
        let completion = Completion {
            vm_id: "id".into(),
            name: "original".into(),
            approval_url: "https://login.tailscale.com/a/example".into(),
            ..Completion::default()
        };
        let result = completion.clone();
        let finalized = Arc::new(AtomicBool::new(false));
        let callback = finalized.clone();
        let operation = registry
            .submit_result(
                "create",
                "original",
                owner(),
                move |_, _| async move { Ok(Some(result)) },
                move || {
                    callback.store(true, Ordering::SeqCst);
                },
            )
            .unwrap();
        let mut first = finished(&registry, &operation.id).await;
        assert!(finalized.load(Ordering::SeqCst));
        assert_eq!(first.completion.as_ref().unwrap(), &completion);
        first.completion.as_mut().unwrap().name = "mutated-observation".into();
        assert_eq!(
            registry
                .observe(&peer(), &operation.id)
                .unwrap()
                .0
                .completion
                .unwrap()
                .name,
            "original"
        );
        let value = serde_json::to_value(first).unwrap();
        assert!(value.get("principal").is_some());
        assert!(value.get("error").is_none());
        assert_eq!(value["state"], "succeeded");
    }

    #[tokio::test]
    async fn rejected_admission_finalizes_once_and_drain_can_be_cancelled() {
        let registry = Registry::new(
            CancellationToken::new(),
            0,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        );
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let finalized = count.clone();
        assert!(registry
            .submit_result(
                "set",
                "vm",
                owner(),
                |_, _| async { Ok(None) },
                move || {
                    finalized.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let registry = Registry::new(
            CancellationToken::new(),
            1,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        );
        let (release_tx, release_rx) = oneshot::channel();
        submit(&registry, "start", "vm", owner(), |_, _| async move {
            release_rx.await.unwrap();
            Ok(())
        })
        .unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            registry.wait(&cancel).await.unwrap_err().code,
            Code::Cancelled
        );
        release_tx.send(()).unwrap();
        registry.drained().await;
    }

    #[tokio::test]
    async fn with_vm_serializes_and_cancellation_removes_lock_reservations() {
        let registry = Registry::new(
            CancellationToken::new(),
            1,
            Arc::new(crate::lobby::metrics::Metrics::new()),
        );
        let cancel = CancellationToken::new();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let holder = registry.clone();
        let task = tokio::spawn(async move {
            holder
                .with_vm(&CancellationToken::new(), "vm", || async move {
                    entered_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    Ok(())
                })
                .await
                .unwrap();
        });
        entered_rx.await.unwrap();
        cancel.cancel();
        assert_eq!(
            registry
                .with_vm(&cancel, "vm", || async { Ok(()) })
                .await
                .unwrap_err()
                .code,
            Code::Cancelled
        );
        release_tx.send(()).unwrap();
        task.await.unwrap();
        assert!(registry.inner.state.lock().locks.is_empty());
    }
}
