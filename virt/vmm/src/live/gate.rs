//! Reversible admission fence for host entry points that start guest sessions,
//! open forward connections, mutate the guest filesystem, register forwards or
//! write serial/session input. Pause closes it synchronously with admission,
//! drains the permits it already granted and reopens it only after the guest
//! is Running again. Stop closes it permanently.
//!
//! ```text
//!   open ──close()──► closed ──drain()──► drained ──reopen()──► open
//!     │                  │                                 
//!     └──── seal() ──────┴────────► sealed (stop, never reopens)
//! ```
//!
//! A permit covers accepted setup or one mutation until its worker completes,
//! never the lifetime of a long-running workload, stream or listener.
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateKind {
    ExecSession,
    SshSession,
    VsockSession,
    FilesystemMutation,
    ForwardRegistration,
    ForwardConnection,
    VsockRegistration,
    SerialInput,
    SessionInput,
}

impl GateKind {
    fn label(self) -> &'static str {
        match self {
            Self::ExecSession => "new execution sessions",
            Self::SshSession => "new SSH sessions",
            Self::VsockSession => "new vsock sessions",
            Self::FilesystemMutation => "guest filesystem mutations",
            Self::ForwardRegistration => "forward registrations",
            Self::ForwardConnection => "new forward connections",
            Self::VsockRegistration => "vsock listener registrations",
            Self::SerialInput => "serial input",
            Self::SessionInput => "session input",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateRefusal {
    /// A live lifecycle operation holds the fence; it may reopen.
    Fenced(GateKind),
    /// The monitor is stopping; it never reopens.
    Sealed(GateKind),
}

impl std::fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fenced(kind) => write!(
                f,
                "{} are fenced while a live lifecycle operation holds the machine",
                kind.label()
            ),
            Self::Sealed(kind) => write!(f, "{} are closed: monitor is stopping", kind.label()),
        }
    }
}

impl GateRefusal {
    pub(crate) fn status(self) -> tonic::Status {
        match self {
            Self::Fenced(_) => protocol::status_with_error(
                tonic::Code::FailedPrecondition,
                protocol::v1::ErrorCode::PreconditionFailed,
                self.to_string(),
                None,
            ),
            Self::Sealed(_) => protocol::status_with_error(
                tonic::Code::Unavailable,
                protocol::v1::ErrorCode::MonitorStopping,
                self.to_string(),
                None,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Open,
    Closed,
    Sealed,
}

#[derive(Debug)]
struct GateState {
    admission: Admission,
    active: u64,
}

/// Published view: the admission and the number of outstanding permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateView {
    admission: Admission,
    active: u64,
}

#[derive(Debug)]
pub(crate) struct LiveGate {
    state: Mutex<GateState>,
    view: watch::Sender<GateView>,
}

/// Outstanding admitted work. Dropping it is the drain evidence.
#[derive(Debug)]
pub(crate) struct GatePermit {
    gate: Arc<LiveGate>,
}

impl Drop for GatePermit {
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        state.active = state.active.saturating_sub(1);
        self.gate.publish(&state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainError {
    TimedOut { outstanding: u64 },
    Sealed,
}

impl Default for LiveGate {
    fn default() -> Self {
        let state = GateState {
            admission: Admission::Open,
            active: 0,
        };
        let (view, _) = watch::channel(GateView {
            admission: state.admission,
            active: state.active,
        });
        Self {
            state: Mutex::new(state),
            view,
        }
    }
}

impl LiveGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        // The state is two plain values updated atomically under the lock; a
        // panicking holder cannot leave it half-written.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, state: &GateState) {
        self.view.send_replace(GateView {
            admission: state.admission,
            active: state.active,
        });
    }

    /// Admit one unit of work now or refuse it.
    pub(crate) fn try_admit(self: &Arc<Self>, kind: GateKind) -> Result<GatePermit, GateRefusal> {
        let mut state = self.lock();
        match state.admission {
            Admission::Open => {}
            Admission::Closed => return Err(GateRefusal::Fenced(kind)),
            Admission::Sealed => return Err(GateRefusal::Sealed(kind)),
        }
        state.active = state.active.saturating_add(1);
        self.publish(&state);
        Ok(GatePermit { gate: self.clone() })
    }

    /// Resolves once admission closes or seals, for streamed ingress that
    /// must abort instead of delaying the drain.
    pub(crate) async fn closed(&self) {
        let mut view = self.view.subscribe();
        let _ = view
            .wait_for(|view| view.admission != Admission::Open)
            .await;
    }

    /// Admit once the fence reopens. Used for input that must not be lost or
    /// written while fenced. Fails only once the gate is sealed.
    pub(crate) async fn admit(self: &Arc<Self>, kind: GateKind) -> Result<GatePermit, GateRefusal> {
        let mut view = self.view.subscribe();
        loop {
            match self.try_admit(kind) {
                Ok(permit) => return Ok(permit),
                Err(GateRefusal::Sealed(kind)) => return Err(GateRefusal::Sealed(kind)),
                Err(GateRefusal::Fenced(_)) => {}
            }
            if view
                .wait_for(|view| view.admission != Admission::Closed)
                .await
                .is_err()
            {
                return Err(GateRefusal::Sealed(kind));
            }
        }
    }

    /// Close admission. Returns false when already sealed.
    pub(crate) fn close(&self) -> bool {
        let mut state = self.lock();
        if state.admission == Admission::Sealed {
            return false;
        }
        state.admission = Admission::Closed;
        self.publish(&state);
        true
    }

    /// Reopen after a lifecycle operation settled Running. Never unseals.
    pub(crate) fn reopen(&self) -> bool {
        let mut state = self.lock();
        if state.admission == Admission::Sealed {
            return false;
        }
        state.admission = Admission::Open;
        self.publish(&state);
        true
    }

    /// Permanently close admission (stop).
    pub(crate) fn seal(&self) {
        let mut state = self.lock();
        state.admission = Admission::Sealed;
        self.publish(&state);
    }

    #[cfg(test)]
    pub(crate) fn is_open(&self) -> bool {
        self.lock().admission == Admission::Open
    }

    /// Wait until every permit granted before the close has been dropped.
    pub(crate) async fn drain(&self, deadline: tokio::time::Instant) -> Result<(), DrainError> {
        let mut view = self.view.subscribe();
        let drained = tokio::time::timeout_at(
            deadline,
            view.wait_for(|view| view.active == 0 || view.admission == Admission::Sealed),
        )
        .await;
        match drained {
            Ok(Ok(view)) if view.admission == Admission::Sealed => Err(DrainError::Sealed),
            Ok(Ok(_)) => Ok(()),
            Ok(Err(_)) => Err(DrainError::Sealed),
            Err(_) => Err(DrainError::TimedOut {
                outstanding: self.lock().active,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::live::gate::{DrainError, GateKind, GateRefusal, LiveGate};

    #[tokio::test]
    async fn close_refuses_new_work_and_drain_waits_for_admitted_work() {
        let gate = LiveGate::new();
        let admitted = gate.try_admit(GateKind::FilesystemMutation).unwrap();
        assert!(gate.close());
        assert_eq!(
            gate.try_admit(GateKind::ExecSession).unwrap_err(),
            GateRefusal::Fenced(GateKind::ExecSession)
        );
        let short = tokio::time::Instant::now() + Duration::from_millis(20);
        assert_eq!(
            gate.drain(short).await,
            Err(DrainError::TimedOut { outstanding: 1 })
        );
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            drop(admitted);
        });
        gate.drain(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        release.await.unwrap();
        assert!(gate.reopen());
        drop(gate.try_admit(GateKind::ExecSession).unwrap());
    }

    #[tokio::test]
    async fn waiting_input_is_admitted_only_after_reopen_and_sealing_is_final() {
        let gate = LiveGate::new();
        gate.close();
        let waiter = tokio::spawn({
            let gate = gate.clone();
            async move { gate.admit(GateKind::SerialInput).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiter.is_finished());
        gate.reopen();
        waiter.await.unwrap().unwrap();

        gate.close();
        let sealed = tokio::spawn({
            let gate = gate.clone();
            async move { gate.admit(GateKind::SessionInput).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        gate.seal();
        assert_eq!(
            sealed.await.unwrap().unwrap_err(),
            GateRefusal::Sealed(GateKind::SessionInput)
        );
        assert!(!gate.reopen());
        assert!(!gate.close());
        assert!(!gate.is_open());
        assert_eq!(
            gate.drain(tokio::time::Instant::now() + Duration::from_secs(1))
                .await,
            Err(DrainError::Sealed)
        );
    }

    #[tokio::test]
    async fn streamed_ingress_observes_the_fence_closing() {
        let gate = LiveGate::new();
        let permit = gate.try_admit(GateKind::FilesystemMutation).unwrap();
        let revoked = tokio::spawn({
            let gate = gate.clone();
            async move {
                gate.closed().await;
                drop(permit);
            }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!revoked.is_finished());
        gate.close();
        revoked.await.unwrap();
        gate.drain(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
    }
}
