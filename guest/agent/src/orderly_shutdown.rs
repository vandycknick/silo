//! One in-memory bridge from the retained PID1 storage shutdown to its RPC.
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use protocol::shutdown::ShutdownIdentity;
use protocol::v1::{ShutdownCompleted, ShutdownCompletionResult};
use tokio::sync::watch;
use tonic::Status;

const RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct OrderlyShutdown {
    runtime: Arc<crate::lifecycle::RuntimeContext>,
    attempt: Mutex<Option<Attempt>>,
    receipt: Condvar,
}

struct Attempt {
    identity: ShutdownIdentity,
    unsupported: Option<String>,
    completion: watch::Sender<Option<ShutdownCompleted>>,
    terminal: bool,
    host_receipt: bool,
    disconnected: bool,
}

impl OrderlyShutdown {
    pub(crate) fn new(runtime: Arc<crate::lifecycle::RuntimeContext>) -> Arc<Self> {
        Arc::new(Self {
            runtime,
            attempt: Mutex::new(None),
            receipt: Condvar::new(),
        })
    }

    pub(crate) fn admit(
        &self,
        identity: ShutdownIdentity,
        manifest: &protocol::shutdown::StorageManifest,
        instance: &str,
        boot: &str,
        agent_pid1: bool,
    ) -> Result<watch::Receiver<Option<ShutdownCompleted>>, Status> {
        let context = self.runtime.identity().shutdown;
        identity
            .validate_context(&context)
            .map_err(Status::invalid_argument)?;
        if identity.agent_instance_id != instance || identity.boot_id != boot {
            return Err(Status::failed_precondition(
                "shutdown agent/boot identity mismatch",
            ));
        }
        if manifest != &context.manifest {
            return Err(Status::failed_precondition(
                "shutdown manifest differs from trusted launch inventory",
            ));
        }
        if !agent_pid1 {
            return Err(Status::unimplemented(
                "image-owned PID1 has no admitted storage shutdown authority",
            ));
        }
        let mut attempt = lock(&self.attempt);
        if attempt.is_some() {
            return Err(Status::already_exists(
                "an orderly shutdown attempt is already admitted",
            ));
        }
        let unsupported = manifest.unsupported_reason().or_else(|| {
            crate::root_storage::verify_mount_namespaces()
                .err()
                .map(|error| error.to_string())
        });
        let (completion, receiver) = watch::channel(None);
        *attempt = Some(Attempt {
            identity,
            unsupported,
            completion,
            terminal: false,
            host_receipt: false,
            disconnected: false,
        });
        Ok(receiver)
    }

    pub(crate) fn manifest(&self) -> protocol::shutdown::StorageManifest {
        self.runtime.identity().shutdown.manifest
    }

    /// Called only by the existing PID1 shutdown worker after all storage work.
    /// Completion and receipt are memory-only; the terminal path must not log.
    pub(crate) fn complete_and_wait(&self, result: eyre::Result<()>, coverage: Option<String>) {
        let mut attempt = lock(&self.attempt);
        let Some(active) = attempt.as_mut() else {
            return;
        };
        if active.terminal {
            return;
        }
        let completion = completion(result, active.unsupported.clone().or(coverage));
        active.terminal = true;
        let _ = active.completion.send_replace(Some(completion));
        let waited = self
            .receipt
            .wait_timeout_while(attempt, RECEIPT_TIMEOUT, |attempt| {
                attempt
                    .as_ref()
                    .is_some_and(|active| !active.host_receipt && !active.disconnected)
            });
        // A timeout or lost RPC permits poweroff, never fabricates host receipt.
        drop(waited);
    }

    pub(crate) fn allow_poweroff(&self, identity: &ShutdownIdentity) -> Result<(), Status> {
        let mut attempt = lock(&self.attempt);
        let active = attempt
            .as_mut()
            .ok_or_else(|| Status::failed_precondition("shutdown was not admitted"))?;
        if &active.identity != identity || !active.terminal {
            return Err(Status::failed_precondition(
                "poweroff receipt precedes completion or has wrong identity",
            ));
        }
        active.host_receipt = true;
        self.receipt.notify_all();
        Ok(())
    }

    fn disconnect(&self) {
        if let Some(active) = lock(&self.attempt).as_mut() {
            active.disconnected = true;
            self.receipt.notify_all();
        }
    }
}

pub(crate) struct ExchangeGuard(pub(crate) Arc<OrderlyShutdown>);
impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        self.0.disconnect();
    }
}

fn completion(result: eyre::Result<()>, unsupported: Option<String>) -> ShutdownCompleted {
    let (result, diagnostic) = match result {
        Err(error) => (ShutdownCompletionResult::Failed, Some(format!("{error:#}"))),
        Ok(()) => match unsupported {
            Some(reason) => (ShutdownCompletionResult::Unsupported, Some(reason)),
            None => (ShutdownCompletionResult::Succeeded, None),
        },
    };
    ShutdownCompleted {
        result: Some(result as i32),
        diagnostic: diagnostic.map(bounded_diagnostic),
    }
}

fn bounded_diagnostic(mut text: String) -> String {
    if text.contains('\0') {
        text = text.replace('\0', "\\0");
    }
    if text.trim().is_empty() {
        text = "guest shutdown failed without a diagnostic".to_owned();
    }
    let mut end = text.len().min(protocol::shutdown::MAX_DIAGNOSTIC_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    pub(crate) fn fixture() -> (
        std::sync::Arc<crate::orderly_shutdown::OrderlyShutdown>,
        protocol::shutdown::ShutdownIdentity,
    ) {
        let identity = protocol::shutdown::ShutdownIdentity {
            version: 1,
            machine_id: uuid::Uuid::new_v4().to_string(),
            run_id: uuid::Uuid::new_v4().to_string(),
            shutdown_id: uuid::Uuid::new_v4().to_string(),
            agent_instance_id: uuid::Uuid::new_v4().to_string(),
            boot_id: uuid::Uuid::new_v4().to_string(),
        };
        let context = protocol::shutdown::StorageShutdownContext {
            version: 1,
            machine_id: identity.machine_id.clone(),
            run_id: identity.run_id.clone(),
            manifest: protocol::shutdown::StorageManifest::Unsupported {
                reason: "unit state-machine inventory".into(),
            },
        };
        (
            crate::orderly_shutdown::OrderlyShutdown::new(
                crate::lifecycle::RuntimeContext::from_identity(
                    context,
                    identity.agent_instance_id.clone(),
                    identity.boot_id.clone(),
                ),
            ),
            identity,
        )
    }

    pub(crate) fn admit(
        owner: &crate::orderly_shutdown::OrderlyShutdown,
        identity: &protocol::shutdown::ShutdownIdentity,
    ) -> tokio::sync::watch::Receiver<Option<protocol::v1::ShutdownCompleted>> {
        owner
            .admit(
                identity.clone(),
                &owner.manifest(),
                &identity.agent_instance_id,
                &identity.boot_id,
                true,
            )
            .unwrap()
    }

    #[test]
    fn activation_rebinds_shutdown_to_destination_and_rejects_source_run() {
        let (owner, source) = fixture();
        let mut context = owner.runtime.identity().shutdown;
        context.machine_id = uuid::Uuid::new_v4().to_string();
        context.run_id = uuid::Uuid::new_v4().to_string();
        let destination = owner.runtime.rotate(context);
        assert!(owner
            .admit(
                source.clone(),
                &owner.manifest(),
                &source.agent_instance_id,
                &source.boot_id,
                true
            )
            .is_err());
        let identity = protocol::shutdown::ShutdownIdentity {
            machine_id: destination.machine_id,
            run_id: destination.run_id,
            agent_instance_id: destination.agent_instance_id,
            boot_id: destination.boot_id,
            ..source
        };
        assert!(owner
            .admit(
                identity.clone(),
                &owner.manifest(),
                &identity.agent_instance_id,
                &identity.boot_id,
                true
            )
            .is_ok());
    }

    #[test]
    fn trusted_identity_manifest_and_authority_precede_admission() {
        let (owner, identity) = fixture();
        let mut wrong = identity.clone();
        wrong.run_id = uuid::Uuid::new_v4().to_string();
        assert!(owner
            .admit(
                wrong,
                &owner.manifest(),
                &identity.agent_instance_id,
                &identity.boot_id,
                true
            )
            .is_err());
        assert!(owner
            .admit(
                identity.clone(),
                &owner.manifest(),
                "other agent",
                &identity.boot_id,
                true
            )
            .is_err());
        assert!(owner
            .admit(
                identity.clone(),
                &owner.manifest(),
                &identity.agent_instance_id,
                "other boot",
                true
            )
            .is_err());
        let other = protocol::shutdown::StorageManifest::Unsupported {
            reason: "omitted Data/share inventory".into(),
        };
        assert!(owner
            .admit(
                identity.clone(),
                &other,
                &identity.agent_instance_id,
                &identity.boot_id,
                true
            )
            .is_err());
        assert_eq!(
            owner
                .admit(
                    identity.clone(),
                    &owner.manifest(),
                    &identity.agent_instance_id,
                    &identity.boot_id,
                    false
                )
                .unwrap_err()
                .code(),
            tonic::Code::Unimplemented
        );
        let _completion = admit(&owner, &identity);
        assert!(owner
            .admit(
                identity.clone(),
                &owner.manifest(),
                &identity.agent_instance_id,
                &identity.boot_id,
                true
            )
            .is_err());
    }

    #[tokio::test]
    async fn completion_is_sticky_and_poweroff_requires_matching_terminal_receipt() {
        let (owner, identity) = fixture();
        let mut completion = admit(&owner, &identity);
        assert!(owner.allow_poweroff(&identity).is_err());
        let worker = std::thread::spawn({
            let owner = owner.clone();
            move || owner.complete_and_wait(Err(eyre::eyre!("retained syncfs EIO")), None)
        });
        completion.changed().await.unwrap();
        assert_eq!(
            completion.borrow().as_ref().unwrap().diagnostic.as_deref(),
            Some("retained syncfs EIO")
        );
        let mut wrong = identity.clone();
        wrong.shutdown_id = uuid::Uuid::new_v4().to_string();
        assert!(owner.allow_poweroff(&wrong).is_err());
        assert!(
            !crate::orderly_shutdown::lock(&owner.attempt)
                .as_ref()
                .unwrap()
                .host_receipt
        );
        owner.allow_poweroff(&identity).unwrap();
        worker.join().unwrap();
        owner.complete_and_wait(Ok(()), None);
        assert_eq!(
            completion.borrow().as_ref().unwrap().result,
            Some(protocol::v1::ShutdownCompletionResult::Failed as i32)
        );
    }

    #[tokio::test]
    async fn disconnected_waiter_does_not_cancel_terminal_work_or_create_receipt() {
        let (owner, identity) = fixture();
        let mut completion = admit(&owner, &identity);
        let guard = crate::orderly_shutdown::ExchangeGuard(owner.clone());
        let worker = std::thread::spawn({
            let owner = owner.clone();
            move || owner.complete_and_wait(Ok(()), None)
        });
        completion.changed().await.unwrap();
        drop(guard);
        worker.join().unwrap();
        let attempt = crate::orderly_shutdown::lock(&owner.attempt);
        let attempt = attempt.as_ref().unwrap();
        assert!(attempt.terminal && attempt.disconnected);
        assert!(!attempt.host_receipt);
        assert_eq!(
            completion.borrow().as_ref().unwrap().result,
            Some(protocol::v1::ShutdownCompletionResult::Unsupported as i32)
        );
    }

    #[tokio::test]
    async fn receipt_deadline_never_fabricates_host_observation() {
        let (owner, identity) = fixture();
        let _completion = admit(&owner, &identity);
        let (done, completed) = tokio::sync::oneshot::channel();
        let worker = std::thread::spawn({
            let owner = owner.clone();
            move || {
                owner.complete_and_wait(Ok(()), None);
                let _ = done.send(());
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(7), completed)
            .await
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(
            !crate::orderly_shutdown::lock(&owner.attempt)
                .as_ref()
                .unwrap()
                .host_receipt
        );
    }

    #[test]
    fn sticky_failure_cannot_be_replaced_by_unsupported_or_success() {
        let mut result = crate::root_storage::ShutdownResult::default();
        result.record(Err(eyre::eyre!("first actual writer deadline")));
        result.record(Ok(()));
        let final_result =
            crate::orderly_shutdown::completion(result.finish(), Some("unsupported shape".into()));
        assert_eq!(
            final_result.result,
            Some(protocol::v1::ShutdownCompletionResult::Failed as i32)
        );
        assert_eq!(
            final_result.diagnostic.as_deref(),
            Some("first actual writer deadline")
        );
    }

    #[test]
    fn partition_completion_needs_clean_coverage_and_every_storage_step() {
        use protocol::v1::ShutdownCompletionResult;
        for failure in [
            "root syncfs failed",
            "ESP syncfs failed",
            "data unmount failed",
            "root read-only verification failed",
            "ESP final syncfs failed",
        ] {
            let mut result = crate::root_storage::ShutdownResult::default();
            result.record(Err(eyre::eyre!(failure)));
            result.record(Ok(()));
            let completed = crate::orderly_shutdown::completion(result.finish(), None);
            assert_eq!(
                completed.result,
                Some(ShutdownCompletionResult::Failed as i32)
            );
            assert_eq!(completed.diagnostic.as_deref(), Some(failure));
        }
        let uncovered = crate::orderly_shutdown::completion(
            Ok(()),
            Some("ESP has no retained mount error cursor".into()),
        );
        assert_eq!(
            uncovered.result,
            Some(ShutdownCompletionResult::Unsupported as i32)
        );
        let completed = crate::orderly_shutdown::completion(Ok(()), None);
        assert_eq!(
            completed.result,
            Some(ShutdownCompletionResult::Succeeded as i32)
        );
    }

    #[test]
    fn diagnostic_bound_preserves_utf8() {
        let text = crate::orderly_shutdown::bounded_diagnostic("界".repeat(4096));
        assert!(text.len() <= protocol::shutdown::MAX_DIAGNOSTIC_BYTES);
        assert!(!text.is_empty());
    }
}
