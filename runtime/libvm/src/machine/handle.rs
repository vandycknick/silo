use crate::runtime::Runtime;
use crate::store::models::MachineId;

/// Handle for an operable Silo virtual machine.
///
/// A handle stores machine identity and the `Runtime` that created it. Use
/// `inspect` to read the machine's current public snapshot.
#[derive(Debug, Clone)]
pub struct Machine {
    runtime: Runtime,
    id: MachineId,
    access: AccessBinding,
}

/// Unbound handles never wake implicitly. Admitted handles only access their
/// exact run, and never wake or replay an operation after that run disappears.
#[derive(Debug, Clone, Default)]
enum AccessBinding {
    #[default]
    Unbound,
    Admitted(crate::MachineRunId),
}

impl Machine {
    pub(crate) fn new(runtime: Runtime, id: MachineId) -> Self {
        Self {
            runtime,
            id,
            access: AccessBinding::Unbound,
        }
    }

    /// Admits guest access once, waking only a hibernated machine. Reuse the
    /// returned handle throughout a multi-step operation.
    pub async fn for_access(
        &self,
        progress: Option<&crate::LiveOperationProgressSender>,
    ) -> Result<Self, crate::LibVmError> {
        if let AccessBinding::Admitted(_) = &self.access {
            self.running_config().await?;
            return Ok(self.clone());
        }
        // The wake path is a large future. Boxing it here keeps every access
        // caller's future small enough for a default task stack.
        let run = Box::pin(self.ensure_running_for_access(progress)).await?;
        let mut machine = self.clone();
        machine.access = AccessBinding::Admitted(run);
        Ok(machine)
    }

    pub(crate) fn validate_access_run(
        &self,
        reference: &str,
        run: Option<&str>,
    ) -> Result<(), crate::LibVmError> {
        if let AccessBinding::Admitted(expected) = &self.access {
            if run != Some(expected.as_str()) {
                return Err(crate::LibVmError::MachineNotRunning {
                    reference: reference.into(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub(crate) fn machine_id(&self) -> MachineId {
        self.id
    }

    /// Returns the stable machine ID.
    pub fn id(&self) -> String {
        self.id.to_string()
    }
}
