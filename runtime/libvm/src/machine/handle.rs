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
}

impl Machine {
    pub(crate) fn new(runtime: Runtime, id: MachineId) -> Self {
        Self { runtime, id }
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
