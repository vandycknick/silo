use async_trait::async_trait;

use crate::image::{ImageDetail, ImageHandle, ImagePruneReport, ImageRemoveOptions};
use crate::store::models::MachineId;
use crate::store::models::{
    DbConfig, ImageRootfsArtifactRecord, MachineConfig, MachineRootfsRecord, MachineState,
    NetworkAttachment, NetworkDefinition, NetworkInstance, OciImageRecord,
};
use crate::LibVmError;

/// Durable runtime configuration storage.
///
/// The config row records the filesystem roots a state database was initialized
/// with. Runtime startup validates those roots after reading the row; the store
/// only provides atomic read/seed operations.
#[async_trait]
pub(crate) trait ConfigStore: std::fmt::Debug + Send + Sync {
    /// Reads the persisted database configuration, if the store has been seeded.
    async fn db_config(&self) -> Result<Option<DbConfig>, LibVmError>;

    /// Inserts `seed` only when the config row is missing and returns the stored row.
    ///
    /// Existing rows are returned as-is and are not compared with `seed`; callers
    /// that care about root compatibility must validate the returned value.
    async fn read_or_seed_db_config(&self, seed: &DbConfig) -> Result<DbConfig, LibVmError>;
}

/// Durable machine configuration and runtime-state storage.
///
/// Machine names are reserved by the `add_machine` unique constraint. Updates
/// require an existing machine unless a method explicitly says otherwise.
#[async_trait]
pub(crate) trait MachineStore: std::fmt::Debug + Send + Sync {
    /// Atomically inserts a machine config and its initial runtime state.
    ///
    /// Returns `MachineAlreadyExists` when the machine name is already reserved.
    #[cfg(test)]
    async fn add_machine(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
    ) -> Result<(), LibVmError>;

    /// Atomically inserts a machine config, initial state, and rootfs pin.
    async fn add_machine_with_rootfs(
        &self,
        config: &MachineConfig,
        initial_state: &MachineState,
        rootfs: &MachineRootfsRecord,
    ) -> Result<(), LibVmError>;

    /// Reads runtime state for an existing machine, if a row is present.
    async fn machine_state(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<MachineState>, LibVmError>;

    /// Upserts runtime state for an existing machine.
    ///
    /// The machine config row must already exist; SQLite enforces that through a
    /// foreign key from `machine_state.machine_id` to `machine_config.id`.
    async fn save_machine_state(&self, state: &MachineState) -> Result<(), LibVmError>;

    /// Persists an existing machine config.
    ///
    /// Missing machine IDs return `MachineNotFound`; duplicate names are rejected
    /// by the store's unique constraint.
    async fn save_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError>;

    /// Looks up a machine config by full machine ID.
    async fn machine_config(&self, id: MachineId) -> Result<Option<MachineConfig>, LibVmError>;

    /// Looks up a machine config by exact machine name.
    async fn machine_config_by_name(&self, name: &str)
        -> Result<Option<MachineConfig>, LibVmError>;

    /// Looks up machine configs by normalized lowercase hex ID prefix.
    ///
    /// `prefix` must be 3-32 lowercase hex characters. Public reference parsing
    /// handles user-facing normalization before reaching the store.
    async fn machine_configs_by_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<MachineConfig>, LibVmError>;

    /// Lists all machine configs sorted by machine name.
    async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError>;

    /// Removes a machine config and runtime state.
    ///
    /// Network attachments are removed by the database foreign-key cascade.
    async fn remove_machine(&self, machine: &MachineConfig) -> Result<(), LibVmError>;
}

/// Durable image metadata and machine rootfs pin storage.
#[async_trait]
pub(crate) trait ImageStore: std::fmt::Debug + Send + Sync {
    /// Upserts OCI manifest metadata, its mutable reference, layers, and rootfs artifact.
    async fn save_oci_image(&self, image: &OciImageRecord) -> Result<(), LibVmError>;

    /// Upserts a non-OCI managed rootfs artifact, currently used by tar sources.
    async fn save_rootfs_artifact(
        &self,
        artifact: &ImageRootfsArtifactRecord,
    ) -> Result<(), LibVmError>;

    /// Reads a lightweight image reference by exact reference.
    async fn image_handle(&self, reference: &str) -> Result<Option<ImageHandle>, LibVmError>;

    /// Lists known image references sorted by reference.
    async fn list_image_handles(&self) -> Result<Vec<ImageHandle>, LibVmError>;

    /// Reads image detail by exact reference.
    async fn image_detail(&self, reference: &str) -> Result<Option<ImageDetail>, LibVmError>;

    /// Removes an image reference.
    async fn remove_image(
        &self,
        reference: &str,
        options: ImageRemoveOptions,
    ) -> Result<(), LibVmError>;

    /// Removes unreferenced image rows and reports best-effort reclaimed bytes.
    async fn prune_images(&self) -> Result<ImagePruneReport, LibVmError>;
}

/// Durable network runtime and named-network definition storage.
#[async_trait]
pub(crate) trait NetworkStore: std::fmt::Debug + Send + Sync {
    /// Reads the network attachment for a machine, if one exists.
    async fn network_attachment(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<NetworkAttachment>, LibVmError>;

    /// Reads a network runtime instance by runtime ID.
    async fn network_instance(
        &self,
        network_id: &str,
    ) -> Result<Option<NetworkInstance>, LibVmError>;

    /// Upserts a network runtime instance.
    ///
    /// Named network instances are unique by `definition_name`; private runtime
    /// instances use `None` and are not subject to that uniqueness constraint.
    async fn save_network_instance(&self, instance: &NetworkInstance) -> Result<(), LibVmError>;

    /// Attaches a machine to a network runtime instance.
    async fn attach_network(&self, attachment: &NetworkAttachment) -> Result<(), LibVmError>;

    /// Detaches any network runtime instance from a machine.
    async fn detach_network(&self, machine_id: MachineId) -> Result<(), LibVmError>;

    /// Removes a network runtime instance.
    ///
    /// Attachments to the runtime instance are removed by the database
    /// foreign-key cascade.
    async fn remove_network_instance(&self, network_id: &str) -> Result<(), LibVmError>;

    /// Counts current machine attachments to a network runtime instance.
    async fn network_attachment_count(&self, network_id: &str) -> Result<u32, LibVmError>;

    /// Upserts a named-network definition.
    async fn define_network(&self, definition: &NetworkDefinition) -> Result<(), LibVmError>;

    /// Lists named-network definitions sorted by name.
    async fn list_network_definitions(&self) -> Result<Vec<NetworkDefinition>, LibVmError>;

    /// Reads a named-network definition by name.
    async fn network_definition(&self, name: &str)
        -> Result<Option<NetworkDefinition>, LibVmError>;

    /// Removes a named-network definition.
    ///
    /// Existing network runtime instances are not cascaded or modified; callers
    /// must decide whether those runtime records should be reconciled separately.
    async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError>;
}

/// Full persistence boundary required by `Runtime`.
pub(crate) trait DataStore:
    std::fmt::Debug + ConfigStore + MachineStore + NetworkStore + ImageStore + Send + Sync
{
}

impl<T> DataStore for T where
    T: std::fmt::Debug + ConfigStore + MachineStore + NetworkStore + ImageStore + Send + Sync
{
}
