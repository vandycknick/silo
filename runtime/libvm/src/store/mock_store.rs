use async_trait::async_trait;
use mockall::mock;

use crate::image::{ImageDetail, ImageHandle, ImagePruneReport, ImageRemoveOptions};
use crate::store::models::MachineId;
use crate::store::models::{
    DbConfig, ImageRootfsArtifactRecord, MachineConfig, MachineRootfsRecord, MachineState,
    NetworkAttachment, NetworkDefinition, NetworkInstance, OciImageRecord,
};
use crate::store::{ConfigStore, ImageStore, MachineStore, NetworkStore};
use crate::LibVmError;

mock! {
    #[derive(Debug)]
    pub DataStore {}

    #[async_trait]
    impl ConfigStore for DataStore {
        async fn db_config(&self) -> Result<Option<DbConfig>, LibVmError>;

        async fn read_or_seed_db_config(&self, seed: &DbConfig) -> Result<DbConfig, LibVmError>;
    }

    #[async_trait]
    impl MachineStore for DataStore {
        #[cfg(test)]
        async fn add_machine(
            &self,
            config: &MachineConfig,
            initial_state: &MachineState,
        ) -> Result<(), LibVmError>;

        async fn add_machine_with_rootfs(
            &self,
            config: &MachineConfig,
            initial_state: &MachineState,
            rootfs: &MachineRootfsRecord,
        ) -> Result<(), LibVmError>;

        async fn machine_state(
            &self,
            machine_id: MachineId,
        ) -> Result<Option<MachineState>, LibVmError>;

        async fn save_machine_state(&self, state: &MachineState) -> Result<(), LibVmError>;

        async fn save_machine_config(&self, config: &MachineConfig) -> Result<(), LibVmError>;

        async fn machine_config(
            &self,
            id: MachineId,
        ) -> Result<Option<MachineConfig>, LibVmError>;

        async fn machine_config_by_name(
            &self,
            name: &str,
        ) -> Result<Option<MachineConfig>, LibVmError>;

        async fn machine_configs_by_id_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<MachineConfig>, LibVmError>;

        async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError>;

        async fn remove_machine(&self, machine: &MachineConfig) -> Result<(), LibVmError>;
    }

    #[async_trait]
    impl ImageStore for DataStore {
        async fn save_oci_image(&self, image: &OciImageRecord) -> Result<(), LibVmError>;

        async fn save_rootfs_artifact(
            &self,
            artifact: &ImageRootfsArtifactRecord,
        ) -> Result<(), LibVmError>;

        async fn image_handle(&self, reference: &str) -> Result<Option<ImageHandle>, LibVmError>;

        async fn list_image_handles(&self) -> Result<Vec<ImageHandle>, LibVmError>;

        async fn image_detail(&self, reference: &str) -> Result<Option<ImageDetail>, LibVmError>;

        async fn remove_image(
            &self,
            reference: &str,
            options: ImageRemoveOptions,
        ) -> Result<(), LibVmError>;

        async fn prune_images(&self) -> Result<ImagePruneReport, LibVmError>;
    }

    #[async_trait]
    impl NetworkStore for DataStore {
        async fn network_attachment(
            &self,
            machine_id: MachineId,
        ) -> Result<Option<NetworkAttachment>, LibVmError>;

        async fn network_instance(
            &self,
            network_id: &str,
        ) -> Result<Option<NetworkInstance>, LibVmError>;

        async fn save_network_instance(&self, instance: &NetworkInstance) -> Result<(), LibVmError>;

        async fn attach_network(&self, attachment: &NetworkAttachment) -> Result<(), LibVmError>;

        async fn detach_network(&self, machine_id: MachineId) -> Result<(), LibVmError>;

        async fn remove_network_instance(&self, network_id: &str) -> Result<(), LibVmError>;

        async fn network_instance_by_definition(
            &self,
            definition_name: &str,
        ) -> Result<Option<NetworkInstance>, LibVmError>;

        async fn network_attachment_count(&self, network_id: &str) -> Result<u32, LibVmError>;

        async fn define_network(&self, definition: &NetworkDefinition) -> Result<(), LibVmError>;

        async fn list_network_definitions(&self) -> Result<Vec<NetworkDefinition>, LibVmError>;

        async fn network_definition(
            &self,
            name: &str,
        ) -> Result<Option<NetworkDefinition>, LibVmError>;

        async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError>;
    }
}
