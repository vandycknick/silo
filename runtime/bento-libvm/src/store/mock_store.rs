use async_trait::async_trait;
use mockall::mock;

use crate::store::models::MachineId;
use crate::store::models::{
    DbConfig, MachineConfig, MachineState, NetworkAttachment, NetworkDefinition, NetworkInstance,
};
use crate::store::{ConfigStore, MachineStore, NetworkStore};
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
        async fn add_machine(
            &self,
            config: &MachineConfig,
            initial_state: &MachineState,
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
