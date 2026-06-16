use bento_vm_spec::VmSpec;

use crate::machine::{validate_machine_name, Machine, MachineData, MachineUpdate};
use crate::network::MachineNetworkConfig;
use crate::runtime::core::{
    current_unix, empty_hardware, validate_root_disk_growth, write_machine_config,
};
use crate::store::models::MachineNetworkConfig as ModelMachineNetworkConfig;
use crate::LibVmError;

impl Machine {
    /// Replaces the VM spec for a stopped machine.
    pub async fn replace_config(&self, spec: VmSpec) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let (_lock, mut config) = runtime.lock_machine_config(self.machine_id()).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }

        let previous_spec = config.spec.clone();
        config.spec = spec;
        config.modified_at = current_unix();
        write_machine_config(&config.instance_dir, &config.name, &config.spec)?;
        if let Err(err) = runtime.update_machine_config(&config).await {
            let _ = write_machine_config(&config.instance_dir, &config.name, &previous_spec);
            return Err(err);
        }
        runtime.machine_inspect_data(config).await
    }

    /// Changes the durable network config for a stopped machine.
    pub async fn set_network(
        &self,
        network: MachineNetworkConfig,
    ) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let network = network.into();
        runtime.validate_machine_network_config(&network).await?;
        let (_lock, mut config) = runtime.lock_machine_config(self.machine_id()).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        config.network = network;
        config.modified_at = current_unix();
        runtime.update_machine_config(&config).await?;
        runtime.machine_inspect_data(config).await
    }

    /// Applies partial settings updates to a stopped machine.
    pub async fn update(&self, update: MachineUpdate) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let network: Option<ModelMachineNetworkConfig> = update.network.clone().map(Into::into);
        if let Some(network) = &network {
            runtime.validate_machine_network_config(network).await?;
        }
        if let Some(name) = update.name.as_deref() {
            validate_machine_name(name)?;
        }

        if update.is_empty() {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason: "at least one setting is required".to_string(),
            });
        }
        if matches!(update.cpus, Some(0)) {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason: "cpus must be greater than 0".to_string(),
            });
        }
        if matches!(update.memory_mib, Some(0)) {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason: "memory must be greater than 0".to_string(),
            });
        }
        if matches!(update.root_disk_size, Some(0)) {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason: "root disk size must be greater than 0".to_string(),
            });
        }

        let machine_id = self.machine_id();
        let (_lock, mut config) = runtime.lock_machine_config(machine_id).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }

        if let Some(new_name) = update.name {
            if new_name != config.name {
                if let Some(existing) = runtime.machine_config_by_name(&new_name).await? {
                    if existing.id != machine_id {
                        return Err(LibVmError::InvalidMachineUpdate {
                            reference: config.name.clone(),
                            reason: format!("machine name {new_name:?} already exists"),
                        });
                    }
                }
                config.name = new_name;
            }
        }

        if let Some(size_bytes) = update.root_disk_size {
            validate_root_disk_growth(&config, size_bytes)?;
            config.root_disk_size = Some(size_bytes);
        }

        let previous_spec = config.spec.clone();
        let mut spec_changed = false;
        if update.cpus.is_some()
            || update.memory_mib.is_some()
            || update.nested_virtualization.is_some()
            || update.rosetta.is_some()
        {
            let hardware = config.spec.hardware.get_or_insert_with(empty_hardware);
            if let Some(cpus) = update.cpus {
                hardware.cpus = Some(cpus);
            }
            if let Some(memory_mib) = update.memory_mib {
                hardware.memory = Some(memory_mib);
            }
            if let Some(nested_virtualization) = update.nested_virtualization {
                hardware.nested_virtualization = Some(nested_virtualization);
            }
            if let Some(rosetta) = update.rosetta {
                hardware.rosetta = Some(rosetta);
            }
            spec_changed = true;
        }
        if let Some(network) = network {
            config.network = network;
        }

        config.modified_at = current_unix();
        if spec_changed {
            write_machine_config(&config.instance_dir, &config.name, &config.spec)?;
        }
        if let Err(err) = runtime.update_machine_config(&config).await {
            if spec_changed {
                let _ = write_machine_config(&config.instance_dir, &config.name, &previous_spec);
            }
            return Err(err);
        }
        runtime.machine_inspect_data(config).await
    }
}
