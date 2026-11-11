use vm_spec::VmSpec;

use crate::machine::{
    validate_machine_name, GuestPublishUpdate, Machine, MachineData, MachineUpdate,
    MachineUserUpdate, NetworkPolicyUpdate,
};
use crate::network::{GuestPublish, MachineNetworkBuilder};
use crate::runtime::core::{empty_hardware, validate_root_disk_growth, write_machine_config};
use crate::store::models::MachineNetworkConfig as ModelMachineNetworkConfig;
use crate::utils::now_unix;
use crate::LibVmError;

impl Machine {
    /// Replaces the VM spec for a stopped machine.
    pub async fn replace_config(&self, mut spec: VmSpec) -> Result<MachineData, LibVmError> {
        let kernel = spec.boot.as_ref().and_then(|boot| boot.kernel.as_ref());
        let (kernel_path, initramfs_path) =
            crate::runtime::boot_assets::canonicalize_boot_overrides(
                crate::runtime::boot_assets::BootAssetOverrides {
                    kernel: kernel.and_then(|kernel| kernel.path.as_deref()),
                    initramfs: kernel.and_then(|kernel| kernel.initramfs.as_deref()),
                },
            )?;
        if let Some(kernel) = spec.boot.as_mut().and_then(|boot| boot.kernel.as_mut()) {
            kernel.path = kernel_path;
            kernel.initramfs = initramfs_path;
        }
        let runtime = self.runtime();
        let (_lock, mut config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        let storage = runtime.machine_storage_record(config.id).await?;
        storage.ownership.ensure_owned(config.id)?;
        runtime
            .preflight_stopped_generation_locked(&config, &storage)
            .await?;
        reject_boot_path_change(&config.spec, &spec, &config.name)?;
        let _node_state = crate::node_state::acquire(&config).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        spec.validate()
            .map_err(|error| LibVmError::InvalidMachineConfig {
                reference: config.name.clone(),
                reason: error.to_string(),
            })?;
        crate::machine::root_storage::validate_spec(&storage, &spec)?;
        crate::runtime::boot_assets::effective_boot(&storage, &spec, runtime.effective_backend())?;

        let previous_spec = config.spec.clone();
        runtime.validate_tailscale_vsock(&config.network, &spec)?;
        config.spec = spec;
        config.modified_at = now_unix();
        write_machine_config(&config.machine_dir, &config.name, &config.spec)?;
        if let Err(err) = runtime.save_machine_config(&config).await {
            let _ = write_machine_config(&config.machine_dir, &config.name, &previous_spec);
            return Err(err);
        }
        runtime.machine_inspect_data(config).await
    }

    /// Changes the durable network config for a stopped machine.
    pub async fn set_network(
        &self,
        configure: impl FnOnce(MachineNetworkBuilder) -> MachineNetworkBuilder,
    ) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let network = configure(MachineNetworkBuilder::new())
            .build()
            .map_err(|reason| LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason,
            })?;
        let network = network.into();
        runtime.validate_machine_network_config(&network).await?;
        let (_lock, mut config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        let storage = runtime.machine_storage_record(config.id).await?;
        storage.ownership.ensure_owned(config.id)?;
        runtime
            .preflight_stopped_generation_locked(&config, &storage)
            .await?;
        let _node_state = crate::node_state::acquire(&config).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        config.network = network;
        if runtime.validate_tailscale_vsock(&config.network, &config.spec)? {
            runtime.ensure_tailscale_directory(config.id)?;
        }
        config.modified_at = now_unix();
        runtime.save_machine_config(&config).await?;
        runtime.machine_inspect_data(config).await
    }

    /// Applies partial settings updates to a stopped machine.
    pub async fn update(&self, update: MachineUpdate) -> Result<MachineData, LibVmError> {
        if update.root_disk_size.is_some() || update.temporary_directory.is_some() {
            let machine = self.clone();
            // Finish the stopped replacement transaction even if its requester
            // disappears; otherwise cancellation after COMMIT can erase the new root.
            return tokio::spawn(async move { machine.update_stopped(update).await }).await?;
        }
        self.update_stopped(update).await
    }

    async fn update_stopped(&self, update: MachineUpdate) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        if let Err(reason) = update.validate_network() {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason: reason.to_owned(),
            });
        }
        let replacement_network: Option<ModelMachineNetworkConfig> =
            update.network.clone().map(Into::into);
        let replacement_guest = update
            .guest
            .clone()
            .map(crate::runtime::boot_assets::canonicalize_guest_config)
            .transpose()?;
        if let Some(MachineUserUpdate::Set(user)) = &update.user {
            user.validate()
                .map_err(|reason| LibVmError::InvalidMachineUpdate {
                    reference: self.id(),
                    reason,
                })?;
        }
        if let Some(network) = &replacement_network {
            runtime.validate_machine_network_config(network).await?;
        }
        if replacement_network.is_some()
            && (update.network_policy.is_some() || update.guest_publish.is_some())
        {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason: "network replacement and partial network updates cannot be combined"
                    .to_string(),
            });
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
        let update_memory = update
            .memory
            .map(|memory| memory.to_update_mebibytes(&self.id()))
            .transpose()?;
        if matches!(update.root_disk_size, Some(0)) {
            return Err(LibVmError::InvalidMachineUpdate {
                reference: self.id(),
                reason: "root disk size must be greater than 0".to_string(),
            });
        }

        let machine_id = self.machine_id();
        let _name_lock = if update.name.is_some() {
            Some(runtime.lock_machine_names().await?)
        } else {
            None
        };
        let (_lock, mut config) = runtime.lock_machine_config(machine_id).await?;
        runtime.validate_machine_data_dir(&config)?;
        // Refuse live attachment owners before node-state lock creation or
        // reconciliation can change the source's durable lifecycle record.
        let storage = runtime.machine_storage_record(config.id).await?;
        storage.ownership.ensure_owned(config.id)?;
        runtime
            .preflight_stopped_generation_locked(&config, &storage)
            .await?;
        let _node_state = crate::node_state::acquire(&config).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        if let Some(guest) = &replacement_guest {
            if guest.agent != config.guest.agent {
                return Err(LibVmError::InvalidMachineUpdate {
                    reference: config.name.clone(),
                    reason: "agent changes alter the pinned boot bundle; use update_boot_assets"
                        .into(),
                });
            }
        }

        if let Some(new_name) = update.name {
            if new_name != config.name {
                crate::machine::reference::validate_new_machine_name(&new_name)?;
                if runtime.validate_tailscale_vsock(&config.network, &config.spec)? {
                    return Err(LibVmError::InvalidMachineUpdate {
                        reference: config.name.clone(),
                        reason: "cannot rename a machine with a current Tailscale declaration"
                            .into(),
                    });
                }
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

        if let Some(labels) = update.labels {
            config.labels = labels;
        }

        let mut storage_update =
            if update.root_disk_size.is_some() || update.temporary_directory.is_some() {
                Some(runtime.machine_storage_record(config.id).await?)
            } else {
                None
            };
        if let Some(size_bytes) = update.root_disk_size {
            if let Some(crate::MachineRoot::OpaqueRaw { path, .. }) =
                storage_update.as_ref().map(|storage| &storage.root)
            {
                validate_root_disk_growth(&config, path.as_path(), size_bytes)?;
            }
            config.root_disk_size = Some(size_bytes);
        }
        if let Some(policy) = update.temporary_directory {
            policy.validate()?;
            match storage_update.as_mut().map(|storage| &mut storage.root) {
                Some(crate::MachineRoot::LinuxOverlay {
                    temporary_directory,
                    ..
                }) => *temporary_directory = policy,
                _ => {
                    return Err(LibVmError::InvalidMachineUpdate {
                        reference: config.name.clone(),
                        reason: "temporary-directory policy requires flat overlay".into(),
                    })
                }
            }
        }

        let previous_spec = config.spec.clone();
        let mut spec_changed = false;
        if update.cpus.is_some()
            || update_memory.is_some()
            || update.nested_virtualization.is_some()
            || update.rosetta.is_some()
        {
            let hardware = config.spec.hardware.get_or_insert_with(empty_hardware);
            if let Some(cpus) = update.cpus {
                hardware.cpus = Some(cpus);
            }
            if let Some(memory) = update_memory {
                hardware.memory = Some(memory);
            }
            if let Some(nested_virtualization) = update.nested_virtualization {
                hardware.nested_virtualization = Some(nested_virtualization);
            }
            if let Some(rosetta) = update.rosetta {
                hardware.rosetta = Some(rosetta);
            }
            spec_changed = true;
        }
        if let Some(forwards) = update.forwards {
            config.spec.forwards = forwards;
            spec_changed = true;
        }
        if let Some(vsock) = update.vsock {
            config.spec.vsock = Some(vsock);
            spec_changed = true;
        }
        if let Some(network) = replacement_network {
            config.network = network;
        }
        if let Some(update) = update.network_policy {
            apply_network_policy_update(&mut config.network, update).map_err(|reason| {
                LibVmError::InvalidMachineUpdate {
                    reference: config.name.clone(),
                    reason,
                }
            })?;
            runtime
                .validate_machine_network_config(&config.network)
                .await?;
        }
        if let Some(publish) = update.guest_publish {
            apply_guest_publish_update(&mut config.network, publish).map_err(|reason| {
                LibVmError::InvalidMachineUpdate {
                    reference: config.name.clone(),
                    reason,
                }
            })?;
        }
        if let Some(mut guest) = replacement_guest {
            if update.user.is_none() {
                guest.user = config.guest.user.clone();
            }
            config.guest = guest;
        }
        if let Some(user) = update.user {
            config.guest.user = match user {
                MachineUserUpdate::Set(user) => Some(user),
                MachineUserUpdate::Clear => None,
            };
        }
        crate::runtime::boot_assets::effective_boot(
            &storage,
            &config.spec,
            runtime.effective_backend(),
        )?;

        if runtime.validate_tailscale_vsock(&config.network, &config.spec)? {
            runtime.ensure_tailscale_directory(config.id)?;
        }
        config.modified_at = now_unix();
        let mut replacement = None;
        let _storage_lifetime = if storage_update.is_some() {
            // Stop cleanup removes this tree. Recreate it only through the
            // owned-directory admission path before opening the lifetime lock.
            runtime.local_paths().ensure_machine_run_dir(config.id)?;
            Some(
                crate::lock_manager::MachineLifetimeLock::try_acquire(
                    &runtime.machine_paths(config.id).vmm_lock_path(),
                )?
                .ok_or_else(|| LibVmError::MachineAlreadyRunning {
                    reference: config.name.clone(),
                })?,
            )
        } else {
            None
        };
        if let Some(storage) = &mut storage_update {
            match &mut storage.root {
                crate::MachineRoot::OpaqueRaw { geometry, .. } => {
                    if let Some(length) = update.root_disk_size {
                        geometry.length = length;
                    }
                }
                crate::MachineRoot::LinuxOverlay {
                    upper, capacity, ..
                } => {
                    if let Some(length) = update.root_disk_size {
                        rootfs_spec::upper_geometry::UpperCapacity::new(length).map_err(
                            |error| LibVmError::InvalidMachineUpdate {
                                reference: config.name.clone(),
                                reason: error.to_string(),
                            },
                        )?;
                        if length < *capacity {
                            return Err(LibVmError::InvalidMachineUpdate {
                                reference: config.name.clone(),
                                reason: "overlay upper cannot be shrunk".into(),
                            });
                        }
                        if length > *capacity {
                            let path = crate::PrivatePath::new(format!(
                                "upper-{}.raw",
                                uuid::Uuid::new_v4().simple()
                            ))?;
                            replacement =
                                Some(crate::machine::root_disk::UpperReplacement::prepare(
                                    &config.machine_dir.join(upper.as_path()),
                                    &config.machine_dir.join(path.as_path()),
                                    length,
                                )?);
                            let disk = config
                                .spec
                                .storage
                                .as_mut()
                                .and_then(|storage| {
                                    storage
                                        .disks
                                        .iter_mut()
                                        .find(|disk| disk.role == vm_spec::DiskRole::RootUpper)
                                })
                                .ok_or_else(|| {
                                    crate::machine::root_storage::invalid(
                                        "overlay upper disk is missing",
                                    )
                                })?;
                            disk.path = path.as_path().to_path_buf();
                            disk.geometry.length = length;
                            *upper = path;
                            *capacity = length;
                            storage.storage_generation =
                                storage.storage_generation.checked_add(1).ok_or_else(|| {
                                    crate::machine::root_storage::invalid(
                                        "storage generation overflow",
                                    )
                                })?;
                            spec_changed = true;
                        }
                    }
                }
            }
            storage.validate()?;
        }
        if spec_changed {
            config
                .spec
                .validate()
                .map_err(|error| LibVmError::InvalidMachineConfig {
                    reference: config.name.clone(),
                    reason: error.to_string(),
                })?;
            write_machine_config(&config.machine_dir, &config.name, &config.spec)?;
        }
        if let Some(replacement) = replacement.as_mut() {
            replacement.begin_publication();
        }
        let saved = if let Some(storage) = storage_update.as_ref() {
            runtime
                .save_machine_config_with_storage(&config, storage)
                .await
        } else {
            runtime.save_machine_config(&config).await
        };
        if let Err(err) = saved {
            if spec_changed {
                let _ = write_machine_config(&config.machine_dir, &config.name, &previous_spec);
            }
            if let Some(candidate) = replacement.take() {
                // A returned error can still leave COMMIT's outcome uncertain.
                // Only a completed semantic reread under our machine/lifetime
                // locks proves the candidate safe to remove. Cancellation of
                // this reread deliberately retains both complete generations.
                if let Ok(storage) = runtime.machine_storage_record(config.id).await {
                    if matches!(&storage.root, crate::MachineRoot::LinuxOverlay { upper, .. }
                        if config.machine_dir.join(upper.as_path()) != candidate.path())
                    {
                        candidate.discard_unpublished();
                    }
                }
            }
            return Err(err);
        }
        if let Some(replacement) = replacement {
            replacement.commit();
        }
        runtime.machine_inspect_data(config).await
    }

    /// Atomically replaces the entire pinned next-boot tuple for a stopped
    /// machine. The blocking owner survives cancellation of the requesting task.
    pub async fn update_boot_assets(
        &self,
        update: crate::BootAssetsUpdate,
    ) -> Result<MachineData, LibVmError> {
        let machine = self.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            handle.block_on(machine.update_boot_assets_stopped(update))
        })
        .await?
    }

    async fn update_boot_assets_stopped(
        &self,
        update: crate::BootAssetsUpdate,
    ) -> Result<MachineData, LibVmError> {
        let runtime = self.runtime();
        let (_lock, mut config) = runtime.lock_machine_config(self.machine_id()).await?;
        runtime.validate_machine_data_dir(&config)?;
        let mut storage = runtime.machine_storage_record(config.id).await?;
        storage.ownership.ensure_owned(config.id)?;
        runtime
            .preflight_stopped_generation_locked(&config, &storage)
            .await?;
        let _node_state = crate::node_state::acquire(&config).await?;
        let status = runtime.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        runtime.local_paths().ensure_machine_run_dir(config.id)?;
        let _lifetime = crate::lock_manager::MachineLifetimeLock::try_acquire(
            &runtime.machine_paths(config.id).vmm_lock_path(),
        )?
        .ok_or_else(|| LibVmError::MachineAlreadyRunning {
            reference: config.name.clone(),
        })?;
        let store = runtime.native_store()?;
        let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir())?;
        let (operation, lease) = store
            .begin_stopped_operation("update-boot-assets", &[], &[])
            .await?;
        let _operation_paths = pool.create_operation_with_lease(operation, lease)?;
        let boot = crate::runtime::boot_assets::pin_boot_selection(
            &storage,
            &update.selection,
            runtime.captured_boot_context(&pool, &store, operation),
        )
        .await?;
        let crate::BootProfile::LinuxDirect { binding, .. } = &boot else {
            return Err(crate::machine::root_storage::invalid(
                "boot update requires direct boot",
            ));
        };
        let crate::BootBinding::Pinned { agent, .. } = binding else {
            return Err(crate::machine::root_storage::invalid(
                "boot update did not pin a complete tuple",
            ));
        };
        config.guest.agent = if agent.is_some() {
            crate::machine::MachineAgent::Default
        } else {
            crate::machine::MachineAgent::Disabled
        };
        config.agent_mode = Some(config.guest.agent.clone());
        let bundle = binding.digest()?;
        storage.boot = boot;
        storage.storage_generation = storage
            .storage_generation
            .checked_add(1)
            .ok_or_else(|| crate::machine::root_storage::invalid("storage generation overflow"))?;
        crate::runtime::boot_assets::effective_boot(
            &storage,
            &config.spec,
            runtime.effective_backend(),
        )?;
        config.modified_at = now_unix();
        // Only the semantic tuple is authoritative. Clear obsolete mutable asset
        // paths in the same catalog transaction, not as a second ordered save.
        if let Some(kernel) = config
            .spec
            .boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
        {
            kernel.path = None;
            kernel.initramfs = None;
        }
        crate::machine::root_storage::validate_spec(&storage, &config.spec)?;
        store
            .preserve_boot_update_operation(
                operation,
                config.id,
                storage.storage_generation,
                bundle,
            )
            .await?;
        // Preserve both generations' roots when COMMIT's outcome is unknown.
        // The journal candidate identifies the exact target bundle/generation.
        runtime
            .save_machine_config_with_storage(&config, &storage)
            .await?;
        store.finish_stopped_operation(operation).await?;
        runtime.machine_inspect_data(config).await
    }
}

fn reject_boot_path_change(
    current: &VmSpec,
    replacement: &VmSpec,
    reference: &str,
) -> Result<(), LibVmError> {
    let paths = |spec: &VmSpec| {
        spec.boot
            .as_ref()
            .and_then(|boot| boot.kernel.as_ref())
            .map(|kernel| (kernel.path.clone(), kernel.initramfs.clone()))
            .unwrap_or_default()
    };
    if paths(current) != paths(replacement) {
        return Err(LibVmError::InvalidMachineUpdate {
            reference: reference.to_owned(),
            reason: "kernel/initramfs changes require the explicit update_boot_assets operation"
                .into(),
        });
    }
    Ok(())
}

fn apply_network_policy_update(
    network: &mut ModelMachineNetworkConfig,
    update: NetworkPolicyUpdate,
) -> Result<(), String> {
    match network {
        ModelMachineNetworkConfig::Private { policy, .. } => {
            match update {
                NetworkPolicyUpdate::Set(next) => {
                    *policy = Some(next.normalized());
                }
                NetworkPolicyUpdate::Clear => {
                    *policy = None;
                }
            }
            Ok(())
        }
        ModelMachineNetworkConfig::None => Err(
            "network policy updates require a private network attachment, but machine networking is disabled"
                .to_string(),
        ),
        ModelMachineNetworkConfig::Named { name } => Err(format!(
            "network policy updates require a private network attachment, but machine uses named network {name:?}"
        )),
    }
}

fn apply_guest_publish_update(
    network: &mut ModelMachineNetworkConfig,
    update: GuestPublishUpdate,
) -> Result<(), String> {
    match network {
        ModelMachineNetworkConfig::Private { publish, .. } => {
            *publish = match update {
                GuestPublishUpdate::Set(bind) => Some(GuestPublish { bind }.into()),
                GuestPublishUpdate::Clear => None,
            };
            Ok(())
        }
        ModelMachineNetworkConfig::None => Err(
            "guest publication updates require a private network attachment, but machine networking is disabled"
                .to_string(),
        ),
        ModelMachineNetworkConfig::Named { name } => Err(format!(
            "guest publication updates require a private network attachment, but machine uses named network {name:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::{ImageSource, MachineUpdate, Runtime, RuntimeNetworkingConfig};
    use std::collections::BTreeMap;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use test_utils::direct_kernel::host_kernel;

    const ROOT_MINIMUM_LENGTH: u64 = 64 * 1024 * 1024;

    async fn test_runtime(path: &std::path::Path) -> Runtime {
        let paths = crate::paths::LocalPaths::new(path);
        let store = std::sync::Arc::new(crate::store::Store::new(&paths).await.unwrap());
        let components = crate::runtime::components::test_components(paths.home());
        std::fs::create_dir_all(components.asset_dir()).unwrap();
        let kernel = host_kernel("known unit test packaged boot");
        for (path, bytes) in [
            (components.kernel(), kernel.as_slice()),
            (
                components.initramfs(),
                b"known unit test packaged boot".as_slice(),
            ),
            (
                components.agent(),
                b"known unit test packaged boot".as_slice(),
            ),
        ] {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Runtime::from_store(
            paths,
            store,
            RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::default(),
            components,
            None,
        )
        .await
        .unwrap()
    }

    async fn stopped_storage_machine(name: &str) -> (tempfile::TempDir, Runtime, crate::Machine) {
        let home = tempfile::tempdir().unwrap();
        let disk = home.path().join("source.raw");
        disk_image::ext4::Formatter::new(&disk, 4096, ROOT_MINIMUM_LENGTH)
            .unwrap()
            .close()
            .unwrap();
        let runtime = test_runtime(&home.path().join("silo")).await;
        let machine = runtime
            .machine()
            .name(name)
            .image_source(ImageSource::disk(&disk))
            .create()
            .await
            .unwrap();
        (home, runtime, machine)
    }

    #[tokio::test]
    async fn stopped_storage_updates_recreate_only_private_runtime_directories_after_cleanup() {
        let (_home, runtime, machine) = stopped_storage_machine("private-run-update").await;
        let id = machine.machine_id();
        let run = runtime.machine_paths(id).machine_run_dir().to_owned();
        let root = runtime
            .machine_config(id)
            .await
            .unwrap()
            .unwrap()
            .machine_dir
            .join("root.raw");
        let initial_length = std::fs::metadata(&root).unwrap().len();
        for length in [initial_length + 512, initial_length + 1024] {
            runtime.local_paths().ensure_machine_run_dir(id).unwrap();
            runtime.local_paths().remove_machine_run_tree(id).unwrap();
            assert!(
                !run.exists(),
                "exercise the same missing tree left by stop cleanup"
            );
            machine
                .update(MachineUpdate::new().root_disk_size(length))
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&run).unwrap().permissions().mode() & 0o777,
                0o700
            );
            // The unmodified admission guard must accept the next lifecycle use.
            runtime.local_paths().ensure_machine_run_dir(id).unwrap();
            assert!(matches!(
                runtime.machine_storage_record(id).await.unwrap().root,
                crate::MachineRoot::OpaqueRaw { geometry, .. } if geometry.length == length
            ));
        }
    }

    #[tokio::test]
    async fn stopped_storage_update_refuses_existing_permissive_runtime_directory_without_repair() {
        let (_home, runtime, machine) = stopped_storage_machine("unsafe-run-update").await;
        let id = machine.machine_id();
        runtime.local_paths().ensure_machine_run_dir(id).unwrap();
        let run = runtime.machine_paths(id).machine_run_dir().to_owned();
        let marker = run.join("preserve-user-state");
        std::fs::write(&marker, b"preserve").unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before = runtime.machine_config(id).await.unwrap().unwrap();
        let storage = runtime.machine_storage_record(id).await.unwrap();
        let root = std::fs::read(before.machine_dir.join("root.raw")).unwrap();
        let requested_length = std::fs::metadata(before.machine_dir.join("root.raw"))
            .unwrap()
            .len()
            + 512;
        let result = machine
            .update(MachineUpdate::new().root_disk_size(requested_length))
            .await;
        assert!(matches!(
            result,
            Err(crate::LibVmError::InvalidOwnedPath { .. })
        ));
        assert_eq!(
            std::fs::metadata(&run).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::read(&marker).unwrap(), b"preserve");
        assert_eq!(runtime.machine_config(id).await.unwrap().unwrap(), before);
        assert_eq!(runtime.machine_storage_record(id).await.unwrap(), storage);
        assert_eq!(
            std::fs::read(before.machine_dir.join("root.raw")).unwrap(),
            root
        );
    }

    #[tokio::test]
    async fn configuration_update_refuses_trusted_init_override_without_changing_the_machine() {
        let (_home, runtime, machine) = stopped_storage_machine("trusted-init-update").await;
        let id = machine.machine_id();
        let before = runtime.machine_config(id).await.unwrap().unwrap();
        let storage = runtime.machine_storage_record(id).await.unwrap();
        let path = before.machine_dir.join("config.json");
        let file = std::fs::read(&path).unwrap();
        let with_args = |args: Vec<&str>| {
            let mut spec = before.spec.clone();
            spec.boot
                .as_mut()
                .and_then(|boot| boot.kernel.as_mut())
                .expect("direct boot kernel")
                .cmdline = args.into_iter().map(String::from).collect();
            spec
        };
        for args in [
            vec!["rdinit=/agent/silo-agent"],
            vec!["\"rdinit=/agent/silo-agent\""],
            vec!["rdinit=\"/agent/silo-agent\""],
            vec!["quiet\u{a0}rdinit=/agent/silo-agent"],
            vec!["console=hvc0", "\"rdinit=/agent/silo-agent", "quiet\""],
        ] {
            let error = machine
                .replace_config(with_args(args.clone()))
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("rdinit= is reserved"),
                "{args:?}: {error}"
            );
            assert_eq!(runtime.machine_config(id).await.unwrap().unwrap(), before);
            assert_eq!(runtime.machine_storage_record(id).await.unwrap(), storage);
            assert_eq!(std::fs::read(&path).unwrap(), file);
        }

        let accepted = with_args(vec!["init=/sbin/init", "\"a rdinit=/x\""]);
        machine.replace_config(accepted.clone()).await.unwrap();
        assert_eq!(
            runtime.machine_config(id).await.unwrap().unwrap().spec,
            accepted
        );
    }
    #[tokio::test]
    async fn stopped_tailscale_update_and_exact_atomic_name_contract() {
        let home = tempfile::tempdir().unwrap();
        let disk = home.path().join("root.raw");
        disk_image::ext4::Formatter::new(&disk, 4096, ROOT_MINIMUM_LENGTH)
            .unwrap()
            .close()
            .unwrap();
        let runtime = test_runtime(&home.path().join("silo")).await;
        let policy =
            crate::NetworkPolicy::from_hcl_str("tailscale \"vm\" { ephemeral = true }").unwrap();
        let missing = runtime
            .machine()
            .name("missing-vsock")
            .image_source(ImageSource::disk(&disk))
            .network(|n| n.policy(policy.clone()))
            .create()
            .await
            .unwrap_err();
        assert!(missing.to_string().contains("vsock"));
        let machine = runtime
            .machine()
            .name("exact")
            .image_source(ImageSource::disk(&disk))
            .vsock(true)
            .network(|n| n.policy(policy.clone()))
            .create()
            .await
            .unwrap();
        let data = machine.inspect().await.unwrap();
        let state = data.tailscale.unwrap();
        assert_eq!(state.hostname, "exact");
        assert!(state.ephemeral);
        assert_eq!(
            std::fs::metadata(&state.state_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(machine
            .update(MachineUpdate::new().vsock(false))
            .await
            .is_err());
        assert!(machine
            .replace_config(vm_spec::VmSpec::current())
            .await
            .is_err());
        assert!(machine
            .update(MachineUpdate::new().name("renamed").clear_network_policy())
            .await
            .is_err());
        assert!(runtime
            .machine()
            .name("exact")
            .image_source(ImageSource::disk(&disk))
            .create()
            .await
            .is_err());
        machine
            .update(MachineUpdate::new().clear_network_policy())
            .await
            .unwrap();
        let labels = BTreeMap::from([("io.silo.lobby.name".into(), "renamed".into())]);
        let data = machine
            .update(MachineUpdate::new().name("renamed").labels(labels.clone()))
            .await
            .unwrap();
        assert_eq!(data.name, "renamed");
        assert_eq!(data.labels, labels);
        assert!(machine
            .update(MachineUpdate::new().root_disk_size(1))
            .await
            .is_err());
        std::fs::remove_dir(&state.state_dir).unwrap();
        symlink(home.path(), &state.state_dir).unwrap();
        assert!(machine
            .update(MachineUpdate::new().set_network_policy(policy.clone()))
            .await
            .is_err());
        std::fs::remove_file(&state.state_dir).unwrap();
        machine
            .update(MachineUpdate::new().set_network_policy(policy))
            .await
            .unwrap();
        machine.remove().await.unwrap();
        assert!(!state.state_dir.exists());
    }

    #[tokio::test]
    async fn boot_update_publishes_the_complete_tuple_and_generation_without_touching_disks() {
        let (home, runtime, machine) = stopped_storage_machine("boot-update").await;
        let before = runtime
            .machine_storage_record(machine.machine_id())
            .await
            .unwrap();
        let config = runtime
            .machine_config(machine.machine_id())
            .await
            .unwrap()
            .unwrap();
        let root = crate::storage::stream::StreamHasher::new()
            .hash_file(&config.machine_dir.join("root.raw"))
            .unwrap()
            .id();
        let source = crate::storage::stream::StreamHasher::new()
            .hash_file(&home.path().join("source.raw"))
            .unwrap()
            .id();
        let kernel = home.path().join("replacement-kernel");
        let kernel_bytes = host_kernel("explicit new kernel");
        std::fs::write(&kernel, &kernel_bytes).unwrap();
        let updated = machine
            .update_boot_assets(crate::BootAssetsUpdate {
                selection: crate::BootAssetSelection::Files {
                    kernel,
                    base_initramfs: runtime.asset_directory().join("initramfs"),
                    agent: None,
                },
            })
            .await
            .unwrap();
        let after = runtime
            .machine_storage_record(machine.machine_id())
            .await
            .unwrap();
        assert_eq!(after.storage_generation, before.storage_generation + 1);
        assert_eq!(after.root, before.root);
        assert_ne!(after.boot, before.boot);
        assert_eq!(updated.guest.agent, crate::machine::MachineAgent::Disabled);
        let crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { kernel, agent, .. },
            ..
        } = after.boot
        else {
            panic!("complete pinned tuple");
        };
        assert_eq!(
            kernel,
            crate::storage::identity::ObjectDigest::of_bytes(&kernel_bytes)
        );
        assert!(agent.is_none());
        assert_eq!(
            crate::storage::stream::StreamHasher::new()
                .hash_file(&config.machine_dir.join("root.raw"))
                .unwrap()
                .id(),
            root
        );
        assert_eq!(
            crate::storage::stream::StreamHasher::new()
                .hash_file(&home.path().join("source.raw"))
                .unwrap()
                .id(),
            source
        );
    }

    #[tokio::test]
    async fn failed_boot_selection_and_ordinary_agent_changes_preserve_the_previous_tuple() {
        let (home, runtime, machine) = stopped_storage_machine("boot-rollback").await;
        let before = runtime
            .machine_storage_record(machine.machine_id())
            .await
            .unwrap();
        let config = runtime
            .machine_config(machine.machine_id())
            .await
            .unwrap()
            .unwrap();
        let result = machine
            .update_boot_assets(crate::BootAssetsUpdate {
                selection: crate::BootAssetSelection::Files {
                    kernel: runtime.asset_directory().join("kernel-default"),
                    base_initramfs: runtime.asset_directory().join("initramfs"),
                    agent: Some(home.path().join("missing-agent")),
                },
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            runtime
                .machine_storage_record(machine.machine_id())
                .await
                .unwrap(),
            before
        );
        assert_eq!(
            runtime
                .machine_config(machine.machine_id())
                .await
                .unwrap()
                .unwrap(),
            config
        );
        let mut update = MachineUpdate::new();
        let mut guest = config.guest.clone();
        guest.agent = crate::machine::MachineAgent::Disabled;
        update.guest = Some(guest);
        assert!(
            matches!(machine.update(update).await, Err(crate::LibVmError::InvalidMachineUpdate { reason, .. }) if reason.contains("update_boot_assets"))
        );
        assert_eq!(
            runtime
                .machine_storage_record(machine.machine_id())
                .await
                .unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn boot_update_refuses_a_real_lifetime_owner_before_replacing_assets() {
        let (_home, runtime, machine) = stopped_storage_machine("boot-owned").await;
        let before = runtime
            .machine_storage_record(machine.machine_id())
            .await
            .unwrap();
        runtime
            .local_paths()
            .ensure_machine_run_dir(machine.machine_id())
            .unwrap();
        let _owner = crate::lock_manager::MachineLifetimeLock::try_acquire(
            &runtime.machine_paths(machine.machine_id()).vmm_lock_path(),
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            machine
                .update_boot_assets(crate::BootAssetsUpdate {
                    selection: crate::BootAssetSelection::Packaged
                })
                .await,
            Err(crate::LibVmError::MachineAlreadyRunning { .. })
        ));
        assert_eq!(
            runtime
                .machine_storage_record(machine.machine_id())
                .await
                .unwrap(),
            before
        );
    }
}
