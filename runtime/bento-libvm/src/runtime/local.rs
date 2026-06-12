use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::launch::prepare_instance_runtime;
use crate::paths::{root_disk_relative_path, vm_spec_path_in, LocalPaths, MachinePaths};
use crate::root_disk::{clone_or_copy_root_disk, resize_raw_disk};
use crate::runtime::RuntimeNetworkingConfig;
use bento_vm_spec::{Boot, Disk, Guest, GuestOs, Hardware, Kernel, Mount, Storage, VmSpec};
use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::{pipe, Pid},
};

use crate::machine::{
    validate_machine_name, MachineCreate, MachineInspect, MachineRef, MachineRefKind,
    MachineRuntimeStatus,
};
use crate::models::{
    MachineConfig, MachineRuntimeState, MachineState, NetworkDefinition as ModelNetworkDefinition,
    RequestedNetwork as ModelRequestedNetwork,
};
use crate::monitor;
use crate::network::{
    prepare_network_runtime, reconcile_network_runtime, RequestedNetwork, RuntimeNetwork,
};
use crate::store::{Database, Sqlite};
use crate::vm_lock::VmLock;
use crate::{LibVmError, MachineId};

const DEFAULT_IMAGE_CPUS: u8 = 1;
const DEFAULT_IMAGE_MEMORY_MIB: u32 = 512;
const ROOT_DISK_KERNEL_ARG: &str = "root=/dev/vda";
const ENV_VM_STARTPIPE: &str = "_VM_STARTPIPE";
const ENV_VM_SYNCPIPE: &str = "_VM_SYNCPIPE";

/// Live runtime observation for a machine: its reconciled state plus the
/// start timestamp when running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeStatus {
    state: MachineRuntimeState,
    started_at: Option<i64>,
}

impl RuntimeStatus {
    fn from_machine_state(state: &MachineState) -> Self {
        Self {
            state: state.status,
            started_at: state.started_at,
        }
    }

    fn is_running(&self) -> bool {
        self.state.is_running()
    }

    fn is_active(&self) -> bool {
        matches!(
            self.state,
            MachineRuntimeState::Starting
                | MachineRuntimeState::Running
                | MachineRuntimeState::Stopping
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LocalRuntime {
    paths: LocalPaths,
    db: Sqlite,
    networking: RuntimeNetworkingConfig,
}

struct PendingMachine {
    id: MachineId,
    name: String,
    spec: VmSpec,
    staged_dir: PathBuf,
    final_dir: PathBuf,
    image_ref: String,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    network: ModelRequestedNetwork,
    committed: bool,
}

struct ObservedRuntime {
    state: MachineRuntimeState,
    pid: Option<i32>,
    started_at: Option<i64>,
    last_error: Option<String>,
    needs_writeback: bool,
}

impl ObservedRuntime {
    fn machine_state(&self, machine_id: MachineId) -> MachineState {
        MachineState {
            machine_id,
            status: self.state,
            vmmon_pid: self.pid,
            started_at: self.started_at,
            last_error: self.last_error.clone(),
            updated_at: current_unix(),
        }
    }

    fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            state: self.state,
            started_at: self.started_at,
        }
    }
}

impl LocalRuntime {
    pub(crate) async fn new(
        paths: LocalPaths,
        networking: RuntimeNetworkingConfig,
    ) -> Result<Self, LibVmError> {
        let db = Sqlite::new(&paths).await?;
        let paths = LocalPaths::from_roots(db.roots().clone());
        Ok(Self {
            paths,
            db,
            networking,
        })
    }

    pub(crate) fn paths(&self) -> &LocalPaths {
        &self.paths
    }

    pub(crate) async fn create_machine(
        &self,
        request: MachineCreate,
    ) -> Result<MachineConfig, LibVmError> {
        if matches!(request.disk_size_bytes, Some(0)) {
            return Err(LibVmError::InvalidCreateRequest {
                name: request.name,
                reason: "root disk size must be greater than 0".to_string(),
            });
        }

        let base_rootfs_path =
            canonicalize_existing_path(&request.base_rootfs_path, "base rootfs")?;
        let kernel_path = canonicalize_optional_existing_path(request.kernel.as_deref(), "kernel")?;
        let initramfs_path =
            canonicalize_optional_existing_path(request.initramfs.as_deref(), "initramfs")?;
        if let Some(userdata) = request.userdata.as_deref() {
            if userdata.trim().is_empty() {
                return Err(LibVmError::InvalidCreateRequest {
                    name: request.name.clone(),
                    reason: "userdata cannot be empty".to_string(),
                });
            }
        }
        let userdata = request.userdata;
        let disk_paths = canonicalize_existing_paths(&request.disks, "disk")?;

        let resolved_cpus = request.cpus.unwrap_or(DEFAULT_IMAGE_CPUS);
        let resolved_memory = request.memory_mib.unwrap_or(DEFAULT_IMAGE_MEMORY_MIB);

        let mounts = assign_mount_tags(request.mounts);
        let disks = std::iter::once(Disk {
            path: root_disk_relative_path(),
            read_only: false,
        })
        .chain(disk_paths.into_iter().map(|path| Disk {
            path,
            read_only: false,
        }))
        .collect();

        let spec = VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: kernel_path,
                    cmdline: vec![ROOT_DISK_KERNEL_ARG.to_string()],
                    initramfs: initramfs_path,
                }),
                userdata,
            }),
            hardware: Some(Hardware {
                cpus: Some(resolved_cpus),
                memory: Some(resolved_memory),
                nested_virtualization: Some(request.nested_virtualization),
                rosetta: Some(request.rosetta),
            }),
            storage: Some(Storage { disks }),
            mounts,
            ..VmSpec::current()
        };

        let network = request.network.unwrap_or_default().into_model();
        self.validate_requested_network(&network).await?;
        let pending = self
            .create_pending(
                request.name.clone(),
                spec,
                request.image_ref.clone(),
                request.labels,
                request.metadata,
                network,
            )
            .await?;
        let rootfs_path = MachinePaths::new(pending.dir()).root_disk_path();
        clone_or_copy_root_disk(&base_rootfs_path, &rootfs_path)?;

        if let Some(size_bytes) = request.disk_size_bytes {
            resize_raw_disk(&rootfs_path, size_bytes)?;
        }

        pending.commit(self).await
    }

    async fn create_pending(
        &self,
        name: String,
        spec: VmSpec,
        image_ref: String,
        labels: BTreeMap<String, String>,
        metadata: BTreeMap<String, String>,
        network: ModelRequestedNetwork,
    ) -> Result<PendingMachine, LibVmError> {
        validate_machine_name(&name)?;

        if self
            .db
            .get_machine_config_by_name(name.as_str())
            .await?
            .is_some()
        {
            return Err(LibVmError::MachineAlreadyExists { name });
        }

        let id = MachineId::new();
        let final_dir = self.paths.machine(id).dir().to_path_buf();
        if final_dir.exists() {
            return Err(LibVmError::MachineIdAlreadyExists { id: id.to_string() });
        }

        let staged_dir = create_staging_dir(&self.paths)?;
        write_machine_config(&staged_dir, &name, &spec)?;

        Ok(PendingMachine {
            id,
            name,
            spec,
            staged_dir,
            final_dir,
            image_ref,
            labels,
            metadata,
            network,
            committed: false,
        })
    }

    async fn inspect(&self, machine: &MachineRef) -> Result<MachineInspect, LibVmError> {
        let config = self.resolve_machine_config(machine).await?;
        self.machine_inspect(config).await
    }

    pub(crate) async fn inspect_by_id(
        &self,
        machine_id: MachineId,
    ) -> Result<MachineInspect, LibVmError> {
        self.inspect(&MachineRef::id(machine_id)).await
    }

    pub(crate) async fn list_machine_configs(&self) -> Result<Vec<MachineConfig>, LibVmError> {
        let machines = self.db.list_machine_configs().await?;
        for config in &machines {
            self.reconcile_machine_runtime_best_effort(config).await?;
        }
        Ok(machines)
    }

    pub(crate) async fn allocate_ephemeral_name(&self, prefix: &str) -> Result<String, LibVmError> {
        self.db.allocate_ephemeral_name(prefix).await
    }

    pub(crate) async fn create_network_definition(
        &self,
        definition: ModelNetworkDefinition,
    ) -> Result<(), LibVmError> {
        self.db.upsert_network_definition(&definition).await
    }

    pub(crate) async fn list_network_definitions(
        &self,
    ) -> Result<Vec<ModelNetworkDefinition>, LibVmError> {
        self.db.list_network_definitions().await
    }

    pub(crate) async fn get_network_definition(
        &self,
        name: &str,
    ) -> Result<Option<ModelNetworkDefinition>, LibVmError> {
        self.db.get_network_definition(name).await
    }

    pub(crate) async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError> {
        self.db.remove_network_definition(name).await
    }

    pub(crate) async fn set_network_by_id(
        &self,
        machine_id: MachineId,
        network: RequestedNetwork,
    ) -> Result<MachineInspect, LibVmError> {
        let network = network.into_model();
        self.validate_requested_network(&network).await?;
        let mut config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let _lock = self.acquire_machine_lock(config.id)?;
        let status = self.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        config.network = network;
        config.modified_at = current_unix();
        self.db.update_machine_config(&config).await?;
        self.machine_inspect(config).await
    }

    pub(crate) async fn replace_config_by_id(
        &self,
        machine_id: MachineId,
        spec: VmSpec,
    ) -> Result<MachineInspect, LibVmError> {
        let mut config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let _lock = self.acquire_machine_lock(config.id)?;
        let status = self.reconcile_machine_runtime_locked(&config).await?;
        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }
        let previous_spec = config.spec.clone();
        config.spec = spec;
        config.modified_at = current_unix();
        write_machine_config(&config.instance_dir, &config.name, &config.spec)?;
        if let Err(err) = self.db.update_machine_config(&config).await {
            let _ = write_machine_config(&config.instance_dir, &config.name, &previous_spec);
            return Err(err);
        }
        self.machine_inspect(config).await
    }

    pub(crate) async fn remove_by_id(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let _lock = self.acquire_machine_lock(config.id)?;
        let status = self.reconcile_machine_runtime_locked(&config).await?;
        reconcile_network_runtime(&self.paths, &self.db, &config, status.is_active()).await?;

        if status.is_active() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: config.name.clone(),
            });
        }

        match fs::remove_dir_all(&config.instance_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        self.db.remove_machine_state(config.id).await?;
        self.db.remove_machine_config(&config).await
    }

    pub(crate) async fn start_by_id(
        &self,
        machine_id: MachineId,
    ) -> Result<MachineInspect, LibVmError> {
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let machine_paths = self.paths.machine(config.id);
        let pid_path = machine_paths.vmmon_pid_path();
        let config_path = machine_paths.vm_spec_path();
        let socket_path = machine_paths.vmmon_socket_path();
        let trace_path = machine_paths.vmmon_trace_log_path();
        let serial_log_path = machine_paths.serial_log_path();
        let metadata_config_path = machine_paths.metadata_config_path();

        let sync_read = {
            let _lock = self.acquire_machine_lock(config.id)?;
            let status = self.reconcile_machine_runtime_locked(&config).await?;
            reconcile_network_runtime(&self.paths, &self.db, &config, status.is_active()).await?;

            if status.is_active() {
                return Err(LibVmError::MachineAlreadyRunning {
                    reference: config.name.clone(),
                });
            }

            let resolved_network =
                prepare_network_runtime(&self.paths, &self.db, &config, &self.networking).await?;
            let mut spec = config.spec.clone();
            prepare_instance_runtime(
                &self.paths,
                &config.instance_dir,
                &config.name,
                &mut spec,
                &resolved_network,
                &self.networking,
            )
            .map_err(|err| LibVmError::InstancePreparationFailed {
                reference: config.name.clone(),
                message: err.to_string(),
            })?;

            self.set_machine_state(config.id, MachineRuntimeState::Starting, None, None, None)
                .await?;

            let launch = VmmonLaunch {
                machine_id: config.id,
                name: &config.name,
                instance_dir: &config.instance_dir,
                pidfile: &pid_path,
                config: &config_path,
                socket: &socket_path,
                serial_log: &serial_log_path,
                trace_log: &trace_path,
                network: &resolved_network,
                metadata_config: &metadata_config_path,
                wait_for_registration: monitor::DEFAULT_GUEST_READINESS_TIMEOUT,
            };
            let VmmonHandshake {
                start_write,
                sync_read,
            } = match spawn_vmmon(&launch) {
                Ok(handshake) => handshake,
                Err(err) => {
                    self.mark_machine_stopped(config.id, Some(err.to_string()))
                        .await?;
                    return Err(err);
                }
            };
            if let Err(err) = release_startpipe(start_write) {
                self.mark_machine_stopped(config.id, Some(err.to_string()))
                    .await?;
                return Err(err.into());
            }

            sync_read
        };

        if let Err(err) = wait_for_monitor_start(sync_read, &trace_path).await {
            let _lock = self.acquire_machine_lock(config.id)?;
            self.mark_machine_stopped(config.id, Some(err.to_string()))
                .await?;
            return Err(err);
        }

        {
            let _lock = self.acquire_machine_lock(config.id)?;
            let pid = read_monitor_pid(&pid_path)?;
            if !process_is_alive(pid)? {
                return Err(LibVmError::MonitorConnection {
                    reference: config.name.clone(),
                    message: format!("vmmon pid {pid} from {} is not running", pid_path.display()),
                });
            }
            let started_at = pid_file_mtime(&pid_path);
            self.set_machine_state(
                config.id,
                MachineRuntimeState::Running,
                Some(pid),
                Some(started_at),
                None,
            )
            .await?;
        }
        self.machine_inspect(config).await
    }

    pub(crate) async fn wait_for_guest_running_by_id(
        &self,
        machine_id: MachineId,
        timeout: std::time::Duration,
    ) -> Result<(), LibVmError> {
        let (config, socket_path) = self.resolve_running_socket_by_id(machine_id).await?;
        monitor::wait_for_guest_running(&socket_path, timeout)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })
    }

    pub(crate) async fn stop_by_id(
        &self,
        machine_id: MachineId,
    ) -> Result<MachineInspect, LibVmError> {
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let pid_path = self.paths.machine(config.id).vmmon_pid_path();
        {
            let _lock = self.acquire_machine_lock(config.id)?;
            let status = self.reconcile_machine_runtime_locked(&config).await?;
            if !status.is_running() {
                return Err(LibVmError::MachineNotRunning {
                    reference: config.name.clone(),
                });
            }
            let pid = read_monitor_pid(&pid_path)?;

            self.set_machine_state(
                config.id,
                MachineRuntimeState::Stopping,
                Some(pid),
                status.started_at,
                None,
            )
            .await?;

            kill(Pid::from_raw(pid), Some(Signal::SIGINT))
                .map_err(|err| io::Error::other(err.to_string()))?;
        }

        wait_for_monitor_stop(&pid_path, &config.name).await?;
        {
            let _lock = self.acquire_machine_lock(config.id)?;
            self.mark_machine_stopped(config.id, None).await?;
            reconcile_network_runtime(&self.paths, &self.db, &config, false).await?;
        }
        self.machine_inspect(config).await
    }

    pub(crate) async fn get_status_by_id(
        &self,
        machine_id: MachineId,
    ) -> Result<MachineRuntimeStatus, LibVmError> {
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let status = self.reconcile_machine_runtime_best_effort(&config).await?;
        reconcile_network_runtime(&self.paths, &self.db, &config, status.is_running()).await?;
        let (config, socket_path) = self.resolve_running_socket_by_id(machine_id).await?;
        let status = monitor::get_vm_monitor_inspect(&socket_path)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })?;
        Ok(MachineRuntimeStatus::from_protocol(status))
    }

    pub(crate) async fn open_serial_stream_by_id(
        &self,
        machine_id: MachineId,
    ) -> Result<tokio::net::UnixStream, LibVmError> {
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let socket_path = self.paths.machine(config.id).vmmon_socket_path();

        if !self
            .reconcile_machine_runtime_best_effort(&config)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name.clone(),
            });
        }

        monitor::open_serial_stream(&socket_path)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })
    }

    pub(crate) async fn open_shell_stream_by_id(
        &self,
        machine_id: MachineId,
        wait_for_guest_readiness: bool,
    ) -> Result<tokio::net::UnixStream, LibVmError> {
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        let socket_path = self.paths.machine(config.id).vmmon_socket_path();

        if !self
            .reconcile_machine_runtime_best_effort(&config)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name.clone(),
            });
        }

        if wait_for_guest_readiness {
            monitor::wait_for_shell_with_timeout(
                &socket_path,
                monitor::DEFAULT_GUEST_READINESS_TIMEOUT,
                Duration::from_secs(1),
            )
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name.clone(),
                message,
            })?;
        }

        monitor::open_shell_stream(&socket_path)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })
    }

    pub(crate) async fn resolve_machine_config(
        &self,
        machine: &MachineRef,
    ) -> Result<MachineConfig, LibVmError> {
        match machine.kind() {
            MachineRefKind::Id(id) => {
                self.db.get_machine_config_by_id(*id).await?.ok_or_else(|| {
                    LibVmError::MachineNotFound {
                        reference: id.to_string(),
                    }
                })
            }
            MachineRefKind::Name(name) => self
                .db
                .get_machine_config_by_name(name)
                .await?
                .ok_or_else(|| LibVmError::MachineNotFound {
                    reference: name.clone(),
                }),
            MachineRefKind::IdPrefix(prefix) => {
                let matches = self.db.get_machine_config_by_id_prefix(prefix).await?;
                match matches.len() {
                    0 => Err(LibVmError::MachineNotFound {
                        reference: prefix.clone(),
                    }),
                    1 => Ok(matches.into_iter().next().expect("just checked len == 1")),
                    count => Err(LibVmError::AmbiguousIdPrefix {
                        prefix: prefix.clone(),
                        count,
                    }),
                }
            }
        }
    }

    fn acquire_machine_lock(&self, machine_id: MachineId) -> Result<VmLock, LibVmError> {
        Ok(VmLock::acquire(
            &self.paths.machine(machine_id).lock_path(),
        )?)
    }

    fn try_acquire_machine_lock(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<VmLock>, LibVmError> {
        Ok(VmLock::try_acquire(
            &self.paths.machine(machine_id).lock_path(),
        )?)
    }

    async fn reconcile_machine_runtime_best_effort(
        &self,
        metadata: &MachineConfig,
    ) -> Result<RuntimeStatus, LibVmError> {
        let observed = self.observe_machine_runtime(metadata).await?;
        if observed.needs_writeback {
            let Some(_lock) = self.try_acquire_machine_lock(metadata.id)? else {
                let state = self.machine_state(metadata.id).await?;
                return Ok(RuntimeStatus::from_machine_state(&state));
            };
            return self.reconcile_machine_runtime_locked(metadata).await;
        }
        Ok(observed.status())
    }

    async fn reconcile_machine_runtime_locked(
        &self,
        metadata: &MachineConfig,
    ) -> Result<RuntimeStatus, LibVmError> {
        let observed = self.observe_machine_runtime(metadata).await?;
        if observed.needs_writeback {
            self.db
                .upsert_machine_state(&observed.machine_state(metadata.id))
                .await?;
        }
        Ok(observed.status())
    }

    async fn observe_machine_runtime(
        &self,
        metadata: &MachineConfig,
    ) -> Result<ObservedRuntime, LibVmError> {
        let runtime = self.db.get_machine_state(metadata.id).await?;
        let pid_path = self.paths.machine(metadata.id).vmmon_pid_path();
        let pid = match read_monitor_pid(&pid_path) {
            Ok(pid) => Some(pid),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(_) => None,
        };
        let live_pid = match pid {
            Some(pid) if process_is_alive(pid)? => Some(pid),
            _ => None,
        };

        let current_state = runtime
            .as_ref()
            .map(|runtime| runtime.status)
            .unwrap_or(MachineRuntimeState::Stopped);
        let desired_state = match (current_state, live_pid) {
            (MachineRuntimeState::Starting | MachineRuntimeState::Stopping, _) => current_state,
            (_, Some(_)) => MachineRuntimeState::Running,
            _ => MachineRuntimeState::Stopped,
        };
        let started_at = live_pid.map(|_| {
            runtime
                .as_ref()
                .and_then(|runtime| runtime.started_at)
                .unwrap_or_else(|| pid_file_mtime(&pid_path))
        });
        let needs_writeback = current_state != desired_state
            || runtime.is_none()
            || runtime.as_ref().and_then(|runtime| runtime.vmmon_pid) != live_pid;

        Ok(ObservedRuntime {
            state: desired_state,
            pid: live_pid,
            started_at,
            last_error: if desired_state == MachineRuntimeState::Stopped {
                runtime.and_then(|runtime| runtime.last_error)
            } else {
                None
            },
            needs_writeback,
        })
    }

    async fn set_machine_state(
        &self,
        machine_id: MachineId,
        status: MachineRuntimeState,
        vmmon_pid: Option<i32>,
        started_at: Option<i64>,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.db
            .upsert_machine_state(&MachineState {
                machine_id,
                status,
                vmmon_pid,
                started_at,
                last_error,
                updated_at: current_unix(),
            })
            .await
    }

    async fn mark_machine_stopped(
        &self,
        machine_id: MachineId,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.set_machine_state(
            machine_id,
            MachineRuntimeState::Stopped,
            None,
            None,
            last_error,
        )
        .await
    }

    async fn validate_requested_network(
        &self,
        network: &ModelRequestedNetwork,
    ) -> Result<(), LibVmError> {
        if let ModelRequestedNetwork::Named { name, .. } = network {
            self.db.get_network_definition(name).await?.ok_or_else(|| {
                LibVmError::NetworkRuntime {
                    reference: name.clone(),
                    message: format!("named network {:?} is not defined", name),
                }
            })?;
        }
        Ok(())
    }

    async fn machine_state(&self, machine_id: MachineId) -> Result<MachineState, LibVmError> {
        if let Some(state) = self.db.get_machine_state(machine_id).await? {
            return Ok(state);
        }

        Ok(stopped_machine_state(machine_id, None))
    }

    async fn machine_inspect(&self, config: MachineConfig) -> Result<MachineInspect, LibVmError> {
        self.reconcile_machine_runtime_best_effort(&config).await?;
        let state = self.machine_state(config.id).await?;
        Ok(MachineInspect::from_model(config, state))
    }

    async fn resolve_running_socket_by_id(
        &self,
        machine_id: MachineId,
    ) -> Result<(MachineConfig, PathBuf), LibVmError> {
        let config = self
            .resolve_machine_config(&MachineRef::id(machine_id))
            .await?;
        if !self
            .reconcile_machine_runtime_best_effort(&config)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name,
            });
        }

        let socket_path = self.paths.machine(config.id).vmmon_socket_path();
        Ok((config, socket_path))
    }
}

fn write_machine_config(instance_dir: &Path, name: &str, spec: &VmSpec) -> Result<(), LibVmError> {
    let config =
        serde_json::to_string_pretty(spec).map_err(|source| LibVmError::VmSpecSerializeFailed {
            name: name.to_string(),
            source,
        })?;
    fs::write(vm_spec_path_in(instance_dir), config)?;
    Ok(())
}

fn assign_mount_tags(mounts: Vec<Mount>) -> Vec<Mount> {
    mounts
        .into_iter()
        .enumerate()
        .map(|(index, mut mount)| {
            if mount.tag.trim().is_empty() {
                mount.tag = format!("mount{index}");
            }
            mount
        })
        .collect()
}

fn canonicalize_optional_existing_path(
    path: Option<&Path>,
    kind: &str,
) -> Result<Option<PathBuf>, LibVmError> {
    let Some(path) = path else {
        return Ok(None);
    };

    Ok(Some(canonicalize_existing_path(path, kind)?))
}

fn canonicalize_existing_paths(paths: &[PathBuf], kind: &str) -> Result<Vec<PathBuf>, LibVmError> {
    paths
        .iter()
        .map(|path| canonicalize_existing_path(path, kind))
        .collect()
}

fn canonicalize_existing_path(path: &Path, kind: &str) -> Result<PathBuf, LibVmError> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    std::fs::canonicalize(&abs).map_err(|err| LibVmError::InvalidCreateRequest {
        name: kind.to_string(),
        reason: format!("{kind} path does not exist: {} ({err})", abs.display()),
    })
}

struct VmmonHandshake {
    start_write: OwnedFd,
    sync_read: OwnedFd,
}

struct VmmonLaunch<'a> {
    machine_id: MachineId,
    name: &'a str,
    instance_dir: &'a Path,
    pidfile: &'a Path,
    config: &'a Path,
    socket: &'a Path,
    serial_log: &'a Path,
    trace_log: &'a Path,
    network: &'a RuntimeNetwork,
    metadata_config: &'a Path,
    wait_for_registration: Duration,
}

fn spawn_vmmon(launch: &VmmonLaunch<'_>) -> Result<VmmonHandshake, LibVmError> {
    let (start_read, start_write) = pipe().map_err(|err| io::Error::other(err.to_string()))?;
    let (sync_read, sync_write) = pipe().map_err(|err| io::Error::other(err.to_string()))?;

    let mut command = Command::new(resolve_vmmon_executable()?);
    command
        .arg("--id")
        .arg(launch.machine_id.to_string())
        .arg("--name")
        .arg(launch.name)
        .arg("--data-dir")
        .arg(launch.instance_dir)
        .arg("--pidfile")
        .arg(launch.pidfile)
        .arg("--config")
        .arg(launch.config)
        .arg("--socket")
        .arg(launch.socket)
        .arg("--serial-log")
        .arg(launch.serial_log)
        .arg("--trace-log")
        .arg(launch.trace_log)
        .arg("--network")
        .arg(launch.network.to_vmmon_arg())
        .arg("--metadata-config")
        .arg(launch.metadata_config)
        .arg("--wait-for-registration")
        .arg(launch.wait_for_registration.as_secs().to_string());
    command
        .env(ENV_VM_STARTPIPE, start_read.as_raw_fd().to_string())
        .env(ENV_VM_SYNCPIPE, sync_write.as_raw_fd().to_string());

    // vmmon handles its own daemonization via double-fork internally,
    // so only the child-side pipe fds must survive exec/self-spawn.
    clear_cloexec(&start_read)?;
    clear_cloexec(&sync_write)?;

    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    drop(start_read);
    drop(sync_write);

    Ok(VmmonHandshake {
        start_write,
        sync_read,
    })
}

fn resolve_vmmon_executable() -> Result<PathBuf, LibVmError> {
    let current_exe = std::env::current_exe()?;
    let expected_path = current_exe
        .parent()
        .map(|parent| parent.join("vmmon"))
        .unwrap_or_else(|| PathBuf::from("vmmon"));

    if expected_path.exists() {
        return Ok(expected_path);
    }

    if let Some(path) = std::env::var_os("PATH") {
        if std::env::split_paths(&path)
            .map(|path| path.join("vmmon"))
            .any(|candidate| candidate.exists())
        {
            return Ok(PathBuf::from("vmmon"));
        }
    }

    Err(LibVmError::VmMonExecutableNotFound { expected_path })
}

async fn wait_for_monitor_start(syncpipe: OwnedFd, trace_path: &Path) -> Result<(), LibVmError> {
    let deadline_duration = std::time::Duration::from_secs(30);
    let trace_path = trace_path.to_path_buf();
    let result = tokio::time::timeout(
        deadline_duration,
        tokio::task::spawn_blocking(move || read_syncpipe(syncpipe)),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "vmmon syncpipe did not report readiness in {:?} (hint: see {})",
                deadline_duration,
                trace_path.display(),
            ),
        )
    })?
    .map_err(|err| io::Error::other(format!("join vmmon syncpipe wait task: {err}")))??;

    match result {
        StartupResult::Started => Ok(()),
        StartupResult::Failed(message) => Err(io::Error::other(message).into()),
    }
}

fn release_startpipe(startpipe: OwnedFd) -> io::Result<()> {
    let mut file = std::fs::File::from(startpipe);
    file.write_all(&[1])?;
    file.flush()
}

fn read_syncpipe(syncpipe: OwnedFd) -> io::Result<StartupResult> {
    let mut input = String::new();
    let mut file = std::fs::File::from(syncpipe);
    std::io::BufReader::new(&mut file).read_line(&mut input)?;

    if input == "started\n" {
        return Ok(StartupResult::Started);
    }

    if let Some(message) = input.strip_prefix("failed\t") {
        return Ok(StartupResult::Failed(message.trim_end().to_string()));
    }

    if input.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "vmmon exited before reporting syncpipe result",
        ));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected vmmon syncpipe message: {input:?}"),
    ))
}

fn clear_cloexec(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let flags = fcntl(fd, FcntlArg::F_GETFD).map_err(|err| io::Error::other(err.to_string()))?;
    let mut fd_flags = FdFlag::from_bits_retain(flags);
    fd_flags.remove(FdFlag::FD_CLOEXEC);
    fcntl(fd, FcntlArg::F_SETFD(fd_flags)).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(())
}

enum StartupResult {
    Started,
    Failed(String),
}

async fn wait_for_monitor_stop(pid_path: &Path, machine_name: &str) -> Result<(), LibVmError> {
    let timeout = std::time::Duration::from_secs(45);
    let poll_interval = std::time::Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match tokio::fs::metadata(pid_path).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out after {:?} waiting for machine {:?} to stop",
                    timeout, machine_name
                ),
            )
            .into());
        }

        tokio::time::sleep(poll_interval).await;
    }
}

fn read_monitor_pid(pid_path: &Path) -> io::Result<i32> {
    let raw = fs::read_to_string(pid_path)?;
    let trimmed = raw.trim();
    trimmed.parse::<i32>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse monitor pid from {}: {err}", pid_path.display()),
        )
    })
}

fn process_is_alive(pid: i32) -> Result<bool, LibVmError> {
    match kill(Pid::from_raw(pid), None) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(Errno::EPERM) => Ok(true),
        Err(err) => Err(io::Error::other(err.to_string()).into()),
    }
}

fn pid_file_mtime(pid_path: &Path) -> i64 {
    std::fs::metadata(pid_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn current_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn stopped_machine_state(machine_id: MachineId, last_error: Option<String>) -> MachineState {
    MachineState {
        machine_id,
        status: MachineRuntimeState::Stopped,
        vmmon_pid: None,
        started_at: None,
        last_error,
        updated_at: current_unix(),
    }
}

impl PendingMachine {
    fn dir(&self) -> &Path {
        &self.staged_dir
    }

    async fn commit(mut self, runtime: &LocalRuntime) -> Result<MachineConfig, LibVmError> {
        if self.final_dir.exists() {
            return Err(LibVmError::MachineIdAlreadyExists {
                id: self.id.to_string(),
            });
        }

        if let Some(parent) = self.final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&self.staged_dir, &self.final_dir)?;

        let now = current_unix();
        let config = MachineConfig {
            id: self.id,
            name: self.name.clone(),
            spec: self.spec.clone(),
            instance_dir: self.final_dir.clone(),
            created_at: now,
            modified_at: now,
            image_ref: self.image_ref.clone(),
            labels: self.labels.clone(),
            metadata: self.metadata.clone(),
            network: self.network.clone(),
        };
        if let Err(err) = runtime.db.insert_machine_config(&config).await {
            let _ = fs::remove_dir_all(&self.final_dir);
            return Err(err);
        }
        if let Err(err) = runtime
            .db
            .upsert_machine_state(&stopped_machine_state(self.id, None))
            .await
        {
            let _ = runtime.db.remove_machine_config(&config).await;
            let _ = fs::remove_dir_all(&self.final_dir);
            return Err(err);
        }

        self.committed = true;
        Ok(config)
    }
}

impl Drop for PendingMachine {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        match fs::remove_dir_all(&self.staged_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
}

fn create_staging_dir(paths: &LocalPaths) -> Result<PathBuf, LibVmError> {
    let staging_root = paths.staging_dir();
    fs::create_dir_all(&staging_root)?;

    for attempt in 0..256u32 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| LibVmError::InvalidMachineName {
                name: "staging".to_string(),
                reason: format!("system clock error while creating staging dir: {err}"),
            })?
            .as_nanos();
        let candidate = staging_root.join(format!("{}-{timestamp}-{attempt}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(LibVmError::InvalidMachineName {
        name: "staging".to_string(),
        reason: "failed to allocate unique staging directory".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        assign_mount_tags, read_syncpipe, release_startpipe, LocalRuntime, PendingMachine,
        StartupResult, ROOT_DISK_KERNEL_ARG,
    };
    use crate::models::MachineRuntimeState;
    use crate::paths::{root_disk_relative_path, LocalPaths};
    use crate::{LibVmError, MachineCreate, MachineRef, MachineStatus, RuntimeNetworkingConfig};
    use bento_vm_spec::{Boot, Guest, GuestOs, Hardware, Kernel, Mount, Storage, VmSpec};
    use nix::unistd::pipe;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::time::Duration;

    fn sample_vm_spec() -> VmSpec {
        VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: None,
                    cmdline: Vec::new(),
                    initramfs: None,
                }),
                userdata: None,
            }),
            hardware: Some(Hardware {
                cpus: Some(4),
                memory: Some(4096),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            ..VmSpec::current()
        }
    }

    fn spec_kernel(spec: &VmSpec) -> &Kernel {
        spec.boot
            .as_ref()
            .and_then(|boot| boot.kernel.as_ref())
            .expect("spec should have kernel section")
    }

    fn spec_hardware(spec: &VmSpec) -> &Hardware {
        spec.hardware
            .as_ref()
            .expect("spec should have hardware section")
    }

    fn spec_hardware_mut(spec: &mut VmSpec) -> &mut Hardware {
        spec.hardware
            .as_mut()
            .expect("spec should have hardware section")
    }

    fn spec_storage(spec: &VmSpec) -> &Storage {
        spec.storage
            .as_ref()
            .expect("spec should have storage section")
    }

    fn spec_userdata(spec: &VmSpec) -> Option<&str> {
        spec.boot.as_ref().and_then(|boot| boot.userdata.as_deref())
    }

    async fn create_pending_sample(
        runtime: &LocalRuntime,
        name: &str,
    ) -> Result<PendingMachine, LibVmError> {
        runtime
            .create_pending(
                name.to_string(),
                sample_vm_spec(),
                "test-image:latest".to_string(),
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
                crate::models::RequestedNetwork::default(),
            )
            .await
    }

    fn create_request(base_rootfs_path: PathBuf, name: &str) -> MachineCreate {
        MachineCreate {
            image_ref: "ghcr.io/vandycknick/archlinuxarm:latest".to_string(),
            base_rootfs_path,
            name: name.to_string(),
            labels: std::collections::BTreeMap::new(),
            metadata: std::collections::BTreeMap::new(),
            cpus: None,
            memory_mib: None,
            kernel: None,
            initramfs: None,
            disk_size_bytes: None,
            nested_virtualization: false,
            rosetta: false,
            userdata: None,
            disks: Vec::new(),
            mounts: Vec::new(),
            network: None,
        }
    }

    fn write_base_rootfs(data_dir: &std::path::Path) -> PathBuf {
        let image_dir = data_dir.join("images/sha256-test/linux-arm64");
        std::fs::create_dir_all(&image_dir).expect("image dir should be created");
        let base_rootfs_path = image_dir.join("rootfs.img");
        std::fs::write(&base_rootfs_path, b"disk").expect("rootfs should be written");
        base_rootfs_path
    }

    struct ChildGuard {
        child: std::process::Child,
    }

    impl ChildGuard {
        fn sleep() -> Self {
            let child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep process");
            Self { child }
        }

        fn id(&self) -> u32 {
            self.child.id()
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    async fn wait_for_machine_state(
        runtime: &LocalRuntime,
        machine_id: crate::MachineId,
        expected: MachineRuntimeState,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = runtime
                    .machine_state(machine_id)
                    .await
                    .expect("read machine state");
                if state.status == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("machine state should change before timeout");
    }

    #[tokio::test]
    async fn create_machine_clones_rootfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = LocalRuntime::new(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let mut request = create_request(base_rootfs_path, "devbox");
        request.userdata = Some("#!/bin/sh\necho profile\n".to_string());
        let machine = runtime
            .create_machine(request)
            .await
            .expect("create from image");

        let root_disk = machine.instance_dir.join(root_disk_relative_path());
        assert_eq!(
            std::fs::read(root_disk).expect("root disk should exist"),
            b"disk"
        );
        assert_eq!(spec_hardware(&machine.spec).cpus, Some(1));
        assert_eq!(spec_hardware(&machine.spec).memory, Some(512));
        assert_eq!(
            spec_kernel(&machine.spec).cmdline,
            vec![ROOT_DISK_KERNEL_ARG.to_string()]
        );
        assert_eq!(spec_storage(&machine.spec).disks.len(), 1);
        assert_eq!(
            spec_storage(&machine.spec).disks[0].path,
            root_disk_relative_path()
        );
        assert!(!spec_storage(&machine.spec).disks[0].read_only);
        assert_eq!(
            spec_userdata(&machine.spec),
            Some("#!/bin/sh\necho profile\n")
        );
    }

    #[tokio::test]
    async fn create_machine_defers_initramfs_generation_until_start() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = LocalRuntime::new(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let machine = runtime
            .create_machine(create_request(base_rootfs_path, "devbox"))
            .await
            .expect("create from image");

        assert_eq!(spec_kernel(&machine.spec).initramfs, None);
        assert!(!machine.instance_dir.join("initramfs").exists());
    }

    #[tokio::test]
    async fn create_machine_respects_explicit_initramfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);
        let explicit = temp.path().join("custom-initramfs");
        std::fs::write(&explicit, b"custom initramfs").expect("write explicit initramfs");

        let runtime = LocalRuntime::new(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let mut request = create_request(base_rootfs_path, "devbox");
        request.initramfs = Some(explicit.clone());
        let machine = runtime
            .create_machine(request)
            .await
            .expect("create from image");

        assert_eq!(
            spec_kernel(&machine.spec).initramfs,
            Some(std::fs::canonicalize(explicit).expect("canonicalize explicit"))
        );
        assert!(!machine.instance_dir.join("initramfs").exists());
    }

    #[tokio::test]
    async fn create_machine_does_not_require_initramfs_assets() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let base_rootfs_path = write_base_rootfs(&data_dir);

        let runtime = LocalRuntime::new(
            LocalPaths::new(data_dir),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");
        let machine = runtime
            .create_machine(create_request(base_rootfs_path, "devbox"))
            .await
            .expect("create without boot assets");

        assert_eq!(spec_kernel(&machine.spec).initramfs, None);
        assert!(!machine.instance_dir.join("initramfs").exists());
    }

    #[test]
    fn assign_mount_tags_fills_missing_tags_without_rewriting_sources() {
        let mounts = assign_mount_tags(vec![Mount {
            source: PathBuf::from("~"),
            tag: String::new(),
            read_only: false,
        }]);

        assert_eq!(mounts[0].tag, "mount0");
        assert_eq!(mounts[0].source, PathBuf::from("~"));
    }

    #[test]
    fn release_startpipe_writes_one_byte() {
        let (read_fd, write_fd) = pipe().expect("create pipe");

        release_startpipe(write_fd).expect("release startpipe");

        let mut file = std::fs::File::from(read_fd);
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).expect("read release byte");
        assert_eq!(byte, [1]);
    }

    #[test]
    fn read_syncpipe_accepts_started_message() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut write_file = std::fs::File::from(write_fd);
        write_file.write_all(b"started\n").expect("write started");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).expect("read syncpipe"),
            StartupResult::Started
        ));
    }

    #[test]
    fn read_syncpipe_accepts_failed_message() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut write_file = std::fs::File::from(write_fd);
        write_file
            .write_all(b"failed\tkrun exploded\n")
            .expect("write failure");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).expect("read syncpipe"),
            StartupResult::Failed(message) if message == "krun exploded"
        ));
    }

    #[tokio::test]
    async fn create_pending_and_commit_write_vm_spec_and_state() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let pending = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine");

        assert!(pending.dir().starts_with(runtime.paths.staging_dir()));

        let machine = pending.commit(&runtime).await.expect("commit machine");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(machine.name, "devbox");
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        assert_eq!(
            machine.instance_dir,
            runtime.paths.machine(machine.id).dir()
        );
        assert!(runtime.paths.machine(machine.id).vm_spec_path().exists());
    }

    #[tokio::test]
    async fn inspect_and_list_use_name_and_id_lookup() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");

        let by_name = runtime
            .inspect(&MachineRef::parse("devbox").expect("parse machine ref"))
            .await
            .expect("inspect by name");
        let by_id = runtime
            .inspect(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
            .await
            .expect("inspect by id");
        let listed = runtime.list_machine_configs().await.expect("list machines");

        assert_eq!(by_name.id(), machine.id.to_string());
        assert_eq!(by_id.id(), machine.id.to_string());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "devbox");
    }

    #[tokio::test]
    async fn inspect_and_list_use_stale_state_when_machine_lock_is_busy() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(std::process::id() as i32),
                Some(42),
                None,
            )
            .await
            .expect("set stale running state");
        let _lock = runtime
            .acquire_machine_lock(machine.id)
            .expect("hold machine lock");

        let inspected = tokio::time::timeout(
            Duration::from_secs(1),
            runtime.inspect(&MachineRef::id(machine.id)),
        )
        .await
        .expect("inspect should not wait for lock")
        .expect("inspect machine");
        let listed = tokio::time::timeout(Duration::from_secs(1), runtime.list_machine_configs())
            .await
            .expect("list should not wait for lock")
            .expect("list machines");
        let state = runtime
            .machine_state(machine.id)
            .await
            .expect("read machine state");

        assert_eq!(inspected.status(), MachineStatus::Running);
        assert_eq!(listed.len(), 1);
        assert_eq!(state.status, MachineRuntimeState::Running);
    }

    #[tokio::test]
    async fn stop_releases_machine_lock_while_waiting_for_monitor_shutdown() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let child = ChildGuard::sleep();
        let pid = child.id() as i32;
        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{pid}\n")).expect("write pid file");
        runtime
            .set_machine_state(
                machine.id,
                MachineRuntimeState::Running,
                Some(pid),
                Some(42),
                None,
            )
            .await
            .expect("set running state");

        let machine_id = machine.id;
        let stop_runtime = runtime.clone();
        let stop_task = tokio::spawn(async move { stop_runtime.stop_by_id(machine_id).await });

        wait_for_machine_state(&runtime, machine_id, MachineRuntimeState::Stopping).await;
        let lock = runtime
            .try_acquire_machine_lock(machine_id)
            .expect("try acquire lock while stop waits")
            .expect("machine lock should be available while stop waits");
        drop(lock);

        std::fs::remove_file(&pid_path).expect("remove pid file");
        let inspected = stop_task
            .await
            .expect("join stop task")
            .expect("stop machine");
        let state = runtime
            .machine_state(machine_id)
            .await
            .expect("read machine state");

        assert_eq!(inspected.status(), MachineStatus::Stopped);
        assert_eq!(state.status, MachineRuntimeState::Stopped);
        drop(child);
    }

    #[tokio::test]
    async fn inspect_uses_sqlite_config_when_config_file_is_missing() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        std::fs::remove_file(runtime.paths.machine(machine.id).vm_spec_path())
            .expect("remove generated config");

        let inspected = runtime
            .inspect(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
            .await
            .expect("inspect machine");

        assert_eq!(inspected.name(), "devbox");
    }

    #[tokio::test]
    async fn replace_config_updates_stopped_machine_config() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");
        let mut updated = machine.spec.clone();
        spec_hardware_mut(&mut updated).cpus = Some(6);

        let edited = runtime
            .replace_config_by_id(machine.id, updated)
            .await
            .expect("replace config");

        assert_eq!(spec_hardware(edited.spec()).cpus, Some(6));
        assert_eq!(
            spec_hardware(
                runtime
                    .inspect(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
                    .await
                    .expect("inspect")
                    .spec(),
            )
            .cpus,
            Some(6)
        );
    }

    #[tokio::test]
    async fn remove_deletes_machine_from_state_and_disk() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");

        runtime
            .remove_by_id(machine.id)
            .await
            .expect("remove machine");

        assert!(!machine.instance_dir.exists());
        assert!(runtime
            .list_machine_configs()
            .await
            .expect("list machines")
            .is_empty());
    }

    #[tokio::test]
    async fn remove_refuses_running_machine_when_pid_file_exists() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let runtime = LocalRuntime::new(
            LocalPaths::new(temp.path().join("bento")),
            RuntimeNetworkingConfig::default(),
        )
        .await
        .expect("create runtime");

        let machine = create_pending_sample(&runtime, "devbox")
            .await
            .expect("create pending machine")
            .commit(&runtime)
            .await
            .expect("commit machine");

        let pid_path = runtime.paths.machine(machine.id).vmmon_pid_path();
        std::fs::write(&pid_path, format!("{}\n", std::process::id())).expect("write pid file");

        let err = runtime
            .remove_by_id(machine.id)
            .await
            .expect_err("removing running machine should fail");

        assert!(matches!(
            err,
            LibVmError::MachineAlreadyRunning { ref reference } if reference == "devbox"
        ));
        assert!(machine.instance_dir.exists());
        assert_eq!(
            runtime
                .list_machine_configs()
                .await
                .expect("list machines")
                .len(),
            1
        );
    }
}
