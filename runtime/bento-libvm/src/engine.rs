use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::images::store::ImageStore;
use crate::launch::prepare_instance_runtime;
use crate::InstanceFile;
use bento_core::{
    Architecture, Boot, Bootstrap, Disk, DiskKind, GuestOs, GuestSpec, MachineId, Mount, Platform,
    Resources, Settings, Storage, VmSpec,
};
use bento_protocol::agent_port_arg;
use bento_protocol::v1::InspectResponse;
use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::{pipe, Pid},
};

use crate::layout::CONFIG_FILE_NAME;
use crate::models::{
    validate_machine_name, Machine, MachineRef, MachineRuntime, MachineRuntimeState,
    NetworkDefinition, RequestedNetwork,
};
use crate::monitor;
use crate::network::{prepare_network_runtime, reconcile_network_runtime, RuntimeNetwork};
use crate::store::{Database, Sqlite};
use crate::vm_lock::VmLock;
use crate::{Layout, LibVmError};

const DEFAULT_IMAGE_CPUS: u8 = 1;
const DEFAULT_IMAGE_MEMORY_MIB: u32 = 512;
const ENV_VM_STARTPIPE: &str = "_VM_STARTPIPE";
const ENV_VM_SYNCPIPE: &str = "_VM_SYNCPIPE";

#[derive(Debug, Clone)]
pub struct CreateMachineRequest {
    pub image_ref: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub cpus: Option<u8>,
    pub memory_mib: Option<u32>,
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    pub disk_size_bytes: Option<u64>,
    pub nested_virtualization: bool,
    pub agent: bool,
    pub rosetta: bool,
    pub userdata: Option<String>,
    pub disks: Vec<PathBuf>,
    pub mounts: Vec<Mount>,
    pub network: Option<RequestedNetwork>,
}

#[derive(Debug, Clone)]
pub struct MachineRecord {
    pub id: MachineId,
    pub name: String,
    pub spec: VmSpec,
    pub dir: PathBuf,
    pub state: MachineRuntimeState,
    /// Unix timestamp when the VM started (derived from the pidfile mtime),
    /// present only while the machine is running.
    pub started_at: Option<i64>,
    pub created_at: i64,
    pub image_ref: String,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub network: RequestedNetwork,
}

impl MachineRecord {
    pub fn is_running(&self) -> bool {
        self.state.is_running()
    }
}

/// Live runtime observation for a machine: its reconciled state plus the
/// start timestamp when running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeStatus {
    state: MachineRuntimeState,
    started_at: Option<i64>,
}

impl RuntimeStatus {
    fn is_running(&self) -> bool {
        self.state.is_running()
    }
}

pub struct LibVm {
    layout: Layout,
    db: Sqlite,
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
    network: RequestedNetwork,
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
    fn runtime(&self, machine_id: MachineId) -> MachineRuntime {
        MachineRuntime {
            machine_id,
            state: self.state,
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

impl LibVm {
    pub async fn new(layout: Layout) -> Result<Self, LibVmError> {
        let db = Sqlite::new(&layout).await?;
        Ok(Self { layout, db })
    }

    pub async fn from_env() -> Result<Self, LibVmError> {
        Self::new(Layout::from_env()?).await
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub async fn create_from_image(
        &self,
        request: CreateMachineRequest,
    ) -> Result<MachineRecord, LibVmError> {
        if matches!(request.disk_size_bytes, Some(0)) {
            return Err(LibVmError::InvalidCreateRequest {
                name: request.name,
                reason: "root disk size must be greater than 0".to_string(),
            });
        }

        let image_store = ImageStore::open(self.layout.images_dir())?;
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
        let selected_image = image_store.resolve(&request.image_ref)?;

        let bootstrap = (userdata.is_some() || request.rosetta).then_some(Bootstrap { userdata });
        let guest = guest_spec_from_request(request.agent);

        let resolved_cpus = request.cpus.unwrap_or(DEFAULT_IMAGE_CPUS);
        let resolved_memory = request.memory_mib.unwrap_or(DEFAULT_IMAGE_MEMORY_MIB);

        let mounts = assign_mount_tags(request.mounts);

        let spec = VmSpec {
            version: 1,
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: host_architecture()?,
            },
            resources: Resources {
                cpus: resolved_cpus,
                memory_mib: resolved_memory,
            },
            boot: Boot {
                kernel: kernel_path,
                initramfs: initramfs_path,
                kernel_cmdline: guest_kernel_cmdline(&guest),
                bootstrap,
            },
            storage: Storage {
                disks: std::iter::once(Disk {
                    path: PathBuf::from(InstanceFile::RootDisk.as_str()),
                    kind: DiskKind::Root,
                    read_only: false,
                })
                .chain(disk_paths.into_iter().map(|path| Disk {
                    path,
                    kind: DiskKind::Data,
                    read_only: false,
                }))
                .collect(),
            },
            mounts,
            vsock_endpoints: Vec::new(),
            settings: Settings {
                nested_virtualization: request.nested_virtualization,
                rosetta: request.rosetta,
            },
            guest,
        };

        let network = request.network.unwrap_or_default();
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
        let rootfs_path = pending.dir().join(InstanceFile::RootDisk.as_str());
        image_store.clone_base_image(&selected_image, &rootfs_path)?;

        if let Some(size_bytes) = request.disk_size_bytes {
            ImageStore::resize_raw_disk(&rootfs_path, size_bytes)?;
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
        network: RequestedNetwork,
    ) -> Result<PendingMachine, LibVmError> {
        validate_machine_name(&name)?;

        if self.db.get_machine_by_name(name.as_str()).await?.is_some() {
            return Err(LibVmError::MachineAlreadyExists { name });
        }

        let id = MachineId::new();
        let final_dir = self.layout.instance_dir(id);
        if final_dir.exists() {
            return Err(LibVmError::MachineIdAlreadyExists { id });
        }

        let staged_dir = create_staging_dir(&self.layout)?;
        let config = serde_yaml_ng::to_string(&spec).map_err(|source| {
            LibVmError::VmSpecSerializeFailed {
                name: name.clone(),
                source,
            }
        })?;
        fs::write(staged_dir.join(CONFIG_FILE_NAME), config)?;

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

    pub async fn inspect(&self, machine: &MachineRef) -> Result<MachineRecord, LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        self.reconcile_machine_runtime(&metadata).await?;
        self.machine_record(metadata)
    }

    pub async fn list(&self) -> Result<Vec<MachineRecord>, LibVmError> {
        let machines = self.db.list_machines().await?;
        for metadata in &machines {
            self.reconcile_machine_runtime(metadata).await?;
        }
        machines
            .into_iter()
            .map(|metadata| self.machine_record(metadata))
            .collect()
    }

    pub async fn allocate_ephemeral_name(&self, prefix: &str) -> Result<String, LibVmError> {
        self.db.allocate_ephemeral_name(prefix).await
    }

    pub async fn create_network_definition(
        &self,
        definition: NetworkDefinition,
    ) -> Result<(), LibVmError> {
        definition
            .validate()
            .map_err(|reason| LibVmError::InvalidCreateRequest {
                name: definition.name.clone(),
                reason,
            })?;
        self.db.upsert_network_definition(&definition).await
    }

    pub async fn list_network_definitions(&self) -> Result<Vec<NetworkDefinition>, LibVmError> {
        self.db.list_network_definitions().await
    }

    pub async fn get_network_definition(
        &self,
        name: &str,
    ) -> Result<Option<NetworkDefinition>, LibVmError> {
        self.db.get_network_definition(name).await
    }

    pub async fn remove_network_definition(&self, name: &str) -> Result<(), LibVmError> {
        self.db.remove_network_definition(name).await
    }

    pub async fn set_network(
        &self,
        machine: &MachineRef,
        network: RequestedNetwork,
    ) -> Result<MachineRecord, LibVmError> {
        self.validate_requested_network(&network).await?;
        let metadata = self.resolve_machine_state(machine).await?;
        let _lock = self.acquire_machine_lock(metadata.id)?;
        let status = self.reconcile_machine_runtime_locked(&metadata).await?;
        if status.is_running() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: metadata.name.clone(),
            });
        }
        self.db
            .update_machine_network(metadata.id, &network)
            .await?;
        let mut updated = metadata;
        updated.network = network;
        self.machine_record(updated)
    }

    pub async fn replace_config(
        &self,
        machine: &MachineRef,
        config: VmSpec,
    ) -> Result<MachineRecord, LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        let _lock = self.acquire_machine_lock(metadata.id)?;
        let status = self.reconcile_machine_runtime_locked(&metadata).await?;
        if status.is_running() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: metadata.name.clone(),
            });
        }
        self.db.update_machine_config(metadata.id, &config).await?;
        let mut updated = metadata;
        updated.config = config;
        self.machine_record(updated)
    }

    pub async fn remove(&self, machine: &MachineRef) -> Result<(), LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        let _lock = self.acquire_machine_lock(metadata.id)?;
        let status = self.reconcile_machine_runtime_locked(&metadata).await?;
        reconcile_network_runtime(&self.layout, &self.db, &metadata, status.is_running()).await?;

        if status.is_running() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: metadata.name.clone(),
            });
        }

        match fs::remove_dir_all(&metadata.instance_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        self.db.remove_machine_runtime(metadata.id).await?;
        self.db.remove_machine(&metadata).await
    }

    pub async fn start(&self, machine: &MachineRef) -> Result<MachineRecord, LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        let _lock = self.acquire_machine_lock(metadata.id)?;
        let status = self.reconcile_machine_runtime_locked(&metadata).await?;
        reconcile_network_runtime(&self.layout, &self.db, &metadata, status.is_running()).await?;

        if status.is_running() {
            return Err(LibVmError::MachineAlreadyRunning {
                reference: metadata.name.clone(),
            });
        }

        let resolved_network = prepare_network_runtime(&self.layout, &self.db, &metadata).await?;
        let mut spec = metadata.config.clone();
        prepare_instance_runtime(
            &self.layout,
            Path::new(&metadata.instance_dir),
            &metadata.name,
            &mut spec,
            &resolved_network,
        )
        .map_err(|err| LibVmError::InstancePreparationFailed {
            reference: metadata.name.clone(),
            message: err.to_string(),
        })?;

        self.set_machine_runtime(metadata.id, MachineRuntimeState::Starting, None, None, None)
            .await?;

        let pid_path = self.layout.monitor_pid_path(metadata.id);
        let config_path = self.layout.instance_config_path(metadata.id);
        let socket_path = self.layout.monitor_socket_path(metadata.id);
        let trace_path = self.layout.monitor_trace_path(metadata.id);
        let serial_log_path = self.layout.monitor_serial_log_path(metadata.id);
        let launch = VmmonLaunch {
            machine_id: metadata.id,
            name: &metadata.name,
            instance_dir: Path::new(&metadata.instance_dir),
            pidfile: &pid_path,
            config: &config_path,
            socket: &socket_path,
            serial_log: &serial_log_path,
            trace_log: &trace_path,
            network: &resolved_network,
        };
        let handshake = match spawn_vmmon(&launch) {
            Ok(handshake) => handshake,
            Err(err) => {
                self.mark_machine_stopped(metadata.id, Some(err.to_string()))
                    .await?;
                return Err(err);
            }
        };
        if let Err(err) = release_startpipe(handshake.start_write) {
            self.mark_machine_stopped(metadata.id, Some(err.to_string()))
                .await?;
            return Err(err.into());
        }
        if let Err(err) = wait_for_monitor_start(
            handshake.sync_read,
            &self.layout.monitor_trace_path(metadata.id),
        )
        .await
        {
            self.mark_machine_stopped(metadata.id, Some(err.to_string()))
                .await?;
            return Err(err);
        }

        let pid = read_monitor_pid(&pid_path)?;
        if !process_is_alive(pid)? {
            return Err(LibVmError::MonitorConnection {
                reference: metadata.name.clone(),
                message: format!("vmmon pid {pid} from {} is not running", pid_path.display()),
            });
        }
        let started_at = pid_file_mtime(&pid_path);
        self.set_machine_runtime(
            metadata.id,
            MachineRuntimeState::Running,
            Some(pid),
            Some(started_at),
            None,
        )
        .await?;
        self.machine_record(metadata)
    }

    pub async fn wait_for_guest_running(
        &self,
        machine: &MachineRef,
        timeout: std::time::Duration,
    ) -> Result<(), LibVmError> {
        let (metadata, socket_path) = self.resolve_running_socket(machine).await?;
        monitor::wait_for_guest_running(&socket_path, timeout)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: metadata.name,
                message,
            })
    }

    pub async fn stop(&self, machine: &MachineRef) -> Result<MachineRecord, LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        let _lock = self.acquire_machine_lock(metadata.id)?;
        let status = self.reconcile_machine_runtime_locked(&metadata).await?;
        if !status.is_running() {
            return Err(LibVmError::MachineNotRunning {
                reference: metadata.name.clone(),
            });
        }
        let pid_path = self.layout.monitor_pid_path(metadata.id);
        let pid = read_monitor_pid(&pid_path)?;

        self.set_machine_runtime(
            metadata.id,
            MachineRuntimeState::Stopping,
            Some(pid),
            status.started_at,
            None,
        )
        .await?;

        kill(Pid::from_raw(pid), Some(Signal::SIGINT))
            .map_err(|err| io::Error::other(err.to_string()))?;
        wait_for_monitor_stop(&pid_path, &metadata.name).await?;
        self.mark_machine_stopped(metadata.id, None).await?;
        reconcile_network_runtime(&self.layout, &self.db, &metadata, false).await?;
        self.machine_record(metadata)
    }

    pub async fn get_status(&self, machine: &MachineRef) -> Result<InspectResponse, LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        let status = self.reconcile_machine_runtime(&metadata).await?;
        reconcile_network_runtime(&self.layout, &self.db, &metadata, status.is_running()).await?;
        let (metadata, socket_path) = self.resolve_running_socket(machine).await?;
        monitor::get_vm_monitor_inspect(&socket_path)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: metadata.name,
                message,
            })
    }

    pub async fn open_serial_stream(
        &self,
        machine: &MachineRef,
    ) -> Result<tokio::net::UnixStream, LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        let socket_path = self.layout.monitor_socket_path(metadata.id);

        if !self
            .reconcile_machine_runtime(&metadata)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: metadata.name.clone(),
            });
        }

        monitor::open_serial_stream(&socket_path)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: metadata.name,
                message,
            })
    }

    pub async fn open_shell_stream(
        &self,
        machine: &MachineRef,
        wait_for_guest_readiness: bool,
    ) -> Result<tokio::net::UnixStream, LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        let socket_path = self.layout.monitor_socket_path(metadata.id);

        if !self
            .reconcile_machine_runtime(&metadata)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: metadata.name.clone(),
            });
        }

        if wait_for_guest_readiness {
            let machine_record = self.machine_record(metadata.clone())?;
            let should_wait = machine_record.spec.guest_agent().is_some();

            if should_wait {
                monitor::wait_for_shell_with_timeout(
                    &socket_path,
                    monitor::DEFAULT_GUEST_READINESS_TIMEOUT,
                    std::time::Duration::from_secs(1),
                )
                .await
                .map_err(|message| LibVmError::MonitorProtocol {
                    reference: metadata.name.clone(),
                    message,
                })?;
            }
        }

        monitor::open_shell_stream(&socket_path)
            .await
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: metadata.name,
                message,
            })
    }

    async fn resolve_machine_state(&self, machine: &MachineRef) -> Result<Machine, LibVmError> {
        match machine {
            MachineRef::Id(id) => {
                self.db
                    .get_machine_by_id(*id)
                    .await?
                    .ok_or_else(|| LibVmError::MachineNotFound {
                        reference: id.to_string(),
                    })
            }
            MachineRef::Name(name) => self.db.get_machine_by_name(name).await?.ok_or_else(|| {
                LibVmError::MachineNotFound {
                    reference: name.clone(),
                }
            }),
            MachineRef::IdPrefix(prefix) => {
                let matches = self.db.get_machine_by_id_prefix(prefix).await?;
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
        Ok(VmLock::acquire(&self.layout.machine_lock_path(machine_id))?)
    }

    async fn reconcile_machine_runtime(
        &self,
        metadata: &Machine,
    ) -> Result<RuntimeStatus, LibVmError> {
        let observed = self.observe_machine_runtime(metadata).await?;
        if observed.needs_writeback {
            let _lock = self.acquire_machine_lock(metadata.id)?;
            return self.reconcile_machine_runtime_locked(metadata).await;
        }
        Ok(observed.status())
    }

    async fn reconcile_machine_runtime_locked(
        &self,
        metadata: &Machine,
    ) -> Result<RuntimeStatus, LibVmError> {
        let observed = self.observe_machine_runtime(metadata).await?;
        if observed.needs_writeback {
            self.db
                .upsert_machine_runtime(&observed.runtime(metadata.id))
                .await?;
        }
        Ok(observed.status())
    }

    async fn observe_machine_runtime(
        &self,
        metadata: &Machine,
    ) -> Result<ObservedRuntime, LibVmError> {
        let runtime = self.db.get_machine_runtime(metadata.id).await?;
        let pid_path = self.layout.monitor_pid_path(metadata.id);
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
            .map(|runtime| runtime.state)
            .unwrap_or(MachineRuntimeState::Stopped);
        let desired_state = if live_pid.is_some() {
            MachineRuntimeState::Running
        } else {
            MachineRuntimeState::Stopped
        };
        let started_at = live_pid.map(|_| {
            runtime
                .as_ref()
                .and_then(|runtime| runtime.started_at)
                .unwrap_or_else(|| pid_file_mtime(&pid_path))
        });
        let needs_writeback = current_state != desired_state
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

    async fn set_machine_runtime(
        &self,
        machine_id: MachineId,
        state: MachineRuntimeState,
        vmmon_pid: Option<i32>,
        started_at: Option<i64>,
        last_error: Option<String>,
    ) -> Result<(), LibVmError> {
        self.db
            .upsert_machine_runtime(&MachineRuntime {
                machine_id,
                state,
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
        self.set_machine_runtime(
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
        network: &RequestedNetwork,
    ) -> Result<(), LibVmError> {
        if let RequestedNetwork::Named { name, .. } = network {
            self.db.get_network_definition(name).await?.ok_or_else(|| {
                LibVmError::NetworkRuntime {
                    reference: name.clone(),
                    message: format!("named network {:?} is not defined", name),
                }
            })?;
        }
        Ok(())
    }

    fn machine_record(&self, machine: Machine) -> Result<MachineRecord, LibVmError> {
        let dir = PathBuf::from(&machine.instance_dir);
        let pid_path = self.layout.monitor_pid_path(machine.id);
        let started_at = read_monitor_pid(&pid_path)
            .ok()
            .and_then(|pid| process_is_alive(pid).ok().filter(|alive| *alive))
            .map(|_| pid_file_mtime(&pid_path));
        let state = if started_at.is_some() {
            MachineRuntimeState::Running
        } else {
            MachineRuntimeState::Stopped
        };

        Ok(MachineRecord {
            id: machine.id,
            name: machine.name,
            spec: machine.config,
            dir,
            state,
            started_at,
            created_at: machine.created_at,
            image_ref: machine.image_ref,
            labels: machine.labels,
            metadata: machine.metadata,
            network: machine.network,
        })
    }

    async fn resolve_running_socket(
        &self,
        machine: &MachineRef,
    ) -> Result<(Machine, PathBuf), LibVmError> {
        let metadata = self.resolve_machine_state(machine).await?;
        if !self
            .reconcile_machine_runtime(&metadata)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: metadata.name,
            });
        }

        let socket_path = self.layout.monitor_socket_path(metadata.id);
        Ok((metadata, socket_path))
    }
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

fn guest_spec_from_request(agent: bool) -> Option<GuestSpec> {
    agent.then(GuestSpec::default)
}

fn guest_kernel_cmdline(guest: &Option<GuestSpec>) -> Vec<String> {
    guest
        .as_ref()
        .map(|guest| vec![agent_port_arg(guest.control_port)])
        .unwrap_or_default()
}

fn host_architecture() -> Result<Architecture, LibVmError> {
    let arch = std::env::consts::ARCH;
    match arch {
        "arm64" | "aarch64" => Ok(Architecture::Aarch64),
        "amd64" | "x86_64" => Ok(Architecture::X86_64),
        other => Err(LibVmError::UnsupportedHostArchitecture {
            arch: other.to_string(),
        }),
    }
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
        .arg(launch.network.to_vmmon_arg());
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

impl PendingMachine {
    fn dir(&self) -> &Path {
        &self.staged_dir
    }

    async fn commit(mut self, libvm: &LibVm) -> Result<MachineRecord, LibVmError> {
        if self.final_dir.exists() {
            return Err(LibVmError::MachineIdAlreadyExists { id: self.id });
        }

        if let Some(parent) = self.final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&self.staged_dir, &self.final_dir)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let metadata = Machine {
            id: self.id,
            name: self.name.clone(),
            config: self.spec.clone(),
            instance_dir: self.final_dir.display().to_string(),
            created_at: now,
            modified_at: now,
            image_ref: self.image_ref.clone(),
            labels: self.labels.clone(),
            metadata: self.metadata.clone(),
            network: self.network.clone(),
        };
        if let Err(err) = libvm.db.insert_machine(&metadata).await {
            let _ = fs::remove_dir_all(&self.final_dir);
            return Err(err);
        }
        if let Err(err) = libvm
            .db
            .upsert_machine_runtime(&MachineRuntime {
                machine_id: self.id,
                state: MachineRuntimeState::Stopped,
                vmmon_pid: None,
                started_at: None,
                last_error: None,
                updated_at: now,
            })
            .await
        {
            let _ = libvm.db.remove_machine(&metadata).await;
            let _ = fs::remove_dir_all(&self.final_dir);
            return Err(err);
        }

        self.committed = true;
        libvm.machine_record(metadata)
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

fn create_staging_dir(layout: &Layout) -> Result<PathBuf, LibVmError> {
    let staging_root = layout.staging_dir();
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
        assign_mount_tags, guest_kernel_cmdline, guest_spec_from_request, read_syncpipe,
        release_startpipe, LibVm, StartupResult,
    };
    use crate::{
        CreateMachineRequest, InstanceFile, Layout, LibVmError, MachineRef, MachineRuntimeState,
    };
    use bento_core::{
        Architecture, Boot, GuestOs, GuestSpec, Mount, Platform, Resources, Settings, Storage,
        VmSpec,
    };
    use nix::unistd::pipe;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    fn sample_vm_spec() -> VmSpec {
        VmSpec {
            version: 1,
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 4,
                memory_mib: 4096,
            },
            boot: Boot {
                kernel: None,
                initramfs: None,
                kernel_cmdline: Vec::new(),
                bootstrap: None,
            },
            storage: Storage { disks: Vec::new() },
            mounts: Vec::new(),
            vsock_endpoints: Vec::new(),
            settings: Settings {
                nested_virtualization: false,
                rosetta: false,
            },
            guest: Some(GuestSpec::default()),
        }
    }

    async fn create_pending_sample(
        libvm: &LibVm,
        name: &str,
    ) -> Result<super::PendingMachine, LibVmError> {
        libvm
            .create_pending(
                name.to_string(),
                sample_vm_spec(),
                "test-image:latest".to_string(),
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
                crate::RequestedNetwork::default(),
            )
            .await
    }

    #[tokio::test]
    async fn create_from_image_clones_registry_rootfs() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_dir = temp.path().join("bento");
        let image_dir = data_dir.join("images/sha256-test");
        std::fs::create_dir_all(&image_dir).expect("image dir should be created");
        std::fs::write(image_dir.join("rootfs.img"), b"disk").expect("rootfs should be written");
        std::fs::write(
            data_dir.join("images/registry.json"),
            r#"{
                "version": 1,
                "images": {
                    "ghcr.io/vandycknick/archlinuxarm:latest": "sha256-test/rootfs.img"
                }
            }"#,
        )
        .expect("registry should be written");

        let libvm = LibVm::new(Layout::new(data_dir))
            .await
            .expect("create libvm");
        let machine = libvm
            .create_from_image(CreateMachineRequest {
                image_ref: "ghcr.io/vandycknick/archlinuxarm:latest".to_string(),
                name: "devbox".to_string(),
                labels: std::collections::BTreeMap::new(),
                metadata: std::collections::BTreeMap::new(),
                cpus: None,
                memory_mib: None,
                kernel: None,
                initramfs: None,
                disk_size_bytes: None,
                nested_virtualization: false,
                agent: false,
                rosetta: false,
                userdata: Some("#!/bin/sh\necho profile\n".to_string()),
                disks: Vec::new(),
                mounts: Vec::new(),
                network: None,
            })
            .await
            .expect("create from image");

        let root_disk = machine.dir.join(InstanceFile::RootDisk.as_str());
        assert_eq!(
            std::fs::read(root_disk).expect("root disk should exist"),
            b"disk"
        );
        assert_eq!(machine.spec.resources.cpus, 1);
        assert_eq!(machine.spec.resources.memory_mib, 512);
        let bootstrap = machine
            .spec
            .boot
            .bootstrap
            .expect("inline userdata should enable bootstrap");
        assert_eq!(
            bootstrap.userdata.as_deref(),
            Some("#!/bin/sh\necho profile\n")
        );
    }

    #[test]
    fn guest_agent_request_controls_guest_spec_and_kernel_arg() {
        let disabled = guest_spec_from_request(false);
        assert!(disabled.is_none());
        assert!(guest_kernel_cmdline(&disabled).is_empty());

        let enabled = guest_spec_from_request(true);
        assert!(enabled.is_some());
        assert!(!guest_kernel_cmdline(&enabled).is_empty());
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
        let libvm = LibVm::new(Layout::new(temp.path().join("bento")))
            .await
            .expect("create libvm");

        let pending = create_pending_sample(&libvm, "devbox")
            .await
            .expect("create pending machine");

        assert!(pending.dir().starts_with(libvm.layout().staging_dir()));

        let machine = pending.commit(&libvm).await.expect("commit machine");

        assert_eq!(machine.name, "devbox");
        assert_eq!(machine.state, MachineRuntimeState::Stopped);
        assert_eq!(machine.dir, libvm.layout().instance_dir(machine.id));
        assert!(libvm.layout().instance_config_path(machine.id).exists());
    }

    #[tokio::test]
    async fn inspect_and_list_use_name_and_id_lookup() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let libvm = LibVm::new(Layout::new(temp.path().join("bento")))
            .await
            .expect("create libvm");

        let machine = create_pending_sample(&libvm, "devbox")
            .await
            .expect("create pending machine")
            .commit(&libvm)
            .await
            .expect("commit machine");

        let by_name = libvm
            .inspect(&MachineRef::parse("devbox").expect("parse machine ref"))
            .await
            .expect("inspect by name");
        let by_id = libvm
            .inspect(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
            .await
            .expect("inspect by id");
        let listed = libvm.list().await.expect("list machines");

        assert_eq!(by_name.id, machine.id);
        assert_eq!(by_id.id, machine.id);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "devbox");
    }

    #[tokio::test]
    async fn inspect_uses_sqlite_config_when_config_file_is_missing() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let libvm = LibVm::new(Layout::new(temp.path().join("bento")))
            .await
            .expect("create libvm");

        let machine = create_pending_sample(&libvm, "devbox")
            .await
            .expect("create pending machine")
            .commit(&libvm)
            .await
            .expect("commit machine");
        std::fs::remove_file(libvm.layout().instance_config_path(machine.id))
            .expect("remove generated config");

        let inspected = libvm
            .inspect(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
            .await
            .expect("inspect machine");

        assert_eq!(inspected.name, "devbox");
    }

    #[tokio::test]
    async fn replace_config_updates_stopped_machine_config() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let libvm = LibVm::new(Layout::new(temp.path().join("bento")))
            .await
            .expect("create libvm");

        let machine = create_pending_sample(&libvm, "devbox")
            .await
            .expect("create pending machine")
            .commit(&libvm)
            .await
            .expect("commit machine");
        let mut updated = machine.spec.clone();
        updated.resources.cpus = 6;

        let edited = libvm
            .replace_config(
                &MachineRef::parse(machine.id.to_string()).expect("parse machine ref"),
                updated,
            )
            .await
            .expect("replace config");

        assert_eq!(edited.spec.resources.cpus, 6);
        assert_eq!(
            libvm
                .inspect(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
                .await
                .expect("inspect")
                .spec
                .resources
                .cpus,
            6
        );
    }

    #[tokio::test]
    async fn remove_deletes_machine_from_state_and_disk() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let libvm = LibVm::new(Layout::new(temp.path().join("bento")))
            .await
            .expect("create libvm");

        let machine = create_pending_sample(&libvm, "devbox")
            .await
            .expect("create pending machine")
            .commit(&libvm)
            .await
            .expect("commit machine");

        libvm
            .remove(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
            .await
            .expect("remove machine");

        assert!(!machine.dir.exists());
        assert!(libvm.list().await.expect("list machines").is_empty());
    }

    #[tokio::test]
    async fn remove_refuses_running_machine_when_pid_file_exists() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let libvm = LibVm::new(Layout::new(temp.path().join("bento")))
            .await
            .expect("create libvm");

        let machine = create_pending_sample(&libvm, "devbox")
            .await
            .expect("create pending machine")
            .commit(&libvm)
            .await
            .expect("commit machine");

        let pid_path = libvm.layout().monitor_pid_path(machine.id);
        std::fs::write(&pid_path, format!("{}\n", std::process::id())).expect("write pid file");

        let err = libvm
            .remove(&MachineRef::parse(machine.id.to_string()).expect("parse machine ref"))
            .await
            .expect_err("removing running machine should fail");

        assert!(matches!(
            err,
            LibVmError::MachineAlreadyRunning { ref reference } if reference == "devbox"
        ));
        assert!(machine.dir.exists());
        assert_eq!(libvm.list().await.expect("list machines").len(), 1);
    }
}
