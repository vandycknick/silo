use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use libvm::{
    ExecutionControl, ExecutionEvent, ExecutionOptionsBuilder, ExecutionOutput, ExecutionResult,
    ExecutionSession, ExecutionStdin, ImageDetail, ImageHandle, ImageLayerDetail, ImagePruneReport,
    ImagePullOptions, ImagePullPolicy, ImageRemoveOptions, ImageSource, Images, LibVmError,
    Machine, MachineBootReport, MachineBuilder, MachineData, MachineLogChunk, MachineLogOptions,
    MachineLogOutput, MachineLogSource, MachineLogStream, MachineNetworkBuilder,
    MachineNetworkConfig, MachineProvisionReport, MachineProvisionStepReport, MachineRef,
    MachineRootfs, MachineStatus, Memory, NetworkAuditBuilder, NetworkCredentialBuilder,
    NetworkEndpointBuilder, NetworkForwardBuilder, NetworkPolicy, NetworkRuleBuilder,
    OciImageConfigMetadata, Runtime, RuntimeConfig, SshExitStatus, SshShellOptionsBuilder,
    TailscaleTunnelBuilder,
};
use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Result, Status};
use napi_derive::napi;
use tokio::sync::watch;
use tokio_stream::StreamExt;
use vm_spec::Mount;

#[napi(object)]
pub struct RuntimeOpenOptions {
    pub data_root: Option<String>,
    pub run_root: Option<String>,
    pub image_root: Option<String>,
    pub vmmon_path: Option<String>,
}

#[napi(object)]
pub struct NativeImageSourceInput {
    pub kind: String,
    pub reference: Option<String>,
    pub path: Option<String>,
}

#[napi(object)]
pub struct NativeKeyValue {
    pub key: String,
    pub value: String,
}

#[napi(object)]
pub struct NativeMountInput {
    pub source: String,
    pub tag: String,
    pub read_only: Option<bool>,
}

#[napi(object)]
pub struct NativeNetworkInput {
    pub kind: String,
    pub name: Option<String>,
    pub policy_json: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkPolicyInput {
    pub default_action: Option<String>,
    pub metadata: Option<Vec<NativeKeyValue>>,
    pub audit: Option<NativeNetworkAuditInput>,
    pub endpoints: Option<Vec<NativeNetworkEndpointInput>>,
    pub credentials: Option<Vec<NativeNetworkCredentialInput>>,
    pub rules: Option<Vec<NativeNetworkRuleInput>>,
    pub tailscale: Option<Vec<NativeTailscaleTunnelInput>>,
    pub forwards: Option<Vec<NativeNetworkForwardInput>>,
}

#[napi(object)]
pub struct NativeNetworkAuditInput {
    pub body_buffer_bytes: Option<i64>,
    pub body_storage_bytes: Option<i64>,
}

#[napi(object)]
pub struct NativeNetworkPortRangeInput {
    pub start: u32,
    pub end: Option<u32>,
}

#[napi(object)]
pub struct NativeNetworkEndpointInput {
    pub name: String,
    pub kind: Option<String>,
    pub source_cidrs: Option<Vec<String>>,
    pub destination_cidrs: Option<Vec<String>>,
    pub protocol: Option<String>,
    pub ports: Option<Vec<NativeNetworkPortRangeInput>>,
    pub hosts: Option<Vec<String>>,
}

#[napi(object)]
pub struct NativeNetworkCredentialInput {
    pub name: String,
    pub kind: Option<String>,
    pub endpoint: Option<String>,
    pub username: Option<String>,
    pub header: Option<String>,
    pub prefix: Option<String>,
    pub idempotency_key: Option<bool>,
    pub condition: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkRuleInput {
    pub name: Option<String>,
    pub endpoints: Option<Vec<String>>,
    pub credential: Option<String>,
    pub condition: Option<String>,
    pub tunnel: Option<String>,
    pub priority: Option<i32>,
    pub disabled: Option<bool>,
    pub reason: Option<String>,
    pub verdict: Option<String>,
}

#[napi(object)]
pub struct NativeTailscaleTunnelInput {
    pub name: String,
    pub tags: Option<Vec<String>>,
    pub hostname: Option<String>,
    pub control_url: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkForwardInput {
    pub name: String,
    pub kind: Option<String>,
    pub target: Option<String>,
    pub target_port: Option<u32>,
    pub listen: Option<String>,
    pub tunnel: Option<String>,
}

#[napi(object)]
pub struct NativeExecutionOptionsInput {
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: Option<Vec<NativeKeyValue>>,
    pub timeout: Option<u32>,
    pub stdin: Option<Uint8Array>,
    pub pipe_stdin: Option<bool>,
    pub tty: Option<bool>,
}

#[napi(object)]
pub struct NativeSshShellOptionsInput {
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: Option<Vec<NativeKeyValue>>,
    pub term: Option<String>,
    pub detach_keys: Option<String>,
    pub forward_agent: Option<bool>,
}

#[napi(object)]
pub struct NativeMachineLogOptionsInput {
    pub follow: Option<bool>,
}

#[napi(object)]
pub struct NativeMachineLogChunk {
    pub output: String,
    pub data: Uint8Array,
}

#[napi(object)]
pub struct NativeMachineData {
    pub id: String,
    pub name: String,
    pub machine_dir: String,
    pub created_at: i64,
    pub modified_at: i64,
    pub image_ref: String,
    pub retention: String,
    pub process: NativeProcessConfig,
    pub template_name: Option<String>,
    pub configured_agent: Option<NativeMachineAgent>,
    pub rootfs: Option<NativeMachineRootfs>,
    pub root_disk_size: Option<i64>,
    pub labels: Vec<NativeKeyValue>,
    pub metadata: Vec<NativeKeyValue>,
    pub network: NativeNetworkData,
    pub agent_mode: String,
    pub agent_path: Option<String>,
    pub status: NativeMachineStatus,
    pub boot_report: Option<NativeMachineBootReport>,
    pub provision_report: Option<NativeMachineProvisionReport>,
    pub started_at: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[napi(object)]
pub struct NativeMachineBootReport {
    pub mode: String,
    pub requested_init: Option<String>,
    pub handoff_init_path: Option<String>,
    pub probed_init_paths: Vec<String>,
    pub agent_path: Option<String>,
    pub agent_pid: u32,
    pub agent_is_pid1: bool,
    pub message: Option<String>,
}

#[napi(object)]
pub struct NativeMachineProvisionReport {
    pub status: String,
    pub started_unix_ms: i64,
    pub finished_unix_ms: i64,
    pub duration_ms: i64,
    pub steps: Vec<NativeMachineProvisionStepReport>,
    pub message: Option<String>,
}

#[napi(object)]
pub struct NativeMachineProvisionStepReport {
    pub id: String,
    pub status: String,
    pub failure_policy: String,
    pub changed: bool,
    pub backend: Option<String>,
    pub duration_ms: i64,
    pub message: Option<String>,
    pub error_chain: Option<String>,
}

#[napi(object)]
pub struct NativeProcessConfig {
    pub entrypoint: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    pub environment: Vec<NativeKeyValue>,
    pub working_directory: String,
    pub user: Option<String>,
}

#[napi(object)]
pub struct NativeMachineAgent {
    pub mode: String,
    pub path: Option<String>,
}

#[napi(object)]
pub struct NativeMachineRootfs {
    pub source_kind: String,
    pub requested_reference: String,
    pub selected_reference: Option<String>,
    pub selected_manifest_digest: Option<String>,
    pub config_digest: Option<String>,
    pub image_id: Option<String>,
    pub root_disk_path: String,
    pub root_disk_size_bytes: i64,
    pub created_at: i64,
}

#[napi(object)]
pub struct NativeMachineStatus {
    pub kind: String,
    pub ready: Option<bool>,
    pub guest_ready: Option<bool>,
    pub message: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkData {
    pub kind: String,
    pub name: Option<String>,
    pub policy_json: Option<String>,
}

#[napi(object)]
pub struct NativeExecutionResult {
    pub kind: String,
    pub code: Option<u32>,
    pub signal: Option<u32>,
    pub reason: Option<String>,
    pub message: Option<String>,
}

#[napi(object)]
pub struct NativeSshExitStatus {
    pub code: i32,
    pub success: bool,
}

#[napi(object)]
pub struct NativeExecutionOutput {
    pub result: NativeExecutionResult,
    pub stdout: Uint8Array,
    pub stderr: Uint8Array,
    pub terminal_output: Uint8Array,
}

#[napi(object)]
pub struct NativeExecutionEvent {
    pub kind: String,
    pub data: Option<Uint8Array>,
    pub code: Option<u32>,
    pub signal: Option<u32>,
    pub reason: Option<String>,
    pub message: Option<String>,
}

#[napi(object)]
pub struct NativeImageHandle {
    pub requested_reference: String,
    pub selected_reference: String,
    pub selected_manifest_digest: String,
    pub config_digest: String,
    pub image_id: String,
    pub platform_os: String,
    pub platform_architecture: String,
    pub platform_variant: Option<String>,
    pub size_bytes: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}

#[napi(object)]
pub struct NativeImageDetail {
    pub handle: NativeImageHandle,
    pub config: NativeOciImageConfig,
    pub layers: Vec<NativeImageLayerDetail>,
}

#[napi(object)]
pub struct NativeOciImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub labels: Option<Vec<NativeKeyValue>>,
    pub stop_signal: Option<String>,
}

#[napi(object)]
pub struct NativeImageLayerDetail {
    pub blob_digest: String,
    pub diff_id: String,
    pub media_type: String,
    pub compressed_size_bytes: Option<i64>,
    pub uncompressed_size_bytes: Option<i64>,
    pub position: i64,
}

#[napi(object)]
pub struct NativeImagePruneReport {
    pub references_removed: i64,
    pub artifacts_removed: i64,
    pub bytes_removed: i64,
}

#[napi(js_name = "NativeRuntime")]
pub struct NativeRuntime {
    inner: Runtime,
}

#[napi(js_name = "NativeMachineBuilder")]
pub struct NativeMachineBuilder {
    inner: Mutex<Option<MachineBuilder>>,
}

#[napi(js_name = "NativeMachine")]
pub struct NativeMachine {
    inner: Machine,
}

#[napi(js_name = "NativeImages")]
pub struct NativeImages {
    inner: Images,
}

#[napi(js_name = "NativeExecutionSession")]
pub struct NativeExecutionSession {
    inner: Mutex<ExecutionSessionState>,
    control: ExecutionControl,
}

#[napi(js_name = "NativeExecutionStdin")]
pub struct NativeExecutionStdin {
    inner: ExecutionStdin,
}

struct ExecutionSessionState {
    session: Option<ExecutionSession>,
    operation_in_flight: bool,
    closed: bool,
    cancellation: watch::Sender<bool>,
}

#[napi(js_name = "NativeMachineLogHandle")]
pub struct NativeMachineLogHandle {
    inner: Mutex<MachineLogHandleState>,
}

struct MachineLogHandleState {
    stream: Option<MachineLogStream>,
    receive_in_flight: bool,
    closed: bool,
    cancellation: watch::Sender<bool>,
}

#[napi(js_name = "openRuntime")]
pub async fn open_runtime(options: Option<RuntimeOpenOptions>) -> Result<NativeRuntime> {
    let mut config = match options
        .as_ref()
        .and_then(|options| options.data_root.as_ref())
    {
        Some(data_root) => RuntimeConfig::local(data_root),
        None => RuntimeConfig::from_env().map_err(to_napi_error)?,
    };

    if let Some(options) = options {
        if let Some(run_root) = options.run_root {
            config = config.with_run_root(run_root);
        }
        if let Some(image_root) = options.image_root {
            config = config.with_image_root(image_root);
        }
        if let Some(vmmon_path) = options.vmmon_path {
            config = config.with_vmmon_path(vmmon_path);
        }
    }

    Runtime::new(config)
        .await
        .map(|inner| NativeRuntime { inner })
        .map_err(to_napi_error)
}

#[napi(js_name = "buildNetworkPolicy")]
pub fn build_network_policy(input: NativeNetworkPolicyInput) -> Result<String> {
    let policy = network_policy_from_input(input)?;
    serde_json::to_string(&policy.normalized())
        .map_err(|err| invalid_arg(format!("serialize network policy: {err}")))
}

#[napi]
impl NativeRuntime {
    #[napi]
    pub fn machine(&self) -> NativeMachineBuilder {
        NativeMachineBuilder {
            inner: Mutex::new(Some(self.inner.machine())),
        }
    }

    #[napi]
    pub fn images(&self) -> NativeImages {
        NativeImages {
            inner: self.inner.images(),
        }
    }

    #[napi(js_name = "getMachine")]
    pub async fn get_machine(&self, reference: String) -> Result<NativeMachine> {
        let runtime = self.inner.clone();
        let machine_ref = MachineRef::parse(reference).map_err(to_napi_error)?;
        runtime
            .get_machine(&machine_ref)
            .await
            .map(|inner| NativeMachine { inner })
            .map_err(to_napi_error)
    }

    #[napi(js_name = "listMachines")]
    pub async fn list_machines(&self) -> Result<Vec<NativeMachine>> {
        let runtime = self.inner.clone();
        runtime
            .list_machines()
            .await
            .map(|machines| {
                machines
                    .into_iter()
                    .map(|inner| NativeMachine { inner })
                    .collect()
            })
            .map_err(to_napi_error)
    }
}

#[napi]
impl NativeMachineBuilder {
    #[napi]
    pub fn image(&self, reference: String) -> Result<()> {
        self.update(|builder| builder.image(reference))
    }

    #[napi(js_name = "imageSource")]
    pub fn image_source(&self, source: NativeImageSourceInput) -> Result<()> {
        let source = image_source_from_input(source)?;
        self.update(|builder| builder.image_source(source))
    }

    #[napi]
    pub fn name(&self, name: String) -> Result<()> {
        self.update(|builder| builder.name(name))
    }

    #[napi]
    pub fn label(&self, key: String, value: String) -> Result<()> {
        self.update(|builder| builder.label(key, value))
    }

    #[napi]
    pub fn labels(&self, labels: Vec<NativeKeyValue>) -> Result<()> {
        self.update(|builder| builder.labels(key_values_to_map(labels)))
    }

    #[napi(js_name = "metadataEntry")]
    pub fn metadata_entry(&self, key: String, value: String) -> Result<()> {
        self.update(|builder| builder.metadata_entry(key, value))
    }

    #[napi]
    pub fn metadata(&self, metadata: Vec<NativeKeyValue>) -> Result<()> {
        self.update(|builder| builder.metadata(key_values_to_map(metadata)))
    }

    #[napi]
    pub fn cpus(&self, cpus: u32) -> Result<()> {
        let cpus = u8::try_from(cpus).map_err(|_| invalid_arg("cpus must fit in u8"))?;
        self.update(|builder| builder.cpus(cpus))
    }

    #[napi]
    pub fn memory(&self, value: u32) -> Result<()> {
        self.update(|builder| builder.memory(Memory::mebibytes(u64::from(value))))
    }

    #[napi]
    pub fn kernel(&self, path: String) -> Result<()> {
        self.update(|builder| builder.kernel(path))
    }

    #[napi]
    pub fn initramfs(&self, path: String) -> Result<()> {
        self.update(|builder| builder.initramfs(path))
    }

    #[napi]
    pub fn agent(&self, path: Option<String>) -> Result<()> {
        self.update(|builder| builder.guest(|guest| guest.agent(path.map(PathBuf::from))))
    }

    #[napi(js_name = "rootDiskSize")]
    pub fn root_disk_size(&self, value: i64) -> Result<()> {
        let value = nonnegative_u64("rootDiskSize", value)?;
        self.update(|builder| builder.root_disk_size(value))
    }

    #[napi(js_name = "nestedVirtualization")]
    pub fn nested_virtualization(&self, enabled: bool) -> Result<()> {
        self.update(|builder| builder.nested_virtualization(enabled))
    }

    #[napi]
    pub fn rosetta(&self, enabled: bool) -> Result<()> {
        self.update(|builder| builder.rosetta(enabled))
    }

    #[napi]
    pub fn userdata(&self, userdata: String) -> Result<()> {
        self.update(|builder| builder.userdata(userdata))
    }

    #[napi]
    pub fn disks(&self, disks: Vec<String>) -> Result<()> {
        let disks = disks.into_iter().map(PathBuf::from).collect();
        self.update(|builder| builder.disks(disks))
    }

    #[napi]
    pub fn mounts(&self, mounts: Vec<NativeMountInput>) -> Result<()> {
        let mounts = mounts
            .into_iter()
            .map(|mount| Mount {
                source: PathBuf::from(mount.source),
                tag: mount.tag,
                read_only: mount.read_only.unwrap_or(false),
            })
            .collect();
        self.update(|builder| builder.mounts(mounts))
    }

    #[napi]
    pub fn network(&self, network: NativeNetworkInput) -> Result<()> {
        let network = ParsedNativeNetworkInput::parse(network)?;
        self.update(|builder| builder.network(|network_builder| network.apply(network_builder)))
    }

    #[napi]
    pub async fn create(&self) -> Result<NativeMachine> {
        let builder = self.take_builder()?;
        builder
            .create()
            .await
            .map(|inner| NativeMachine { inner })
            .map_err(to_napi_error)
    }
}

impl NativeMachineBuilder {
    fn take_builder(&self) -> Result<MachineBuilder> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("machine builder lock is poisoned"))?
            .take()
            .ok_or_else(|| invalid_state("machine builder has already been consumed"))
    }

    fn update(&self, update: impl FnOnce(MachineBuilder) -> MachineBuilder) -> Result<()> {
        let builder = self.take_builder()?;
        *self
            .inner
            .lock()
            .map_err(|_| invalid_state("machine builder lock is poisoned"))? =
            Some(update(builder));
        Ok(())
    }
}

#[napi]
impl NativeMachine {
    #[napi]
    pub fn id(&self) -> String {
        self.inner.id()
    }

    #[napi]
    pub async fn inspect(&self) -> Result<NativeMachineData> {
        let machine = self.inner.clone();
        machine
            .inspect()
            .await
            .map(machine_data_to_native)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn start(&self) -> Result<NativeMachineData> {
        let machine = self.inner.clone();
        machine
            .start()
            .await
            .map(|start| machine_data_to_native(start.machine))
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn stop(&self) -> Result<NativeMachineData> {
        let machine = self.inner.clone();
        machine
            .stop()
            .await
            .map(machine_data_to_native)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn remove(&self) -> Result<()> {
        let machine = self.inner.clone();
        machine.remove().await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn exec(
        &self,
        program: String,
        args: Option<Vec<String>>,
        options: Option<NativeExecutionOptionsInput>,
    ) -> Result<NativeExecutionOutput> {
        let machine = self.inner.clone();
        let output = run_exec(machine, program, args.unwrap_or_default(), options).await?;
        Ok(execution_output_to_native(output))
    }

    #[napi]
    pub async fn spawn(
        &self,
        program: String,
        args: Option<Vec<String>>,
        options: Option<NativeExecutionOptionsInput>,
    ) -> Result<NativeExecutionSession> {
        let machine = self.inner.clone();
        let session = spawn_exec(machine, program, args.unwrap_or_default(), options).await?;
        let control = session.control();
        Ok(NativeExecutionSession {
            inner: Mutex::new(ExecutionSessionState::new(session)),
            control,
        })
    }

    #[napi]
    pub async fn shell(
        &self,
        script: String,
        options: Option<NativeExecutionOptionsInput>,
    ) -> Result<NativeExecutionOutput> {
        let machine = self.inner.clone();
        let output = run_shell(machine, script, options).await?;
        Ok(execution_output_to_native(output))
    }

    #[napi]
    pub async fn attach(
        &self,
        program: String,
        args: Option<Vec<String>>,
        options: Option<NativeExecutionOptionsInput>,
    ) -> Result<NativeExecutionResult> {
        let machine = self.inner.clone();
        let status = attach(machine, program, args.unwrap_or_default(), options).await?;
        Ok(execution_result_to_native(status))
    }

    #[napi(js_name = "attachShell")]
    pub async fn attach_shell(
        &self,
        options: Option<NativeSshShellOptionsInput>,
    ) -> Result<NativeSshExitStatus> {
        let machine = self.inner.clone();
        attach_shell(machine, options)
            .await
            .map(ssh_exit_status_to_native)
    }

    #[napi]
    pub async fn logs(
        &self,
        source: String,
        options: Option<NativeMachineLogOptionsInput>,
    ) -> Result<NativeMachineLogHandle> {
        let machine = self.inner.clone();
        let source = machine_log_source_from_native(&source)?;
        let stream = machine
            .logs(
                source,
                MachineLogOptions {
                    follow: options.and_then(|options| options.follow).unwrap_or(false),
                },
            )
            .await
            .map_err(to_napi_error)?;
        Ok(NativeMachineLogHandle {
            inner: Mutex::new(MachineLogHandleState::new(stream)),
        })
    }
}

#[napi]
impl NativeMachineLogHandle {
    #[napi]
    pub async fn recv(&self) -> Result<Option<NativeMachineLogChunk>> {
        let (mut stream, mut cancellation) = self.begin_recv()?;
        let chunk = tokio::select! {
            biased;
            _ = cancellation.changed() => {
                self.finish_recv(None)?;
                return Err(machine_log_handle_closed());
            }
            chunk = stream.next() => chunk,
        };

        match chunk {
            Some(Ok(chunk)) => {
                let converted = machine_log_chunk_to_native(chunk);
                let keep_stream = converted.is_ok();
                if !self.finish_recv(keep_stream.then_some(stream))? {
                    return Err(machine_log_handle_closed());
                }
                converted.map(Some)
            }
            Some(Err(error)) => {
                self.finish_recv(None)?;
                Err(to_napi_error(error))
            }
            None => {
                self.finish_recv(None)?;
                Ok(None)
            }
        }
    }

    #[napi]
    pub fn close(&self) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("machine log handle lock is poisoned"))?
            .close();
        Ok(())
    }
}

impl NativeMachineLogHandle {
    fn begin_recv(&self) -> Result<(MachineLogStream, watch::Receiver<bool>)> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("machine log handle lock is poisoned"))?
            .begin_recv()
    }

    fn finish_recv(&self, stream: Option<MachineLogStream>) -> Result<bool> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("machine log handle lock is poisoned"))?
            .finish_recv(stream)
    }
}

impl MachineLogHandleState {
    fn new(stream: MachineLogStream) -> Self {
        let (cancellation, _) = watch::channel(false);
        Self {
            stream: Some(stream),
            receive_in_flight: false,
            closed: false,
            cancellation,
        }
    }

    fn begin_recv(&mut self) -> Result<(MachineLogStream, watch::Receiver<bool>)> {
        if self.closed {
            return Err(machine_log_handle_closed());
        }
        if self.receive_in_flight {
            return Err(machine_log_handle_busy());
        }

        let stream = self.stream.take().ok_or_else(machine_log_handle_closed)?;
        self.receive_in_flight = true;
        Ok((stream, self.cancellation.subscribe()))
    }

    fn finish_recv(&mut self, stream: Option<MachineLogStream>) -> Result<bool> {
        if !self.receive_in_flight {
            return Err(invalid_state("machine log handle has no active receive"));
        }

        self.receive_in_flight = false;
        if self.closed {
            return Ok(false);
        }

        match stream {
            Some(stream) => {
                self.stream = Some(stream);
                Ok(true)
            }
            None => {
                self.closed = true;
                Ok(true)
            }
        }
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }

        self.closed = true;
        self.stream = None;
        self.cancellation.send_replace(true);
    }
}

#[napi]
impl NativeExecutionSession {
    #[napi]
    pub async fn recv(&self) -> Result<Option<NativeExecutionEvent>> {
        let (mut session, mut cancellation) = self.begin_operation()?;
        let event = tokio::select! {
            biased;
            _ = cancellation.changed() => {
                self.finish_operation(None)?;
                return Err(execution_session_closed());
            }
            event = session.recv() => event,
        };
        match event {
            Ok(Some(event)) => {
                let terminal = matches!(event, ExecutionEvent::Terminal(_));
                let event = execution_event_to_native(event);
                self.finish_operation((!terminal).then_some(session))?;
                Ok(Some(event))
            }
            Ok(None) => {
                self.finish_operation(None)?;
                Ok(None)
            }
            Err(error) => {
                self.finish_operation(None)?;
                Err(to_napi_error(error))
            }
        }
    }

    #[napi(js_name = "stdin")]
    pub fn stdin(&self) -> Result<Option<NativeExecutionStdin>> {
        Ok(self
            .control
            .stdin()
            .map(|inner| NativeExecutionStdin { inner }))
    }

    #[napi]
    pub async fn wait(&self) -> Result<NativeExecutionResult> {
        let (mut session, mut cancellation) = self.begin_operation()?;
        let result = tokio::select! {
            biased;
            _ = cancellation.changed() => Err(execution_session_closed()),
            result = session.wait() => result.map(execution_result_to_native).map_err(to_napi_error),
        };
        self.finish_operation(None)?;
        result
    }

    #[napi]
    pub async fn collect(&self) -> Result<NativeExecutionOutput> {
        let (mut session, mut cancellation) = self.begin_operation()?;
        let result = tokio::select! {
            biased;
            _ = cancellation.changed() => Err(execution_session_closed()),
            result = session.collect() => result.map(execution_output_to_native).map_err(to_napi_error),
        };
        self.finish_operation(None)?;
        result
    }

    #[napi]
    pub async fn signal(&self, signal: u32) -> Result<()> {
        self.control.signal(signal).await.map_err(to_napi_error)
    }

    #[napi(js_name = "resizePty")]
    pub async fn resize_pty(&self, rows: u32, cols: u32) -> Result<()> {
        let rows = u16::try_from(rows).map_err(|_| invalid_arg("rows must fit in u16"))?;
        let cols = u16::try_from(cols).map_err(|_| invalid_arg("cols must fit in u16"))?;
        self.control
            .resize_pty(rows, cols)
            .await
            .map_err(to_napi_error)
    }

    #[napi(js_name = "closeRequests")]
    pub fn close_requests(&self) {
        self.control.close_requests();
    }

    #[napi]
    pub fn cancel(&self) -> Result<()> {
        self.control.close_requests();
        self.inner
            .lock()
            .map_err(|_| invalid_state("execution session lock is poisoned"))?
            .close();
        Ok(())
    }
}

impl NativeExecutionSession {
    fn begin_operation(&self) -> Result<(ExecutionSession, watch::Receiver<bool>)> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("execution session lock is poisoned"))?
            .begin_operation()
    }

    fn finish_operation(&self, session: Option<ExecutionSession>) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("execution session lock is poisoned"))?
            .finish_operation(session)
    }
}

impl ExecutionSessionState {
    fn new(session: ExecutionSession) -> Self {
        let (cancellation, _) = watch::channel(false);
        Self {
            session: Some(session),
            operation_in_flight: false,
            closed: false,
            cancellation,
        }
    }

    fn begin_operation(&mut self) -> Result<(ExecutionSession, watch::Receiver<bool>)> {
        if self.closed {
            return Err(execution_session_closed());
        }
        if self.operation_in_flight {
            return Err(invalid_state(
                "execution session already has an active receiver",
            ));
        }
        let session = self.session.take().ok_or_else(execution_session_closed)?;
        self.operation_in_flight = true;
        Ok((session, self.cancellation.subscribe()))
    }

    fn finish_operation(&mut self, session: Option<ExecutionSession>) -> Result<()> {
        if !self.operation_in_flight {
            return Err(invalid_state("execution session has no active receiver"));
        }
        self.operation_in_flight = false;
        if self.closed {
            return Ok(());
        }
        match session {
            Some(session) => self.session = Some(session),
            None => self.close(),
        }
        Ok(())
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.session = None;
        self.cancellation.send_replace(true);
    }
}

#[napi]
impl NativeExecutionStdin {
    #[napi]
    pub async fn write(&self, data: Uint8Array) -> Result<()> {
        self.inner
            .write(data.as_ref().to_vec())
            .await
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn close(&self) -> Result<()> {
        self.inner.close().await.map_err(to_napi_error)
    }
}

#[napi]
impl NativeImages {
    #[napi]
    pub async fn pull(
        &self,
        reference: String,
        policy: Option<String>,
    ) -> Result<NativeImageHandle> {
        let images = self.inner.clone();
        let handle = match policy {
            Some(policy) => {
                images
                    .pull_with(
                        reference,
                        ImagePullOptions {
                            policy: Some(pull_policy_from_string(&policy)?),
                        },
                    )
                    .await
            }
            None => images.pull(reference).await,
        };
        handle.map(image_handle_to_native).map_err(to_napi_error)
    }

    #[napi]
    pub async fn get(&self, reference: String) -> Result<Option<NativeImageHandle>> {
        let images = self.inner.clone();
        images
            .get(&reference)
            .await
            .map(|handle| handle.map(image_handle_to_native))
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn list(&self) -> Result<Vec<NativeImageHandle>> {
        let images = self.inner.clone();
        images
            .list()
            .await
            .map(|handles| handles.into_iter().map(image_handle_to_native).collect())
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn inspect(&self, reference: String) -> Result<Option<NativeImageDetail>> {
        let images = self.inner.clone();
        images
            .inspect(&reference)
            .await
            .map(|detail| detail.map(image_detail_to_native))
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn remove(&self, reference: String, force: Option<bool>) -> Result<()> {
        let images = self.inner.clone();
        images
            .remove_with(
                &reference,
                ImageRemoveOptions {
                    force: force.unwrap_or(false),
                },
            )
            .await
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn prune(&self) -> Result<NativeImagePruneReport> {
        let images = self.inner.clone();
        images
            .prune()
            .await
            .map(prune_report_to_native)
            .map_err(to_napi_error)
    }
}

async fn run_exec(
    machine: Machine,
    program: String,
    args: Vec<String>,
    options: Option<NativeExecutionOptionsInput>,
) -> Result<ExecutionOutput> {
    machine
        .exec_with(program, |builder| {
            apply_execution_options(builder.args(args), options)
        })
        .await
        .map_err(to_napi_error)
}

async fn spawn_exec(
    machine: Machine,
    program: String,
    args: Vec<String>,
    options: Option<NativeExecutionOptionsInput>,
) -> Result<ExecutionSession> {
    machine
        .spawn_with(program, |builder| {
            apply_execution_options(builder.args(args), options)
        })
        .await
        .map_err(to_napi_error)
}

async fn run_shell(
    machine: Machine,
    script: String,
    options: Option<NativeExecutionOptionsInput>,
) -> Result<ExecutionOutput> {
    machine
        .shell_with(script, |builder| apply_execution_options(builder, options))
        .await
        .map_err(to_napi_error)
}

async fn attach(
    machine: Machine,
    program: String,
    args: Vec<String>,
    options: Option<NativeExecutionOptionsInput>,
) -> Result<ExecutionResult> {
    machine
        .attach_with(program, |builder| {
            apply_execution_options(builder.args(args), options).tty(true)
        })
        .await
        .map_err(to_napi_error)
}

async fn attach_shell(
    machine: Machine,
    options: Option<NativeSshShellOptionsInput>,
) -> Result<SshExitStatus> {
    machine
        .attach_shell_with(|builder| apply_ssh_shell_options(builder, options))
        .await
        .map_err(to_napi_error)
}

fn apply_execution_options(
    mut builder: ExecutionOptionsBuilder,
    options: Option<NativeExecutionOptionsInput>,
) -> ExecutionOptionsBuilder {
    let Some(options) = options else {
        return builder;
    };
    if let Some(args) = options.args {
        builder = builder.args(args);
    }
    if let Some(cwd) = options.cwd {
        builder = builder.cwd(cwd);
    }
    if let Some(user) = options.user {
        builder = builder.user(user);
    }
    if let Some(env) = options.env {
        for pair in env {
            builder = builder.env(pair.key, pair.value);
        }
    }
    if let Some(timeout) = options.timeout {
        builder = builder.timeout(Duration::from_secs(u64::from(timeout)));
    }
    if let Some(stdin) = options.stdin {
        builder = builder.stdin_bytes(stdin.as_ref().to_vec());
    } else if options.pipe_stdin.unwrap_or(false) {
        builder = builder.stdin_pipe();
    }
    if let Some(tty) = options.tty {
        builder = builder.tty(tty);
    }
    builder
}

fn apply_ssh_shell_options(
    mut builder: SshShellOptionsBuilder,
    options: Option<NativeSshShellOptionsInput>,
) -> SshShellOptionsBuilder {
    let Some(options) = options else {
        return builder;
    };
    if let Some(cwd) = options.cwd {
        builder = builder.cwd(cwd);
    }
    if let Some(user) = options.user {
        builder = builder.user(user);
    }
    if let Some(env) = options.env {
        for pair in env {
            builder = builder.env(pair.key, pair.value);
        }
    }
    if let Some(term) = options.term {
        builder = builder.term(term);
    }
    if let Some(detach_keys) = options.detach_keys {
        builder = builder.detach_keys(detach_keys);
    }
    if let Some(forward_agent) = options.forward_agent {
        builder = builder.forward_agent(forward_agent);
    }
    builder
}

fn image_source_from_input(input: NativeImageSourceInput) -> Result<ImageSource> {
    match input.kind.as_str() {
        "oci" => input
            .reference
            .map(ImageSource::oci)
            .ok_or_else(|| invalid_arg("OCI image source requires reference")),
        "disk" => input
            .path
            .map(ImageSource::disk)
            .ok_or_else(|| invalid_arg("disk image source requires path")),
        kind => Err(invalid_arg(format!(
            "unsupported image source kind {kind:?}"
        ))),
    }
}

struct ParsedNativeNetworkInput {
    selection: NativeNetworkSelection,
    policy: Option<NetworkPolicy>,
}

enum NativeNetworkSelection {
    Private,
    None,
    Named(String),
}

impl ParsedNativeNetworkInput {
    fn parse(input: NativeNetworkInput) -> Result<Self> {
        let selection = match input.kind.as_str() {
            "private" => NativeNetworkSelection::Private,
            "none" => NativeNetworkSelection::None,
            "named" => NativeNetworkSelection::Named(
                input
                    .name
                    .ok_or_else(|| invalid_arg("named network requires name"))?,
            ),
            kind => return Err(invalid_arg(format!("unsupported network kind {kind:?}"))),
        };
        let policy = input
            .policy_json
            .map(|policy_json| {
                NetworkPolicy::from_json_str(&policy_json)
                    .map_err(|err| invalid_arg(format!("invalid network.policyJson: {err}")))
            })
            .transpose()?;
        Ok(Self { selection, policy })
    }

    fn apply(self, builder: MachineNetworkBuilder) -> MachineNetworkBuilder {
        let builder = match self.selection {
            NativeNetworkSelection::Private => builder.private(),
            NativeNetworkSelection::None => builder.none(),
            NativeNetworkSelection::Named(name) => builder.named(name),
        };
        if let Some(policy) = self.policy {
            builder.policy(policy)
        } else {
            builder
        }
    }
}

fn network_policy_from_input(input: NativeNetworkPolicyInput) -> Result<NetworkPolicy> {
    let mut builder = NetworkPolicy::builder();
    if let Some(default_action) = input.default_action {
        builder = match default_action.as_str() {
            "allow" => builder.default_allow(),
            "deny" => builder.default_deny(),
            other => return Err(invalid_arg(format!("unsupported default action {other:?}"))),
        };
    }
    for pair in input.metadata.unwrap_or_default() {
        builder = builder.metadata(pair.key, pair.value);
    }
    if let Some(audit) = input.audit {
        validate_audit_input(&audit)?;
        builder = builder.audit(|audit_builder| apply_audit_input(audit_builder, audit));
    }
    for endpoint in input.endpoints.unwrap_or_default() {
        validate_endpoint_input(&endpoint)?;
        let name = endpoint.name.clone();
        builder = builder.endpoint(name, |endpoint_builder| {
            apply_endpoint_input(endpoint_builder, endpoint)
        });
    }
    for credential in input.credentials.unwrap_or_default() {
        validate_credential_input(&credential)?;
        let name = credential.name.clone();
        builder = builder.credential(name, |credential_builder| {
            apply_credential_input(credential_builder, credential)
        });
    }
    for rule in input.rules.unwrap_or_default() {
        validate_rule_input(&rule)?;
        builder = if let Some(name) = rule.name.clone() {
            builder.rule(name, |rule_builder| apply_rule_input(rule_builder, rule))
        } else {
            builder.unnamed_rule(|rule_builder| apply_rule_input(rule_builder, rule))
        };
    }
    for tunnel in input.tailscale.unwrap_or_default() {
        let name = tunnel.name.clone();
        builder = builder.tailscale(name, |tunnel_builder| {
            apply_tailscale_input(tunnel_builder, tunnel)
        });
    }
    for forward in input.forwards.unwrap_or_default() {
        validate_forward_input(&forward)?;
        let name = forward.name.clone();
        builder = builder.forward(name, |forward_builder| {
            apply_forward_input(forward_builder, forward)
        });
    }
    builder
        .build()
        .map_err(|err| invalid_arg(format!("invalid network policy: {err}")))
}

fn validate_audit_input(input: &NativeNetworkAuditInput) -> Result<()> {
    if input.body_buffer_bytes.is_some_and(|bytes| bytes < 0) {
        return Err(invalid_arg("audit.bodyBufferBytes must be non-negative"));
    }
    if input.body_storage_bytes.is_some_and(|bytes| bytes < 0) {
        return Err(invalid_arg("audit.bodyStorageBytes must be non-negative"));
    }
    Ok(())
}

fn validate_endpoint_input(input: &NativeNetworkEndpointInput) -> Result<()> {
    if let Some(kind) = input.kind.as_deref() {
        match kind {
            "ip" | "http" | "https" => {}
            _ => return Err(invalid_arg(format!("unsupported endpoint kind {kind:?}"))),
        }
    }
    if let Some(protocol) = input.protocol.as_deref() {
        match protocol {
            "any" | "tcp" | "udp" => {}
            _ => {
                return Err(invalid_arg(format!(
                    "unsupported endpoint protocol {protocol:?}"
                )));
            }
        }
    }
    for port in input.ports.as_deref().unwrap_or_default() {
        validate_u16_port(port.start, "endpoint port start")?;
        if let Some(end) = port.end {
            validate_u16_port(end, "endpoint port end")?;
        }
    }
    Ok(())
}

fn validate_credential_input(input: &NativeNetworkCredentialInput) -> Result<()> {
    if let Some(kind) = input.kind.as_deref() {
        match kind {
            "basic_auth" | "bearer_token" | "header_token" | "github_oauth"
            | "openai_codex_oauth" | "aws_credential" => {}
            _ => return Err(invalid_arg(format!("unsupported credential kind {kind:?}"))),
        }
    }
    Ok(())
}

fn validate_rule_input(input: &NativeNetworkRuleInput) -> Result<()> {
    if let Some(verdict) = input.verdict.as_deref() {
        match verdict {
            "allow" | "deny" => {}
            _ => return Err(invalid_arg(format!("unsupported rule verdict {verdict:?}"))),
        }
    }
    Ok(())
}

fn validate_forward_input(input: &NativeNetworkForwardInput) -> Result<()> {
    if let Some(kind) = input.kind.as_deref() {
        match kind {
            "host" | "tailscale" => {}
            _ => return Err(invalid_arg(format!("unsupported forward kind {kind:?}"))),
        }
    }
    if let Some(port) = input.target_port {
        validate_u16_port(port, "forward targetPort")?;
    }
    Ok(())
}

fn validate_u16_port(value: u32, field: &str) -> Result<()> {
    match u16::try_from(value) {
        Ok(0) => Err(invalid_arg(format!("{field} must be greater than 0"))),
        Ok(_) => Ok(()),
        Err(_) => Err(invalid_arg(format!("{field} must be at most {}", u16::MAX))),
    }
}

fn apply_audit_input(
    mut builder: NetworkAuditBuilder,
    input: NativeNetworkAuditInput,
) -> NetworkAuditBuilder {
    if let Some(bytes) = input.body_buffer_bytes {
        if let Ok(bytes) = u64::try_from(bytes) {
            builder = builder.body_buffer_bytes(bytes);
        }
    }
    if let Some(bytes) = input.body_storage_bytes {
        if let Ok(bytes) = u64::try_from(bytes) {
            builder = builder.body_storage_bytes(bytes);
        }
    }
    builder
}

fn apply_endpoint_input(
    mut builder: NetworkEndpointBuilder,
    input: NativeNetworkEndpointInput,
) -> NetworkEndpointBuilder {
    if let Some(kind) = input.kind {
        builder = match kind.as_str() {
            "ip" => builder.ip(),
            "http" => builder.http(),
            "https" => builder.https(),
            _ => builder,
        };
    }
    for cidr in input.source_cidrs.unwrap_or_default() {
        builder = builder.source_cidr(cidr);
    }
    for cidr in input.destination_cidrs.unwrap_or_default() {
        builder = builder.destination_cidr(cidr);
    }
    if let Some(protocol) = input.protocol {
        builder = match protocol.as_str() {
            "any" => builder.any_protocol(),
            "tcp" => builder.tcp(),
            "udp" => builder.udp(),
            _ => builder,
        };
    }
    for port in input.ports.unwrap_or_default() {
        if let Ok(start) = u16::try_from(port.start) {
            if let Some(end) = port.end {
                if let Ok(end) = u16::try_from(end) {
                    builder = builder.port_range(start, end);
                }
            } else {
                builder = builder.port(start);
            }
        }
    }
    for host in input.hosts.unwrap_or_default() {
        builder = builder.host(host);
    }
    builder
}

fn apply_credential_input(
    mut builder: NetworkCredentialBuilder,
    input: NativeNetworkCredentialInput,
) -> NetworkCredentialBuilder {
    if let Some(kind) = input.kind {
        builder = match kind.as_str() {
            "basic_auth" => builder.basic_auth(),
            "bearer_token" => builder.bearer_token(),
            "header_token" => builder.header_token(),
            "github_oauth" => builder.github_oauth(),
            "openai_codex_oauth" => builder.openai_codex_oauth(),
            "aws_credential" => builder.aws_credential(),
            _ => builder,
        };
    }
    if let Some(endpoint) = input.endpoint {
        builder = builder.endpoint(endpoint);
    }
    if let Some(username) = input.username {
        builder = builder.username(username);
    }
    if let Some(header) = input.header {
        builder = builder.header(header);
    }
    if let Some(prefix) = input.prefix {
        builder = builder.prefix(prefix);
    }
    if let Some(enabled) = input.idempotency_key {
        builder = builder.idempotency_key_enabled(enabled);
    }
    if let Some(condition) = input.condition {
        builder = builder.condition(condition);
    }
    builder
}

fn apply_rule_input(
    mut builder: NetworkRuleBuilder,
    input: NativeNetworkRuleInput,
) -> NetworkRuleBuilder {
    for endpoint in input.endpoints.unwrap_or_default() {
        builder = builder.endpoint(endpoint);
    }
    if let Some(credential) = input.credential {
        builder = builder.credential(credential);
    }
    if let Some(condition) = input.condition {
        builder = builder.condition(condition);
    }
    if let Some(tunnel) = input.tunnel {
        builder = builder.tunnel(tunnel);
    }
    if let Some(priority) = input.priority {
        builder = builder.priority(priority);
    }
    if let Some(disabled) = input.disabled {
        builder = builder.disabled(disabled);
    }
    if let Some(reason) = input.reason {
        builder = builder.reason(reason);
    }
    if let Some(verdict) = input.verdict {
        builder = match verdict.as_str() {
            "allow" => builder.allow(),
            "deny" => builder.deny(),
            _ => builder,
        };
    }
    builder
}

fn apply_tailscale_input(
    mut builder: TailscaleTunnelBuilder,
    input: NativeTailscaleTunnelInput,
) -> TailscaleTunnelBuilder {
    if let Some(tags) = input.tags {
        builder = builder.tags(tags);
    }
    if let Some(hostname) = input.hostname {
        builder = builder.hostname(hostname);
    }
    if let Some(control_url) = input.control_url {
        builder = builder.control_url(control_url);
    }
    builder
}

fn apply_forward_input(
    mut builder: NetworkForwardBuilder,
    input: NativeNetworkForwardInput,
) -> NetworkForwardBuilder {
    if let Some(kind) = input.kind {
        builder = match kind.as_str() {
            "host" => builder.host(),
            "tailscale" => match input.tunnel.as_deref() {
                Some(tunnel) => builder.tailscale(tunnel.to_string()),
                None => builder,
            },
            _ => builder,
        };
    } else if let Some(tunnel) = input.tunnel.as_deref() {
        builder = builder.tailscale(tunnel.to_string());
    }
    if let Some(target) = input.target {
        builder = builder.target(target);
    }
    if let Some(port) = input.target_port.and_then(|port| u16::try_from(port).ok()) {
        builder = builder.target_port(port);
    }
    if let Some(listen) = input.listen {
        builder = builder.listen(listen);
    }
    builder
}

fn key_values_to_map(values: Vec<NativeKeyValue>) -> BTreeMap<String, String> {
    values
        .into_iter()
        .map(|value| (value.key, value.value))
        .collect()
}

fn key_values_from_map(values: BTreeMap<String, String>) -> Vec<NativeKeyValue> {
    values
        .into_iter()
        .map(|(key, value)| NativeKeyValue { key, value })
        .collect()
}

fn machine_data_to_native(data: MachineData) -> NativeMachineData {
    let (agent_mode, agent_path) = match data.guest.agent {
        libvm::MachineAgent::Default => ("default".to_string(), None),
        libvm::MachineAgent::Custom { path } => {
            ("custom".to_string(), Some(path.display().to_string()))
        }
        libvm::MachineAgent::Disabled => ("disabled".to_string(), None),
        _ => ("unknown".to_string(), None),
    };
    NativeMachineData {
        id: data.id,
        name: data.name,
        machine_dir: data.machine_dir.display().to_string(),
        created_at: data.created_at,
        modified_at: data.modified_at,
        image_ref: data.image_ref,
        retention: machine_retention_to_native(data.retention),
        process: process_config_to_native(data.process),
        template_name: data.template_name,
        configured_agent: data.agent_mode.map(machine_agent_to_native),
        rootfs: data.rootfs.map(machine_rootfs_to_native),
        root_disk_size: data.root_disk_size.map(u64_to_i64),
        labels: key_values_from_map(data.labels),
        metadata: key_values_from_map(data.metadata),
        network: network_to_native(data.network),
        agent_mode,
        agent_path,
        status: machine_status_to_native(data.status),
        boot_report: data.boot_report.map(machine_boot_report_to_native),
        provision_report: data
            .provision_report
            .map(machine_provision_report_to_native),
        started_at: data.started_at,
        last_error: data.last_error,
        updated_at: data.updated_at,
    }
}

fn machine_boot_report_to_native(report: MachineBootReport) -> NativeMachineBootReport {
    NativeMachineBootReport {
        mode: report.mode.label().to_string(),
        requested_init: report.requested_init,
        handoff_init_path: report.handoff_init_path,
        probed_init_paths: report.probed_init_paths,
        agent_path: report.agent_path,
        agent_pid: report.agent_pid,
        agent_is_pid1: report.agent_is_pid1,
        message: report.message,
    }
}

fn machine_provision_report_to_native(
    report: MachineProvisionReport,
) -> NativeMachineProvisionReport {
    NativeMachineProvisionReport {
        status: report.status.label().to_string(),
        started_unix_ms: report.started_unix_ms,
        finished_unix_ms: report.finished_unix_ms,
        duration_ms: u64_to_i64(report.duration_ms),
        steps: report
            .steps
            .into_iter()
            .map(machine_provision_step_report_to_native)
            .collect(),
        message: report.message,
    }
}

fn machine_provision_step_report_to_native(
    report: MachineProvisionStepReport,
) -> NativeMachineProvisionStepReport {
    NativeMachineProvisionStepReport {
        id: report.id,
        status: report.status.label().to_string(),
        failure_policy: report.failure_policy.label().to_string(),
        changed: report.changed,
        backend: report.backend,
        duration_ms: u64_to_i64(report.duration_ms),
        message: report.message,
        error_chain: report.error_chain,
    }
}

fn machine_retention_to_native(retention: libvm::MachineRetention) -> String {
    match retention {
        libvm::MachineRetention::Persistent => "persistent".to_string(),
        libvm::MachineRetention::Ephemeral => "ephemeral".to_string(),
    }
}

fn process_config_to_native(process: libvm::ProcessConfig) -> NativeProcessConfig {
    NativeProcessConfig {
        entrypoint: process.entrypoint,
        command: process.command,
        environment: key_values_from_map(process.environment),
        working_directory: process.working_directory,
        user: process.user,
    }
}

fn machine_agent_to_native(agent: libvm::MachineAgent) -> NativeMachineAgent {
    match agent {
        libvm::MachineAgent::Default => NativeMachineAgent {
            mode: "default".to_string(),
            path: None,
        },
        libvm::MachineAgent::Custom { path } => NativeMachineAgent {
            mode: "custom".to_string(),
            path: Some(path.display().to_string()),
        },
        libvm::MachineAgent::Disabled => NativeMachineAgent {
            mode: "disabled".to_string(),
            path: None,
        },
        _ => NativeMachineAgent {
            mode: "unknown".to_string(),
            path: None,
        },
    }
}

fn machine_rootfs_to_native(rootfs: MachineRootfs) -> NativeMachineRootfs {
    NativeMachineRootfs {
        source_kind: match rootfs.source_kind {
            libvm::ImageSourceKind::Oci => "oci".to_string(),
            libvm::ImageSourceKind::Disk => "disk".to_string(),
        },
        requested_reference: rootfs.requested_reference,
        selected_reference: rootfs.selected_reference,
        selected_manifest_digest: rootfs.selected_manifest_digest,
        config_digest: rootfs.config_digest,
        image_id: rootfs.image_id,
        root_disk_path: rootfs.root_disk_path.display().to_string(),
        root_disk_size_bytes: u64_to_i64(rootfs.root_disk_size_bytes),
        created_at: rootfs.created_at,
    }
}

fn machine_status_to_native(status: MachineStatus) -> NativeMachineStatus {
    match status {
        MachineStatus::Stopped => NativeMachineStatus {
            kind: "stopped".to_string(),
            ready: None,
            guest_ready: None,
            message: None,
        },
        MachineStatus::Starting { message } => NativeMachineStatus {
            kind: "starting".to_string(),
            ready: None,
            guest_ready: None,
            message,
        },
        MachineStatus::Running {
            ready,
            guest_ready,
            message,
        } => NativeMachineStatus {
            kind: "running".to_string(),
            ready: Some(ready),
            guest_ready: Some(guest_ready),
            message,
        },
        MachineStatus::Stopping { message } => NativeMachineStatus {
            kind: "stopping".to_string(),
            ready: None,
            guest_ready: None,
            message,
        },
        MachineStatus::Error { message } => NativeMachineStatus {
            kind: "error".to_string(),
            ready: None,
            guest_ready: None,
            message,
        },
        _ => NativeMachineStatus {
            kind: "unknown".to_string(),
            ready: None,
            guest_ready: None,
            message: None,
        },
    }
}

fn network_to_native(network: MachineNetworkConfig) -> NativeNetworkData {
    match network {
        MachineNetworkConfig::Private { policy } => NativeNetworkData {
            kind: "private".to_string(),
            name: None,
            policy_json: policy.and_then(|policy| serde_json::to_string(&policy.normalized()).ok()),
        },
        MachineNetworkConfig::None => NativeNetworkData {
            kind: "none".to_string(),
            name: None,
            policy_json: None,
        },
        MachineNetworkConfig::Named { name } => NativeNetworkData {
            kind: "named".to_string(),
            name: Some(name),
            policy_json: None,
        },
        _ => NativeNetworkData {
            kind: "unknown".to_string(),
            name: None,
            policy_json: None,
        },
    }
}

fn execution_output_to_native(output: ExecutionOutput) -> NativeExecutionOutput {
    NativeExecutionOutput {
        result: execution_result_to_native(output.result().clone()),
        stdout: output.stdout_bytes().to_vec().into(),
        stderr: output.stderr_bytes().to_vec().into(),
        terminal_output: output.terminal_output_bytes().to_vec().into(),
    }
}

fn execution_result_to_native(result: ExecutionResult) -> NativeExecutionResult {
    match result {
        ExecutionResult::Exited { code } => NativeExecutionResult {
            kind: "exited".to_string(),
            code,
            signal: None,
            reason: None,
            message: None,
        },
        ExecutionResult::Signaled { signal } => NativeExecutionResult {
            kind: "signaled".to_string(),
            code: None,
            signal,
            reason: None,
            message: None,
        },
        ExecutionResult::LaunchFailed(failure) => NativeExecutionResult {
            kind: "launch_failed".to_string(),
            code: None,
            signal: None,
            reason: Some(execution_launch_failure_reason(failure.reason).to_string()),
            message: failure.message,
        },
        ExecutionResult::Lost(lost) => NativeExecutionResult {
            kind: "lost".to_string(),
            code: None,
            signal: None,
            reason: Some(execution_lost_reason(lost.reason).to_string()),
            message: lost.message,
        },
    }
}

fn execution_launch_failure_reason(reason: libvm::ExecutionLaunchFailureReason) -> &'static str {
    match reason {
        libvm::ExecutionLaunchFailureReason::Unspecified => "unspecified",
        libvm::ExecutionLaunchFailureReason::CommandNotFound => "command_not_found",
        libvm::ExecutionLaunchFailureReason::InvalidProcessSpec => "invalid_process_spec",
        libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotFound => {
            "working_directory_not_found"
        }
        libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotDirectory => {
            "working_directory_not_directory"
        }
        libvm::ExecutionLaunchFailureReason::InvalidIdentity => "invalid_identity",
        libvm::ExecutionLaunchFailureReason::IdentityNotFound => "identity_not_found",
        libvm::ExecutionLaunchFailureReason::PermissionDenied => "permission_denied",
        libvm::ExecutionLaunchFailureReason::SpawnFailed => "spawn_failed",
        libvm::ExecutionLaunchFailureReason::CancelledBeforeStart => "cancelled_before_start",
    }
}

fn execution_lost_reason(reason: libvm::ExecutionLostReason) -> &'static str {
    match reason {
        libvm::ExecutionLostReason::Unspecified => "unspecified",
        libvm::ExecutionLostReason::AgentInstanceReplaced => "agent_instance_replaced",
        libvm::ExecutionLostReason::AgentBootReplaced => "agent_boot_replaced",
        libvm::ExecutionLostReason::AgentUnavailable => "agent_unavailable",
        libvm::ExecutionLostReason::GuestStreamLost => "guest_stream_lost",
        libvm::ExecutionLostReason::VmStopped => "vm_stopped",
        libvm::ExecutionLostReason::VmmonExited => "vmmon_exited",
    }
}

fn ssh_exit_status_to_native(status: SshExitStatus) -> NativeSshExitStatus {
    NativeSshExitStatus {
        code: status.code,
        success: status.success,
    }
}

fn execution_event_to_native(event: ExecutionEvent) -> NativeExecutionEvent {
    match event {
        ExecutionEvent::Accepted => NativeExecutionEvent {
            kind: "accepted".to_string(),
            data: None,
            code: None,
            signal: None,
            reason: None,
            message: None,
        },
        ExecutionEvent::Started => NativeExecutionEvent {
            kind: "started".to_string(),
            data: None,
            code: None,
            signal: None,
            reason: None,
            message: None,
        },
        ExecutionEvent::Stdout(data) => NativeExecutionEvent {
            kind: "stdout".to_string(),
            data: Some(data.into()),
            code: None,
            signal: None,
            reason: None,
            message: None,
        },
        ExecutionEvent::Stderr(data) => NativeExecutionEvent {
            kind: "stderr".to_string(),
            data: Some(data.into()),
            code: None,
            signal: None,
            reason: None,
            message: None,
        },
        ExecutionEvent::TerminalOutput(data) => NativeExecutionEvent {
            kind: "terminal_output".to_string(),
            data: Some(data.into()),
            code: None,
            signal: None,
            reason: None,
            message: None,
        },
        ExecutionEvent::Terminal(result) => {
            let result = execution_result_to_native(result);
            NativeExecutionEvent {
                kind: result.kind,
                data: None,
                code: result.code,
                signal: result.signal,
                reason: result.reason,
                message: result.message,
            }
        }
    }
}

fn machine_log_source_from_native(source: &str) -> Result<MachineLogSource> {
    match source {
        "monitor" => Ok(MachineLogSource::Monitor),
        "serial" => Ok(MachineLogSource::Serial),
        "exec" => Ok(MachineLogSource::Exec),
        "network" => Ok(MachineLogSource::Network),
        "networkAudit" => Ok(MachineLogSource::NetworkAudit),
        _ => Err(invalid_arg(format!(
            "unsupported machine log source {source:?}"
        ))),
    }
}

fn machine_log_chunk_to_native(chunk: MachineLogChunk) -> Result<NativeMachineLogChunk> {
    let output = match chunk.output {
        MachineLogOutput::Stdout => "stdout",
        MachineLogOutput::Stderr => "stderr",
        _ => return Err(invalid_state("unsupported machine log output")),
    };
    Ok(NativeMachineLogChunk {
        output: output.to_string(),
        data: chunk.data.to_vec().into(),
    })
}

fn image_handle_to_native(handle: ImageHandle) -> NativeImageHandle {
    NativeImageHandle {
        requested_reference: handle.requested_reference,
        selected_reference: handle.selected_reference,
        selected_manifest_digest: handle.selected_manifest_digest,
        config_digest: handle.config_digest,
        image_id: handle.image_id,
        platform_os: handle.platform_os,
        platform_architecture: handle.platform_architecture,
        platform_variant: handle.platform_variant,
        size_bytes: handle.size_bytes.map(u64_to_i64),
        created_at: handle.created_at,
        updated_at: handle.updated_at,
        last_used_at: handle.last_used_at,
    }
}

fn image_detail_to_native(detail: ImageDetail) -> NativeImageDetail {
    NativeImageDetail {
        handle: image_handle_to_native(detail.handle),
        config: oci_image_config_to_native(detail.config),
        layers: detail
            .layers
            .into_iter()
            .map(image_layer_to_native)
            .collect(),
    }
}

fn oci_image_config_to_native(config: OciImageConfigMetadata) -> NativeOciImageConfig {
    NativeOciImageConfig {
        entrypoint: config.entrypoint,
        cmd: config.cmd,
        env: config.env,
        working_dir: config.working_dir,
        user: config.user,
        labels: config.labels.map(key_values_from_map),
        stop_signal: config.stop_signal,
    }
}

fn image_layer_to_native(layer: ImageLayerDetail) -> NativeImageLayerDetail {
    NativeImageLayerDetail {
        blob_digest: layer.blob_digest,
        diff_id: layer.diff_id,
        media_type: layer.media_type,
        compressed_size_bytes: layer.compressed_size_bytes.map(u64_to_i64),
        uncompressed_size_bytes: layer.uncompressed_size_bytes.map(u64_to_i64),
        position: layer.position,
    }
}

fn prune_report_to_native(report: ImagePruneReport) -> NativeImagePruneReport {
    NativeImagePruneReport {
        references_removed: u64_to_i64(report.references_removed),
        artifacts_removed: u64_to_i64(report.artifacts_removed),
        bytes_removed: u64_to_i64(report.bytes_removed),
    }
}

fn nonnegative_u64(field: &str, value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| invalid_arg(format!("{field} must be non-negative")))
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn pull_policy_from_string(policy: &str) -> Result<ImagePullPolicy> {
    match policy {
        "if_missing" | "ifMissing" => Ok(ImagePullPolicy::IfMissing),
        "always" => Ok(ImagePullPolicy::Always),
        "never" => Ok(ImagePullPolicy::Never),
        policy => Err(invalid_arg(format!(
            "unsupported image pull policy {policy:?}"
        ))),
    }
}

fn to_napi_error(error: LibVmError) -> Error {
    let variant = match &error {
        LibVmError::DataDirUnavailable => "DataDirUnavailable",
        LibVmError::ConfigDirUnavailable => "ConfigDirUnavailable",
        LibVmError::RelativeEnvironmentPath { .. } => "RelativeEnvironmentPath",
        LibVmError::InvalidMachineName { .. } => "InvalidMachineName",
        LibVmError::InvalidMachineIdPrefix { .. } => "InvalidMachineIdPrefix",
        LibVmError::MachineAlreadyExists { .. } => "MachineAlreadyExists",
        LibVmError::MachineNameGenerationFailed { .. } => "MachineNameGenerationFailed",
        LibVmError::MachineNotFound { .. } => "MachineNotFound",
        LibVmError::ImageNotFound { .. } => "ImageNotFound",
        LibVmError::ImageInUse { .. } => "ImageInUse",
        LibVmError::Image { .. } => "Image",
        LibVmError::MachineIdAlreadyExists { .. } => "MachineIdAlreadyExists",
        LibVmError::MachineAlreadyRunning { .. } => "MachineAlreadyRunning",
        LibVmError::MachineNotRunning { .. } => "MachineNotRunning",
        LibVmError::MachineLogSourceUnavailable { .. } => "MachineLogSourceUnavailable",
        LibVmError::MonitorConnection { .. } => "MonitorConnection",
        LibVmError::MonitorProtocol { .. } => "MonitorProtocol",
        LibVmError::GuestSession { .. } => "GuestSession",
        LibVmError::MachinePreparationFailed { .. } => "MachinePreparationFailed",
        LibVmError::NetworkRuntime { .. } => "NetworkRuntime",
        LibVmError::VmMonExecutableNotFound { .. } => "VmMonExecutableNotFound",
        LibVmError::VmMonExecutableInvalid { .. } => "VmMonExecutableInvalid",
        LibVmError::BootAssetNotFound { .. } => "BootAssetNotFound",
        LibVmError::BootAssetInvalid { .. } => "BootAssetInvalid",
        LibVmError::InvalidCreateRequest { .. } => "InvalidCreateRequest",
        LibVmError::InvalidMachineUpdate { .. } => "InvalidMachineUpdate",
        LibVmError::UnsupportedHostArchitecture { .. } => "UnsupportedHostArchitecture",
        LibVmError::CorruptState { .. } => "CorruptState",
        LibVmError::VmSpecSerializeFailed { .. } => "VmSpecSerializeFailed",
        LibVmError::VmSpecLoadFailed { .. } => "VmSpecLoadFailed",
        LibVmError::AmbiguousIdPrefix { .. } => "AmbiguousIdPrefix",
        LibVmError::StateDecode { .. } => "StateDecode",
        LibVmError::StateDatabaseConfigMismatch { .. } => "StateDatabaseConfigMismatch",
        LibVmError::Database(_) => "Database",
        LibVmError::DatabaseMigration(_) => "DatabaseMigration",
        LibVmError::Io(_) => "Io",
        LibVmError::RootDisk { .. } => "RootDisk",
        _ => "LibVmError",
    };
    Error::new(Status::GenericFailure, format!("[{variant}] {error}"))
}

fn invalid_arg(message: impl Into<String>) -> Error {
    Error::new(Status::InvalidArg, message.into())
}

fn invalid_state(message: impl Into<String>) -> Error {
    Error::new(Status::GenericFailure, message.into())
}

fn machine_log_handle_closed() -> Error {
    invalid_state("machine log handle is closed")
}

fn machine_log_handle_busy() -> Error {
    invalid_state("machine log handle is busy")
}

fn execution_session_closed() -> Error {
    invalid_state("execution session is closed")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use libvm::{
        MachineBootMode, MachineBootReport, MachineLogChunk, MachineLogOutput,
        MachineNetworkConfig, MachineProvisionFailurePolicy, MachineProvisionReport,
        MachineProvisionStatus, MachineProvisionStepReport, MachineProvisionStepStatus,
        NetworkPolicy, OciImageConfigMetadata, ProcessConfig,
    };
    use serde_json::json;
    use tokio::sync::watch;

    use crate::{
        machine_boot_report_to_native, machine_log_chunk_to_native, machine_log_source_from_native,
        machine_provision_report_to_native, network_policy_from_input, network_to_native,
        oci_image_config_to_native, process_config_to_native, MachineLogHandleState,
        NativeKeyValue, NativeNetworkInput, NativeNetworkPolicyInput, ParsedNativeNetworkInput,
    };

    fn sample_policy_json() -> String {
        r#"{ "version": 1, "metadata": { "source": "test" } }"#.to_string()
    }

    #[test]
    fn network_input_preserves_private_policy_json() {
        let network = ParsedNativeNetworkInput::parse(NativeNetworkInput {
            kind: "private".to_string(),
            name: None,
            policy_json: Some(sample_policy_json()),
        })
        .expect("private network with policy json");

        assert_eq!(network.policy.expect("policy").metadata()["source"], "test");
    }

    #[test]
    fn network_policy_input_builds_canonical_policy() {
        let policy = network_policy_from_input(NativeNetworkPolicyInput {
            default_action: Some("deny".to_string()),
            metadata: Some(vec![NativeKeyValue {
                key: "source".to_string(),
                value: "builder".to_string(),
            }]),
            audit: None,
            endpoints: None,
            credentials: None,
            rules: None,
            tailscale: None,
            forwards: None,
        })
        .expect("network policy");

        assert_eq!(policy.metadata()["source"], "builder");
    }

    #[test]
    fn network_output_preserves_private_policy_json() {
        let policy = NetworkPolicy::from_json_str(&sample_policy_json()).expect("policy");
        let network: MachineNetworkConfig = serde_json::from_value(json!({
            "kind": "private",
            "policy": policy,
        }))
        .expect("machine network config");

        let native = network_to_native(network);

        assert_eq!(native.kind, "private");
        assert_eq!(native.name, None);
        let policy_json = native.policy_json.expect("policy json");
        let parsed = NetworkPolicy::from_json_str(&policy_json).expect("parse output policy json");
        assert_eq!(parsed.metadata()["source"], "test");
    }

    #[test]
    fn machine_log_source_requires_one_semantic_source() {
        assert!(machine_log_source_from_native("monitor").is_ok());
        assert!(machine_log_source_from_native("serial").is_ok());
        assert!(machine_log_source_from_native("exec").is_ok());
        assert!(machine_log_source_from_native("network").is_ok());
        assert!(machine_log_source_from_native("networkAudit").is_ok());
        assert!(machine_log_source_from_native("network_audit").is_err());
        assert!(machine_log_source_from_native("path").is_err());
    }

    #[test]
    fn machine_log_chunks_preserve_bytes_and_output_channels() {
        let stdout = machine_log_chunk_to_native(MachineLogChunk {
            output: MachineLogOutput::Stdout,
            data: vec![0, 255, 128, 10].into(),
        })
        .expect("convert stdout chunk");
        let stderr = machine_log_chunk_to_native(MachineLogChunk {
            output: MachineLogOutput::Stderr,
            data: vec![1, 2, 3].into(),
        })
        .expect("convert stderr chunk");

        assert_eq!(stdout.output, "stdout");
        assert_eq!(stdout.data.as_ref(), &[0, 255, 128, 10]);
        assert_eq!(stderr.output, "stderr");
        assert_eq!(stderr.data.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn oci_image_config_preserves_absent_and_empty_collections() {
        let absent = oci_image_config_to_native(OciImageConfigMetadata::default());
        let empty = oci_image_config_to_native(OciImageConfigMetadata {
            entrypoint: Some(Vec::new()),
            cmd: Some(Vec::new()),
            env: Some(Vec::new()),
            labels: Some(BTreeMap::new()),
            ..OciImageConfigMetadata::default()
        });

        assert!(absent.entrypoint.is_none());
        assert!(absent.labels.is_none());
        assert_eq!(empty.entrypoint, Some(Vec::new()));
        assert_eq!(empty.cmd, Some(Vec::new()));
        assert_eq!(empty.env, Some(Vec::new()));
        assert!(empty.labels.is_some_and(|labels| labels.is_empty()));
    }

    #[test]
    fn process_config_preserves_unset_and_empty_command_arrays() {
        let unset = process_config_to_native(ProcessConfig::default());
        let process = ProcessConfig {
            entrypoint: Some(Vec::new()),
            command: Some(Vec::new()),
            environment: BTreeMap::new(),
            working_directory: "/workspace".to_string(),
            user: Some("1000:1000".to_string()),
        };
        let empty = process_config_to_native(process);

        assert!(unset.entrypoint.is_none());
        assert!(unset.command.is_none());
        assert!(unset.environment.is_empty());
        assert_eq!(empty.entrypoint, Some(Vec::new()));
        assert_eq!(empty.command, Some(Vec::new()));
        assert!(empty.environment.is_empty());
        assert_eq!(empty.working_directory, "/workspace");
        assert_eq!(empty.user.as_deref(), Some("1000:1000"));
    }

    #[test]
    fn guest_reports_preserve_fields_and_optional_values() {
        let boot = machine_boot_report_to_native(MachineBootReport {
            mode: MachineBootMode::InitChild,
            requested_init: Some("/sbin/init".to_string()),
            handoff_init_path: None,
            probed_init_paths: vec!["/sbin/init".to_string(), "/init".to_string()],
            agent_path: Some("/usr/bin/silo-agent".to_string()),
            agent_pid: 42,
            agent_is_pid1: false,
            message: None,
        });
        let provision = machine_provision_report_to_native(MachineProvisionReport {
            status: MachineProvisionStatus::Degraded,
            started_unix_ms: 1_700_000_000_001,
            finished_unix_ms: 1_700_000_000_123,
            duration_ms: 122,
            steps: vec![MachineProvisionStepReport {
                id: "packages".to_string(),
                status: MachineProvisionStepStatus::Failed,
                failure_policy: MachineProvisionFailurePolicy::BestEffort,
                changed: true,
                backend: None,
                duration_ms: 122,
                message: Some("package mirror unavailable".to_string()),
                error_chain: None,
            }],
            message: None,
        });

        assert_eq!(boot.mode, "init-child");
        assert_eq!(boot.requested_init.as_deref(), Some("/sbin/init"));
        assert_eq!(boot.handoff_init_path, None);
        assert_eq!(boot.probed_init_paths, ["/sbin/init", "/init"]);
        assert_eq!(boot.agent_path.as_deref(), Some("/usr/bin/silo-agent"));
        assert_eq!(boot.agent_pid, 42);
        assert!(!boot.agent_is_pid1);
        assert_eq!(boot.message, None);
        assert_eq!(provision.status, "degraded");
        assert_eq!(provision.started_unix_ms, 1_700_000_000_001);
        assert_eq!(provision.finished_unix_ms, 1_700_000_000_123);
        assert_eq!(provision.duration_ms, 122);
        assert_eq!(provision.message, None);
        assert_eq!(provision.steps.len(), 1);
        let step = &provision.steps[0];
        assert_eq!(step.id, "packages");
        assert_eq!(step.status, "failed");
        assert_eq!(step.failure_policy, "best-effort");
        assert!(step.changed);
        assert_eq!(step.backend, None);
        assert_eq!(step.duration_ms, 122);
        assert_eq!(step.message.as_deref(), Some("package mirror unavailable"));
        assert_eq!(step.error_chain, None);
    }

    #[test]
    fn machine_log_handle_rejects_concurrent_receives_as_busy() {
        let (cancellation, _) = watch::channel(false);
        let mut state = MachineLogHandleState {
            stream: None,
            receive_in_flight: true,
            closed: false,
            cancellation,
        };

        let result = state.begin_recv();

        match result {
            Err(error) => assert!(error.to_string().contains("machine log handle is busy")),
            Ok(_) => panic!("concurrent receive must fail"),
        }
    }

    #[test]
    fn machine_log_handle_close_is_idempotent_and_cancels_pending_receive() {
        let (cancellation, _) = watch::channel(false);
        let mut state = MachineLogHandleState {
            stream: None,
            receive_in_flight: true,
            closed: false,
            cancellation,
        };
        let receiver = state.cancellation.subscribe();

        state.close();
        state.close();

        assert!(state.closed);
        assert!(state.stream.is_none());
        assert!(*receiver.borrow());
    }
}
