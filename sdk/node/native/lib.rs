use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use libvm::{
    AttachOptionsBuilder, ExecControl, ExecEvent, ExecHandle, ExecOptionsBuilder, ExecOutput,
    ExecSink, ExitStatus, ImageDetail, ImageHandle, ImageLayerDetail, ImagePruneReport,
    ImagePullOptions, ImagePullPolicy, ImageRemoveOptions, ImageSource, Images, LibVmError,
    Machine, MachineBuilder, MachineData, MachineNetworkConfig, MachineRef, MachineStatus, Memory,
    NetworkPolicyRef, Runtime, RuntimeConfig,
};
use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Result, Status};
use napi_derive::napi;
use vm_spec::Mount;

#[napi(object)]
pub struct RuntimeOpenOptions {
    pub data_root: Option<String>,
    pub run_root: Option<String>,
    pub image_root: Option<String>,
    pub default_kernel: Option<String>,
    pub default_initramfs: Option<String>,
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
    pub policy_ref: Option<String>,
}

#[napi(object)]
pub struct NativeExecOptionsInput {
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: Option<Vec<NativeKeyValue>>,
    pub timeout: Option<u32>,
    pub stdin: Option<Uint8Array>,
    pub pipe_stdin: Option<bool>,
    pub tty: Option<bool>,
    pub forward_agent: Option<bool>,
}

#[napi(object)]
pub struct NativeAttachOptionsInput {
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: Option<Vec<NativeKeyValue>>,
    pub term: Option<String>,
    pub detach_keys: Option<String>,
    pub forward_agent: Option<bool>,
}

#[napi(object)]
pub struct NativeMachineData {
    pub id: String,
    pub name: String,
    pub machine_dir: String,
    pub created_at: i64,
    pub modified_at: i64,
    pub image_ref: String,
    pub root_disk_size: Option<i64>,
    pub labels: Vec<NativeKeyValue>,
    pub metadata: Vec<NativeKeyValue>,
    pub network: NativeNetworkData,
    pub status: NativeMachineStatus,
    pub started_at: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[napi(object)]
pub struct NativeMachineStatus {
    pub kind: String,
    pub guest_ready: Option<bool>,
    pub message: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkData {
    pub kind: String,
    pub name: Option<String>,
    pub policy_ref: Option<String>,
}

#[napi(object)]
pub struct NativeExitStatus {
    pub code: i32,
    pub success: bool,
}

#[napi(object)]
pub struct NativeExecOutput {
    pub status: NativeExitStatus,
    pub stdout: Uint8Array,
    pub stderr: Uint8Array,
}

#[napi(object)]
pub struct NativeExecEvent {
    pub kind: String,
    pub data: Option<Uint8Array>,
    pub code: Option<i32>,
    pub message: Option<String>,
}

#[napi(object)]
pub struct NativeImageHandle {
    pub reference: String,
    pub image_id: String,
    pub manifest_digest: Option<String>,
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
    pub layers: Vec<NativeImageLayerDetail>,
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

#[napi(js_name = "NativeExecHandle")]
pub struct NativeExecHandle {
    inner: Mutex<Option<ExecHandle>>,
}

#[napi(js_name = "NativeExecSink")]
pub struct NativeExecSink {
    inner: Mutex<Option<ExecSink>>,
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
        if let Some(default_kernel) = options.default_kernel {
            config = config.with_default_kernel(default_kernel);
        }
        if let Some(default_initramfs) = options.default_initramfs {
            config = config.with_default_initramfs(default_initramfs);
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
        let network = network_from_input(network)?;
        self.update(|builder| builder.network(network))
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
            .map(machine_data_to_native)
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
        options: Option<NativeExecOptionsInput>,
    ) -> Result<NativeExecOutput> {
        let machine = self.inner.clone();
        let output = run_exec(machine, program, args.unwrap_or_default(), options).await?;
        Ok(exec_output_to_native(output))
    }

    #[napi]
    pub async fn spawn(
        &self,
        program: String,
        args: Option<Vec<String>>,
        options: Option<NativeExecOptionsInput>,
    ) -> Result<NativeExecHandle> {
        let machine = self.inner.clone();
        let handle = spawn_exec(machine, program, args.unwrap_or_default(), options).await?;
        Ok(NativeExecHandle {
            inner: Mutex::new(Some(handle)),
        })
    }

    #[napi]
    pub async fn shell(
        &self,
        script: String,
        options: Option<NativeExecOptionsInput>,
    ) -> Result<NativeExecOutput> {
        let machine = self.inner.clone();
        let output = run_shell(machine, script, options).await?;
        Ok(exec_output_to_native(output))
    }

    #[napi]
    pub async fn attach(
        &self,
        program: String,
        args: Option<Vec<String>>,
        options: Option<NativeAttachOptionsInput>,
    ) -> Result<NativeExitStatus> {
        let machine = self.inner.clone();
        let status = attach(machine, program, args.unwrap_or_default(), options).await?;
        Ok(exit_status_to_native(status))
    }

    #[napi(js_name = "attachShell")]
    pub async fn attach_shell(
        &self,
        options: Option<NativeAttachOptionsInput>,
    ) -> Result<NativeExitStatus> {
        let machine = self.inner.clone();
        let status = attach_shell(machine, options).await?;
        Ok(exit_status_to_native(status))
    }
}

#[napi]
impl NativeExecHandle {
    #[napi]
    pub async fn recv(&self) -> Result<Option<NativeExecEvent>> {
        let mut handle = self.take_handle()?;
        let event = handle.recv().await.map(exec_event_to_native);
        if event.is_some() {
            self.replace_handle(handle)?;
        }
        Ok(event)
    }

    #[napi(js_name = "takeStdin")]
    pub fn take_stdin(&self) -> Result<Option<NativeExecSink>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| invalid_state("exec handle lock is poisoned"))?;
        let handle = guard
            .as_mut()
            .ok_or_else(|| invalid_state("exec handle is closed"))?;
        Ok(handle.take_stdin().map(|inner| NativeExecSink {
            inner: Mutex::new(Some(inner)),
        }))
    }

    #[napi]
    pub async fn wait(&self) -> Result<NativeExitStatus> {
        let mut handle = self.take_handle()?;
        handle
            .wait()
            .await
            .map(exit_status_to_native)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn collect(&self) -> Result<NativeExecOutput> {
        let mut handle = self.take_handle()?;
        handle
            .collect()
            .await
            .map(exec_output_to_native)
            .map_err(to_napi_error)
    }

    #[napi]
    pub async fn signal(&self, signal: i32) -> Result<()> {
        let control = self.control()?;
        control.signal(signal).await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn kill(&self) -> Result<()> {
        let control = self.control()?;
        control.kill().await.map_err(to_napi_error)
    }

    #[napi]
    pub async fn resize(&self, rows: u32, cols: u32) -> Result<()> {
        let rows = u16::try_from(rows).map_err(|_| invalid_arg("rows must fit in u16"))?;
        let cols = u16::try_from(cols).map_err(|_| invalid_arg("cols must fit in u16"))?;
        let control = self.control()?;
        control.resize(rows, cols).await.map_err(to_napi_error)
    }
}

impl NativeExecHandle {
    fn take_handle(&self) -> Result<ExecHandle> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("exec handle lock is poisoned"))?
            .take()
            .ok_or_else(|| invalid_state("exec handle is closed"))
    }

    fn replace_handle(&self, handle: ExecHandle) -> Result<()> {
        *self
            .inner
            .lock()
            .map_err(|_| invalid_state("exec handle lock is poisoned"))? = Some(handle);
        Ok(())
    }

    fn control(&self) -> Result<ExecControl> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| invalid_state("exec handle lock is poisoned"))?;
        guard
            .as_ref()
            .map(ExecHandle::control)
            .ok_or_else(|| invalid_state("exec handle is closed"))
    }
}

#[napi]
impl NativeExecSink {
    #[napi]
    pub async fn write(&self, data: Uint8Array) -> Result<()> {
        let sink = self.take_sink()?;
        let result = sink.write(data.as_ref().to_vec()).await;
        if result.is_ok() {
            self.replace_sink(sink)?;
        }
        result.map_err(to_napi_error)
    }

    #[napi]
    pub fn close(&self) -> Result<()> {
        self.take_sink().map(|_| ())
    }
}

impl NativeExecSink {
    fn take_sink(&self) -> Result<ExecSink> {
        self.inner
            .lock()
            .map_err(|_| invalid_state("exec stdin lock is poisoned"))?
            .take()
            .ok_or_else(|| invalid_state("exec stdin is closed"))
    }

    fn replace_sink(&self, sink: ExecSink) -> Result<()> {
        *self
            .inner
            .lock()
            .map_err(|_| invalid_state("exec stdin lock is poisoned"))? = Some(sink);
        Ok(())
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
    options: Option<NativeExecOptionsInput>,
) -> Result<ExecOutput> {
    machine
        .exec_with(program, |builder| {
            apply_exec_options(builder.args(args), options)
        })
        .await
        .map_err(to_napi_error)
}

async fn spawn_exec(
    machine: Machine,
    program: String,
    args: Vec<String>,
    options: Option<NativeExecOptionsInput>,
) -> Result<ExecHandle> {
    machine
        .spawn_with(program, |builder| {
            apply_exec_options(builder.args(args), options)
        })
        .await
        .map_err(to_napi_error)
}

async fn run_shell(
    machine: Machine,
    script: String,
    options: Option<NativeExecOptionsInput>,
) -> Result<ExecOutput> {
    machine
        .shell_with(script, |builder| apply_exec_options(builder, options))
        .await
        .map_err(to_napi_error)
}

async fn attach(
    machine: Machine,
    program: String,
    args: Vec<String>,
    options: Option<NativeAttachOptionsInput>,
) -> Result<ExitStatus> {
    machine
        .attach_with(program, |builder| {
            apply_attach_options(builder.args(args), options)
        })
        .await
        .map_err(to_napi_error)
}

async fn attach_shell(
    machine: Machine,
    options: Option<NativeAttachOptionsInput>,
) -> Result<ExitStatus> {
    machine
        .attach_shell_with(|builder| apply_attach_options(builder, options))
        .await
        .map_err(to_napi_error)
}

fn apply_exec_options(
    mut builder: ExecOptionsBuilder,
    options: Option<NativeExecOptionsInput>,
) -> ExecOptionsBuilder {
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
    if let Some(forward_agent) = options.forward_agent {
        builder = builder.forward_agent(forward_agent);
    }
    builder
}

fn apply_attach_options(
    mut builder: AttachOptionsBuilder,
    options: Option<NativeAttachOptionsInput>,
) -> AttachOptionsBuilder {
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
        "tar" => input
            .path
            .map(ImageSource::tar)
            .ok_or_else(|| invalid_arg("tar image source requires path")),
        kind => Err(invalid_arg(format!(
            "unsupported image source kind {kind:?}"
        ))),
    }
}

fn network_from_input(input: NativeNetworkInput) -> Result<MachineNetworkConfig> {
    match input.kind.as_str() {
        "private" => match input.policy_ref {
            Some(policy_ref) => NetworkPolicyRef::new(policy_ref)
                .map(MachineNetworkConfig::private_with_policy)
                .map_err(invalid_arg),
            None => Ok(MachineNetworkConfig::private()),
        },
        "none" => Ok(MachineNetworkConfig::none()),
        "named" => input
            .name
            .map(MachineNetworkConfig::named)
            .ok_or_else(|| invalid_arg("named network requires name")),
        kind => Err(invalid_arg(format!("unsupported network kind {kind:?}"))),
    }
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
    NativeMachineData {
        id: data.id,
        name: data.name,
        machine_dir: data.machine_dir.display().to_string(),
        created_at: data.created_at,
        modified_at: data.modified_at,
        image_ref: data.image_ref,
        root_disk_size: data.root_disk_size.map(u64_to_i64),
        labels: key_values_from_map(data.labels),
        metadata: key_values_from_map(data.metadata),
        network: network_to_native(data.network),
        status: machine_status_to_native(data.status),
        started_at: data.started_at,
        last_error: data.last_error,
        updated_at: data.updated_at,
    }
}

fn machine_status_to_native(status: MachineStatus) -> NativeMachineStatus {
    match status {
        MachineStatus::Stopped => NativeMachineStatus {
            kind: "stopped".to_string(),
            guest_ready: None,
            message: None,
        },
        MachineStatus::Starting { message } => NativeMachineStatus {
            kind: "starting".to_string(),
            guest_ready: None,
            message,
        },
        MachineStatus::Running {
            guest_ready,
            message,
        } => NativeMachineStatus {
            kind: "running".to_string(),
            guest_ready: Some(guest_ready),
            message,
        },
        MachineStatus::Stopping { message } => NativeMachineStatus {
            kind: "stopping".to_string(),
            guest_ready: None,
            message,
        },
        MachineStatus::Error { message } => NativeMachineStatus {
            kind: "error".to_string(),
            guest_ready: None,
            message,
        },
        _ => NativeMachineStatus {
            kind: "unknown".to_string(),
            guest_ready: None,
            message: None,
        },
    }
}

fn network_to_native(network: MachineNetworkConfig) -> NativeNetworkData {
    match network {
        MachineNetworkConfig::Private { policy_ref } => NativeNetworkData {
            kind: "private".to_string(),
            name: None,
            policy_ref: policy_ref.map(|policy_ref| policy_ref.as_str().to_string()),
        },
        MachineNetworkConfig::None => NativeNetworkData {
            kind: "none".to_string(),
            name: None,
            policy_ref: None,
        },
        MachineNetworkConfig::Named { name } => NativeNetworkData {
            kind: "named".to_string(),
            name: Some(name),
            policy_ref: None,
        },
        _ => NativeNetworkData {
            kind: "unknown".to_string(),
            name: None,
            policy_ref: None,
        },
    }
}

fn exec_output_to_native(output: ExecOutput) -> NativeExecOutput {
    NativeExecOutput {
        status: exit_status_to_native(output.status()),
        stdout: output.stdout_bytes().to_vec().into(),
        stderr: output.stderr_bytes().to_vec().into(),
    }
}

fn exit_status_to_native(status: ExitStatus) -> NativeExitStatus {
    NativeExitStatus {
        code: status.code,
        success: status.success,
    }
}

fn exec_event_to_native(event: ExecEvent) -> NativeExecEvent {
    match event {
        ExecEvent::Started => NativeExecEvent {
            kind: "started".to_string(),
            data: None,
            code: None,
            message: None,
        },
        ExecEvent::Stdout(data) => NativeExecEvent {
            kind: "stdout".to_string(),
            data: Some(data.into()),
            code: None,
            message: None,
        },
        ExecEvent::Stderr(data) => NativeExecEvent {
            kind: "stderr".to_string(),
            data: Some(data.into()),
            code: None,
            message: None,
        },
        ExecEvent::Exited { code } => NativeExecEvent {
            kind: "exited".to_string(),
            data: None,
            code: Some(code),
            message: None,
        },
        ExecEvent::Failed { message } => NativeExecEvent {
            kind: "failed".to_string(),
            data: None,
            code: None,
            message: Some(message),
        },
        ExecEvent::StdinError { message } => NativeExecEvent {
            kind: "stdin_error".to_string(),
            data: None,
            code: None,
            message: Some(message),
        },
    }
}

fn image_handle_to_native(handle: ImageHandle) -> NativeImageHandle {
    NativeImageHandle {
        reference: handle.reference,
        image_id: handle.image_id,
        manifest_digest: handle.manifest_digest,
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
        layers: detail
            .layers
            .into_iter()
            .map(image_layer_to_native)
            .collect(),
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

#[cfg(test)]
mod tests {
    use libvm::{MachineNetworkConfig, NetworkPolicyRef};

    use crate::{network_from_input, network_to_native, NativeNetworkInput};

    #[test]
    fn network_input_preserves_private_policy_ref() {
        let network = network_from_input(NativeNetworkInput {
            kind: "private".to_string(),
            name: None,
            policy_ref: Some("github".to_string()),
        })
        .expect("private network with policy ref");

        assert_eq!(
            network.policy_ref().map(|policy_ref| policy_ref.as_str()),
            Some("github")
        );
    }

    #[test]
    fn network_output_preserves_private_policy_ref() {
        let network = MachineNetworkConfig::private_with_policy(
            NetworkPolicyRef::new("github").expect("policy ref"),
        );

        let native = network_to_native(network);

        assert_eq!(native.kind, "private");
        assert_eq!(native.name, None);
        assert_eq!(native.policy_ref.as_deref(), Some("github"));
    }
}
