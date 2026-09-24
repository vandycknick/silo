//! libvm operations for the managed appliance, independent of CLI policy and UI.
use eyre::Context as _;
use libvm::{
    ExecutionOutput, Forward, ImagePullPolicy, ImageResolveOptions, MachineData, MachineReadiness,
    MachineRef, MachineRetention, MachineRunId, MachineStart, MachineStartOptions,
    MachineStopOptions, MachineUpdate, Memory, ProcessConfig, ResolvedOciImage, Runtime,
    RuntimeConfig,
};
use silod_spec::labels::{INSTALLATION_LABEL, MANAGED_ROLE, MANAGED_ROLE_LABEL};
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct SystemRuntime {
    runtime: Runtime,
}

impl SystemRuntime {
    pub(crate) async fn connect(config: RuntimeConfig) -> eyre::Result<Self> {
        Ok(Self {
            runtime: Runtime::new(config)
                .await
                .context("initialize local libvm adapter")?,
        })
    }

    pub(crate) async fn list_machines(&mut self) -> eyre::Result<Vec<MachineData>> {
        let machines = self.runtime.list_machines().await?;
        let mut data = Vec::with_capacity(machines.len());
        for machine in machines {
            data.push(machine.inspect().await?);
        }
        Ok(data)
    }

    pub(crate) async fn inspect_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        Ok(self.machine(reference).await?.inspect().await?)
    }

    pub(crate) async fn update_system_machine(
        &mut self,
        reference: &str,
        update: MachineUpdate,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        machine.inner.update(update).await.map_err(Into::into)
    }

    /// Stops the daemon-managed system machine. Bypasses the ordinary-mutation guard,
    /// which exists to keep `silo stop`/`rm` away from that machine; callers here are
    /// the daemon lifecycle paths that own it.
    pub(crate) async fn stop_system_machine(
        &mut self,
        reference: &str,
        timeout: Duration,
    ) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let data = machine.inspect().await?;
        if !data.is_running() {
            return Ok(data);
        }
        machine
            .inner
            .stop_with(MachineStopOptions::new().timeout(timeout))
            .await?;
        Ok(machine.inspect().await?)
    }

    pub(crate) async fn remove_machine(&mut self, reference: &str) -> eyre::Result<MachineData> {
        let machine = self.machine(reference).await?;
        let data = machine.inspect().await?;
        machine.inner.remove().await?;
        Ok(data)
    }

    pub(crate) async fn machine(&mut self, reference: &str) -> eyre::Result<SystemMachine> {
        let reference = MachineRef::parse(reference)?;
        Ok(SystemMachine {
            inner: self.runtime.get_machine(&reference).await?,
        })
    }

    pub(crate) async fn ensure_name_available(&mut self, name: &str) -> eyre::Result<()> {
        let reference = MachineRef::parse(name)?;
        match self.runtime.get_machine(&reference).await {
            Ok(_) => eyre::bail!("machine {name:?} already exists"),
            Err(libvm::LibVmError::MachineNotFound { .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Resolves `reference` without materializing it. `Always` asks the registry
    /// which manifest a tag currently names.
    pub(crate) async fn resolve_image(
        &mut self,
        reference: &str,
        policy: ImagePullPolicy,
    ) -> eyre::Result<ResolvedOciImage> {
        Ok(self
            .runtime
            .images()
            .resolve_with(
                reference.to_string(),
                ImageResolveOptions {
                    policy: Some(policy),
                },
            )
            .await?)
    }

    pub(crate) async fn create_system_machine(
        &mut self,
        name: &str,
        config: &crate::config::ResolvedSystemConfig,
        installation_id: uuid::Uuid,
        data_image: &std::path::Path,
        image: ResolvedOciImage,
    ) -> eyre::Result<MachineData> {
        use libvm::{ForwardAddress, ForwardEndpoint};
        use vm_spec::Mount;

        let mounts = config
            .shares
            .iter()
            .map(|share| Mount {
                source: share.path.clone(),
                tag: share.path.to_string_lossy().into_owned(),
                read_only: share.read_only,
            })
            .collect();
        let forward = Forward::new(
            ForwardEndpoint::host(ForwardAddress::unix(config.docker_socket.clone())),
            ForwardEndpoint::guest(ForwardAddress::unix("/run/docker.sock")),
        )
        .with_name("docker");
        forward.validate()?;
        let machine = self
            .runtime
            .machine()
            .name(name)
            .resolved_image(image)
            .label(MANAGED_ROLE_LABEL, MANAGED_ROLE)
            .label(INSTALLATION_LABEL, installation_id.to_string())
            .retention(MachineRetention::Persistent)
            .process(ProcessConfig::default())
            .cpus(config.cpus)
            .memory(Memory::bytes(config.memory_bytes))
            .root_disk_size(config.root_size_bytes)
            .disks(vec![data_image.to_path_buf()])
            .rosetta(config.rosetta)
            .mounts(mounts)
            .forwards(vec![forward])
            .network(|network| network.private().publish(config.publish_bind))
            .create()
            .await?;
        Ok(machine.inspect().await?)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SystemMachine {
    inner: libvm::Machine,
}
impl SystemMachine {
    pub(crate) async fn inspect(&self) -> Result<MachineData, libvm::LibVmError> {
        self.inner.inspect().await
    }

    pub(crate) async fn start_with_options(
        &self,
        options: MachineStartOptions,
    ) -> Result<MachineStart, libvm::LibVmError> {
        self.inner.start_with_options(options).await
    }

    pub(crate) async fn wait_ready(
        &self,
        timeout: std::time::Duration,
    ) -> Result<MachineReadiness, libvm::LibVmError> {
        self.inner.wait_ready(timeout).await
    }

    /// Stops exactly `run_id`, as started by the caller.
    pub(crate) async fn stop_run(
        &self,
        run_id: MachineRunId,
    ) -> Result<MachineData, libvm::LibVmError> {
        self.inner.stop_run_with(run_id, stop_options()).await
    }

    /// Stops whichever run is current. The supervisor owns the system VM outright,
    /// so shutdown must not depend on having observed the run that is live now.
    pub(crate) async fn stop(&self) -> Result<MachineData, libvm::LibVmError> {
        self.inner.stop_with(stop_options()).await
    }

    pub(crate) async fn exec_with_input(
        &self,
        program: &str,
        args: &[&str],
        user: &str,
        input: Vec<u8>,
        timeout: std::time::Duration,
    ) -> Result<ExecutionOutput, libvm::LibVmError> {
        self.inner
            .exec_with(program, |options| {
                options
                    .args(args.iter().copied())
                    .user(user)
                    .stdin_bytes(input)
                    .timeout(timeout)
            })
            .await
    }

    pub(crate) async fn metrics(&self) -> Result<libvm::MachineMetrics, libvm::LibVmError> {
        self.inner.metrics().await
    }
}

// silo-vmm can spend 45s stopping the backend, then drain its services. Give that
// sequence room to finish before escalating a stuck monitor.
fn stop_options() -> MachineStopOptions {
    MachineStopOptions::new()
        .timeout(Duration::from_secs(60))
        .force_after_timeout(Duration::from_secs(5))
}
