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
        let machines = self.runtime.inventory().await?;
        let mut data = Vec::with_capacity(machines.len());
        for machine in machines {
            match machine.data {
                Some(snapshot) => data.push(snapshot),
                None => eprintln!(
                    "machine {} ({}) configuration unavailable: {:?}; inspect with silo show",
                    machine.name, machine.id, machine.issues
                ),
            }
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

#[cfg(test)]
mod tests {
    use crate::runtime::SystemRuntime;
    use libvm::{MachineStartOptions, NetworkPolicy, RuntimeConfig};

    #[tokio::test]
    async fn real_vm_starts_bearer_policy_from_default_home_store() {
        if std::env::var("SILO_E2E_KVM").as_deref() != Ok("1") {
            eprintln!("SKIPPED: SILO_E2E_KVM=1 is required for the silod real-VM secret test");
            return;
        }
        assert!(
            std::path::Path::new("/dev/kvm").exists(),
            "SILO_E2E_KVM=1 requires /dev/kvm"
        );
        let root = match std::env::var_os("SILO_TEST_RUNTIME_ROOT") {
            Some(root) => root,
            None => {
                eprintln!("SKIPPED: SILO_TEST_RUNTIME_ROOT is required");
                return;
            }
        };
        let image = match std::env::var("SILO_TEST_IMAGE") {
            Ok(image) => image,
            Err(_) => {
                eprintln!("SKIPPED: SILO_TEST_IMAGE is required");
                return;
            }
        };
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("secrets.json"),
            br#"{"bearer_token.api.token":{"type":"plain","value":"synthetic-silod-secret"}}"#,
        )
        .unwrap();
        let mut service =
            SystemRuntime::connect(RuntimeConfig::local(home.path()).with_runtime_root(root))
                .await
                .unwrap();
        let policy = NetworkPolicy::from_json_str(r#"{"version":1,"endpoints":[{"name":"api","kind":"https","family":"http","transport":"https-mitm","tls":"terminate","capabilities":["credential-injection"],"hosts":["example.com"]}],"credentials":[{"name":"api","kind":"bearer_token","endpoint":"api"}],"rules":[{"endpoints":["api"],"credential":"api","verdict":"allow"}]}"#).unwrap();
        let created = service
            .runtime
            .machine()
            .name("silod-secret-e2e")
            .image(image)
            .vsock(true)
            .network(|network| network.private().policy(policy))
            .create()
            .await
            .unwrap();
        let machine = service.machine(&created.id()).await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(180), async {
            machine
                .start_with_options(MachineStartOptions::new())
                .await?;
            machine.wait_ready(std::time::Duration::from_secs(90)).await
        })
        .await;
        let stopped = machine.stop().await;
        let removed = service.remove_machine(&created.id()).await;
        assert_eq!(
            result.unwrap().unwrap().outcome,
            libvm::MachineReadinessOutcome::Ready
        );
        stopped.unwrap();
        removed.unwrap();
    }
}
