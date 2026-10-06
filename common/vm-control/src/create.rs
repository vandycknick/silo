//! Native creation settings shared by local and daemon management adapters.
//!
//! Source selection, template expansion, host-user selection and policy lookup
//! happen before this boundary. Applying these settings does not resolve an
//! image or create a machine; those remain native builder operations.

use std::collections::BTreeMap;
use std::path::PathBuf;

use libvm::{
    Forward, LibVmError, MachineAgent, MachineBuilder, MachineNetworkBuilder, MachineRetention,
    MachineUserConfig, Memory, NetworkPolicy, ProcessConfig, PublishBind,
};
use vm_spec::Mount;

/// A network attachment whose policy has already been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedNetwork {
    Private {
        policy: Option<NetworkPolicy>,
        publish: Option<PublishBind>,
    },
    None,
    Named {
        name: String,
    },
}

impl ResolvedNetwork {
    pub fn apply(self, builder: MachineNetworkBuilder) -> MachineNetworkBuilder {
        match self {
            Self::Private { policy, publish } => {
                let mut builder = builder.private();
                if let Some(policy) = policy {
                    builder = builder.policy(policy);
                }
                if let Some(publish) = publish {
                    builder = builder.publish(publish);
                }
                builder
            }
            Self::None => builder.none(),
            Self::Named { name } => builder.named(name),
        }
    }
}

/// Fully normalized creation settings, independent of image materialization.
///
/// Optional settings retain native defaults when absent. In particular, an
/// absent network is different from an explicit `ResolvedNetwork::None`, and
/// process entrypoint/command retain their absent versus present-empty values.
#[derive(Debug, Clone)]
pub struct NormalizedMachineCreate {
    pub name: Option<String>,
    pub template_name: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub process: ProcessConfig,
    pub retention: MachineRetention,
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    pub kernel_args: Vec<String>,
    pub nested_virtualization: bool,
    pub rosetta: bool,
    pub disks: Vec<PathBuf>,
    pub mounts: Vec<Mount>,
    pub forwards: Vec<Forward>,
    pub vsock: Option<bool>,
    pub cpus: Option<u8>,
    pub memory_bytes: Option<u64>,
    pub root_disk_size_bytes: Option<u64>,
    pub userdata: Option<String>,
    pub network: Option<ResolvedNetwork>,
    pub agent: MachineAgent,
    pub provision_user: Option<MachineUserConfig>,
}

impl NormalizedMachineCreate {
    /// Applies native setters once, leaving the builder's prepared source intact.
    /// Native creation remains responsible for validating the resulting request.
    pub fn apply_to_builder(
        self,
        mut builder: MachineBuilder,
    ) -> Result<MachineBuilder, LibVmError> {
        if let Some(name) = self.name {
            builder = builder.name(name);
        }
        builder = builder
            .labels(self.labels)
            .process(self.process)
            .retention(self.retention)
            .template_name(self.template_name)
            .kernel_args(self.kernel_args)
            .nested_virtualization(self.nested_virtualization)
            .rosetta(self.rosetta)
            .disks(self.disks)
            .mounts(self.mounts)
            .forwards(self.forwards);
        if let Some(vsock) = self.vsock {
            builder = builder.vsock(vsock);
        }
        if let Some(cpus) = self.cpus {
            builder = builder.cpus(cpus);
        }
        if let Some(bytes) = self.memory_bytes {
            builder = builder.memory(Memory::bytes(bytes));
        }
        if let Some(bytes) = self.root_disk_size_bytes {
            builder = builder.root_disk_size(bytes);
        }
        if let Some(userdata) = self.userdata {
            builder = builder.userdata(userdata);
        }
        if let Some(network) = self.network {
            builder = builder.network(|builder| network.apply(builder));
        }
        if let Some(kernel) = self.kernel {
            builder = builder.kernel(kernel);
        }
        if let Some(initramfs) = self.initramfs {
            builder = builder.initramfs(initramfs);
        }
        let agent = self.agent;
        builder = builder.guest(|guest| {
            let guest = match &agent {
                MachineAgent::Default => guest,
                MachineAgent::Custom { path } => guest.agent(Some(path.clone())),
                MachineAgent::Disabled => guest.agent(None),
                _ => guest,
            };
            match self.provision_user {
                Some(user) => guest.user(user),
                None => guest,
            }
        });
        Ok(builder.agent_mode(Some(agent)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use libvm::{
        ImageSource, MachineAgent, MachineNetworkConfig, MachineRetention, MachineUserConfig,
        ProcessConfig, Runtime, RuntimeConfig,
    };

    use crate::create::{NormalizedMachineCreate, ResolvedNetwork};

    async fn runtime(root: &Path) -> Runtime {
        let components = root.join("runtime");
        for (name, executable) in [
            ("bin/silo-vmm", true),
            ("bin/netd", true),
            ("assets/kernel-default", false),
            ("assets/initramfs", false),
            ("assets/agent", true),
        ] {
            let path = components.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"component").unwrap();
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
            )
            .unwrap();
        }
        Runtime::new(RuntimeConfig::local(root.join("home")).with_runtime_root(components))
            .await
            .unwrap()
    }

    fn settings(name: &str) -> NormalizedMachineCreate {
        NormalizedMachineCreate {
            name: Some(name.into()),
            template_name: None,
            labels: BTreeMap::new(),
            process: ProcessConfig::default(),
            retention: MachineRetention::Persistent,
            kernel: None,
            initramfs: None,
            kernel_args: Vec::new(),
            nested_virtualization: false,
            rosetta: false,
            disks: Vec::new(),
            mounts: Vec::new(),
            forwards: Vec::new(),
            vsock: None,
            cpus: None,
            memory_bytes: None,
            root_disk_size_bytes: None,
            userdata: None,
            network: None,
            agent: MachineAgent::Default,
            provision_user: None,
        }
    }

    #[tokio::test]
    async fn normalized_create_preserves_process_agent_user_and_prepared_disk() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path()).await;
        let disk = root.path().join("root.raw");
        std::fs::write(&disk, b"root-disk").unwrap();
        let mut normalized = settings("normalized");
        normalized.template_name = Some("fixture".into());
        normalized.labels.insert("owner".into(), "alice".into());
        normalized.process.entrypoint = Some(Vec::new());
        normalized.process.command = Some(vec!["exact argument".into(), "".into()]);
        normalized.agent = MachineAgent::Disabled;
        normalized.network = Some(ResolvedNetwork::None);
        let user = MachineUserConfig::new("alice", 1000, 1000, "/home/alice");
        normalized.provision_user = Some(user.clone());
        let expected_process = normalized.process.clone();
        let expected_labels = normalized.labels.clone();
        let machine = normalized
            .apply_to_builder(runtime.machine().image_source(ImageSource::disk(&disk)))
            .unwrap()
            .create()
            .await
            .unwrap();
        let data = machine.inspect().await.unwrap();
        assert_eq!(data.process, expected_process);
        assert_eq!(data.labels, expected_labels);
        assert_eq!(data.template_name.as_deref(), Some("fixture"));
        assert_eq!(data.agent_mode, Some(MachineAgent::Disabled));
        assert_eq!(data.guest.agent, MachineAgent::Disabled);
        assert_eq!(data.guest.user, Some(user));
        assert_eq!(data.network, MachineNetworkConfig::None);
        let rootfs = data.rootfs.unwrap();
        assert_eq!(std::fs::read(rootfs.root_disk_path).unwrap(), b"root-disk");
    }

    #[tokio::test]
    async fn absent_network_and_process_lists_retain_native_defaults() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime(root.path()).await;
        let disk = root.path().join("root.raw");
        std::fs::write(&disk, b"root-disk").unwrap();
        let machine = settings("defaults")
            .apply_to_builder(runtime.machine().image_source(ImageSource::disk(&disk)))
            .unwrap()
            .create()
            .await
            .unwrap();
        let data = machine.inspect().await.unwrap();
        assert_eq!(data.process.entrypoint, None);
        assert_eq!(data.process.command, None);
        assert_eq!(data.network, MachineNetworkConfig::default());
        assert_eq!(data.agent_mode, Some(MachineAgent::Default));
        assert_eq!(data.retention, MachineRetention::Persistent);
    }
}
