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
    pub root_profile: libvm::RootProfile,
    pub temporary_directory: libvm::TemporaryDirectoryPolicy,
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
            .root_profile(self.root_profile)
            .temporary_directory(self.temporary_directory)
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
