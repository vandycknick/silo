use crate::create::{NormalizedMachineCreate, ResolvedNetwork};
use crate::values::*;
use crate::{invalid, path_from_wire, path_to_wire, required, ConversionError};
use silod_spec::daemon::v1 as w;
pub fn cpu_from_wire(v: u32) -> Result<u8, ConversionError> {
    if v == 0 {
        return Err(invalid("cpus", "must be positive"));
    }
    v.try_into().map_err(|_| invalid("cpus", "overflow"))
}
pub fn memory_from_wire(v: u64) -> Result<libvm::Memory, ConversionError> {
    if v == 0 || v.div_ceil(1024 * 1024) > u32::MAX as u64 {
        return Err(invalid("memory_bytes", "outside native range"));
    }
    Ok(libvm::Memory::bytes(v))
}
pub fn update_from_wire(v: w::MachineUpdate) -> Result<libvm::MachineUpdate, ConversionError> {
    let mut out = libvm::MachineUpdate::new();
    out.name = v.name;
    out.labels = v.labels.map(|v| v.values);
    out.cpus = v.cpus.map(cpu_from_wire).transpose()?;
    out.memory = v.memory_bytes.map(memory_from_wire).transpose()?;
    out.root_disk_size = v.root_disk_size_bytes;
    out.nested_virtualization = v.nested_virtualization;
    out.rosetta = v.rosetta;
    out.forwards = v
        .forwards
        .map(|v| v.values.into_iter().map(forward_from_wire).collect())
        .transpose()?;
    out.vsock = v.vsock.map(vsock_from_wire).transpose()?;
    out.network = v.network.map(network_from_wire).transpose()?;
    out.guest = v.guest.map(guest_from_wire).transpose()?;
    out.network_policy = v
        .policy
        .map(|v| match required(v.update, "policy.update")? {
            w::policy_update::Update::Set(v) => {
                Ok::<_, ConversionError>(libvm::NetworkPolicyUpdate::Set(policy_from_wire(&v)?))
            }
            w::policy_update::Update::Clear(()) => Ok(libvm::NetworkPolicyUpdate::Clear),
        })
        .transpose()?;
    out.guest_publish = v
        .publication
        .map(|v| match required(v.update, "publication.update")? {
            w::publication_update::Update::Set(v) => {
                Ok::<_, ConversionError>(libvm::GuestPublishUpdate::Set(publish_from_wire(v)?))
            }
            w::publication_update::Update::Clear(()) => Ok(libvm::GuestPublishUpdate::Clear),
        })
        .transpose()?;
    out.user = v
        .user
        .map(|v| match required(v.update, "user.update")? {
            w::user_update::Update::Set(v) => {
                Ok::<_, ConversionError>(libvm::MachineUserUpdate::Set(user_from_wire(v)))
            }
            w::user_update::Update::Clear(()) => Ok(libvm::MachineUserUpdate::Clear),
        })
        .transpose()?;
    Ok(out)
}
pub fn update_to_wire(v: &libvm::MachineUpdate) -> Result<w::MachineUpdate, ConversionError> {
    v.validate_network()
        .map_err(|_| invalid("update.network", "invalid native network selection"))?;
    Ok(w::MachineUpdate {
        name: v.name.clone(),
        labels: v.labels.clone().map(|values| w::StringMap { values }),
        cpus: v.cpus.map(u32::from),
        memory_bytes: v.memory.map(|v| v.as_bytes()),
        root_disk_size_bytes: v.root_disk_size,
        nested_virtualization: v.nested_virtualization,
        rosetta: v.rosetta,
        forwards: v.forwards.as_ref().map(|v| w::ForwardList {
            values: v.iter().map(forward_to_wire).collect(),
        }),
        vsock: v.vsock.as_ref().map(vsock_to_wire),
        network: v.network.as_ref().map(network_to_wire).transpose()?,
        guest: v.guest.as_ref().map(guest_to_wire).transpose()?,
        policy: v
            .network_policy
            .as_ref()
            .map(|v| {
                Ok(w::PolicyUpdate {
                    update: Some(match v {
                        libvm::NetworkPolicyUpdate::Set(v) => {
                            w::policy_update::Update::Set(policy_to_wire(v)?)
                        }
                        libvm::NetworkPolicyUpdate::Clear => w::policy_update::Update::Clear(()),
                        _ => return Err(invalid("policy", "unsupported native variant")),
                    }),
                })
            })
            .transpose()?,
        publication: v
            .guest_publish
            .as_ref()
            .map(|v| {
                Ok(w::PublicationUpdate {
                    update: Some(match v {
                        libvm::GuestPublishUpdate::Set(v) => {
                            w::publication_update::Update::Set(publish_to_wire(*v))
                        }
                        libvm::GuestPublishUpdate::Clear => {
                            w::publication_update::Update::Clear(())
                        }
                        _ => return Err(invalid("publication", "unsupported native variant")),
                    }),
                })
            })
            .transpose()?,
        user: v
            .user
            .as_ref()
            .map(|v| {
                Ok(w::UserUpdate {
                    update: Some(match v {
                        libvm::MachineUserUpdate::Set(v) => {
                            w::user_update::Update::Set(user_to_wire(v))
                        }
                        libvm::MachineUserUpdate::Clear => w::user_update::Update::Clear(()),
                        _ => return Err(invalid("user", "unsupported native variant")),
                    }),
                })
            })
            .transpose()?,
    })
}
fn resolved_to_wire(v: &ResolvedNetwork) -> Result<w::ResolvedNetwork, ConversionError> {
    use w::resolved_network::Attachment;
    Ok(w::ResolvedNetwork {
        attachment: Some(match v {
            ResolvedNetwork::None => Attachment::None(()),
            ResolvedNetwork::Named { name } => Attachment::Named(w::Name { name: name.clone() }),
            ResolvedNetwork::Private { policy, publish } => {
                Attachment::Private(w::PrivateNetwork {
                    policy_json: policy.as_ref().map(policy_to_wire).transpose()?,
                    publish: publish.map(publish_to_wire),
                })
            }
        }),
    })
}

pub fn create_to_wire(
    v: &NormalizedMachineCreate,
) -> Result<w::NormalizedMachineCreate, ConversionError> {
    Ok(w::NormalizedMachineCreate {
        name: v.name.clone(),
        template_name: v.template_name.clone(),
        labels: v.labels.clone(),
        process: Some(process_to_wire(&v.process)),
        retention: retention_to_wire(v.retention),
        kernel: v.kernel.as_deref().map(path_to_wire),
        initramfs: v.initramfs.as_deref().map(path_to_wire),
        kernel_args: v.kernel_args.clone(),
        nested_virtualization: v.nested_virtualization,
        rosetta: v.rosetta,
        disks: v.disks.iter().map(|v| path_to_wire(v)).collect(),
        mounts: v.mounts.iter().map(mount_to_wire).collect(),
        forwards: v.forwards.iter().map(forward_to_wire).collect(),
        vsock: v.vsock,
        cpus: v.cpus.map(u32::from),
        memory_bytes: v.memory_bytes,
        root_disk_size_bytes: v.root_disk_size_bytes,
        userdata: v.userdata.clone(),
        network: v.network.as_ref().map(resolved_to_wire).transpose()?,
        agent: Some(agent_to_wire(&v.agent)?),
        provision_user: v.provision_user.as_ref().map(user_to_wire),
    })
}
pub fn create_from_wire(
    v: w::NormalizedMachineCreate,
) -> Result<NormalizedMachineCreate, ConversionError> {
    Ok(NormalizedMachineCreate {
        name: v.name,
        template_name: v.template_name,
        labels: v.labels,
        process: process_from_wire(required(v.process, "create.process")?),
        retention: retention_from_wire(v.retention)?,
        kernel: v.kernel.map(path_from_wire).transpose()?,
        initramfs: v.initramfs.map(path_from_wire).transpose()?,
        kernel_args: v.kernel_args,
        nested_virtualization: v.nested_virtualization,
        rosetta: v.rosetta,
        disks: v
            .disks
            .into_iter()
            .map(path_from_wire)
            .collect::<Result<_, _>>()?,
        mounts: v
            .mounts
            .into_iter()
            .map(mount_from_wire)
            .collect::<Result<_, _>>()?,
        forwards: v
            .forwards
            .into_iter()
            .map(forward_from_wire)
            .collect::<Result<_, _>>()?,
        vsock: v.vsock,
        cpus: v.cpus.map(cpu_from_wire).transpose()?,
        memory_bytes: v
            .memory_bytes
            .map(|v| memory_from_wire(v).map(|v| v.as_bytes()))
            .transpose()?,
        root_disk_size_bytes: v.root_disk_size_bytes,
        userdata: v.userdata,
        network: v
            .network
            .map(|v| {
                Ok(match network_from_wire(v)? {
                    libvm::MachineNetworkConfig::None => ResolvedNetwork::None,
                    libvm::MachineNetworkConfig::Named { name } => ResolvedNetwork::Named { name },
                    libvm::MachineNetworkConfig::Private { policy, publish } => {
                        ResolvedNetwork::Private {
                            policy,
                            publish: publish.map(|v| v.bind),
                        }
                    }
                    _ => return Err(invalid("network", "unsupported native variant")),
                })
            })
            .transpose()?,
        agent: agent_from_wire(required(v.agent, "create.agent")?)?,
        provision_user: v.provision_user.map(user_from_wire),
    })
}
