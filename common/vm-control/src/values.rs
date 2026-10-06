use crate::{invalid, path_from_wire, path_to_wire, required, ConversionError};
use silod_spec::daemon::v1 as w;

pub fn process_to_wire(v: &libvm::ProcessConfig) -> w::ProcessConfig {
    w::ProcessConfig {
        entrypoint: v
            .entrypoint
            .as_ref()
            .map(|x| w::StringList { values: x.clone() }),
        command: v
            .command
            .as_ref()
            .map(|x| w::StringList { values: x.clone() }),
        environment: v.environment.clone(),
        working_directory: v.working_directory.clone(),
        user: v.user.clone(),
    }
}
pub fn process_from_wire(v: w::ProcessConfig) -> libvm::ProcessConfig {
    libvm::ProcessConfig {
        entrypoint: v.entrypoint.map(|x| x.values),
        command: v.command.map(|x| x.values),
        environment: v.environment,
        working_directory: v.working_directory,
        user: v.user,
    }
}
pub fn user_to_wire(v: &libvm::MachineUserConfig) -> w::User {
    w::User {
        name: v.name.clone(),
        uid: v.uid,
        gid: v.gid,
        home: v.home.clone(),
    }
}
pub fn user_from_wire(v: w::User) -> libvm::MachineUserConfig {
    libvm::MachineUserConfig {
        name: v.name,
        uid: v.uid,
        gid: v.gid,
        home: v.home,
    }
}
pub fn agent_to_wire(v: &libvm::MachineAgent) -> Result<w::Agent, ConversionError> {
    use w::agent::Mode;
    Ok(w::Agent {
        mode: Some(match v {
            libvm::MachineAgent::Default => Mode::DefaultAgent(()),
            libvm::MachineAgent::Disabled => Mode::None(()),
            libvm::MachineAgent::Custom { path } => Mode::CustomPath(path_to_wire(path)),
            _ => return Err(invalid("agent", "unsupported native variant")),
        }),
    })
}
pub fn agent_from_wire(v: w::Agent) -> Result<libvm::MachineAgent, ConversionError> {
    use w::agent::Mode;
    Ok(match required(v.mode, "agent.mode")? {
        Mode::DefaultAgent(()) => libvm::MachineAgent::Default,
        Mode::None(()) => libvm::MachineAgent::Disabled,
        Mode::CustomPath(p) => libvm::MachineAgent::Custom {
            path: path_from_wire(p)?,
        },
    })
}
pub fn guest_to_wire(v: &libvm::MachineGuestConfig) -> Result<w::GuestConfig, ConversionError> {
    Ok(w::GuestConfig {
        agent: Some(agent_to_wire(&v.agent)?),
        user: v.user.as_ref().map(user_to_wire),
    })
}
pub fn guest_from_wire(v: w::GuestConfig) -> Result<libvm::MachineGuestConfig, ConversionError> {
    Ok(libvm::MachineGuestConfig {
        agent: agent_from_wire(required(v.agent, "guest.agent")?)?,
        user: v.user.map(user_from_wire),
    })
}
pub fn retention_to_wire(v: libvm::MachineRetention) -> i32 {
    match v {
        libvm::MachineRetention::Persistent => 1,
        libvm::MachineRetention::Ephemeral => 2,
    }
}
pub fn retention_from_wire(v: i32) -> Result<libvm::MachineRetention, ConversionError> {
    match v {
        1 => Ok(libvm::MachineRetention::Persistent),
        2 => Ok(libvm::MachineRetention::Ephemeral),
        _ => Err(invalid("retention", "invalid enum")),
    }
}
pub fn mount_to_wire(v: &vm_spec::Mount) -> w::Mount {
    w::Mount {
        source: path_to_wire(&v.source),
        tag: v.tag.clone(),
        read_only: v.read_only,
    }
}
pub fn mount_from_wire(v: w::Mount) -> Result<vm_spec::Mount, ConversionError> {
    Ok(vm_spec::Mount {
        source: path_from_wire(v.source)?,
        tag: v.tag,
        read_only: v.read_only,
    })
}
pub fn vsock_to_wire(v: &vm_spec::Vsock) -> w::Vsock {
    w::Vsock {
        enabled: v.enabled,
        uds: v.uds.as_deref().map(path_to_wire),
    }
}
pub fn vsock_from_wire(v: w::Vsock) -> Result<vm_spec::Vsock, ConversionError> {
    Ok(vm_spec::Vsock {
        enabled: v.enabled,
        uds: v.uds.map(path_from_wire).transpose()?,
    })
}
fn address_to_wire(v: &forward_spec::Address) -> w::Address {
    use w::address::Address;
    w::Address {
        address: Some(match v {
            forward_spec::Address::Tcp(v) => Address::Tcp(v.to_string()),
            forward_spec::Address::Unix(v) => Address::Unix(path_to_wire(v)),
        }),
    }
}
fn address_from_wire(v: w::Address) -> Result<forward_spec::Address, ConversionError> {
    use w::address::Address;
    Ok(match required(v.address, "address")? {
        Address::Tcp(v) => forward_spec::Address::Tcp(
            v.parse()
                .map_err(|_| invalid("address.tcp", "invalid socket address"))?,
        ),
        Address::Unix(v) => forward_spec::Address::Unix(path_from_wire(v)?),
    })
}
fn endpoint_to_wire(v: &forward_spec::Endpoint) -> w::Endpoint {
    use w::endpoint::Endpoint;
    w::Endpoint {
        endpoint: Some(match v {
            forward_spec::Endpoint::Host(v) => Endpoint::Host(address_to_wire(v)),
            forward_spec::Endpoint::Guest(v) => Endpoint::Guest(address_to_wire(v)),
            forward_spec::Endpoint::Vsock(v) => Endpoint::Vsock(*v),
        }),
    }
}
fn endpoint_from_wire(v: w::Endpoint) -> Result<forward_spec::Endpoint, ConversionError> {
    use w::endpoint::Endpoint;
    Ok(match required(v.endpoint, "endpoint")? {
        Endpoint::Host(v) => forward_spec::Endpoint::Host(address_from_wire(v)?),
        Endpoint::Guest(v) => forward_spec::Endpoint::Guest(address_from_wire(v)?),
        Endpoint::Vsock(v) => forward_spec::Endpoint::Vsock(v),
    })
}
pub fn forward_to_wire(v: &forward_spec::Forward) -> w::Forward {
    w::Forward {
        name: v.name.clone(),
        listen: Some(endpoint_to_wire(&v.listen)),
        connect: Some(endpoint_to_wire(&v.connect)),
        unix_mode: v.mode.map(u32::from),
    }
}
pub fn forward_from_wire(v: w::Forward) -> Result<forward_spec::Forward, ConversionError> {
    Ok(forward_spec::Forward {
        name: v.name,
        listen: endpoint_from_wire(required(v.listen, "forward.listen")?)?,
        connect: endpoint_from_wire(required(v.connect, "forward.connect")?)?,
        mode: v
            .unix_mode
            .map(|v| {
                v.try_into()
                    .map_err(|_| invalid("forward.mode", "invalid Unix mode"))
            })
            .transpose()?,
    })
}
pub fn publish_to_wire(v: libvm::PublishBind) -> i32 {
    match v {
        libvm::PublishBind::Loopback => 1,
        libvm::PublishBind::Any => 2,
    }
}
pub fn publish_from_wire(v: i32) -> Result<libvm::PublishBind, ConversionError> {
    match v {
        1 => Ok(libvm::PublishBind::Loopback),
        2 => Ok(libvm::PublishBind::Any),
        _ => Err(invalid("publish", "invalid enum")),
    }
}
pub fn policy_to_wire(v: &libvm::NetworkPolicy) -> Result<String, ConversionError> {
    serde_json::to_string(v).map_err(|_| invalid("policy", "cannot encode canonical policy"))
}
pub fn policy_from_wire(v: &str) -> Result<libvm::NetworkPolicy, ConversionError> {
    libvm::NetworkPolicy::from_json_str(v)
        .map_err(|_| invalid("policy", "invalid canonical policy"))
}
pub fn network_to_wire(
    v: &libvm::MachineNetworkConfig,
) -> Result<w::ResolvedNetwork, ConversionError> {
    use w::resolved_network::Attachment;
    Ok(w::ResolvedNetwork {
        attachment: Some(match v {
            libvm::MachineNetworkConfig::None => Attachment::None(()),
            libvm::MachineNetworkConfig::Named { name } => {
                Attachment::Named(w::Name { name: name.clone() })
            }
            libvm::MachineNetworkConfig::Private { policy, publish } => {
                Attachment::Private(w::PrivateNetwork {
                    policy_json: policy.as_ref().map(policy_to_wire).transpose()?,
                    publish: publish.map(|x| publish_to_wire(x.bind)),
                })
            }
            _ => return Err(invalid("network", "unsupported native variant")),
        }),
    })
}
pub fn network_from_wire(
    v: w::ResolvedNetwork,
) -> Result<libvm::MachineNetworkConfig, ConversionError> {
    use w::resolved_network::Attachment;
    Ok(match required(v.attachment, "network.attachment")? {
        Attachment::None(()) => libvm::MachineNetworkConfig::None,
        Attachment::Named(v) => libvm::MachineNetworkConfig::Named { name: v.name },
        Attachment::Private(v) => libvm::MachineNetworkConfig::Private {
            policy: v.policy_json.as_deref().map(policy_from_wire).transpose()?,
            publish: v
                .publish
                .map(publish_from_wire)
                .transpose()?
                .map(|bind| libvm::GuestPublish { bind }),
        },
    })
}
