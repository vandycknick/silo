use crate::snapshots::{snapshot_from_wire, snapshot_to_wire};
use crate::{invalid, required, ConversionError};
use silod_spec::daemon::v1 as w;
pub fn entrypoint_to_wire(v: &libvm::Entrypoint) -> w::Entrypoint {
    w::Entrypoint {
        program: v.program().into(),
        args: v.arguments().to_vec(),
        cwd: v.working_directory().map(str::to_owned),
        environment: v
            .environment()
            .iter()
            .map(|(name, value)| w::EnvironmentPair {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        user: v.user_selector().map(str::to_owned),
    }
}
pub fn entrypoint_from_wire(v: w::Entrypoint) -> Result<libvm::Entrypoint, ConversionError> {
    if v.program.is_empty() || v.program.contains('\0') || v.args.iter().any(|v| v.contains('\0')) {
        return Err(invalid("entrypoint", "invalid program or argv"));
    }
    let mut out = libvm::Entrypoint::new(v.program).args(v.args);
    if let Some(v) = v.cwd {
        out = out.cwd(v);
    }
    if let Some(v) = v.user {
        out = out.user(v);
    }
    Ok(out.envs(v.environment.into_iter().map(|v| (v.name, v.value))))
}
/// Cleanup intent is transport data; the backend supplies its own trusted hook.
#[derive(Clone)]
pub struct StartOptions {
    pub cleanup_on_exit: bool,
    pub credentials: libvm::EgressCredentials,
    pub entrypoint: Option<libvm::Entrypoint>,
}
pub fn start_options_to_wire(v: &StartOptions) -> w::StartOptions {
    w::StartOptions {
        cleanup_on_exit: v.cleanup_on_exit,
        egress_secrets: v
            .credentials
            .secrets
            .iter()
            .map(|v| w::EgressSecret {
                slot: v.slot.clone(),
                value: v.value.clone(),
            })
            .collect(),
        entrypoint: v.entrypoint.as_ref().map(entrypoint_to_wire),
    }
}
pub fn start_options_from_wire(v: w::StartOptions) -> Result<StartOptions, ConversionError> {
    {
        let mut slots = std::collections::HashSet::with_capacity(v.egress_secrets.len());
        for secret in &v.egress_secrets {
            if secret.slot.is_empty()
                || secret.slot.contains('\0')
                || secret.value.len() > 16 * 1024
                || !slots.insert(secret.slot.as_str())
            {
                return Err(invalid(
                    "egress_secrets",
                    "invalid slot, size, or duplicate",
                ));
            }
        }
    }
    let mut credentials = libvm::EgressCredentials::new();
    credentials.secrets.reserve(v.egress_secrets.len());
    for secret in v.egress_secrets {
        credentials = credentials.secret_bytes(secret.slot, secret.value);
    }
    Ok(StartOptions {
        cleanup_on_exit: v.cleanup_on_exit,
        credentials,
        entrypoint: v.entrypoint.map(entrypoint_from_wire).transpose()?,
    })
}
pub fn start_to_wire(v: &libvm::MachineStart) -> Result<w::MachineStart, ConversionError> {
    Ok(w::MachineStart {
        run_id: v.run_id.to_string(),
        data: Some(snapshot_to_wire(&v.machine)?),
    })
}
pub fn start_from_wire(v: w::MachineStart) -> Result<libvm::MachineStart, ConversionError> {
    let run = v
        .run_id
        .parse()
        .map_err(|_| invalid("start.run_id", "invalid UUID"))?;
    let machine = snapshot_from_wire(required(v.data, "start.data")?)?;
    Ok(libvm::MachineStart::new(machine, run))
}
pub fn exit_to_wire(v: &libvm::MachineExit) -> Result<w::MachineExit, ConversionError> {
    let (outcome, error_message) = match &v.outcome {
        libvm::MachineExitOutcome::Clean => (1, None),
        libvm::MachineExitOutcome::Error { message } => (2, message.clone()),
        libvm::MachineExitOutcome::AlreadyStopped => (3, None),
        libvm::MachineExitOutcome::Forced => (4, None),
        libvm::MachineExitOutcome::Unknown => (5, None),
        _ => return Err(invalid("exit.outcome", "unsupported native variant")),
    };
    Ok(w::MachineExit {
        run_id: v.run_id.as_ref().map(ToString::to_string),
        outcome,
        data: Some(snapshot_to_wire(&v.machine)?),
        exited_at: v
            .exited_at
            .map(crate::readiness::system_time_to_wire)
            .transpose()?,
        error_message,
    })
}
pub fn exit_from_wire(v: w::MachineExit) -> Result<libvm::MachineExit, ConversionError> {
    Ok(libvm::MachineExit::new(
        snapshot_from_wire(required(v.data, "exit.data")?)?,
        v.run_id
            .map(|v| {
                v.parse()
                    .map_err(|_| invalid("exit.run_id", "invalid UUID"))
            })
            .transpose()?,
        v.exited_at
            .map(crate::readiness::system_time_from_wire)
            .transpose()?,
        match v.outcome {
            1 => libvm::MachineExitOutcome::Clean,
            2 => libvm::MachineExitOutcome::Error {
                message: v.error_message,
            },
            3 => libvm::MachineExitOutcome::AlreadyStopped,
            4 => libvm::MachineExitOutcome::Forced,
            5 => libvm::MachineExitOutcome::Unknown,
            _ => return Err(invalid("exit.outcome", "invalid enum")),
        },
    ))
}
pub fn reference_to_wire(v: &libvm::MachineRef) -> Result<w::MachineRef, ConversionError> {
    use w::machine_ref::Reference;
    let reference = if let Some(id) = v.id_uuid() {
        Reference::Id(id.simple().to_string())
    } else if let Some(name) = v.name() {
        Reference::Name(name.into())
    } else if let Some(prefix) = v.id_prefix() {
        Reference::IdPrefix(prefix.into())
    } else {
        return Err(invalid("machine.reference", "unsupported native variant"));
    };
    Ok(w::MachineRef {
        reference: Some(reference),
    })
}

pub fn reference_from_wire(v: w::MachineRef) -> Result<libvm::MachineRef, ConversionError> {
    use w::machine_ref::Reference;
    let reference = required(v.reference, "machine.reference")?;
    let (text, kind) = match reference {
        Reference::Id(v) => (v, 1),
        Reference::Name(v) => (v, 2),
        Reference::IdPrefix(v) => (v, 3),
    };
    let native = libvm::MachineRef::parse(text)
        .map_err(|_| invalid("machine.reference", "invalid native reference"))?;
    let matches = match kind {
        1 => native.id_uuid().is_some(),
        2 => native.name().is_some(),
        3 => native.id_prefix().is_some(),
        _ => false,
    };
    if !matches {
        return Err(invalid(
            "machine.reference",
            "oneof does not match native parser semantics",
        ));
    }
    Ok(native)
}
