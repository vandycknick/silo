use crate::{invalid, path_from_wire, required, validate_uuid, ConversionError};
use silod_spec::daemon::v1 as w;
/// A prepared immutable identity or a caller-owned local disk, never a mutable OCI tag ticket.
#[derive(Debug, Clone)]
pub enum CreateSource {
    Oci(crate::images::OciIdentity),
    Disk(std::path::PathBuf),
}
pub fn create_request_from_wire(
    v: w::CreateMachineRequest,
) -> Result<(crate::create::NormalizedMachineCreate, CreateSource), ConversionError> {
    let config =
        crate::updates::create_from_wire(required(v.configuration, "create.configuration")?)?;
    let source = match required(v.source, "create.source")? {
        w::create_machine_request::Source::Oci(v) => {
            CreateSource::Oci(crate::images::identity_from_wire(v)?)
        }
        w::create_machine_request::Source::DiskPath(v) => {
            let path = path_from_wire(v)?;
            if !path.is_absolute() {
                return Err(invalid("disk_path", "must be absolute"));
            }
            CreateSource::Disk(path)
        }
    };
    Ok((config, source))
}
pub fn parse_resource(v: w::ParseResourceRequest) -> Result<w::Size, ConversionError> {
    let bytes = match v.kind {
        1 => libvm::planning::parse_machine_memory(&v.value)
            .map_err(|_| invalid("resource.memory", "invalid memory size"))?,
        2 => libvm::planning::parse_root_disk_size(&v.value)
            .map_err(|_| invalid("resource.root_disk", "invalid root disk size"))?,
        _ => return Err(invalid("resource.kind", "invalid enum")),
    };
    Ok(w::Size { bytes })
}
pub fn log_source_from_wire(v: i32) -> Result<libvm::MachineLogSource, ConversionError> {
    Ok(match v {
        2 => libvm::MachineLogSource::Monitor,
        3 => libvm::MachineLogSource::Serial,
        4 => libvm::MachineLogSource::Exec,
        5 => libvm::MachineLogSource::Network,
        6 => libvm::MachineLogSource::NetworkAudit,
        _ => return Err(invalid("log.source", "invalid native source")),
    })
}
pub fn log_source_to_wire(v: libvm::MachineLogSource) -> Result<i32, ConversionError> {
    Ok(match v {
        libvm::MachineLogSource::Monitor => 2,
        libvm::MachineLogSource::Serial => 3,
        libvm::MachineLogSource::Exec => 4,
        libvm::MachineLogSource::Network => 5,
        libvm::MachineLogSource::NetworkAudit => 6,
        _ => return Err(invalid("log.source", "unsupported native variant")),
    })
}
pub fn log_output_from_wire(v: i32) -> Result<libvm::MachineLogOutput, ConversionError> {
    Ok(match v {
        2 => libvm::MachineLogOutput::Stdout,
        3 => libvm::MachineLogOutput::Stderr,
        _ => return Err(invalid("log.output", "invalid native output")),
    })
}
pub fn log_chunk_to_wire(
    v: &libvm::MachineLogChunk,
    source: libvm::MachineLogSource,
) -> Result<w::LogChunk, ConversionError> {
    Ok(w::LogChunk {
        data: v.data.to_vec(),
        source: log_source_to_wire(source)?,
        output: match v.output {
            libvm::MachineLogOutput::Stdout => 2,
            libvm::MachineLogOutput::Stderr => 3,
            _ => return Err(invalid("log.output", "unsupported native variant")),
        },
    })
}
pub fn log_chunk_from_wire(v: w::LogChunk) -> Result<libvm::MachineLogChunk, ConversionError> {
    log_source_from_wire(v.source)?;
    if v.data.len() > 64 * 1024 {
        return Err(invalid("log.data", "chunk exceeds limit"));
    }
    Ok(libvm::MachineLogChunk {
        data: v.data.into(),
        output: log_output_from_wire(v.output)?,
    })
}
/// Validate scope, exact secret name and size without echoing any credential bytes.
pub fn validate_machine_secret(v: &w::SetMachineSecretRequest) -> Result<(), ConversionError> {
    validate_uuid(&v.id, "secret.machine_id")?;
    silo_secrets::SecretName::new(&v.name)
        .map_err(|_| invalid("secret.name", "invalid exact name"))?;
    if v.value.len() > 16 * 1024 {
        return Err(invalid("secret.value", "exceeds 16 KiB"));
    }
    Ok(())
}
