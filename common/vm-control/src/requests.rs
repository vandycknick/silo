use crate::{invalid, required, validate_uuid, ConversionError};
use silod_spec::daemon::v1 as w;
/// A selected immutable OCI identity, a typed local disk import, or a typed
/// managed image/snapshot reference; never a mutable OCI tag ticket.
#[derive(Debug, Clone)]
pub enum CreateSource {
    Oci(crate::images::OciIdentity),
    Disk(libvm::DiskImportRequest),
    Managed(libvm::ManagedSourceRef),
}
pub fn create_request_to_wire(
    config: &crate::create::NormalizedMachineCreate,
    source: &CreateSource,
) -> Result<w::CreateMachineRequest, ConversionError> {
    use w::create_machine_request::Source;
    Ok(w::CreateMachineRequest {
        configuration: Some(crate::updates::create_to_wire(config)?),
        source: Some(match source {
            CreateSource::Oci(identity) => {
                Source::Oci(crate::images::oci_identity_to_wire(identity))
            }
            CreateSource::Disk(request) => {
                Source::Disk(crate::boot::import_request_to_wire(request)?)
            }
            CreateSource::Managed(reference) => {
                Source::Managed(crate::images::managed_ref_to_wire(reference)?)
            }
        }),
    })
}
pub fn create_request_from_wire(
    v: w::CreateMachineRequest,
) -> Result<(crate::create::NormalizedMachineCreate, CreateSource), ConversionError> {
    use w::create_machine_request::Source;
    let config =
        crate::updates::create_from_wire(required(v.configuration, "create.configuration")?)?;
    let source = match required(v.source, "create.source")? {
        Source::Oci(v) => {
            let identity = crate::images::identity_from_wire(v)?;
            crate::boot::platform_from_oci(&identity.platform)?;
            CreateSource::Oci(identity)
        }
        Source::Disk(v) => CreateSource::Disk(crate::boot::import_request_from_wire(v)?),
        Source::Managed(v) => CreateSource::Managed(crate::images::managed_ref_from_wire(v)?),
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
