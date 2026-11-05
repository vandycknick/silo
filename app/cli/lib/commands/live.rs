use crate::context::Context;
use clap::{Args, Subcommand};

const EXACT_BYTES_WARNING: &str = "Copies exact storage bytes, including credentials, guest keys, dirty journals and deleted-data remnants. No sanitization, journal replay, implicit stop or implicit start is performed. External resources require explicit policy; snapshots support opaque raw roots only.";

#[derive(Debug, Args)]
#[command(about = "Pause a running VM (requires live capability admission)")]
pub struct Pause {
    #[arg(value_name = "VM")]
    machine: String,
}
impl Pause {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        context
            .app_api()
            .await?
            .pause_machine(&self.machine)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Args)]
#[command(about = "Resume the current user-owned pause of a VM")]
pub struct Resume {
    #[arg(value_name = "VM")]
    machine: String,
}
impl Resume {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        context
            .app_api()
            .await?
            .resume_machine(&self.machine)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Args)]
#[command(about = "Create and manage immutable stopped-storage checkpoints", after_help = EXACT_BYTES_WARNING)]
pub struct Snapshot {
    #[command(subcommand)]
    command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    /// Capture a stopped opaque raw machine, or explicitly request live execution capture.
    Create {
        #[arg(value_name = "VM")]
        machine: String,
        /// Optional alias in the shared image: namespace. Unnamed snapshots remain retained.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Request live execution capture, never fall back to stopped storage.
        #[arg(long, conflicts_with = "external_requirements")]
        live: bool,
        /// Omit external resources and record required mappings for a later restore.
        #[arg(long)]
        external_requirements: bool,
    },
    /// Inspect an immutable snapshot by image: alias or image:sha256: identity.
    Inspect {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
    /// List retained snapshots, including unnamed checkpoints.
    List,
    /// Release explicit snapshot retention. Aliases and other consumers still retain bytes.
    Remove {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
}
impl Snapshot {
    pub(crate) fn is_live(&self) -> bool {
        matches!(self.command, SnapshotCommand::Create { live: true, .. })
    }

    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let api = context.app_api().await?;
        match self.command {
            SnapshotCommand::Create {
                machine,
                name,
                live: true,
                ..
            } => api.capture_execution(&machine, name.as_deref()).await,
            SnapshotCommand::Create {
                machine,
                name,
                live: false,
                external_requirements,
            } => {
                let external_resources = if external_requirements {
                    libvm::ExternalResourcePolicy::RequireMappings
                } else {
                    libvm::ExternalResourcePolicy::Reject
                };
                let options = libvm::SnapshotOptions {
                    name,
                    external_resources,
                };
                let info = api.snapshot_stopped(&machine, options).await?;
                crate::ui::warn(EXACT_BYTES_WARNING);
                println!("{}", serde_json::to_string_pretty(&info)?);
                Ok(())
            }
            SnapshotCommand::Inspect { reference } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&api.inspect_snapshot(&reference).await?)?
                );
                Ok(())
            }
            SnapshotCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&api.list_snapshots().await?)?
                );
                Ok(())
            }
            SnapshotCommand::Remove { reference } => api.release_snapshot(&reference).await,
        }
    }
}

#[derive(Debug, Args)]
#[command(about = "Fork a stopped VM into a new stopped machine", long_about = "Fork a stopped VM into a new stopped machine.\n\nStopped child publication requires catalog-owned secret-scope recovery. Custom Runtime::with_secret_store overrides are refused; the ordinary CLI FileStore and secret-provider path remains supported.", after_help = EXACT_BYTES_WARNING)]
pub struct Fork {
    #[arg(value_name = "VM")]
    machine: String,
    #[arg(long, value_name = "CHILD")]
    name: String,
    /// Request live execution fork, never implicitly stop the source.
    #[arg(long, conflicts_with_all = ["external_requirements", "map_disk", "map_share"])]
    pub(crate) live: bool,
    #[command(flatten)]
    external: ExternalResources,
}
impl Fork {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let api = context.app_api().await?;
        if self.live {
            api.fork_execution(&self.machine, &self.name).await
        } else {
            let options = libvm::ForkOptions {
                name: Some(self.name),
                external_resources: self.external.policy()?,
            };
            let machine = api.fork_stopped(&self.machine, options).await?;
            crate::ui::warn(EXACT_BYTES_WARNING);
            println!("{}", machine.id);
            Ok(())
        }
    }
}

#[derive(Debug, Args)]
#[command(about = "Restore image:NAME into a new stopped machine", long_about = "Restore image:NAME into a new stopped machine.\n\nStopped child publication requires catalog-owned secret-scope recovery. Custom Runtime::with_secret_store overrides are refused; the ordinary CLI FileStore and secret-provider path remains supported.", after_help = EXACT_BYTES_WARNING)]
pub struct Restore {
    #[arg(value_name = "IMAGE_OR_CHECKPOINT")]
    checkpoint: String,
    /// Restore execution state, never cold boot an execution artifact's disks.
    #[arg(long, conflicts_with_all = ["external_requirements", "map_disk", "map_share"])]
    pub(crate) execution: bool,
    #[arg(long, value_name = "CHILD", required_unless_present = "execution")]
    name: Option<String>,
    #[command(flatten)]
    external: ExternalResources,
}
impl Restore {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let api = context.app_api().await?;
        if self.execution {
            api.restore_execution(&self.checkpoint, self.name.as_deref())
                .await
        } else {
            let name = self
                .name
                .ok_or_else(|| eyre::eyre!("stopped restore requires --name"))?;
            let options = libvm::RestoreOptions {
                name: Some(name),
                external_resources: self.external.policy()?,
            };
            let machine = api.restore_snapshot(&self.checkpoint, options).await?;
            crate::ui::warn(EXACT_BYTES_WARNING);
            println!("{}", machine.id);
            Ok(())
        }
    }
}

#[derive(Debug, Args)]
#[command(about = "Manage shared image aliases")]
pub struct Image {
    #[command(subcommand)]
    command: ImageCommand,
}
#[derive(Debug, Subcommand)]
enum ImageCommand {
    /// Remove only an image: alias, never release a snapshot's explicit retention.
    Remove {
        #[arg(value_name = "IMAGE_ALIAS")]
        alias: String,
    },
}
impl Image {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            ImageCommand::Remove { alias } => {
                context.app_api().await?.remove_image_alias(&alias).await
            }
        }
    }
}

#[derive(Debug, Args)]
struct ExternalResources {
    /// Omit external files from capture and retain explicit required destination mappings.
    #[arg(long, conflicts_with_all = ["map_disk", "map_share"])]
    external_requirements: bool,
    /// Map an external disk's configured order to an absolute destination host path.
    #[arg(long, value_name = "ORDER=PATH", value_parser = disk_mapping)]
    map_disk: Vec<libvm::ExternalResourceMapping>,
    /// Map an external share tag to an absolute destination host path. No host trees are copied.
    #[arg(long, value_name = "TAG=PATH", value_parser = share_mapping)]
    map_share: Vec<libvm::ExternalResourceMapping>,
}
impl ExternalResources {
    fn policy(self) -> eyre::Result<libvm::ExternalResourcePolicy> {
        if self.external_requirements {
            return Ok(libvm::ExternalResourcePolicy::RequireMappings);
        }
        let mappings: Vec<_> = self.map_disk.into_iter().chain(self.map_share).collect();
        if mappings.is_empty() {
            return Ok(libvm::ExternalResourcePolicy::Reject);
        }
        // Use the same strict management validation for local and daemon callers.
        let policy = libvm::ExternalResourcePolicy::Map { mappings };
        Ok(silo_vm_control::stopped::policy_from_wire(
            silo_vm_control::stopped::policy_to_wire(&policy),
        )?)
    }
}

fn mapping_parts(value: &str) -> Result<(&str, std::path::PathBuf), String> {
    let (key, path) = value
        .split_once('=')
        .ok_or_else(|| "expected KEY=PATH".to_owned())?;
    let path = std::path::PathBuf::from(path);
    if key.is_empty() || !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err("expected a nonempty resource key and absolute destination path".into());
    }
    Ok((key, path))
}
fn disk_mapping(value: &str) -> Result<libvm::ExternalResourceMapping, String> {
    let (key, path) = mapping_parts(value)?;
    let order = key
        .parse()
        .map_err(|_| "disk order must be an unsigned 32-bit integer".to_owned())?;
    let resource =
        silo_vm_control::stopped::resource_key(libvm::ExternalResourceKey::Disk { order })
            .map_err(|error| error.to_string())?;
    Ok(libvm::ExternalResourceMapping { resource, path })
}
fn share_mapping(value: &str) -> Result<libvm::ExternalResourceMapping, String> {
    let (tag, path) = mapping_parts(value)?;
    let resource = silo_vm_control::stopped::resource_key(libvm::ExternalResourceKey::Share {
        tag: tag.into(),
    })
    .map_err(|error| error.to_string())?;
    Ok(libvm::ExternalResourceMapping { resource, path })
}
