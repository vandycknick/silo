use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use crate::context::Context;
use crate::ui::{self, OutputFormat};

#[derive(Debug, Args)]
#[command(about = "Export stopped machine root storage")]
pub struct Cmd {
    #[command(subcommand)]
    command: StorageCommand,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum ExportFormat {
    Raw,
}

#[derive(Debug, Subcommand)]
enum StorageCommand {
    /// Export a root disk and its boot/geometry metadata without overwriting files.
    #[command(
        after_help = "Opaque roots preserve exact bytes, including deleted data and dirty journals. Layered roots require --flatten-filesystem and a clean on-disk upper; flattening creates a new ext4 filesystem identity, preserves the visible namespace, and removes OverlayFS controls. No implicit stop, journal replay, source repair, EFI synthesis, or sanitization is performed. Attached data disks are not exported."
    )]
    Export {
        #[arg(value_name = "VM")]
        machine: String,
        #[arg(value_name = "DEST")]
        destination: PathBuf,
        /// Explicit output format. VMDK descriptors are not portable disk exports.
        #[arg(long, value_enum, required = true)]
        disk_format: ExportFormat,
        /// Explicitly flatten a layered root into a new whole-disk ext4 filesystem.
        #[arg(long)]
        flatten_filesystem: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
        format: OutputFormat,
    },
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            StorageCommand::Export {
                machine,
                destination,
                disk_format: ExportFormat::Raw,
                flatten_filesystem,
                format,
            } => {
                let options = libvm::RawDiskExportOptions {
                    destination: std::path::absolute(destination)?,
                    flatten_filesystem,
                };
                let report = context
                    .app_api()
                    .await?
                    .export_raw_disk(&machine, options)
                    .await?;
                match format {
                    OutputFormat::Json => ui::print_json(&report),
                    OutputFormat::Plain => {
                        println!("{}", report.path.display());
                        eprintln!(
                            "{} bytes; metadata {}",
                            report.geometry.length,
                            report.metadata_path.display()
                        );
                        Ok(())
                    }
                }
            }
        }
    }
}
