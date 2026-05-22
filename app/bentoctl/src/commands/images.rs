use std::fmt::{Display, Formatter};
use std::io::Write;
use std::path::PathBuf;

use bento_core::InstanceFile;
use bento_libvm::images::metadata::{
    host_arch, ImageMetadata, ImageMetadataBootstrap, ImageMetadataDefaults,
};
use bento_libvm::images::store::{human_size, image_size_bytes, ImageStore};
use bento_libvm::{LibVm, MachineRef};
use clap::{Args, Subcommand};
use tabwriter::TabWriter;

#[derive(Args, Debug)]
#[command(about = "Manage local VM images")]
pub struct Cmd {
    #[command(subcommand)]
    pub command: ImageSubcommand,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "images")
    }
}

#[derive(Subcommand, Debug)]
pub enum ImageSubcommand {
    #[command(about = "List local images")]
    List,
    #[command(about = "Pull an image into the local store")]
    Pull(PullCmd),
    #[command(about = "Import an OCI image archive")]
    Import(ImportCmd),
    #[command(about = "Pack a stopped VM into an image")]
    Pack(PackCmd),
    #[command(about = "Remove an image tag or image")]
    Rm(RmCmd),
}

#[derive(Args, Debug)]
pub struct PullCmd {
    /// Image reference to pull.
    #[arg(value_name = "REF")]
    pub reference: String,
    /// Local tag name to assign to the pulled image.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args, Debug)]
pub struct ImportCmd {
    /// Path to an OCI tar archive.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct PackCmd {
    /// Stopped VM to pack.
    #[arg(value_name = "VM")]
    pub vm: String,
    /// Image reference to create.
    #[arg(value_name = "REF")]
    pub reference: String,
    /// Include the resolved kernel in the image artifact.
    #[arg(long)]
    pub include_kernel: bool,
    /// Include the resolved initramfs in the image artifact.
    #[arg(long, visible_alias = "include-initramfs")]
    pub include_initrd: bool,
    /// Write the OCI archive to this path instead of importing it.
    #[arg(long, value_name = "PATH")]
    pub outfile: Option<PathBuf>,
    /// Keep the temporary OCI layout for inspection.
    #[arg(long)]
    pub debug: bool,
}

#[derive(Args, Debug)]
pub struct RmCmd {
    /// Image tag to remove.
    #[arg(value_name = "TAG")]
    pub tag: String,
}

impl Cmd {
    pub async fn run(&self) -> eyre::Result<()> {
        match &self.command {
            ImageSubcommand::List => {
                let store = ImageStore::open()?;
                print_list(&store)?
            }
            ImageSubcommand::Pull(cmd) => {
                let mut store = ImageStore::open()?;
                let rec = store.pull(&cmd.reference, cmd.name.as_deref())?;
                println!("pulled {}", rec.source_ref);
            }
            ImageSubcommand::Import(cmd) => {
                if !cmd.path.is_file() {
                    eyre::bail!("import path must point to an OCI tar archive file");
                }

                let mut store = ImageStore::open()?;
                let rec = store.import(&cmd.path)?;
                println!("imported {}", rec.source_ref);
            }
            ImageSubcommand::Pack(cmd) => {
                let libvm =
                    LibVm::from_env().map_err(|e| eyre::eyre!("initialize bento-libvm: {e}"))?;
                let machine_ref = MachineRef::parse(cmd.vm.clone())?;
                let machine = libvm.inspect(&machine_ref)?;
                if machine.status.is_running() {
                    eyre::bail!(
                        "instance {} must be stopped before packing",
                        machine.spec.name
                    );
                }

                let root_disk_path = machine.dir.join(InstanceFile::RootDisk.as_str());
                if !root_disk_path.is_file() {
                    eyre::bail!("instance {} has no root disk to pack", machine.spec.name);
                }

                let kernel_path = if cmd.include_kernel {
                    machine.spec.boot.kernel.as_ref().map(|k| {
                        if k.is_absolute() {
                            k.clone()
                        } else {
                            machine.dir.join(k)
                        }
                    })
                } else {
                    None
                };
                let initramfs_path = if cmd.include_initrd {
                    machine.spec.boot.initramfs.as_ref().map(|i| {
                        if i.is_absolute() {
                            i.clone()
                        } else {
                            machine.dir.join(i)
                        }
                    })
                } else {
                    None
                };

                let os_str = match machine.spec.platform.guest_os {
                    bento_core::GuestOs::Linux => "linux",
                };

                let metadata = ImageMetadata {
                    schema_version: 1,
                    os: os_str.to_string(),
                    arch: host_arch().to_string(),
                    defaults: ImageMetadataDefaults {
                        cpu: machine.spec.resources.cpus,
                        memory_mib: machine.spec.resources.memory_mib,
                    },
                    bootstrap: ImageMetadataBootstrap {
                        cidata_cloud_init: machine.spec.boot.bootstrap.is_some(),
                    },
                };

                let mut annotations = std::collections::BTreeMap::new();
                annotations.insert(
                    "org.opencontainers.image.created".to_string(),
                    chrono::Utc::now().to_rfc3339(),
                );

                let mut image_store = ImageStore::open()?;
                let pack_layout = ImageStore::build_pack_layout(
                    &cmd.reference,
                    &root_disk_path,
                    &metadata,
                    kernel_path.as_deref(),
                    initramfs_path.as_deref(),
                    annotations,
                )?;

                if let Some(outfile) = &cmd.outfile {
                    ImageStore::write_oci_archive(&pack_layout.layout_root, outfile)?;
                    println!("packed archive {}", outfile.display());
                } else {
                    let rec =
                        image_store.import_pack_layout(&cmd.reference, &pack_layout.layout_root)?;
                    println!("packed {}", rec.source_ref);
                }

                if cmd.debug {
                    println!("kept work dir {}", pack_layout.work_dir.display());
                } else {
                    let _ = std::fs::remove_dir_all(&pack_layout.work_dir);
                }
            }
            ImageSubcommand::Rm(cmd) => {
                let mut store = ImageStore::open()?;
                store.remove_image(&cmd.tag)?;
                println!("removed {}", cmd.tag);
            }
        }

        Ok(())
    }
}

fn print_list(store: &ImageStore) -> eyre::Result<()> {
    let records = store.list()?;
    let mut out = TabWriter::new(std::io::stdout()).padding(2);
    writeln!(&mut out, "NAME\tID\tOS\tSIZE\tSOURCE_REF\tARCH")?;

    for rec in records {
        let size = image_size_bytes(store, &rec.image)
            .map(human_size)
            .unwrap_or_else(|_| "unknown".to_string());
        let short_id = rec.image.id.chars().take(10).collect::<String>();

        writeln!(
            &mut out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            rec.tag,
            short_id,
            rec.image.os.unwrap_or_else(|| "-".to_string()),
            size,
            rec.image.source_ref,
            rec.image.arch.unwrap_or_else(|| "-".to_string())
        )?;
    }

    out.flush()?;

    Ok(())
}
