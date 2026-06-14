use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::process::Command;

use bento_libvm::RequestedNetwork;
use bento_utils::HumanSize;
use clap::{Args, Subcommand};
use tabwriter::TabWriter;

use crate::profile::{
    parse_profile, MountMode, Profile, ProfileMount, ProfileNetwork, ProfileResources, ProfileStore,
};

#[derive(Args, Debug)]
#[command(
    about = "Manage reusable VM profiles",
    after_help = "Examples:\n  bento profile list\n  bento profile show dev\n  bento profile create dev --image ghcr.io/me/dev:latest\n  bento profile edit dev\n  bento profile validate dev\n"
)]
pub struct Cmd {
    #[command(subcommand)]
    pub command: ProfileSubcommand,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "profile")
    }
}

#[derive(Subcommand, Debug)]
pub enum ProfileSubcommand {
    #[command(about = "List available profiles", visible_alias = "ls")]
    List(ListCmd),
    #[command(about = "Show a profile")]
    Show(ShowCmd),
    #[command(about = "Create a profile")]
    Create(CreateCmd),
    #[command(about = "Edit a profile in $EDITOR")]
    Edit(EditCmd),
    #[command(name = "rm", about = "Remove a profile")]
    Rm(RmCmd),
    #[command(about = "Validate a profile")]
    Validate(ValidateCmd),
    #[command(about = "Print a profile path")]
    Path(PathCmd),
}

#[derive(Args, Debug)]
pub struct ListCmd {
    /// Output profiles as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ShowCmd {
    /// Profile name to show.
    #[arg(value_name = "PROFILE")]
    pub name: String,
    /// Output the parsed profile as JSON.
    #[arg(long)]
    pub json: bool,
    /// Print only the profile path.
    #[arg(long)]
    pub path: bool,
}

#[derive(Args, Debug)]
#[command(
    about = "Create a profile",
    after_help = "Examples:\n  bento profile create dev --image ghcr.io/me/dev:latest\n  bento profile create offline --image ubuntu:24.04 --network none\n  bento profile create dev --image ghcr.io/me/dev:latest --cpus 4 --memory 4gb --disk-size 40gb\n"
)]
pub struct CreateCmd {
    /// Profile name to create.
    #[arg(value_name = "PROFILE")]
    pub name: String,
    /// Image reference used by this profile.
    #[arg(long)]
    pub image: String,
    /// Human-readable profile description.
    #[arg(long)]
    pub description: Option<String>,
    /// Default number of virtual CPUs for VMs created from this profile.
    #[arg(long)]
    pub cpus: Option<u8>,
    /// Default RAM size for VMs created from this profile, for example 512mb or 4gb.
    #[arg(long, value_name = "SIZE")]
    pub memory: Option<HumanSize>,
    /// Default root disk resize for VMs created from this profile, for example 10gb or 512mb.
    #[arg(long, value_name = "SIZE")]
    pub disk_size: Option<HumanSize>,
    /// Network target for VMs created from this profile. Allowed: private, none, NAME, or name:NAME.
    #[arg(long, value_parser = parse_requested_network, default_value = "private")]
    pub network: RequestedNetwork,
    /// Add a mount. Format: SRC:DST[:ro|rw].
    #[arg(long = "mount", value_name = "SRC:DST[:MODE]", value_parser = parse_profile_mount)]
    pub mounts: Vec<ProfileMount>,
    /// Add a label. Format: KEY=VALUE.
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    pub labels: Vec<(String, String)>,
}

#[derive(Args, Debug)]
pub struct EditCmd {
    /// Profile name to edit.
    #[arg(value_name = "PROFILE")]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct RmCmd {
    /// Profile name to remove.
    #[arg(value_name = "PROFILE")]
    pub name: String,
    /// Remove without prompting.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ValidateCmd {
    /// Profile name or profile file path to validate.
    #[arg(value_name = "PROFILE_OR_PATH")]
    pub profile: String,
}

#[derive(Args, Debug)]
pub struct PathCmd {
    /// Profile name to resolve.
    #[arg(value_name = "PROFILE")]
    pub name: String,
}

impl Cmd {
    pub async fn run(&self) -> eyre::Result<()> {
        let store = ProfileStore::from_env()?;
        match &self.command {
            ProfileSubcommand::List(cmd) => list_profiles(&store, cmd),
            ProfileSubcommand::Show(cmd) => show_profile(&store, cmd),
            ProfileSubcommand::Create(cmd) => create_profile(&store, cmd),
            ProfileSubcommand::Edit(cmd) => edit_profile(&store, cmd),
            ProfileSubcommand::Rm(cmd) => remove_profile(&store, cmd),
            ProfileSubcommand::Validate(cmd) => validate_profile_arg(&store, cmd),
            ProfileSubcommand::Path(cmd) => print_profile_path(&store, cmd),
        }
    }
}

fn list_profiles(store: &ProfileStore, cmd: &ListCmd) -> eyre::Result<()> {
    let profiles = store.list()?;
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&profiles)?);
        return Ok(());
    }

    let mut out = TabWriter::new(std::io::stdout()).padding(2);
    writeln!(&mut out, "NAME\tIMAGE\tNETWORK\tDESCRIPTION")?;
    for named in profiles {
        writeln!(
            &mut out,
            "{}\t{}\t{}\t{}",
            named.name,
            named.profile.image,
            named.profile.network_name(),
            named.profile.description.unwrap_or_default(),
        )?;
    }
    out.flush()?;
    Ok(())
}

fn show_profile(store: &ProfileStore, cmd: &ShowCmd) -> eyre::Result<()> {
    let named = store.resolve(&cmd.name)?;
    if cmd.path {
        match named.path {
            Some(path) => println!("{}", path.display()),
            None => println!("<built-in:{}>", named.name),
        }
        return Ok(());
    }
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&named)?);
    } else {
        println!("{}", serde_yaml_ng::to_string(&named.profile)?);
    }
    Ok(())
}

fn create_profile(store: &ProfileStore, cmd: &CreateCmd) -> eyre::Result<()> {
    store.ensure_dir()?;
    if store.find_profile_path(&cmd.name)?.is_some() {
        eyre::bail!("profile `{}` already exists", cmd.name);
    }

    let labels = cmd.labels.iter().cloned().collect::<BTreeMap<_, _>>();
    let profile = Profile {
        version: "1".to_string(),
        description: cmd.description.clone(),
        image: cmd.image.clone(),
        resources: (cmd.cpus.is_some() || cmd.memory.is_some()).then(|| ProfileResources {
            cpus: cmd.cpus,
            memory: cmd.memory.map(|memory| memory.to_string()),
        }),
        disk_size: cmd.disk_size.map(|disk_size| disk_size.to_string()),
        userdata: None,
        mounts: cmd.mounts.clone(),
        network: Some(requested_network_to_profile(cmd.network.clone())),
        labels,
    };
    crate::profile::validate_profile(&profile)?;
    let path = store.path_for_new_profile(&cmd.name);
    std::fs::write(&path, serde_yaml_ng::to_string(&profile)?)?;
    println!("created {}", path.display());
    Ok(())
}

fn edit_profile(store: &ProfileStore, cmd: &EditCmd) -> eyre::Result<()> {
    let named = store.resolve(&cmd.name)?;
    let Some(path) = named.path else {
        eyre::bail!(
            "built-in profile `{}` cannot be edited; create {} first",
            cmd.name,
            store.path_for_new_profile(&cmd.name).display()
        );
    };
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = Command::new(editor).arg(&path).status()?;
    if !status.success() {
        eyre::bail!("editor exited with status {status}");
    }
    let raw = std::fs::read_to_string(&path)?;
    parse_profile(&raw)?;
    println!("validated {}", path.display());
    Ok(())
}

fn remove_profile(store: &ProfileStore, cmd: &RmCmd) -> eyre::Result<()> {
    if !cmd.force {
        eyre::bail!("refusing to remove profile `{}` without --force", cmd.name);
    }
    let named = store.resolve(&cmd.name)?;
    let Some(path) = named.path else {
        eyre::bail!("built-in profile `{}` cannot be removed", cmd.name);
    };
    std::fs::remove_file(&path)?;
    println!("removed {}", path.display());
    Ok(())
}

fn validate_profile_arg(store: &ProfileStore, cmd: &ValidateCmd) -> eyre::Result<()> {
    let path = std::path::PathBuf::from(&cmd.profile);
    if path.components().count() > 1 || path.extension().is_some() {
        let raw = std::fs::read_to_string(&path)?;
        parse_profile(&raw)?;
        println!("valid {}", path.display());
    } else {
        let named = store.resolve(&cmd.profile)?;
        println!("valid {}", named.name);
    }
    Ok(())
}

fn print_profile_path(store: &ProfileStore, cmd: &PathCmd) -> eyre::Result<()> {
    let named = store.resolve(&cmd.name)?;
    match named.path {
        Some(path) => println!("{}", path.display()),
        None => println!("<built-in:{}>", named.name),
    }
    Ok(())
}

pub(crate) fn parse_profile_mount(input: &str) -> Result<ProfileMount, String> {
    let parts = input.split(':').collect::<Vec<_>>();
    if !(2..=3).contains(&parts.len()) {
        return Err("invalid mount, expected SRC:DST[:ro|rw]".to_string());
    }
    if parts[0].is_empty() || parts[1].is_empty() {
        return Err("invalid mount, source and target are required".to_string());
    }
    if !parts[1].starts_with('/') {
        return Err("invalid mount, target must be an absolute guest path".to_string());
    }
    let mode = match parts.get(2).copied().unwrap_or("rw") {
        "ro" => MountMode::Ro,
        "rw" => MountMode::Rw,
        other => return Err(format!("invalid mount mode '{other}', expected ro or rw")),
    };
    Ok(ProfileMount {
        source: parts[0].into(),
        target: parts[1].to_string(),
        mode,
    })
}

pub(crate) fn parse_requested_network(input: &str) -> Result<RequestedNetwork, String> {
    match input {
        "private" => Ok(RequestedNetwork::Private { policy_ref: None }),
        "none" => Ok(RequestedNetwork::None),
        other if other.starts_with("name:") => {
            named_requested_network(other.trim_start_matches("name:"))
        }
        other => named_requested_network(other),
    }
}

fn named_requested_network(name: &str) -> Result<RequestedNetwork, String> {
    if name.is_empty() {
        return Err("invalid network name: cannot be empty".to_string());
    }
    if matches!(name, "private" | "none") {
        return Err(format!("invalid network name: '{name}' is reserved"));
    }
    Ok(RequestedNetwork::Named {
        name: name.to_string(),
        policy_ref: None,
    })
}

fn requested_network_to_profile(requested: RequestedNetwork) -> ProfileNetwork {
    match requested {
        RequestedNetwork::Private { policy_ref } => ProfileNetwork::Private { policy_ref },
        RequestedNetwork::None => ProfileNetwork::None,
        RequestedNetwork::Named { name, policy_ref } => ProfileNetwork::Named { name, policy_ref },
    }
}

pub(crate) fn parse_label(input: &str) -> Result<(String, String), String> {
    let (key, value) = input
        .split_once('=')
        .ok_or_else(|| "invalid label, expected KEY=VALUE".to_string())?;
    if key.is_empty() {
        return Err("invalid label, key cannot be empty".to_string());
    }
    Ok((key.to_string(), value.to_string()))
}
