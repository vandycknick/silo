use std::collections::BTreeMap;
use std::process::Command;

use clap::{Args, Subcommand};
use libvm::MachineNetworkConfig;
use utils::HumanSize;

use crate::context::Context;
use crate::network_policy::policy_source_display;
use crate::profile::{
    parse_profile, validate_profile, MountMode, NamedProfile, Profile, ProfileMount,
    ProfileNetwork, ProfileResources, ProfileStore,
};
use crate::ui::{self, OutputFormat, Table};

const EXAMPLES: &[&str] = &[
    "bento profile list",
    "bento profile show dev",
    "bento profile create dev --image ghcr.io/me/dev:latest",
    "bento profile edit dev",
    "bento profile validate dev",
];

const CREATE_EXAMPLES: &[&str] = &[
    "bento profile create dev --image ghcr.io/me/dev:latest",
    "bento profile create offline --image ubuntu:24.04 --network none",
    "bento profile create dev --image ghcr.io/me/dev:latest --cpus 4 --memory 4gb --disk-size 40gb",
];

#[derive(Debug, Args)]
#[command(
    about = "Manage reusable VM profiles",
    after_help = crate::help::examples(EXAMPLES)
)]
pub struct Cmd {
    #[command(subcommand)]
    pub command: ProfileSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileSubcommand {
    #[command(about = "List available profiles", visible_alias = "ls")]
    List(ListCmd),
    #[command(about = "Show a profile")]
    Show(ShowCmd),
    #[command(about = "Create a profile")]
    Create(Box<CreateCmd>),
    #[command(about = "Edit a profile in $EDITOR")]
    Edit(EditCmd),
    #[command(name = "rm", about = "Remove a profile")]
    Rm(RmCmd),
    #[command(about = "Validate a profile")]
    Validate(ValidateCmd),
    #[command(about = "Print a profile path")]
    Path(PathCmd),
}

#[derive(Debug, Args)]
pub struct ListCmd {
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ShowCmd {
    /// Profile name to show.
    #[arg(value_name = "PROFILE")]
    pub name: String,
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    pub format: OutputFormat,
    /// Print only the profile path.
    #[arg(long)]
    pub path: bool,
}

#[derive(Debug, Args)]
#[command(
    about = "Create a profile",
    after_help = crate::help::examples(CREATE_EXAMPLES)
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
    #[arg(long, value_parser = parse_machine_network_config, default_value = "private")]
    pub network: MachineNetworkConfig,
    /// Add a mount. Format: SRC:DST[:ro|rw].
    #[arg(long = "mount", value_name = "SRC:DST[:MODE]", value_parser = parse_profile_mount)]
    pub(crate) mounts: Vec<ProfileMount>,
    /// Add a label. Format: KEY=VALUE.
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    pub labels: Vec<(String, String)>,
}

#[derive(Debug, Args)]
pub struct EditCmd {
    /// Profile name to edit.
    #[arg(value_name = "PROFILE")]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct RmCmd {
    /// Profile name to remove.
    #[arg(value_name = "PROFILE")]
    pub name: String,
    /// Remove without prompting.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ValidateCmd {
    /// Profile name or profile file path to validate.
    #[arg(value_name = "PROFILE_OR_PATH")]
    pub profile: String,
}

#[derive(Debug, Args)]
pub struct PathCmd {
    /// Profile name to resolve.
    #[arg(value_name = "PROFILE")]
    pub name: String,
}

impl Cmd {
    pub async fn run(self, _context: &mut Context) -> eyre::Result<()> {
        let store = ProfileStore::from_env()?;
        match self.command {
            ProfileSubcommand::List(command) => list_profiles(&store, command),
            ProfileSubcommand::Show(command) => show_profile(&store, command),
            ProfileSubcommand::Create(command) => create_profile(&store, *command),
            ProfileSubcommand::Edit(command) => edit_profile(&store, command),
            ProfileSubcommand::Rm(command) => remove_profile(&store, command),
            ProfileSubcommand::Validate(command) => validate_profile_arg(&store, command),
            ProfileSubcommand::Path(command) => print_profile_path(&store, command),
        }
    }
}

fn list_profiles(store: &ProfileStore, command: ListCmd) -> eyre::Result<()> {
    let profiles = store.list()?;
    if command.format == OutputFormat::Json {
        return ui::print_json(&profiles);
    }

    let mut table = Table::new(["NAME", "IMAGE", "NETWORK", "DESCRIPTION"]);
    for named in profiles {
        let network = named.profile.network_name();
        table.add_row([
            named.name,
            named.profile.image,
            network,
            named.profile.description.unwrap_or_default(),
        ]);
    }
    table.print()
}

fn show_profile(store: &ProfileStore, command: ShowCmd) -> eyre::Result<()> {
    let named = store.resolve(&command.name)?;
    if command.path {
        print_profile_location(&named)?;
        return Ok(());
    }
    if command.format == OutputFormat::Json {
        ui::print_json(&named)
    } else {
        print_profile_details(&named)
    }
}

fn print_profile_details(named: &NamedProfile) -> eyre::Result<()> {
    let profile = &named.profile;
    let rows = vec![
        ("name".to_string(), named.name.clone()),
        ("path".to_string(), profile_location(named)),
        (
            "description".to_string(),
            profile
                .description
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        ("image".to_string(), profile.image.clone()),
        (
            "cpus".to_string(),
            profile
                .cpus()
                .map(|cpus| cpus.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "memory".to_string(),
            profile
                .resources
                .as_ref()
                .and_then(|resources| resources.memory.clone())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "disk".to_string(),
            profile.disk_size.clone().unwrap_or_else(|| "-".to_string()),
        ),
        ("network".to_string(), format_profile_network(profile)),
        (
            "userdata".to_string(),
            ui::yes_no(profile.userdata.is_some()).to_string(),
        ),
        ("mounts".to_string(), format_profile_mounts(&profile.mounts)),
        ("labels".to_string(), format_profile_labels(&profile.labels)),
    ];
    ui::print_detail_rows(&rows)
}

fn create_profile(store: &ProfileStore, command: CreateCmd) -> eyre::Result<()> {
    store.ensure_dir()?;
    if store.find_profile_path(&command.name)?.is_some() {
        eyre::bail!("profile `{}` already exists", command.name);
    }

    let labels = command.labels.into_iter().collect::<BTreeMap<_, _>>();
    let profile = Profile {
        version: "1".to_string(),
        description: command.description,
        image: command.image,
        resources: (command.cpus.is_some() || command.memory.is_some()).then(|| ProfileResources {
            cpus: command.cpus,
            memory: command.memory.map(|memory| memory.to_string()),
        }),
        disk_size: command.disk_size.map(|disk_size| disk_size.to_string()),
        userdata: None,
        mounts: command.mounts,
        network: Some(machine_network_to_profile(command.network)),
        labels,
    };
    validate_profile(&profile)?;
    let path = store.path_for_new_profile(&command.name);
    std::fs::write(&path, serde_yaml_ng::to_string(&profile)?)?;
    ui::success(format!("created {}", path.display()));
    Ok(())
}

fn edit_profile(store: &ProfileStore, command: EditCmd) -> eyre::Result<()> {
    let named = store.resolve(&command.name)?;
    let Some(path) = named.path else {
        eyre::bail!(
            "built-in profile `{}` cannot be edited; create {} first",
            command.name,
            store.path_for_new_profile(&command.name).display()
        );
    };
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = Command::new(editor).arg(&path).status()?;
    if !status.success() {
        eyre::bail!("editor exited with status {status}");
    }
    let raw = std::fs::read_to_string(&path)?;
    parse_profile(&raw)?;
    ui::success(format!("validated {}", path.display()));
    Ok(())
}

fn remove_profile(store: &ProfileStore, command: RmCmd) -> eyre::Result<()> {
    if !command.force {
        eyre::bail!(
            "refusing to remove profile `{}` without --force",
            command.name
        );
    }
    let named = store.resolve(&command.name)?;
    let Some(path) = named.path else {
        eyre::bail!("built-in profile `{}` cannot be removed", command.name);
    };
    std::fs::remove_file(&path)?;
    ui::success(format!("removed {}", path.display()));
    Ok(())
}

fn validate_profile_arg(store: &ProfileStore, command: ValidateCmd) -> eyre::Result<()> {
    let path = std::path::PathBuf::from(&command.profile);
    if path.components().count() > 1 || path.extension().is_some() {
        let raw = std::fs::read_to_string(&path)?;
        parse_profile(&raw)?;
        ui::success(format!("valid {}", path.display()));
    } else {
        let named = store.resolve(&command.profile)?;
        ui::success(format!("valid {}", named.name));
    }
    Ok(())
}

fn print_profile_path(store: &ProfileStore, command: PathCmd) -> eyre::Result<()> {
    let named = store.resolve(&command.name)?;
    print_profile_location(&named)
}

fn print_profile_location(named: &NamedProfile) -> eyre::Result<()> {
    println!("{}", profile_location(named));
    Ok(())
}

fn profile_location(named: &NamedProfile) -> String {
    match &named.path {
        Some(path) => path.display().to_string(),
        None => format!("<built-in:{}>", named.name),
    }
}

fn format_profile_network(profile: &Profile) -> String {
    match profile.network() {
        ProfileNetwork::Private { policy_ref: None } => "private".to_string(),
        ProfileNetwork::Private {
            policy_ref: Some(policy_ref),
        } => format!("private (policy {})", policy_source_display(&policy_ref)),
        ProfileNetwork::None => "none".to_string(),
        ProfileNetwork::Named { name } => format!("named ({name})"),
    }
}

fn format_profile_mounts(mounts: &[ProfileMount]) -> String {
    if mounts.is_empty() {
        return "-".to_string();
    }

    mounts
        .iter()
        .map(|mount| {
            let mode = match mount.mode {
                MountMode::Ro => "ro",
                MountMode::Rw => "rw",
            };
            format!("{}:{}:{mode}", mount.source.display(), mount.target)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_profile_labels(labels: &BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return "-".to_string();
    }

    labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
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

pub(crate) fn parse_machine_network_config(input: &str) -> Result<MachineNetworkConfig, String> {
    match input {
        "private" => Ok(MachineNetworkConfig::Private {
            policy: None,
            policy_ref: None,
        }),
        "none" => Ok(MachineNetworkConfig::None),
        other if other.starts_with("name:") => {
            named_machine_network(other.trim_start_matches("name:"))
        }
        other => named_machine_network(other),
    }
}

fn named_machine_network(name: &str) -> Result<MachineNetworkConfig, String> {
    MachineNetworkConfig::try_named(name)
}

fn machine_network_to_profile(network: MachineNetworkConfig) -> ProfileNetwork {
    match network {
        MachineNetworkConfig::Private { policy_ref, .. } => ProfileNetwork::Private {
            policy_ref: policy_ref.map(|policy_ref| policy_ref.as_str().to_string()),
        },
        MachineNetworkConfig::None => ProfileNetwork::None,
        MachineNetworkConfig::Named { name } => ProfileNetwork::Named { name },
        other => ProfileNetwork::Named { name: other.name() },
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

#[cfg(test)]
mod tests {
    use clap::Parser;
    use libvm::MachineNetworkConfig;

    use crate::app::Cli;
    use crate::commands::profile::{parse_label, parse_profile_mount};
    use crate::commands::Command;
    use crate::profile::MountMode;

    #[test]
    fn profile_list_alias_parses() {
        let cli = Cli::try_parse_from(["bento", "profile", "ls", "--format", "json"])
            .expect("profile ls should parse");

        let Command::Profile(profile) = cli.command else {
            panic!("expected profile command");
        };
        assert!(matches!(profile.command, super::ProfileSubcommand::List(_)));
    }

    #[test]
    fn create_parses_mounts_labels_and_networks() {
        let cli = Cli::try_parse_from([
            "bento",
            "profile",
            "create",
            "dev",
            "--image",
            "ubuntu:24.04",
            "--network",
            "name:devnet",
            "--mount",
            "./src:/work:ro",
            "--label",
            "team=runtime",
        ])
        .expect("profile create should parse");

        let Command::Profile(profile) = cli.command else {
            panic!("expected profile command");
        };
        let super::ProfileSubcommand::Create(create) = profile.command else {
            panic!("expected profile create command");
        };
        let create = *create;

        assert_eq!(
            create.network,
            MachineNetworkConfig::Named {
                name: "devnet".to_string()
            }
        );
        assert_eq!(create.mounts[0].target, "/work");
        assert_eq!(create.mounts[0].mode, MountMode::Ro);
        assert_eq!(
            create.labels,
            vec![("team".to_string(), "runtime".to_string())]
        );
    }

    #[test]
    fn mount_parser_rejects_relative_guest_path() {
        let err = parse_profile_mount("./src:work").expect_err("relative target should fail");
        assert!(err.contains("absolute guest path"));
    }

    #[test]
    fn label_parser_rejects_missing_separator() {
        let err = parse_label("team").expect_err("missing separator should fail");
        assert!(err.contains("KEY=VALUE"));
    }
}
