use std::process::Command;

use clap::{Args, Subcommand};

use crate::context::Context;
use crate::machine_defaults::{MachineMount, MachineNetwork, MountMode};
use crate::template::{parse_template, NamedTemplate, Template, TemplateStore};
use crate::ui::{self, OutputFormat, Table};

const EXAMPLES: &[&str] = &[
    "silo template list",
    "silo template inspect dev",
    "silo template create dev ubuntu:24.04",
    "silo template edit dev",
    "silo template validate dev",
];

#[derive(Debug, Args)]
#[command(
    about = "Manage reusable VM templates",
    after_help = crate::help::examples(EXAMPLES)
)]
pub struct Cmd {
    #[command(subcommand)]
    command: TemplateSubcommand,
}

#[derive(Debug, Subcommand)]
enum TemplateSubcommand {
    #[command(about = "List available templates", visible_alias = "ls")]
    List(ListCmd),
    #[command(about = "Inspect a template")]
    Inspect(InspectCmd),
    #[command(about = "Create a template")]
    Create(CreateCmd),
    #[command(about = "Edit a template in $EDITOR")]
    Edit(EditCmd),
    #[command(about = "Validate a template")]
    Validate(ValidateCmd),
    #[command(about = "Print a template path")]
    Path(PathCmd),
    #[command(name = "rm", about = "Remove a template")]
    Rm(RmCmd),
}

#[derive(Debug, Args)]
struct ListCmd {
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct InspectCmd {
    /// Template name to inspect.
    #[arg(value_name = "TEMPLATE")]
    name: String,
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct CreateCmd {
    /// Template name to create.
    #[arg(value_name = "TEMPLATE")]
    name: String,
    /// Optional image reference used by this template.
    #[arg(value_name = "IMAGE")]
    image: Option<String>,
}

#[derive(Debug, Args)]
struct EditCmd {
    /// Template name to edit.
    #[arg(value_name = "TEMPLATE")]
    name: String,
}

#[derive(Debug, Args)]
struct ValidateCmd {
    /// Template name or template file path to validate.
    #[arg(value_name = "TEMPLATE_OR_PATH")]
    template: String,
}

#[derive(Debug, Args)]
struct PathCmd {
    /// Template name to resolve.
    #[arg(value_name = "TEMPLATE")]
    name: String,
}

#[derive(Debug, Args)]
struct RmCmd {
    /// Template name to remove.
    #[arg(value_name = "TEMPLATE")]
    name: String,
    /// Remove without prompting.
    #[arg(long)]
    force: bool,
}

impl Cmd {
    pub async fn run(self, _context: &mut Context) -> eyre::Result<()> {
        let store = TemplateStore::from_env()?;
        match self.command {
            TemplateSubcommand::List(command) => list_templates(&store, command),
            TemplateSubcommand::Inspect(command) => inspect_template(&store, command),
            TemplateSubcommand::Create(command) => create_template(&store, command),
            TemplateSubcommand::Edit(command) => edit_template(&store, command),
            TemplateSubcommand::Validate(command) => validate_template_arg(&store, command),
            TemplateSubcommand::Path(command) => print_template_path(&store, command),
            TemplateSubcommand::Rm(command) => remove_template(&store, command),
        }
    }
}

fn list_templates(store: &TemplateStore, command: ListCmd) -> eyre::Result<()> {
    let templates = store.list()?;
    match command.format {
        OutputFormat::Json => ui::print_json(&templates),
        OutputFormat::Plain => {
            let mut table = Table::new(["NAME", "IMAGE", "DESCRIPTION"]);
            for named in templates {
                table.add_row([
                    named.name,
                    named.template.image.unwrap_or_default(),
                    named.template.description.unwrap_or_default(),
                ]);
            }
            table.print()
        }
    }
}

fn inspect_template(store: &TemplateStore, command: InspectCmd) -> eyre::Result<()> {
    let named = store.resolve(&command.name)?;
    match command.format {
        OutputFormat::Json => ui::print_json(&named),
        OutputFormat::Plain => print_template_details(&named),
    }
}

fn print_template_details(named: &NamedTemplate) -> eyre::Result<()> {
    let template = &named.template;
    let rows = vec![
        ("name".to_string(), named.name.clone()),
        ("path".to_string(), named.path.display().to_string()),
        ("version".to_string(), template.version.clone()),
        (
            "description".to_string(),
            template
                .description
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "image".to_string(),
            template.image.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "cpus".to_string(),
            template
                .resources
                .as_ref()
                .and_then(|resources| resources.cpus)
                .map(|cpus| cpus.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "memory".to_string(),
            template
                .resources
                .as_ref()
                .and_then(|resources| resources.memory.clone())
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "disk".to_string(),
            template
                .disk_size
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "network".to_string(),
            format_template_network(template.network.as_ref()),
        ),
        (
            "userdata".to_string(),
            ui::yes_no(template.userdata.is_some()).to_string(),
        ),
        (
            "mounts".to_string(),
            format_template_mounts(&template.mounts),
        ),
        (
            "forwards".to_string(),
            if template.forwards.is_empty() {
                "-".to_string()
            } else {
                template
                    .forwards
                    .iter()
                    .map(|forward| format!("{}={}", forward.listen, forward.connect))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ),
        (
            "vsock".to_string(),
            template.vsock.map(ui::yes_no).unwrap_or("-").to_string(),
        ),
        (
            "labels".to_string(),
            format_template_labels(&template.labels),
        ),
    ];
    ui::print_detail_rows(&rows)
}

fn create_template(store: &TemplateStore, command: CreateCmd) -> eyre::Result<()> {
    let template = Template {
        version: "1".to_string(),
        description: None,
        image: command.image,
        resources: None,
        disk_size: None,
        userdata: None,
        mounts: Vec::new(),
        forwards: Vec::new(),
        vsock: None,
        network: None,
        labels: Default::default(),
    };
    let path = store.write(&command.name, &template)?;
    ui::success(format!("created {}", path.display()));
    Ok(())
}

fn edit_template(store: &TemplateStore, command: EditCmd) -> eyre::Result<()> {
    let named = store.resolve(&command.name)?;
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = Command::new(editor).arg(&named.path).status()?;
    if !status.success() {
        eyre::bail!("editor exited with status {status}");
    }
    let raw = std::fs::read_to_string(&named.path)?;
    parse_template(&raw)?;
    ui::success(format!("validated {}", named.path.display()));
    Ok(())
}

fn validate_template_arg(store: &TemplateStore, command: ValidateCmd) -> eyre::Result<()> {
    let path = std::path::PathBuf::from(&command.template);
    if path.components().count() > 1 || path.extension().is_some() {
        let raw = std::fs::read_to_string(&path)?;
        parse_template(&raw)?;
        ui::success(format!("valid {}", path.display()));
    } else {
        let named = store.resolve(&command.template)?;
        ui::success(format!("valid {}", named.name));
    }
    Ok(())
}

fn print_template_path(store: &TemplateStore, command: PathCmd) -> eyre::Result<()> {
    let named = store.resolve(&command.name)?;
    println!("{}", named.path.display());
    Ok(())
}

fn remove_template(store: &TemplateStore, command: RmCmd) -> eyre::Result<()> {
    if !command.force {
        eyre::bail!(
            "refusing to remove template `{}` without --force",
            command.name
        );
    }
    let named = store.resolve(&command.name)?;
    std::fs::remove_file(&named.path)?;
    ui::success(format!("removed {}", named.path.display()));
    Ok(())
}

fn format_template_network(network: Option<&MachineNetwork>) -> String {
    match network {
        None => "-".to_string(),
        Some(MachineNetwork::Private { policy_ref: None }) => "private".to_string(),
        Some(MachineNetwork::Private {
            policy_ref: Some(policy_ref),
        }) => format!("private (policy {policy_ref})"),
        Some(MachineNetwork::None) => "none".to_string(),
        Some(MachineNetwork::Named { name }) => format!("named ({name})"),
    }
}

fn format_template_mounts(mounts: &[MachineMount]) -> String {
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

fn format_template_labels(labels: &std::collections::BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return "-".to_string();
    }

    labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::app::Cli;
    use crate::commands::Command;
    use crate::template::TemplateStore;

    use super::{
        create_template, remove_template, validate_template_arg, CreateCmd, RmCmd,
        TemplateSubcommand, ValidateCmd,
    };

    #[test]
    fn template_command_parses_all_subcommands() {
        let cli = Cli::try_parse_from(["silo", "template", "ls", "--format", "json"])
            .expect("template list should parse");
        let Command::Template(template) = cli.command else {
            panic!("expected template command");
        };
        assert!(matches!(template.command, TemplateSubcommand::List(_)));

        let cli = Cli::try_parse_from(["silo", "template", "inspect", "dev"])
            .expect("template inspect should parse");
        let Command::Template(template) = cli.command else {
            panic!("expected template command");
        };
        assert!(matches!(template.command, TemplateSubcommand::Inspect(_)));

        let cli = Cli::try_parse_from(["silo", "template", "create", "dev", "ubuntu:24.04"])
            .expect("template create should parse");
        let Command::Template(template) = cli.command else {
            panic!("expected template command");
        };
        let TemplateSubcommand::Create(create) = template.command else {
            panic!("expected template create command");
        };
        assert_eq!(create.name, "dev");
        assert_eq!(create.image.as_deref(), Some("ubuntu:24.04"));

        let cli = Cli::try_parse_from(["silo", "template", "create", "image-free"])
            .expect("image-free template create should parse");
        let Command::Template(template) = cli.command else {
            panic!("expected template command");
        };
        let TemplateSubcommand::Create(create) = template.command else {
            panic!("expected template create command");
        };
        assert_eq!(create.image, None);

        Cli::try_parse_from(["silo", "template", "edit", "dev"])
            .expect("template edit should parse");
        Cli::try_parse_from(["silo", "template", "validate", "templates/dev.yaml"])
            .expect("template validate should parse");
        Cli::try_parse_from(["silo", "template", "path", "dev"])
            .expect("template path should parse");
        Cli::try_parse_from(["silo", "template", "rm", "dev", "--force"])
            .expect("template remove should parse");
    }

    #[test]
    fn create_validate_and_remove_templates_in_a_real_directory() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let store = TemplateStore::from_config_root(config_root.path());

        create_template(
            &store,
            CreateCmd {
                name: "image-free".to_string(),
                image: None,
            },
        )
        .expect("create image-free template");
        let path = config_root.path().join("templates/image-free.yaml");
        assert!(path.is_file());

        let named = store.resolve("image-free").expect("resolve template");
        assert_eq!(named.template.version, "1");
        assert_eq!(named.template.image, None);

        validate_template_arg(
            &store,
            ValidateCmd {
                template: path.display().to_string(),
            },
        )
        .expect("validate template path");

        remove_template(
            &store,
            RmCmd {
                name: "image-free".to_string(),
                force: true,
            },
        )
        .expect("remove template");
        assert!(!path.exists());
    }

    #[test]
    fn remove_requires_force() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let store = TemplateStore::from_config_root(config_root.path());

        let error = remove_template(
            &store,
            RmCmd {
                name: "dev".to_string(),
                force: false,
            },
        )
        .expect_err("removal without force must fail");

        assert!(error.to_string().contains("without --force"));
        assert!(!config_root.path().join("templates").exists());
    }
}
