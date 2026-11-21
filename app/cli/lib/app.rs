use clap::{CommandFactory, FromArgMatches, Parser};

use crate::commands::Command;
use crate::context::Context;

const HELP_TEMPLATE: &str = "{about}\n\n{usage-heading} {usage}\n\n{all-args}{after-help}";

#[derive(Debug, Parser)]
#[command(
    name = "silo",
    about = "Silo VM lifecycle control",
    version = env!("CARGO_PKG_VERSION"),
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Increase diagnostics (-v: debug without SQL, -vv: debug with SQL, -vvv: trace). RUST_LOG overrides verbosity; registry auth logs stay capped.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    pub fn parse() -> Self {
        let mut matches = Self::command().get_matches();
        Self::from_arg_matches_mut(&mut matches).unwrap_or_else(|error| error.exit())
    }

    pub fn command() -> clap::Command {
        apply_help_template(<Self as CommandFactory>::command().styles(crate::ui::clap_styles()))
    }

    pub async fn run(self) -> eyre::Result<()> {
        let mut context = Context::new(self.verbose, self.command.transport_admission());
        self.command.run(&mut context).await
    }
}

fn apply_help_template(command: clap::Command) -> clap::Command {
    command
        .help_template(HELP_TEMPLATE)
        .mut_subcommands(apply_help_template)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::commands::Command;

    use crate::app::Cli;

    #[test]
    fn version_flags_report_the_authoritative_product_version_without_a_command() {
        for flag in ["--version", "-V"] {
            let error = Cli::try_parse_from(["silo", flag]).expect_err("version exits parsing");
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
            assert_eq!(error.exit_code(), 0);
            assert!(!error.use_stderr());
            assert_eq!(
                error.to_string(),
                format!("silo {}\n", env!("CARGO_PKG_VERSION"))
            );
            let error = Cli::command()
                .try_get_matches_from(["silo", flag])
                .expect_err("version exits command parsing");
            assert_eq!(
                error.to_string(),
                format!("silo {}\n", env!("CARGO_PKG_VERSION"))
            );
        }
    }

    #[test]
    fn parses_list_alias() {
        let cli = Cli::try_parse_from(["silo", "ls"]).expect("list alias should parse");

        assert!(matches!(cli.command, Command::List(_)));
    }

    #[test]
    fn parses_hibernate_for_named_and_default_machine() {
        for args in [vec!["silo", "hibernate"], vec!["silo", "hibernate", "dev"]] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(matches!(cli.command, Command::Hibernate(_)));
            assert_eq!(
                cli.command.transport_admission(),
                silo_vm_control::transport::Admission::Owned
            );
        }
        assert!(Cli::try_parse_from(["silo", "hibernate", "dev", "--force"]).is_err());
    }

    #[test]
    fn live_commands_have_explicit_artifact_kinds() {
        let cli = Cli::try_parse_from(["silo", "info", "vm"]).expect("info parses");
        assert!(matches!(cli.command, Command::Info(_)));
        assert!(Cli::try_parse_from(["silo", "system", "info"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "show", "vm"]).is_err());
        assert!(Cli::try_parse_from(["silo", "status", "vm"]).is_err());
        assert!(Cli::try_parse_from(["silo", "daemon", "status"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "pause", "vm"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "snapshot", "create", "vm", "--memory"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "snapshot", "create", "vm", "--live"]).is_err());
        assert!(Cli::try_parse_from(["silo", "snapshot", "create", "vm"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "snapshot", "vm", "--memory"]).is_err());
        assert!(Cli::try_parse_from(["silo", "fork", "vm", "--name", "child"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "fork", "vm", "--name", "child", "--live"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "restore", "web", "--name", "child"]).is_ok());
        assert!(
            Cli::try_parse_from(["silo", "restore", "ghcr.io/acme/web:1", "--name", "child"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["silo", "snapshot", "inspect", "web"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "snapshot", "list"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "snapshot", "rm", "web"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "image", "rm", "base"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "restore", "web", "--execution"]).is_err());
        assert!(Cli::try_parse_from(["silo", "restore", "web"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "restore", "web", "--without-memory"]).is_ok());
        assert!(Cli::try_parse_from(["silo", "recover-disks", "web"]).is_err());
    }

    #[test]
    fn live_refusal_transport_admits_owned_stopping_daemon_without_relaxing_other_commands() {
        use silo_vm_control::transport::Admission;
        for args in [
            vec!["silo", "pause", "vm"],
            vec!["silo", "snapshot", "create", "vm", "--memory"],
            vec!["silo", "fork", "vm", "--name", "child", "--live"],
            vec![
                "silo",
                "fork",
                "--operation",
                "00000000-0000-4000-8000-0000000000aa",
                "--cancel",
            ],
            vec!["silo", "restore", "web"],
            vec!["silo", "restore", "web", "--without-memory"],
            vec!["silo", "system", "info"],
        ] {
            assert_eq!(
                Cli::try_parse_from(args)
                    .unwrap()
                    .command
                    .transport_admission(),
                Admission::Owned
            );
        }
        for args in [
            vec!["silo", "info", "vm"],
            vec!["silo", "list"],
            vec!["silo", "start", "vm"],
            vec!["silo", "stop", "vm"],
            vec!["silo", "fork", "vm", "--name", "child"],
            vec!["silo", "snapshot", "create", "vm"],
            vec!["silo", "snapshot", "rm", "web"],
            vec!["silo", "image", "rm", "base"],
            vec!["silo", "image", "list"],
            vec!["silo", "image", "pull", "alpine:3.21"],
        ] {
            assert_eq!(
                Cli::try_parse_from(args)
                    .unwrap()
                    .command
                    .transport_admission(),
                Admission::Ready
            );
        }
    }

    #[test]
    fn parses_default_command_forms() {
        let cli =
            Cli::try_parse_from(["silo", "default", "devbox"]).expect("default set should parse");
        assert!(matches!(cli.command, Command::Default(_)));

        let cli = Cli::try_parse_from(["silo", "default", "--unset"])
            .expect("default unset should parse");
        assert!(matches!(cli.command, Command::Default(_)));
    }

    #[test]
    fn output_format_replaces_json_flag() {
        Cli::try_parse_from(["silo", "list", "--format", "plain"])
            .expect("plain format should parse");
        Cli::try_parse_from(["silo", "list", "--format", "json"])
            .expect("json format should parse");

        assert!(Cli::try_parse_from(["silo", "list", "--json"]).is_err());
    }

    #[test]
    fn edit_command_is_not_available() {
        assert!(Cli::try_parse_from(["silo", "edit"]).is_err());
    }

    #[test]
    fn hidden_commands_do_not_render_in_help() {
        let help = Cli::command().render_long_help().to_string();

        assert!(!help.contains("cleanup"));
    }

    #[test]
    fn verbosity_help_describes_each_diagnostic_level() {
        let help = Cli::command().render_long_help().to_string();
        for level in [
            "-v: debug without SQL",
            "-vv: debug with SQL",
            "-vvv: trace",
            "RUST_LOG overrides verbosity",
            "registry auth logs stay capped",
        ] {
            assert!(help.contains(level), "missing verbosity help: {level}");
        }
    }

    #[test]
    fn stopped_external_resource_flags_are_explicit_and_mode_specific() {
        for args in [
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--external-requirements",
            ],
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--map-disk",
                "1=/tmp/data.raw",
            ],
            vec![
                "silo",
                "snapshot",
                "create",
                "vm",
                "--external-requirements",
            ],
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--map-share",
                "work=/tmp/work",
            ],
            vec![
                "silo",
                "restore",
                "web",
                "--name",
                "child",
                "--map-disk",
                "1=/tmp/data.raw",
            ],
            vec![
                "silo",
                "restore",
                "web",
                "--without-memory",
                "--map-share",
                "work=/tmp/work",
            ],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_ok(), "{args:?}");
        }
        for args in [
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--live",
                "--external-requirements",
            ],
            vec![
                "silo",
                "snapshot",
                "create",
                "vm",
                "--memory",
                "--map-share",
                "work=/tmp/work",
            ],
            vec![
                "silo",
                "snapshot",
                "create",
                "vm",
                "--map-share",
                "work=/tmp/work",
            ],
            vec![
                "silo",
                "snapshot",
                "create",
                "vm",
                "--map-disk",
                "1=/tmp/data.raw",
            ],
            vec![
                "silo",
                "snapshot",
                "create",
                "vm",
                "--memory",
                "--external-requirements",
            ],
            vec![
                "silo",
                "restore",
                "web",
                "--execution",
                "--map-disk",
                "1=/tmp/data.raw",
            ],
            vec![
                "silo",
                "restore",
                "web",
                "--external-requirements",
                "--map-disk",
                "1=/tmp/data.raw",
            ],
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--map-disk",
                "-1=/tmp/data.raw",
            ],
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--map-disk",
                "1=relative.raw",
            ],
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--map-disk",
                "0=/tmp/data.raw",
            ],
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--map-disk",
                "16=/tmp/data.raw",
            ],
            vec![
                "silo",
                "fork",
                "vm",
                "--name",
                "child",
                "--external-requirements",
                "--map-disk",
                "1=/tmp/data.raw",
            ],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_err(), "{args:?}");
        }
    }

    #[test]
    fn restore_activation_hook_cli_uses_the_strict_bounded_shared_type() {
        let valid =
            r#"{"argv":["/bin/false"],"environment":[],"workingDirectory":"/","timeoutMs":30000}"#;
        assert!(
            Cli::try_parse_from(["silo", "restore", "web", "--activation-hook", valid]).is_ok()
        );
        for invalid in [
            r#"{"argv":[],"environment":[],"workingDirectory":"/","timeoutMs":30000}"#,
            r#"{"argv":["/bin/false"],"environment":[],"workingDirectory":"/","timeoutMs":30001}"#,
            r#"{"argv":["/bin/false"],"environment":[],"workingDirectory":"/","timeoutMs":30000,"unknown":true}"#,
        ] {
            assert!(
                Cli::try_parse_from(["silo", "restore", "web", "--activation-hook", invalid])
                    .is_err()
            );
        }
    }
}
