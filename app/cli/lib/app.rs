use clap::{CommandFactory, FromArgMatches, Parser};

use crate::commands::Command;
use crate::context::Context;

const HELP_TEMPLATE: &str = "{about}\n\n{usage-heading} {usage}\n\n{all-args}{after-help}";

#[derive(Debug, Parser)]
#[command(
    name = "bento",
    about = "BentoBox VM lifecycle control",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Increase diagnostic output. Repeat for full error chains.
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
        let mut context = Context::new(self.verbose);
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

    use super::Cli;

    #[test]
    fn parses_list_alias() {
        let cli = Cli::try_parse_from(["bento", "ls"]).expect("list alias should parse");

        assert!(matches!(cli.command, Command::List(_)));
    }

    #[test]
    fn parses_status_alias() {
        let cli = Cli::try_parse_from(["bento", "status"]).expect("status alias should parse");

        assert!(matches!(cli.command, Command::Show(_)));
    }

    #[test]
    fn parses_default_command_forms() {
        let cli =
            Cli::try_parse_from(["bento", "default", "devbox"]).expect("default set should parse");
        assert!(matches!(cli.command, Command::Default(_)));

        let cli = Cli::try_parse_from(["bento", "default", "--unset"])
            .expect("default unset should parse");
        assert!(matches!(cli.command, Command::Default(_)));
    }

    #[test]
    fn output_format_replaces_json_flag() {
        Cli::try_parse_from(["bento", "list", "--format", "plain"])
            .expect("plain format should parse");
        Cli::try_parse_from(["bento", "list", "--format", "json"])
            .expect("json format should parse");

        assert!(Cli::try_parse_from(["bento", "list", "--json"]).is_err());
    }

    #[test]
    fn edit_command_is_not_available() {
        assert!(Cli::try_parse_from(["bento", "edit"]).is_err());
    }

    #[test]
    fn hidden_commands_do_not_render_in_help() {
        let help = Cli::command().render_long_help().to_string();

        assert!(!help.contains("cleanup"));
    }
}
