mod api;
pub mod app;
pub mod commands;
mod config;
pub mod context;
mod daemon;
pub mod environment;
pub mod errors;
pub mod help;
pub mod machine_defaults;
mod network_policy;
pub mod planning;
pub mod template;
pub mod terminal;
pub mod ui;
pub mod view;

use std::process::ExitCode;

use app::Cli;

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let verbose = cli.verbose;
    if let Err(error) = utils::logging::init(
        utils::logging::Profile::Cli { verbosity: verbose },
        ui::LogWriter::new(),
    ) {
        let error = eyre::eyre!("initialize CLI tracing: {error}");
        errors::print(&error, verbose);
        return errors::exit_code(&error);
    }

    match cli.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            errors::print(&error, verbose);
            errors::exit_code(&error)
        }
    }
}
