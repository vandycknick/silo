pub mod app;
pub mod commands;
pub mod config;
pub mod context;
pub mod environment;
pub mod errors;
pub mod guest;
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

    match cli.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            errors::print(&error, verbose);
            errors::execution_exit_code(&error)
                .and_then(|code| u8::try_from(code).ok())
                .map(ExitCode::from)
                .unwrap_or(ExitCode::FAILURE)
        }
    }
}
