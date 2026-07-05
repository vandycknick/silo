pub mod app;
pub mod commands;
pub mod config;
pub mod constants;
pub mod context;
pub mod errors;
pub mod guest;
pub mod help;
mod network_policy;
pub mod profile;
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
            ExitCode::FAILURE
        }
    }
}
