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
use tracing::instrument::WithSubscriber;

use app::Cli;

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let verbose = cli.verbose;
    // Keep tracing local to this CLI future, including embedded library calls.
    // stderr is captured by smoke and never contaminates machine-readable stdout.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("warn,libvm::runtime::start_timeline=info")
    });
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(false)
        .with_writer(std::io::stderr)
        .finish();

    match cli.run().with_subscriber(subscriber).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            errors::print(&error, verbose);
            errors::exit_code(&error)
        }
    }
}
