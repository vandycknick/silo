mod api;
pub mod app;
pub mod commands;
mod config;
pub mod context;
mod daemon;
pub mod environment;
pub mod errors;
pub mod help;
mod lobby;
pub mod machine_defaults;
mod network_policy;
pub mod planning;
mod progress_list;
mod pull_progress;
pub mod template;
pub mod terminal;
pub mod ui;
pub mod view;

use std::process::ExitCode;

use app::Cli;

/// Process entry point. The runtime and the top-level future are built here,
/// not in `bin/main.rs`, so the whole async state machine is code-generated in
/// this crate's parallel codegen units instead of serially in the binary crate.
pub fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let error = eyre::eyre!("start the async runtime: {error}");
            errors::print(&error, 0);
            return errors::exit_code(&error);
        }
    };
    runtime.block_on(run())
}

async fn run() -> ExitCode {
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
