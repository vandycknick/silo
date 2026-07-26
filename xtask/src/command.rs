use std::process::{Command, ExitStatus, Output};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("failed to run {program}")]
    Run {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{program} failed with status {status}")]
    Failed { program: String, status: String },
}

pub fn run(mut command: Command) -> Result<(), CommandError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let status = command.status().map_err(|source| CommandError::Run {
        program: program.clone(),
        source,
    })?;

    if status.success() {
        Ok(())
    } else {
        Err(CommandError::Failed {
            program,
            status: status_text(status),
        })
    }
}

pub fn output(mut command: Command) -> Result<Output, CommandError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let output = command.output().map_err(|source| CommandError::Run {
        program: program.clone(),
        source,
    })?;

    if output.status.success() {
        Ok(output)
    } else {
        Err(CommandError::Failed {
            program,
            status: status_text(output.status),
        })
    }
}

fn status_text(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_string(),
        |code| code.to_string(),
    )
}
