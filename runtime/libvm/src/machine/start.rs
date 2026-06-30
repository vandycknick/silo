use std::ffi::OsString;
use std::path::PathBuf;

/// Optional settings for starting a machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MachineStartOptions {
    /// Command executed by the local machine monitor after the runtime exits.
    ///
    /// When unset, no exit command is registered. The command is passed as
    /// structured argv and is never interpreted by a shell.
    pub exit_command: Option<MachineExitCommand>,
}

/// Structured command to run after the machine runtime exits.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MachineExitCommand {
    /// Executable path or binary name.
    pub command: PathBuf,
    /// Arguments passed to the executable.
    pub args: Vec<OsString>,
}

impl MachineExitCommand {
    /// Creates a structured exit command.
    pub fn new<I, A>(command: impl Into<PathBuf>, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        Self {
            command: command.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

impl MachineStartOptions {
    /// Creates start options with no exit command.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a command for vmmon to execute after this machine run exits.
    pub fn exit_command(mut self, exit_command: MachineExitCommand) -> Self {
        self.exit_command = Some(exit_command);
        self
    }
}
