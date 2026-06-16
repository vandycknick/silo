use std::fs;
use std::io;
use std::path::Path;

use serde::Deserialize;

/// Exit status written by vmmon when a machine run ends.
///
/// This is vmmon telemetry, not the machine lifecycle state stored in SQLite.
/// The runtime uses it as one input while reconciling `MachineState` after a
/// monitor exits or disappears.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmonExitStatus {
    #[serde(default)]
    pub(crate) run_id: Option<String>,
    #[serde(default)]
    pub(crate) pid: Option<i32>,
    pub(crate) exited_at: i64,
    pub(crate) outcome: VmmonExitOutcome,
    #[serde(default)]
    pub(crate) error: Option<String>,
}

/// High-level outcome reported in a vmmon exit status file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VmmonExitOutcome {
    Clean,
    Error,
}

pub(crate) fn read(path: &Path) -> io::Result<Option<VmmonExitStatus>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let status = serde_json::from_str(&raw).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse vmmon exit status from {}: {err}", path.display()),
        )
    })?;
    Ok(Some(status))
}

pub(crate) fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}
