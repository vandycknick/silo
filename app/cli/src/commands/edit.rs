use std::fmt::{Display, Formatter};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use clap::Args;
use eyre::Context;
use libvm::{MachineRef, Runtime};
use vm_spec::VmSpec;

#[derive(Args, Debug)]
#[command(about = "Edit a stopped VM config in $EDITOR")]
pub struct Cmd {
    /// Name or ID of the VM to edit.
    #[arg(value_name = "VM")]
    pub name: String,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machine_ref = MachineRef::parse(self.name.clone())?;
        let machine = libvm.get_machine(&machine_ref).await?;
        let inspect_data = machine.inspect().await?;
        if inspect_data.is_running() {
            eyre::bail!(
                "VM `{}` is running; stop it before editing",
                inspect_data.name
            );
        }

        let edit_file = EditFile::create(&inspect_data.name, &inspect_data.spec)?;
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
        let status = Command::new(editor).arg(edit_file.path()).status()?;
        if !status.success() {
            eyre::bail!("editor exited with status {status}");
        }

        let raw = std::fs::read_to_string(edit_file.path())
            .with_context(|| format!("read edited config {}", edit_file.path().display()))?;
        let edited: VmSpec = serde_json::from_str(&raw)
            .with_context(|| format!("parse edited config {}", edit_file.path().display()))?;
        let updated = machine.replace_config(edited).await?;
        println!("updated {}", updated.name);
        Ok(())
    }
}

struct EditFile {
    path: PathBuf,
}

impl EditFile {
    fn create(name: &str, spec: &VmSpec) -> eyre::Result<Self> {
        let path = unique_edit_path(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("create edit file {}", path.display()))?;
        file.write_all(serde_json::to_string_pretty(spec)?.as_bytes())?;
        file.flush()?;
        Ok(Self { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for EditFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn unique_edit_path(name: &str) -> PathBuf {
    let safe_name = name
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '_',
        })
        .collect::<String>();
    std::env::temp_dir().join(format!(
        "bento-{safe_name}-{}-{}.json",
        std::process::id(),
        unix_nanos()
    ))
}

fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::commands::{BentoCmd, Command};

    #[test]
    fn edit_command_parses_vm_reference() {
        let cmd = BentoCmd::try_parse_from(["bento", "edit", "devbox"])
            .expect("edit command should parse");

        let edit = match cmd.cmd {
            Command::Edit(cmd) => cmd,
            other => panic!("expected edit command, got {other:?}"),
        };

        assert_eq!(edit.name, "devbox");
    }
}
