use std::fmt::{Display, Formatter};
use std::io::Write;

use bento_libvm::{LibVm, MachineStatus};
use clap::Args;
use tabwriter::TabWriter;

use crate::constants::PROFILE_METADATA_KEY;

#[derive(Args, Debug, Default)]
#[command(about = "List VMs")]
pub struct Cmd {
    /// Output VMs as JSON.
    #[arg(long)]
    pub json: bool,
}

impl Display for Cmd {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        let machines = libvm.list()?;
        let host_arch = std::env::consts::ARCH;
        let now = now_unix();

        if self.json {
            let values = machines
                .into_iter()
                .map(|machine| {
                    serde_json::json!({
                        "id": machine.id.to_string(),
                        "name": machine.spec.name,
                        "state": state_label(machine.status),
                        "profile": machine.metadata.get(PROFILE_METADATA_KEY),
                        "image": machine.image_ref,
                        "created_at": machine.created_at,
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&values)?);
            return Ok(());
        }

        let mut out = TabWriter::new(std::io::stdout()).padding(2);
        writeln!(
            &mut out,
            "ID\tNAME\tSTATE\tPROFILE\tIMAGE\tCREATED\tARCH\tCPUS\tMEMORY"
        )?;

        for machine in machines {
            let cpus = machine.spec.resources.cpus.to_string();
            let memory = machine.spec.resources.memory_mib.to_string();
            let created = relative_time(machine.created_at, now);
            let status = status_label(machine.status, now);
            let profile = machine
                .metadata
                .get(PROFILE_METADATA_KEY)
                .map(String::as_str)
                .unwrap_or("-");
            let image = if machine.image_ref.is_empty() {
                "-"
            } else {
                machine.image_ref.as_str()
            };

            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                short_id(&machine.id.to_string()),
                machine.spec.name,
                status,
                profile,
                image,
                created,
                host_arch,
                cpus,
                memory,
            )?;
        }

        out.flush()?;

        Ok(())
    }
}

fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

fn state_label(status: MachineStatus) -> &'static str {
    match status {
        MachineStatus::Running { .. } => "running",
        MachineStatus::Stopped => "stopped",
    }
}

fn status_label(status: MachineStatus, now: i64) -> String {
    match status {
        MachineStatus::Running { started_at } => {
            let uptime = relative_time(started_at, now);
            format!("Up {uptime}")
        }
        MachineStatus::Stopped => "Stopped".to_string(),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn relative_time(timestamp: i64, now: i64) -> String {
    if timestamp == 0 {
        return "N/A".to_string();
    }

    let seconds = (now - timestamp).max(0);

    if seconds < 5 {
        return "Less than a second ago".to_string();
    }
    if seconds < 60 {
        return format!("{seconds} seconds ago");
    }

    let minutes = seconds / 60;
    if minutes == 1 {
        return "About a minute ago".to_string();
    }
    if minutes < 60 {
        return format!("{minutes} minutes ago");
    }

    let hours = minutes / 60;
    if hours == 1 {
        return "About an hour ago".to_string();
    }
    if hours < 48 {
        return format!("{hours} hours ago");
    }

    let days = hours / 24;
    if days < 14 {
        return format!("{days} days ago");
    }

    let weeks = days / 7;
    if weeks < 8 {
        return format!("{weeks} weeks ago");
    }

    let months = days / 30;
    if months < 12 {
        return format!("{months} months ago");
    }

    let years = days / 365;
    format!("{years} years ago")
}

#[cfg(test)]
mod tests {
    use super::{relative_time, short_id};

    #[test]
    fn relative_time_formatting() {
        let now = 1000000;

        assert_eq!(relative_time(0, now), "N/A");
        assert_eq!(relative_time(now, now), "Less than a second ago");
        assert_eq!(relative_time(now - 3, now), "Less than a second ago");
        assert_eq!(relative_time(now - 30, now), "30 seconds ago");
        assert_eq!(relative_time(now - 60, now), "About a minute ago");
        assert_eq!(relative_time(now - 90, now), "About a minute ago");
        assert_eq!(relative_time(now - 300, now), "5 minutes ago");
        assert_eq!(relative_time(now - 3600, now), "About an hour ago");
        assert_eq!(relative_time(now - 7200, now), "2 hours ago");
        assert_eq!(relative_time(now - 86400, now), "24 hours ago");
        assert_eq!(relative_time(now - 172800, now), "2 days ago");
        assert_eq!(relative_time(now - 604800, now), "7 days ago");
        assert_eq!(relative_time(now - 604800 * 2, now), "2 weeks ago");
    }

    #[test]
    fn short_id_uses_first_eight_characters_when_available() {
        assert_eq!(short_id("1234567890abcdef"), "12345678");
        assert_eq!(short_id("1234"), "1234");
    }
}
