use std::fmt::{Display, Formatter};
use std::io::Write;

use bento_libvm::{MachineStatus, Runtime};
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
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machines = libvm.list_machines().await?;
        let mut inspections = Vec::with_capacity(machines.len());
        for machine in machines {
            inspections.push(machine.inspect().await?);
        }
        let host_arch = std::env::consts::ARCH;
        let now = now_unix();

        if self.json {
            let values = inspections
                .into_iter()
                .map(|inspection| {
                    serde_json::json!({
                        "id": inspection.id(),
                        "name": inspection.name(),
                        "state": state_label(inspection.status()),
                        "profile": inspection.metadata().get(PROFILE_METADATA_KEY).cloned(),
                        "image": inspection.image_ref(),
                        "created_at": inspection.created_at(),
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

        for inspection in inspections {
            let hardware = inspection.spec().hardware.as_ref();
            let cpus = hardware
                .and_then(|hardware| hardware.cpus)
                .unwrap_or(1)
                .to_string();
            let memory = hardware
                .and_then(|hardware| hardware.memory)
                .unwrap_or(512)
                .to_string();
            let created = relative_time(inspection.created_at(), now);
            let status = status_label(inspection.status(), inspection.started_at(), now);
            let profile = inspection
                .metadata()
                .get(PROFILE_METADATA_KEY)
                .map(String::as_str)
                .unwrap_or("-");
            let image = if inspection.image_ref().is_empty() {
                "-"
            } else {
                inspection.image_ref()
            };
            let id = inspection.id();

            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                short_id(&id),
                inspection.name(),
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

fn state_label(state: MachineStatus) -> &'static str {
    if state.is_running() {
        "running"
    } else {
        "stopped"
    }
}

fn status_label(state: MachineStatus, started_at: Option<i64>, now: i64) -> String {
    if state.is_running() {
        let uptime = started_at
            .map(|started_at| relative_time(started_at, now))
            .unwrap_or_else(|| "N/A".to_string());
        format!("Up {uptime}")
    } else {
        "Stopped".to_string()
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
