use std::fmt::{Display, Formatter};
use std::io::Write;

use clap::Args;
use libvm::Runtime;
use tabwriter::TabWriter;

use crate::commands::machine_view::MachineView;
use crate::commands::output::{human_bytes, human_memory_mib};
use crate::config::GlobalConfig;

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
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        let machines = libvm.list_machines().await?;
        let mut views = Vec::with_capacity(machines.len());
        let default_machine = config.default_machine();
        for machine in machines {
            let inspect_data = machine.inspect().await?;
            views.push(MachineView::new(
                &inspect_data,
                default_machine == Some(inspect_data.name.as_str()),
            ));
        }
        let now = now_unix();

        if self.json {
            println!("{}", serde_json::to_string_pretty(&views)?);
            return Ok(());
        }

        let mut out = TabWriter::new(std::io::stdout()).padding(2);
        writeln!(
            &mut out,
            "ID\tNAME\tSTATE\tCPUS\tMEMORY\tDISK\tCREATED\tDEFAULT"
        )?;

        for view in views {
            let cpus = view.resources.cpus.to_string();
            let memory = human_memory_mib(Some(view.resources.memory_mib));
            let disk = human_bytes(view.root_disk_size);
            let created = relative_time(view.created_at, now);
            let default_marker = if view.default { "*" } else { "-" };

            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                short_id(&view.id),
                &view.name,
                view.state,
                cpus,
                memory,
                disk,
                created,
                default_marker,
            )?;
        }

        out.flush()?;

        Ok(())
    }
}

fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
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
