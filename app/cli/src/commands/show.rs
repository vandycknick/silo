use std::fmt::{Display, Formatter};
use std::io::Write;

use chrono::{DateTime, Utc};
use clap::Args;
use libvm::Runtime;
use tabwriter::TabWriter;

use crate::commands::get_machine;
use crate::commands::machine_view::MachineView;
use crate::commands::output::{human_bytes, human_memory_mib};
use crate::config::GlobalConfig;

#[derive(Args, Debug)]
#[command(about = "Show VM details")]
pub struct Cmd {
    /// Name or ID of the VM to show. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    pub name: Option<String>,

    /// Output details as JSON.
    #[arg(long)]
    pub json: bool,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.name.as_deref() {
            Some(name) => f.write_str(name),
            None => Ok(()),
        }
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        let (_name, machine) = get_machine(libvm, config, self.name.as_deref()).await?;
        let inspect_data = machine.inspect().await?;
        let view = MachineView::new(
            &inspect_data,
            config.default_machine() == Some(inspect_data.name.as_str()),
        );

        if self.json {
            println!("{}", serde_json::to_string_pretty(&view)?);
            return Ok(());
        }

        print_human(&view)
    }
}

fn print_human(view: &MachineView) -> eyre::Result<()> {
    let mut out = TabWriter::new(std::io::stdout()).padding(2);
    writeln!(&mut out, "Name:\t{}", view.name)?;
    writeln!(&mut out, "ID:\t{}", view.id)?;
    writeln!(&mut out, "State:\t{}", view.state)?;
    writeln!(&mut out, "Default:\t{}", yes_no(view.default))?;
    writeln!(&mut out, "Ready:\t{}", yes_no(view.ready))?;
    writeln!(&mut out, "Guest:\t{}", view.guest.status)?;
    writeln!(&mut out, "CPUs:\t{}", view.resources.cpus)?;
    writeln!(
        &mut out,
        "Memory:\t{}",
        human_memory_mib(Some(view.resources.memory_mib))
    )?;
    writeln!(&mut out, "Disk:\t{}", human_bytes(view.root_disk_size))?;
    writeln!(&mut out, "Network:\t{}", view.network.name())?;
    if let Some(profile) = &view.profile {
        writeln!(&mut out, "Profile:\t{profile}")?;
    }
    if !view.image.is_empty() {
        writeln!(&mut out, "Image:\t{}", view.image)?;
    }
    writeln!(&mut out, "Created:\t{}", format_unix(view.created_at))?;
    if let Some(started_at) = view.started_at {
        writeln!(&mut out, "Started:\t{}", format_unix(started_at))?;
    }
    if let Some(summary) = &view.summary {
        writeln!(&mut out, "Summary:\t{summary}")?;
    }
    out.flush()?;
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_unix(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}
