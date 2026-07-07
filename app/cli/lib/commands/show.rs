use clap::Args;

use crate::context::Context;
use crate::ui::{self, OutputFormat};
use crate::view::MachineView;

#[derive(Debug, Args)]
#[command(about = "Show VM details")]
pub struct Cmd {
    /// Name or ID of the VM to show. Defaults to the configured default VM.
    #[arg(value_name = "VM")]
    name: Option<String>,

    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let (_name, machine) = context.machine(self.name.as_deref()).await?;
        let data = machine.inspect().await?;
        let default = context.config()?.default_machine() == Some(data.name.as_str());
        let view = MachineView::new(&data, default);

        match self.format {
            OutputFormat::Json => ui::print_json(&view),
            OutputFormat::Plain => print_human(&view),
        }
    }
}

fn print_human(view: &MachineView) -> eyre::Result<()> {
    let mut rows = vec![
        ("Name".to_string(), view.name.clone()),
        ("ID".to_string(), view.id.clone()),
        ("State".to_string(), view.state.to_string()),
        ("Default".to_string(), ui::yes_no(view.default).to_string()),
        ("Ready".to_string(), ui::yes_no(view.ready).to_string()),
        ("Guest".to_string(), view.guest.status.clone()),
        ("CPUs".to_string(), view.resources.cpus.to_string()),
        (
            "Memory".to_string(),
            ui::human_memory_mib(Some(view.resources.memory_mib)),
        ),
        ("Disk".to_string(), ui::human_bytes(view.root_disk_size)),
        ("Network".to_string(), view.network.name()),
    ];

    if let Some(profile) = &view.profile {
        rows.push(("Profile".to_string(), profile.clone()));
    }
    if !view.image.is_empty() {
        rows.push(("Image".to_string(), view.image.clone()));
    }
    rows.push(("Created".to_string(), ui::format_unix(view.created_at)));
    if let Some(started_at) = view.started_at {
        rows.push(("Started".to_string(), ui::format_unix(started_at)));
    }
    if let Some(summary) = &view.summary {
        rows.push(("Summary".to_string(), summary.clone()));
    }
    if let Some(boot) = &view.guest.boot {
        rows.push(("Boot".to_string(), boot_summary(boot)));
    }
    if let Some(provision) = &view.guest.provision {
        rows.push(("Provision".to_string(), provision_summary(provision)));
    }

    ui::print_detail_rows(&rows)
}

fn boot_summary(boot: &crate::view::MachineGuestBootReportView) -> String {
    let mut summary = boot.mode.clone();
    if let Some(init) = &boot.handoff_init_path {
        summary.push_str(" -> ");
        summary.push_str(init);
    } else if let Some(requested) = &boot.requested_init {
        summary.push_str(" requested=");
        summary.push_str(requested);
    }
    summary.push_str(&format!(" pid={}", boot.agent_pid));
    if boot.agent_is_pid1 {
        summary.push_str(" pid1");
    }
    summary
}

fn provision_summary(provision: &crate::view::MachineGuestProvisionReportView) -> String {
    format!(
        "{} ({} steps, {} failed, {}ms)",
        provision.status, provision.step_count, provision.failed_step_count, provision.duration_ms
    )
}
