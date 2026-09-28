use clap::Args;

use crate::context::Context;
use crate::ui::{self, OutputFormat, Table};
use crate::view::InventoryView;

#[derive(Debug, Args)]
#[command(about = "List VMs")]
pub struct Cmd {
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let default_machine = context.config()?.default_machine().map(str::to_string);
        let machines = context.app_api().await?.list_machines().await?;
        let mut views = Vec::with_capacity(machines.len());

        for data in machines {
            views.push(InventoryView::new(
                &data,
                default_machine.as_deref() == Some(data.name.as_str()),
            ));
        }

        match self.format {
            OutputFormat::Json => ui::print_json(&views),
            OutputFormat::Plain => print_table(&views),
        }
    }
}

fn print_table(views: &[InventoryView]) -> eyre::Result<()> {
    let now = ui::now_unix();
    let mut table = Table::new([
        "ID", "NAME", "STATE", "CPUS", "MEMORY", "DISK", "CREATED", "DEFAULT", "ISSUES",
    ]);

    for entry in views {
        let view = match entry {
            InventoryView::Available(view) => view,
            InventoryView::Unavailable {
                id, name, issues, ..
            } => {
                table.add_row([
                    ui::short_id(id).to_string(),
                    name.clone(),
                    "unknown".into(),
                    "-".into(),
                    "-".into(),
                    "-".into(),
                    "-".into(),
                    "-".into(),
                    issues.len().to_string(),
                ]);
                continue;
            }
        };
        table.add_row([
            ui::short_id(&view.id).to_string(),
            view.name.clone(),
            view.state.to_string(),
            view.resources.cpus.to_string(),
            ui::human_memory_mib(Some(view.resources.memory_mib)),
            ui::human_bytes(view.root_disk_size),
            ui::relative_time(view.created_at, now),
            if view.default { "*" } else { "-" }.to_string(),
            if view.issues.is_empty() {
                "-".to_string()
            } else {
                view.issues.len().to_string()
            },
        ]);
    }

    table.print()
}
