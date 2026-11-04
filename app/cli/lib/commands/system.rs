use crate::context::Context;
use crate::ui::{self, OutputFormat};
use clap::{Args, Subcommand};
use serde::Serialize;
use vm_spec::live::{
    LiveAvailability, LiveBackend, LiveCapabilityVector, LiveHostReport, LiveLane, LiveOperation,
};

#[derive(Debug, Args)]
#[command(about = "Inspect host system capabilities")]
pub struct Cmd {
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
enum Command {
    Info(Info),
}
#[derive(Debug, Args)]
struct Info {
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    /// Prospective backend for ordinary manager operations, not an existing run.
    manager: LiveHostReport,
    /// Separately configured system appliance prospective backend.
    appliance: Option<LiveHostReport>,
}
impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            Command::Info(command) => {
                let api = context.app_api().await?;
                let info = SystemInfo {
                    manager: api.live_capabilities().await?,
                    appliance: api.appliance_live_capabilities().await?,
                };
                match command.format {
                    OutputFormat::Json => ui::print_json(&info),
                    OutputFormat::Plain => {
                        let mut rows = Vec::new();
                        append_live_rows(
                            &mut rows,
                            "Manager prospective host",
                            info.manager.backend,
                            info.manager.lane,
                            &info.manager.live,
                        );
                        if let Some(appliance) = info.appliance {
                            append_live_rows(
                                &mut rows,
                                "Appliance prospective host",
                                appliance.backend,
                                appliance.lane,
                                &appliance.live,
                            );
                        }
                        ui::print_detail_rows(&rows)
                    }
                }
            }
        }
    }
}

pub(crate) fn append_live_rows(
    rows: &mut Vec<(String, String)>,
    scope: &str,
    backend: LiveBackend,
    lane: LiveLane,
    live: &LiveCapabilityVector,
) {
    rows.push((format!("{scope} backend"), backend.to_string()));
    rows.push((format!("{scope} lane"), lane.to_string()));
    for operation in LiveOperation::ALL {
        let capability = live.get(operation);
        let availability = match &capability.availability {
            LiveAvailability::Supported => "supported".to_owned(),
            LiveAvailability::Unsupported { reason } => format!("unsupported: {reason}"),
        };
        rows.push((
            format!("{scope} {operation}"),
            format!("{availability}; native={}", capability.native),
        ));
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::system::append_live_rows;
    use vm_spec::live::{
        LiveBackend, LiveCapabilityVector, LiveLane, LiveOperation, LiveReasonCode,
    };
    #[test]
    fn all_five_capabilities_render_with_scope_and_native() {
        let mut rows = Vec::new();
        append_live_rows(
            &mut rows,
            "Manager prospective host",
            LiveBackend::Vz,
            LiveLane::NotApplicable,
            &LiveCapabilityVector::all_unsupported(LiveReasonCode::BackendExcluded),
        );
        assert_eq!(rows.len(), 7);
        for operation in LiveOperation::ALL {
            assert!(rows.iter().any(|(label, value)| label
                == &format!("Manager prospective host {operation}")
                && value == "unsupported: backend-excluded; native=false"));
        }
    }
}
