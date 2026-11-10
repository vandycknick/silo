use clap::Args;

use crate::context::Context;
use crate::ui::{self, OutputFormat};
use crate::view::{InventoryView, MachineView};

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
        let name = context.resolve_machine_name(self.name.as_deref())?;
        let api = context.app_api().await?;
        let data = api.inspect_inventory(&name).await?;
        let reclaim = if data
            .data
            .as_ref()
            .is_some_and(|machine| machine.is_running())
        {
            match api.machine(&data.id).await {
                Ok(machine) => machine.host_memory_reclaim().await,
                Err(_) => None,
            }
        } else {
            None
        };
        let default = context.config()?.default_machine() == Some(data.name.as_str());
        let mut view = InventoryView::new(&data, default);
        if let InventoryView::Available(machine) = &mut view {
            machine.host_memory_reclaim = reclaim
                .as_ref()
                .map(crate::view::HostMemoryReclaimView::new);
        }

        match self.format {
            OutputFormat::Json => ui::print_json(&view),
            OutputFormat::Plain => match &view {
                InventoryView::Available(view) => print_human(view),
                InventoryView::Unavailable {
                    id, name, issues, ..
                } => {
                    let mut rows = vec![
                        ("Name".into(), name.clone()),
                        ("ID".into(), id.clone()),
                        ("State".into(), "unknown (configuration unavailable)".into()),
                    ];
                    append_issues(&mut rows, name, issues);
                    ui::print_detail_rows(&rows)
                }
            },
        }
    }
}

fn print_human(view: &MachineView) -> eyre::Result<()> {
    let mut rows = vec![
        ("Name".to_string(), view.name.clone()),
        ("ID".to_string(), view.id.clone()),
        ("State".to_string(), view.state.to_string()),
        ("Default".to_string(), ui::yes_no(view.default).to_string()),
        ("Retention".to_string(), view.retention.clone()),
        ("Agent mode".to_string(), view.agent_mode.clone()),
        ("Ready".to_string(), ui::yes_no(view.ready).to_string()),
        (
            "Durability".to_string(),
            match view.durability {
                libvm::MachineDurability::Constructed => "constructed",
                libvm::MachineDurability::Durable => "durable",
            }
            .to_string(),
        ),
        ("Guest".to_string(), view.guest.status.clone()),
        ("CPUs".to_string(), view.resources.cpus.to_string()),
        (
            "Memory".to_string(),
            ui::human_memory_mib(Some(view.resources.memory_mib)),
        ),
        ("Disk".to_string(), ui::human_bytes(view.root_disk_size)),
        ("Network".to_string(), view.network.name()),
        (
            "Template".to_string(),
            view.template_name
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ),
    ];

    if let Some(reclaim) = &view.host_memory_reclaim {
        rows.push(("Host memory reclaim".to_string(), reclaim.summary()));
    }
    if !view.image.is_empty() {
        rows.push(("Image".to_string(), view.image.clone()));
    }
    if let Some(tailscale) = &view.tailscale {
        rows.push((
            "Tailscale state".into(),
            tailscale.state_dir.display().to_string(),
        ));
        rows.push(("Tailscale hostname".into(), tailscale.hostname.clone()));
    }
    let pin = view.dir.join("ssh/known_host");
    if pin.exists() {
        let key = ssh_key::PublicKey::from_openssh(&std::fs::read_to_string(pin)?)?;
        rows.push((
            "SSH host key".into(),
            key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        ));
    }
    rows.push(("Process".to_string(), process_summary(&view.process)));
    rows.push((
        "Rootfs".to_string(),
        view.rootfs
            .as_ref()
            .map(rootfs_summary)
            .unwrap_or_else(|| "none".to_string()),
    ));
    if let Some(boot) = &view.boot {
        rows.push(("Platform".to_string(), platform_summary(boot)));
        rows.push(("Boot bundle".to_string(), bundle_summary(boot)));
        if let Some(replacement) = &boot.packaged_replacement {
            rows.push((
                "Boot update".to_string(),
                format!(
                    "{replacement} available; apply with `silo set {} boot-assets=packaged`",
                    view.name
                ),
            ));
        }
    }
    rows.push((
        "User".to_string(),
        view.guest
            .settings
            .user
            .as_ref()
            .map(|user| format!("{} ({}:{}, {})", user.name, user.uid, user.gid, user.home))
            .unwrap_or_else(|| "none".to_string()),
    ));
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

    rows.push(("Observation".into(), format!("{:?}", view.observation)));
    if let Some(state) = view.last_known_state {
        rows.push(("Last known state".into(), state.into()));
    }
    if let Some(error) = &view.last_error {
        rows.push(("Last failure".into(), error.clone()));
    }
    if let Some(run) = &view.run_id {
        rows.push(("Run".into(), run.clone()));
    }
    if let Some(current) = &view.lifecycle {
        if let Some(pause) = &current.lifecycle.current_pause {
            rows.push(("Pause operation".into(), pause.operation_id.to_string()));
            rows.push((
                "Pause generation".into(),
                pause.token.generation.to_string(),
            ));
            rows.push((
                "Pause owner".into(),
                match &pause.token.owner {
                    vm_spec::lifecycle::PauseOwner::User => "user".into(),
                    vm_spec::lifecycle::PauseOwner::Capture { operation_id } => {
                        format!("capture({operation_id})")
                    }
                },
            ));
        }
        if let Some(activity) = &current.lifecycle.activity {
            rows.push(("Live operation".into(), activity.operation_id.to_string()));
            rows.push(("Live stage".into(), activity.stage.to_string()));
        }
        if let Some(error) = &current.lifecycle.error {
            rows.push(("Live failure".into(), error.to_string()));
        }
        if let Some(operation) = &current.operation {
            rows.push((
                "Original operation result".into(),
                operation.status().to_string(),
            ));
        }
    }
    if let Some(outcome) = view.storage_stop_outcome {
        let label = match outcome {
            libvm::StorageStopOutcome::Clean => "clean",
            libvm::StorageStopOutcome::Forced => "forced",
            libvm::StorageStopOutcome::Unknown => "unknown",
        };
        rows.push(("Last storage stop".into(), label.into()));
    }
    if let Some(live) = &view.live {
        crate::commands::system::append_live_rows(
            &mut rows,
            "Machine run",
            live.backend,
            live.lane,
            &live.live,
        );
    }
    if let Some(live) = &view.prospective_live {
        crate::commands::system::append_live_rows(
            &mut rows,
            "Next-start prospective host",
            live.backend,
            live.lane,
            &live.live,
        );
    }
    append_issues(&mut rows, &view.name, &view.issues);
    ui::print_detail_rows(&rows)
}

fn append_issues(rows: &mut Vec<(String, String)>, name: &str, issues: &[libvm::MachineIssue]) {
    for issue in issues {
        rows.push((
            format!("Issue ({:?})", issue.component),
            issue.message.clone(),
        ));
    }
    rows.push(("Monitor logs".into(), format!("silo logs {name}")));
    rows.push((
        "Network logs".into(),
        format!("silo logs {name} --stream network"),
    ));
}

fn process_summary(process: &libvm::ProcessConfig) -> String {
    format!(
        "entrypoint={:?} command={:?} cwd={:?} user={:?}",
        process.entrypoint, process.command, process.working_directory, process.user
    )
}

fn platform_summary(boot: &crate::view::MachineBootView) -> String {
    let rosetta = match boot.rosetta_intent {
        Some(true) => ", rosetta requested",
        Some(false) => ", rosetta disabled",
        None => "",
    };
    format!(
        "{} on {} kernel, translation {}{rosetta}; root {} ({})",
        boot.platform, boot.kernel_architecture, boot.translation, boot.root, boot.root_filesystem
    )
}

fn bundle_summary(boot: &crate::view::MachineBootView) -> String {
    match (&boot.bundle, &boot.abi) {
        (Some(bundle), Some(abi)) => {
            let agent = boot.agent.as_deref().unwrap_or("none");
            format!("{bundle} ({abi}; agent {agent})")
        }
        _ => "not pinned".to_string(),
    }
}

fn rootfs_summary(rootfs: &crate::view::MachineRootfsView) -> String {
    match &rootfs.selected_reference {
        Some(reference) => format!("{} ({reference})", rootfs.source_kind),
        None => format!("{} ({})", rootfs.source_kind, rootfs.requested_reference),
    }
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
