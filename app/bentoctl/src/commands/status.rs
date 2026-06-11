use clap::Args;
use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use bento_libvm::{LibVm, MachineRef, MachineRuntimeState};
use bento_protocol::v1::LifecycleState;
use bento_vm_spec::VmSpec;

use crate::constants::PROFILE_METADATA_KEY;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestConfigStatus {
    bootstrap: bool,
    initramfs_present: bool,
}

#[derive(Args, Debug)]
#[command(about = "Show VM status")]
pub struct Cmd {
    /// Name or ID of the VM to check.
    #[arg(value_name = "VM")]
    pub name: String,
    /// Output concise VM status as JSON.
    #[arg(long)]
    pub json: bool,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        let machine_ref = MachineRef::parse(self.name.clone())?;
        let machine = libvm.inspect(&machine_ref).await?;
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": machine.name,
                    "state": process_status_label(machine.state),
                    "profile": machine.metadata.get(PROFILE_METADATA_KEY),
                    "image": machine.image_ref,
                    "network": machine.network.clone(),
                    "created_at": machine.created_at,
                }))?
            );
            return Ok(());
        }

        println!("name: {}", machine.name);
        if let Some(profile) = machine.metadata.get(PROFILE_METADATA_KEY) {
            println!("profile: {profile}");
        }
        if !machine.image_ref.is_empty() {
            println!("image: {}", machine.image_ref);
        }
        println!("network: {}", machine.network.name());
        print_process(machine.state, machine.started_at);

        if !machine.is_running() {
            print_guest(None, guest_config_status(&machine.spec, &machine.dir));
            println!("ready: no");
            return Ok(());
        }

        let status = libvm.get_status(&MachineRef::Id(machine.id)).await?;

        println!("vm: {}", lifecycle_label(status.vm_state));
        print_guest(
            Some((lifecycle_label(status.guest_state), status.ready)),
            guest_config_status(&machine.spec, &machine.dir),
        );
        println!("ready: {}", if status.ready { "yes" } else { "no" });
        if !status.summary.is_empty() {
            println!("summary: {}", status.summary);
        }

        Ok(())
    }
}

fn guest_config_status(spec: &VmSpec, machine_dir: &std::path::Path) -> GuestConfigStatus {
    GuestConfigStatus {
        bootstrap: spec
            .boot
            .as_ref()
            .and_then(|boot| boot.userdata.as_deref())
            .is_some(),
        initramfs_present: initramfs_path_exists(spec, machine_dir),
    }
}

fn initramfs_path_exists(spec: &VmSpec, machine_dir: &std::path::Path) -> bool {
    let Some(initramfs) = spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .and_then(|kernel| kernel.initramfs.as_deref())
    else {
        return false;
    };

    if initramfs.is_absolute() {
        initramfs.is_file()
    } else {
        machine_dir.join(initramfs).is_file()
    }
}

fn print_process(state: MachineRuntimeState, started_at: Option<i64>) {
    println!("process:");
    println!("  status: {}", process_status_label(state));
    if let Some(label) = process_started_at(state, started_at) {
        println!("  started_at: {}", label);
    }
}

fn print_guest(runtime: Option<(&str, bool)>, config: GuestConfigStatus) {
    println!("guest:");
    match runtime {
        Some((status, ready)) => {
            println!("  status: {}", status);
            println!("  ready: {}", yes_no(ready));
        }
        None => {
            println!("  status: stopped");
            println!("  ready: no");
        }
    }
    println!("  settings:");
    println!("    bootstrap: {}", yes_no(config.bootstrap));
    println!(
        "    initramfs: {}",
        present_absent(config.initramfs_present)
    );
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn present_absent(value: bool) -> &'static str {
    if value {
        "present"
    } else {
        "absent"
    }
}

fn process_status_label(state: MachineRuntimeState) -> &'static str {
    if state.is_running() {
        "running"
    } else {
        "stopped"
    }
}

fn process_started_at(state: MachineRuntimeState, started_at: Option<i64>) -> Option<String> {
    if state.is_running() {
        started_at.map(|started_at| relative_time(started_at, now_unix()))
    } else {
        None
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

fn lifecycle_label(raw: i32) -> &'static str {
    match LifecycleState::try_from(raw).unwrap_or(LifecycleState::Unspecified) {
        LifecycleState::Unspecified => "unspecified",
        LifecycleState::Starting => "starting",
        LifecycleState::Running => "running",
        LifecycleState::Stopping => "stopping",
        LifecycleState::Stopped => "stopped",
        LifecycleState::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        guest_config_status, now_unix, process_started_at, process_status_label, relative_time,
    };
    use bento_libvm::MachineRuntimeState;
    use bento_vm_spec::{Boot, Guest, GuestOs, Hardware, Kernel, Storage, VmSpec};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_spec(initramfs: bool, bootstrap: bool) -> VmSpec {
        VmSpec {
            guest: Some(Guest {
                os: Some(GuestOs::Linux),
            }),
            boot: Some(Boot {
                kernel: Some(Kernel {
                    path: None,
                    cmdline: Vec::new(),
                    initramfs: initramfs.then_some(std::path::PathBuf::from("initramfs")),
                }),
                userdata: bootstrap.then_some("#!/bin/sh\n".to_string()),
            }),
            hardware: Some(Hardware {
                cpus: Some(2),
                memory: Some(1024),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            }),
            storage: Some(Storage { disks: Vec::new() }),
            ..VmSpec::current()
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("bento-status-test-{name}-{now}"))
    }

    #[test]
    fn guest_config_status_reports_missing_initramfs() {
        let dir = temp_dir("missing-initramfs");
        fs::create_dir_all(&dir).expect("create temp dir");

        let config = guest_config_status(&sample_spec(false, false), &dir);

        assert!(!config.initramfs_present);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn guest_config_status_reports_initramfs_when_present() {
        let dir = temp_dir("enabled");
        fs::create_dir_all(&dir).expect("create temp dir");
        fs::write(dir.join("initramfs"), b"initramfs").expect("write initramfs marker");

        let config = guest_config_status(&sample_spec(true, false), &dir);

        assert!(config.initramfs_present);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_time_matches_list_style_formatting() {
        let now = 1_000_000;

        assert_eq!(relative_time(0, now), "N/A");
        assert_eq!(relative_time(now, now), "Less than a second ago");
        assert_eq!(relative_time(now - 30, now), "30 seconds ago");
        assert_eq!(relative_time(now - 60, now), "About a minute ago");
        assert_eq!(relative_time(now - 300, now), "5 minutes ago");
        assert_eq!(relative_time(now - 3600, now), "About an hour ago");
    }

    #[test]
    fn process_helpers_render_running_and_stopped_states() {
        assert_eq!(
            process_status_label(MachineRuntimeState::Stopped),
            "stopped"
        );
        assert_eq!(process_started_at(MachineRuntimeState::Stopped, None), None);

        let started = process_started_at(MachineRuntimeState::Running, Some(now_unix() - 60))
            .expect("running machine should have started_at");
        assert!(!started.is_empty());
    }
}
