use clap::Args;
use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use bento_core::{InstanceFile, VmSpec};
use bento_libvm::{LibVm, MachineRef, MachineStatus};
use bento_protocol::v1::LifecycleState;

use crate::constants::PROFILE_METADATA_KEY;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestConfigStatus {
    enabled: bool,
    bootstrap: bool,
    agent_port: Option<u32>,
    cidata_present: bool,
    shell_expected: bool,
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
        let machine = libvm.inspect(&machine_ref)?;
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": machine.spec.name,
                    "state": process_status_label(machine.status),
                    "profile": machine.metadata.get(PROFILE_METADATA_KEY),
                    "image": machine.image_ref,
                    "network": network_label(machine.spec.network.driver),
                    "created_at": machine.created_at,
                }))?
            );
            return Ok(());
        }

        println!("name: {}", machine.spec.name);
        if let Some(profile) = machine.metadata.get(PROFILE_METADATA_KEY) {
            println!("profile: {profile}");
        }
        if !machine.image_ref.is_empty() {
            println!("image: {}", machine.image_ref);
        }
        println!("network: {}", network_label(machine.spec.network.driver));
        print_process(machine.status);

        if !machine.status.is_running() {
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

        if !status.services.is_empty() {
            println!("services:");
            for service in status.services {
                println!(
                    "  - {} startup_required={} healthy={}",
                    service.name, service.startup_required, service.healthy,
                );
                if !service.summary.is_empty() {
                    println!("    summary: {}", service.summary);
                }
                for problem in service.problems {
                    println!("    problem: {}", problem);
                }
            }
        }

        if !status.vsock_endpoints.is_empty() {
            println!("vsock_endpoints:");
            for endpoint in status.vsock_endpoints {
                println!(
                    "  - {} port={} active={}",
                    endpoint.name, endpoint.port, endpoint.active
                );
                if !endpoint.summary.is_empty() {
                    println!("    summary: {}", endpoint.summary);
                }
                for problem in endpoint.problems {
                    println!("    problem: {}", problem);
                }
            }
        }

        Ok(())
    }
}

fn guest_config_status(spec: &VmSpec, machine_dir: &std::path::Path) -> GuestConfigStatus {
    let guest = spec.guest_agent();
    GuestConfigStatus {
        enabled: guest.is_some(),
        bootstrap: spec.boot.bootstrap.is_some(),
        agent_port: guest.map(|guest| guest.control_port),
        cidata_present: machine_dir
            .join(InstanceFile::CidataDisk.as_str())
            .is_file(),
        shell_expected: spec.guest_agent().is_some(),
    }
}

fn print_process(status: MachineStatus) {
    println!("process:");
    println!("  status: {}", process_status_label(status));
    if let Some(started_at) = process_started_at(status) {
        println!("  started_at: {}", started_at);
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
    println!("    enabled: {}", yes_no(config.enabled));
    println!("    bootstrap: {}", yes_no(config.bootstrap));
    match config.agent_port {
        Some(port) => println!("    agent_port: {}", port),
        None => println!("    agent_port: none"),
    }
    println!("    cidata: {}", present_absent(config.cidata_present));
    println!("    shell_expected: {}", yes_no(config.shell_expected));
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

fn process_status_label(status: MachineStatus) -> &'static str {
    match status {
        MachineStatus::Running { .. } => "running",
        MachineStatus::Stopped => "stopped",
    }
}

fn process_started_at(status: MachineStatus) -> Option<String> {
    match status {
        MachineStatus::Running { started_at } => Some(relative_time(started_at, now_unix())),
        MachineStatus::Stopped => None,
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

fn network_label(driver: bento_core::NetworkDriver) -> &'static str {
    match driver {
        bento_core::NetworkDriver::Gvisor => "isolated",
        bento_core::NetworkDriver::None => "none",
        bento_core::NetworkDriver::VzNat => "vznat",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        guest_config_status, now_unix, process_started_at, process_status_label, relative_time,
    };
    use bento_core::{
        Architecture, Boot, GuestOs, GuestSpec, Network, NetworkDriver, Platform, Resources,
        Settings, Storage, VmSpec,
    };
    use bento_libvm::MachineStatus;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_spec(guest: Option<GuestSpec>, bootstrap: bool) -> VmSpec {
        VmSpec {
            version: 1,
            name: "devbox".to_string(),
            platform: Platform {
                guest_os: GuestOs::Linux,
                architecture: Architecture::Aarch64,
            },
            resources: Resources {
                cpus: 2,
                memory_mib: 1024,
            },
            boot: Boot {
                kernel: None,
                initramfs: None,
                kernel_cmdline: Vec::new(),
                bootstrap: bootstrap.then_some(bento_core::Bootstrap { cloud_init: None }),
            },
            storage: Storage { disks: Vec::new() },
            mounts: Vec::new(),
            vsock_endpoints: Vec::new(),
            network: Network {
                driver: NetworkDriver::Gvisor,
            },
            settings: Settings {
                nested_virtualization: false,
                rosetta: false,
            },
            guest,
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
    fn guest_config_status_reports_disabled_guest_without_agent_port() {
        let dir = temp_dir("disabled");
        fs::create_dir_all(&dir).expect("create temp dir");

        let config = guest_config_status(&sample_spec(None, false), &dir);

        assert!(!config.enabled);
        assert_eq!(config.agent_port, None);
        assert!(!config.cidata_present);
        assert!(!config.shell_expected);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn guest_config_status_reports_agent_port_and_cidata_when_present() {
        let dir = temp_dir("enabled");
        fs::create_dir_all(&dir).expect("create temp dir");
        fs::write(dir.join("cidata.img"), b"cidata").expect("write cidata marker");

        let config = guest_config_status(
            &sample_spec(Some(GuestSpec { control_port: 7001 }), false),
            &dir,
        );

        assert!(config.enabled);
        assert_eq!(config.agent_port, Some(7001));
        assert!(config.cidata_present);
        assert!(config.shell_expected);

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
        assert_eq!(process_status_label(MachineStatus::Stopped), "stopped");
        assert_eq!(process_started_at(MachineStatus::Stopped), None);

        let started = process_started_at(MachineStatus::Running {
            started_at: now_unix() - 60,
        })
        .expect("running machine should have started_at");
        assert!(!started.is_empty());
    }
}
