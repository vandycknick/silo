use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{BorrowedFd, FromRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::virt::VirtualMachine;
use eyre::Context;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use vm_spec::VmSpec;

use crate::context::{DaemonContext, RuntimeContext};
use crate::machine::{
    machine_identifier_path_from_dir, vm_spec_machine_config, RuntimeNetwork, VmSpecInputs,
};
use crate::start_request::StartRequestPipe;
use crate::state::new_instance_store;
use protocol::v1::VmState;

pub const ENV_STARTPIPE: &str = "_VM_STARTPIPE";
pub const ENV_SYNCPIPE: &str = "_VM_SYNCPIPE";
pub const ENV_MACHINE_LOG_DIR: &str = "_VM_MACHINE_LOG_DIR";

#[derive(Clone, Copy, Debug)]
pub struct InheritedPipeFds {
    pub startpipe: Option<RawFd>,
    pub syncpipe: Option<RawFd>,
    pub machine_log_dir: Option<RawFd>,
}

impl InheritedPipeFds {
    pub fn from_env() -> eyre::Result<Self> {
        Ok(Self {
            startpipe: parse_env_fd(ENV_STARTPIPE)?,
            syncpipe: parse_env_fd(ENV_SYNCPIPE)?,
            machine_log_dir: parse_env_fd(ENV_MACHINE_LOG_DIR)?,
        })
    }

    pub fn require_for_daemon(self) -> eyre::Result<Self> {
        if self.startpipe.is_none() || self.syncpipe.is_none() {
            return Err(eyre::eyre!(
                "{ENV_STARTPIPE} and {ENV_SYNCPIPE} are required unless running with --foreground"
            ));
        }
        Ok(self)
    }

    #[cfg(target_os = "macos")]
    pub fn clear_cloexec(self) -> eyre::Result<()> {
        for fd in [self.startpipe, self.syncpipe, self.machine_log_dir]
            .into_iter()
            .flatten()
        {
            set_cloexec(fd, false).map_err(|err| eyre::eyre!("clear CLOEXEC on fd {fd}: {err}"))?;
        }
        Ok(())
    }
}

pub struct SyncReporter {
    file: Option<File>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupCommandLaunchFailure<'a> {
    reason: Option<i32>,
    message: Option<&'a str>,
}

impl SyncReporter {
    pub fn from_fd(sync_fd: Option<RawFd>) -> io::Result<Self> {
        match sync_fd {
            Some(fd) => Self::from_sync_fd(fd),
            None => Self::from_stdout(),
        }
    }

    fn from_sync_fd(fd: RawFd) -> io::Result<Self> {
        set_cloexec(fd, true)?;
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self { file: Some(file) })
    }

    fn from_stdout() -> io::Result<Self> {
        let borrowed = unsafe { BorrowedFd::borrow_raw(libc::STDOUT_FILENO) };
        let duplicated = nix::unistd::dup(borrowed).map_err(io::Error::other)?;
        let file = File::from(duplicated);
        Ok(Self { file: Some(file) })
    }

    pub fn report_started(&mut self) -> io::Result<()> {
        self.write_message("started\n")
    }

    pub fn report_failed(&mut self, message: &str) -> io::Result<()> {
        self.write_message(&format!("failed\t{message}\n"))
    }

    pub fn report_startup_command_launch_failed(
        &mut self,
        reason: Option<i32>,
        message: Option<&str>,
    ) -> io::Result<()> {
        let failure = serde_json::to_string(&StartupCommandLaunchFailure { reason, message })
            .map_err(io::Error::other)?;
        self.write_message(&format!("startup-command-launch-failed\t{failure}\n"))
    }

    fn write_message(&mut self, message: &str) -> io::Result<()> {
        let Some(mut file) = self.file.take() else {
            return Ok(());
        };
        file.write_all(message.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

pub(crate) struct InitInputs<'a> {
    pub(crate) machine_id: &'a str,
    pub(crate) machine_run_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) network_args: &'a [String],
    pub(crate) agent_enabled: bool,
    pub(crate) krun_path: &'a Path,
    pub(crate) serial_file: File,
}

pub(crate) struct InitResult {
    pub(crate) context: DaemonContext,
    pub(crate) startup_command: Option<crate::start_request::StartupCommand>,
}

pub async fn init(
    runtime: &RuntimeContext,
    inputs: InitInputs<'_>,
    start_request: &mut StartRequestPipe,
) -> eyre::Result<InitResult> {
    let InitInputs {
        machine_id,
        machine_run_id,
        name,
        network_args,
        agent_enabled,
        krun_path,
        serial_file,
    } = inputs;
    let start_request = start_request.read(machine_id, machine_run_id).await?;
    let spec = load_spec(runtime)?;
    let guest_services_enabled = agent_enabled;
    let network = parse_network_args(network_args)?;

    tracing::info!(
        instance = %name,
        machine_id,
        agent_enabled = guest_services_enabled,
        "vmmon starting"
    );
    secure_machine_dir(runtime.dir())?;
    remove_stale_socket(runtime.socket())?;

    let machine_config = vm_spec_machine_config(VmSpecInputs {
        name,
        id: machine_id,
        data_dir: runtime.dir(),
        spec: &spec,
        network: &network,
        guest_services_enabled,
        krun_path,
    })?;
    let machine =
        create_virtual_machine(start_request.virt_backend.as_ref(), machine_config.config)?;
    let serial_console = machine.serial();
    serial_console
        .add_sink(tokio::fs::File::from_std(serial_file))
        .await;
    if let Some(machine_identifier) = machine_config.machine_identifier.as_ref() {
        if machine_identifier.was_generated() {
            let machine_identifier_path = machine_identifier_path_from_dir(runtime.dir());
            std::fs::write(machine_identifier_path, machine_identifier.bytes())?;
        }
    }

    let machine_id = uuid::Uuid::parse_str(machine_id)
        .map_err(|error| eyre::eyre!("invalid machine UUID {machine_id}: {error}"))?;
    let machine_run_id = uuid::Uuid::parse_str(machine_run_id)
        .map_err(|error| eyre::eyre!("invalid machine run UUID {machine_run_id}: {error}"))?;
    let store = Arc::new(new_instance_store(
        machine_id.hyphenated().to_string(),
        name.to_string(),
        guest_services_enabled,
    ));

    store.set_vm_state(VmState::Starting, "vm starting")?;
    machine.start().await?;
    store.set_vm_state(VmState::Running, "vm running")?;

    Ok(InitResult {
        context: DaemonContext {
            machine_id,
            machine_run_id,
            guest_services_enabled,
            machine,
            serial_console,
            store,
            stop_requested: CancellationToken::new(),
            shutdown: CancellationToken::new(),
        },
        startup_command: start_request.startup_command,
    })
}

/// Construct the machine on the backend the start request selects; absent
/// selection means the platform default. Selecting "mock" in a vmmon built
/// without the mock-backend feature fails cleanly (surfaced on the syncpipe
/// as a start failure).
fn create_virtual_machine(
    virt_backend: Option<&crate::start_request::VirtBackendRequest>,
    config: crate::virt::VmConfig,
) -> eyre::Result<VirtualMachine> {
    match virt_backend {
        None => Ok(VirtualMachine::new(config)?),
        Some(backend) if backend.kind == "mock" => {
            #[cfg(feature = "mock-backend")]
            {
                let mut config = config;
                if let Some(scenario) = backend.scenario.as_ref() {
                    config.set_mock_scenario(scenario.clone());
                }
                Ok(VirtualMachine::with_backend(
                    crate::virt::BackendKind::Mock,
                    config,
                )?)
            }
            #[cfg(not(feature = "mock-backend"))]
            {
                let _ = config;
                Err(crate::virt::VirtError::UnsupportedBackend {
                    kind: "mock",
                    reason: "vmmon was built without the mock-backend feature".to_string(),
                }
                .into())
            }
        }
        Some(backend) => Err(eyre::eyre!(
            "start request selected unknown virt backend {:?}",
            backend.kind
        )),
    }
}

fn secure_machine_dir(path: &std::path::Path) -> eyre::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .context(format!("secure machine directory {}", path.display()))
}

fn load_spec(runtime: &RuntimeContext) -> eyre::Result<VmSpec> {
    let raw = std::fs::read_to_string(runtime.config())
        .wrap_err_with(|| format!("read vm spec at {}", runtime.config().display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| eyre::eyre!("parse vm spec at {}: {}", runtime.config().display(), err))
}

fn parse_network_args(values: &[String]) -> eyre::Result<RuntimeNetwork> {
    match values {
        [] => Ok(RuntimeNetwork::None),
        [value] => parse_network_arg(value),
        _ => Err(eyre::eyre!(
            "multiple --network attachments are not supported by this virt backend yet"
        )),
    }
}

fn parse_network_arg(value: &str) -> eyre::Result<RuntimeNetwork> {
    let parts = value.split(',').collect::<Vec<_>>();
    match parts.as_slice() {
        ["none"] => Ok(RuntimeNetwork::None),
        ["unixdg", path, mac] => Ok(RuntimeNetwork::UnixDatagram {
            path: PathBuf::from(path),
            mac: parse_key_value(mac, "mac")?.to_string(),
        }),
        _ => Err(eyre::eyre!("invalid --network value {value:?}")),
    }
}

fn parse_key_value<'a>(value: &'a str, key: &str) -> eyre::Result<&'a str> {
    let Some((actual_key, actual_value)) = value.split_once('=') else {
        return Err(eyre::eyre!("expected {key}=... in {value:?}"));
    };
    if actual_key != key || actual_value.is_empty() {
        return Err(eyre::eyre!("expected {key}=... in {value:?}"));
    }
    Ok(actual_value)
}

fn remove_stale_socket(path: &std::path::Path) -> eyre::Result<()> {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err).context(format!("remove stale socket {}", path.display()));
        }
    }

    Ok(())
}

fn parse_env_fd(name: &str) -> eyre::Result<Option<RawFd>> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|_| eyre::eyre!("{name} is not valid UTF-8"))?;
    if raw.is_empty() {
        return Err(eyre::eyre!("{name} is empty"));
    }
    let fd = raw
        .parse::<RawFd>()
        .map_err(|err| eyre::eyre!("parse {name}={raw:?}: {err}"))?;
    if fd < 0 {
        return Err(eyre::eyre!("{name} must be a non-negative fd"));
    }

    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD)
        .map_err(|err| eyre::eyre!("validate {name} fd {fd}: {err}"))?;

    Ok(Some(fd))
}

pub(crate) fn set_cloexec(fd: RawFd, enabled: bool) -> io::Result<()> {
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags =
        nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD).map_err(io::Error::other)?;
    let mut fd_flags = nix::fcntl::FdFlag::from_bits_retain(flags);
    if enabled {
        fd_flags.insert(nix::fcntl::FdFlag::FD_CLOEXEC);
    } else {
        fd_flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
    }
    nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_SETFD(fd_flags))
        .map_err(io::Error::other)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use nix::unistd::pipe;

    use crate::machine::RuntimeNetwork;
    use crate::startup::{parse_network_arg, secure_machine_dir, SyncReporter};

    #[tokio::test]
    async fn malformed_start_request_fails_before_vm_spec_or_vmm_construction() {
        use crate::context::RuntimeContext;
        use crate::start_request::StartRequestPipe;
        use crate::startup::{init, InitInputs};

        let directory =
            std::env::temp_dir().join(format!("silo-vmmon-order-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let serial_path = directory.join("serial.log");
        let serial_file = std::fs::File::create(&serial_path).expect("create serial file");
        let (read_fd, write_fd) = pipe().expect("create start pipe");
        let mut writer = std::fs::File::from(write_fd);
        std::io::Write::write_all(&mut writer, b"{invalid}\n").expect("write malformed request");
        drop(writer);
        let mut start_request = StartRequestPipe::from_fd(Some(read_fd.into_raw_fd()))
            .expect("open start request pipe");
        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let runtime = RuntimeContext::new(
            directory.clone(),
            directory.join("missing-vm-spec.json"),
            directory.join("vm.sock"),
        );
        let network = vec!["none".to_string()];
        let krun_path = directory.join("missing-krun");

        let result = init(
            &runtime,
            InitInputs {
                machine_id: &machine_id,
                machine_run_id: &run_id,
                name: "ordering-test",
                network_args: &network,
                agent_enabled: false,
                krun_path: &krun_path,
                serial_file,
            },
            &mut start_request,
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("malformed request must fail"),
        };

        assert!(error.to_string().contains("parse vmmon start request"));
        assert!(!error.to_string().contains("read vm spec"));
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[tokio::test]
    async fn identity_and_size_boundaries_are_enforced_before_vm_spec_or_vmm_construction() {
        use crate::start_request::{VMMON_START_REQUEST_MAX_BYTES, VMMON_START_REQUEST_VERSION};

        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let mismatch = encode_start_request(serde_json::json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": uuid::Uuid::new_v4().to_string(),
            "machineRunId": run_id,
        }));
        let mismatch_error = init_error_for_start_request(mismatch, &machine_id, &run_id).await;
        assert!(mismatch_error.contains("machineId does not match --id"));
        assert!(!mismatch_error.contains("read vm spec"));

        let base = serde_json::json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": uuid::Uuid::new_v4().to_string(),
                "process": {
                    "argv": ["true"],
                    "environment": [{"name": "VALUE", "value": ""}]
                }
            }
        });
        let base_len = encode_start_request(base.clone()).len();
        let mut exact = base.clone();
        exact["startupCommand"]["process"]["environment"][0]["value"] =
            serde_json::json!("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base_len));
        let exact_error =
            init_error_for_start_request(encode_start_request(exact), &machine_id, &run_id).await;
        assert!(exact_error.contains("read vm spec"));

        let mut oversized = base;
        oversized["startupCommand"]["process"]["environment"][0]["value"] =
            serde_json::json!("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base_len + 1));
        let oversized_error =
            init_error_for_start_request(encode_start_request(oversized), &machine_id, &run_id)
                .await;
        assert!(oversized_error.contains("exceeds 16777216 bytes"));
        assert!(!oversized_error.contains("read vm spec"));
    }

    async fn init_error_for_start_request(
        encoded: Vec<u8>,
        machine_id: &str,
        run_id: &str,
    ) -> String {
        use crate::context::RuntimeContext;
        use crate::start_request::StartRequestPipe;
        use crate::startup::{init, InitInputs};

        let directory = std::env::temp_dir().join(format!(
            "silo-vmmon-start-order-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let serial_file =
            std::fs::File::create(directory.join("serial.log")).expect("create serial file");
        let (read_fd, write_fd) = pipe().expect("create start pipe");
        let writer = tokio::task::spawn_blocking(move || {
            let mut writer = std::fs::File::from(write_fd);
            std::io::Write::write_all(&mut writer, &encoded).expect("write start request");
        });
        let mut start_request = StartRequestPipe::from_fd(Some(read_fd.into_raw_fd()))
            .expect("open start request pipe");
        let runtime = RuntimeContext::new(
            directory.clone(),
            directory.join("missing-vm-spec.json"),
            directory.join("vm.sock"),
        );
        let network = vec!["none".to_string()];
        let krun_path = directory.join("missing-krun");
        let result = init(
            &runtime,
            InitInputs {
                machine_id,
                machine_run_id: run_id,
                name: "start-order-test",
                network_args: &network,
                agent_enabled: false,
                krun_path: &krun_path,
                serial_file,
            },
            &mut start_request,
        )
        .await;
        writer.await.expect("join start request writer");
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("start request should fail before VM construction"),
        };
        std::fs::remove_dir_all(directory).expect("remove test directory");
        error
    }

    fn encode_start_request(value: serde_json::Value) -> Vec<u8> {
        let mut encoded = serde_json::to_vec(&value).expect("encode start request");
        encoded.push(b'\n');
        encoded
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inherited_pipes_survive_macos_self_spawn() {
        use std::os::fd::AsRawFd;

        use crate::startup::{set_cloexec, InheritedPipeFds};

        let (start_read, _start_write) = pipe().expect("create start pipe");
        let (_sync_read, sync_write) = pipe().expect("create sync pipe");
        set_cloexec(start_read.as_raw_fd(), true).expect("set start CLOEXEC");
        set_cloexec(sync_write.as_raw_fd(), true).expect("set sync CLOEXEC");

        InheritedPipeFds {
            startpipe: Some(start_read.as_raw_fd()),
            syncpipe: Some(sync_write.as_raw_fd()),
            machine_log_dir: None,
        }
        .clear_cloexec()
        .expect("preserve inherited pipes");

        for fd in [start_read.as_raw_fd(), sync_write.as_raw_fd()] {
            let flags = nix::fcntl::fcntl(
                unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
                nix::fcntl::FcntlArg::F_GETFD,
            )
            .expect("read fd flags");
            assert!(!nix::fcntl::FdFlag::from_bits_retain(flags)
                .contains(nix::fcntl::FdFlag::FD_CLOEXEC));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inherited_pipes_deliver_request_and_sync_across_exec() {
        use std::io::{Read as _, Write as _};
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};

        use crate::startup::InheritedPipeFds;

        let (start_read, start_write) = pipe().expect("create start pipe");
        let (sync_read, sync_write) = pipe().expect("create sync pipe");
        InheritedPipeFds {
            startpipe: Some(start_read.as_raw_fd()),
            syncpipe: Some(sync_write.as_raw_fd()),
            machine_log_dir: None,
        }
        .clear_cloexec()
        .expect("preserve inherited pipes");
        let script = format!(
            "IFS= read -r line <&{}; printf 'received:%s\\n' \"$line\" >&{}",
            start_read.as_raw_fd(),
            sync_write.as_raw_fd()
        );
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn inherited-fd child");
        drop(start_read);
        drop(sync_write);

        let mut writer = std::fs::File::from(start_write);
        writer
            .write_all(b"{\"version\":1}\n")
            .expect("write start request");
        drop(writer);
        let mut reader = std::fs::File::from(sync_read);
        let mut response = String::new();
        reader
            .read_to_string(&mut response)
            .expect("read sync response");

        assert!(child.wait().expect("wait for child").success());
        assert_eq!(response, "received:{\"version\":1}\n");
    }

    #[test]
    fn machine_directory_is_restricted_to_its_owner() {
        let directory =
            std::env::temp_dir().join(format!("silo-vmmon-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test machine directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))
            .expect("make legacy directory permissive");

        secure_machine_dir(&directory).expect("secure machine directory");

        assert_eq!(
            std::fs::metadata(&directory)
                .expect("machine directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::remove_dir(directory).expect("remove test machine directory");
    }

    #[test]
    fn sync_reporter_writes_started_once() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");

        reporter.report_started().expect("report started");

        let mut file = std::fs::File::from(read_fd);
        let mut message = String::new();
        file.read_to_string(&mut message).expect("read message");
        assert_eq!(message, "started\n");
    }

    #[test]
    fn sync_reporter_writes_failed_once() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");

        reporter.report_failed("vz failed").expect("report failure");

        let mut file = std::fs::File::from(read_fd);
        let mut message = String::new();
        file.read_to_string(&mut message).expect("read message");
        assert_eq!(message, "failed\tvz failed\n");
    }

    #[test]
    fn sync_reporter_writes_structured_startup_command_launch_failure() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut reporter =
            SyncReporter::from_fd(Some(write_fd.into_raw_fd())).expect("open sync reporter");

        reporter
            .report_startup_command_launch_failed(Some(1), Some("command was not found"))
            .expect("report startup command launch failure");

        let mut file = std::fs::File::from(read_fd);
        let mut message = String::new();
        file.read_to_string(&mut message).expect("read message");
        assert_eq!(
            message,
            "startup-command-launch-failed\t{\"reason\":1,\"message\":\"command was not found\"}\n"
        );
    }

    #[test]
    fn network_parser_rejects_unsupported_runtime_attachments() {
        assert!(parse_network_arg("vznat").is_err());
        assert!(parse_network_arg("unixstream,/tmp/net.sock,mac=02:00:00:00:00:01").is_err());
        assert!(parse_network_arg("tap,tap0,mac=02:00:00:00:00:01").is_err());
    }

    #[test]
    fn network_parser_accepts_supported_runtime_attachments() {
        assert_eq!(parse_network_arg("none").unwrap(), RuntimeNetwork::None);
        assert_eq!(
            parse_network_arg("unixdg,/tmp/net.sock,mac=02:00:00:00:00:01").unwrap(),
            RuntimeNetwork::UnixDatagram {
                path: PathBuf::from("/tmp/net.sock"),
                mac: "02:00:00:00:00:01".to_string()
            }
        );
    }
}
