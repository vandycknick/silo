use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{BorrowedFd, FromRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use eyre::Context;
use tokio_util::sync::CancellationToken;
use virt::VirtualMachine;
use vm_spec::VmSpec;

use crate::context::{DaemonContext, RuntimeContext};
use crate::machine::{
    machine_identifier_path_from_dir, vm_spec_machine_config, RuntimeNetwork, VmSpecInputs,
};
use crate::state::new_instance_store;
use protocol::v1::VmState;

pub const ENV_STARTPIPE: &str = "_VM_STARTPIPE";
pub const ENV_SYNCPIPE: &str = "_VM_SYNCPIPE";

#[derive(Clone, Copy, Debug)]
pub struct InheritedPipeFds {
    pub startpipe: Option<RawFd>,
    pub syncpipe: Option<RawFd>,
}

impl InheritedPipeFds {
    pub fn from_env() -> eyre::Result<Self> {
        Ok(Self {
            startpipe: parse_env_fd(ENV_STARTPIPE)?,
            syncpipe: parse_env_fd(ENV_SYNCPIPE)?,
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
        for fd in [self.startpipe, self.syncpipe].into_iter().flatten() {
            set_cloexec(fd, false).map_err(|err| eyre::eyre!("clear CLOEXEC on fd {fd}: {err}"))?;
        }
        Ok(())
    }
}

pub struct StartGate {
    file: Option<File>,
}

impl StartGate {
    pub fn from_fd(fd: Option<RawFd>) -> io::Result<Self> {
        match fd {
            Some(fd) => {
                set_cloexec(fd, true)?;
                let file = unsafe { File::from_raw_fd(fd) };
                Ok(Self { file: Some(file) })
            }
            None => Ok(Self { file: None }),
        }
    }

    pub async fn wait_for_release(&mut self) -> io::Result<()> {
        let Some(mut file) = self.file.take() else {
            return Ok(());
        };

        tokio::task::spawn_blocking(move || {
            let mut byte = [0_u8; 1];
            file.read_exact(&mut byte)
        })
        .await
        .map_err(|err| io::Error::other(format!("join startpipe wait task: {err}")))??;

        Ok(())
    }
}

pub struct SyncReporter {
    file: Option<File>,
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

    fn write_message(&mut self, message: &str) -> io::Result<()> {
        let Some(mut file) = self.file.take() else {
            return Ok(());
        };
        file.write_all(message.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

pub async fn init(
    runtime: &RuntimeContext,
    machine_id: &str,
    name: &str,
    network_args: &[String],
    agent_enabled: bool,
    start_gate: &mut StartGate,
) -> eyre::Result<DaemonContext> {
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
    })?;
    let machine = VirtualMachine::new(machine_config.config)?;
    if let Some(machine_identifier) = machine_config.machine_identifier.as_ref() {
        if machine_identifier.was_generated() {
            let machine_identifier_path = machine_identifier_path_from_dir(runtime.dir());
            std::fs::write(machine_identifier_path, machine_identifier.bytes())?;
        }
    }

    let serial_console = machine.serial();
    let canonical_machine_id = uuid::Uuid::parse_str(machine_id)
        .map_err(|error| eyre::eyre!("invalid machine UUID {machine_id}: {error}"))?
        .hyphenated()
        .to_string();
    let store = Arc::new(new_instance_store(
        canonical_machine_id,
        name.to_string(),
        guest_services_enabled,
    ));

    store.set_vm_state(VmState::Starting, "vm starting")?;
    start_gate.wait_for_release().await?;
    machine.start().await?;
    store.set_vm_state(VmState::Running, "vm running")?;

    Ok(DaemonContext {
        spec,
        guest_services_enabled,
        machine,
        serial_console,
        store,
        shutdown: CancellationToken::new(),
    })
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

fn set_cloexec(fd: RawFd, enabled: bool) -> io::Result<()> {
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
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use nix::unistd::pipe;

    use crate::machine::RuntimeNetwork;
    use crate::startup::{parse_network_arg, secure_machine_dir, StartGate, SyncReporter};

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

    #[tokio::test]
    async fn start_gate_waits_for_release_byte() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut gate = StartGate::from_fd(Some(read_fd.into_raw_fd())).expect("open start gate");

        let waiter = tokio::spawn(async move { gate.wait_for_release().await });

        let mut write_file = std::fs::File::from(write_fd);
        write_file.write_all(&[1]).expect("write release byte");
        drop(write_file);

        waiter
            .await
            .expect("join wait task")
            .expect("wait for release");
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
