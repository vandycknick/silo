use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{BorrowedFd, FromRawFd};
use std::sync::Arc;

use bento_core::{InstanceFile, Network, VmSpec};
use bento_virt::VirtualMachine;
use eyre::Context;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::context::{DaemonContext, RuntimeContext};
use crate::machine::{machine_identifier_path_from_dir, vm_spec_machine_config, VmSpecInputs};
use crate::state::{new_instance_store, Action};

pub struct StartupReporter {
    file: Option<File>,
}

impl StartupReporter {
    pub fn from(startup_fd: Option<i32>) -> io::Result<Self> {
        match startup_fd {
            Some(fd) => Self::from_startup_fd(fd),
            None => Self::from_stdout(),
        }
    }

    fn from_startup_fd(fd: i32) -> io::Result<Self> {
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let flags =
            nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD).map_err(io::Error::other)?;
        let mut fd_flags = nix::fcntl::FdFlag::from_bits_retain(flags);
        fd_flags.insert(nix::fcntl::FdFlag::FD_CLOEXEC);
        nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_SETFD(fd_flags))
            .map_err(io::Error::other)?;

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

pub async fn init(runtime: &RuntimeContext, machine_id: &str) -> eyre::Result<DaemonContext> {
    let spec = load_spec(runtime)?;
    let network = load_network_runtime(runtime)?;

    tracing::info!(instance = %spec.name, "vmmon starting");
    remove_stale_socket(&runtime.file(InstanceFile::VmmonSocket))?;

    let machine_config = vm_spec_machine_config(VmSpecInputs {
        name: &spec.name,
        id: machine_id,
        data_dir: runtime.dir(),
        spec: &spec,
        network: &network,
    })?;
    let machine = VirtualMachine::new(machine_config.config)?;
    if let Some(machine_identifier) = machine_config.machine_identifier.as_ref() {
        if machine_identifier.was_generated() {
            let machine_identifier_path = machine_identifier_path_from_dir(runtime.dir());
            std::fs::write(machine_identifier_path, machine_identifier.bytes())?;
        }
    }

    let serial_console = machine.serial();
    let store = Arc::new(new_instance_store());

    store.dispatch(Action::vm_starting());
    machine.start().await?;
    store.dispatch(Action::vm_running());

    Ok(DaemonContext {
        spec,
        machine,
        serial_console,
        store,
        shutdown: CancellationToken::new(),
    })
}

#[derive(Debug, Deserialize)]
struct NetworkRuntimeFile {
    attachment: Network,
}

fn load_spec(runtime: &RuntimeContext) -> eyre::Result<VmSpec> {
    let config_path = runtime.file(InstanceFile::Config);
    let raw = std::fs::read_to_string(&config_path)
        .wrap_err_with(|| format!("read vm spec at {}", config_path.display()))?;
    serde_yaml_ng::from_str(&raw)
        .map_err(|err| eyre::eyre!("parse vm spec at {}: {}", config_path.display(), err))
}

fn load_network_runtime(runtime: &RuntimeContext) -> eyre::Result<Network> {
    let runtime_path = runtime.dir().join("net/runtime.json");
    let raw = match std::fs::read_to_string(&runtime_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Network::None),
        Err(err) => {
            return Err(err)
                .wrap_err_with(|| format!("read network runtime at {}", runtime_path.display()))
        }
    };
    let runtime: NetworkRuntimeFile = serde_json::from_str(&raw)
        .wrap_err_with(|| format!("parse network runtime at {}", runtime_path.display()))?;
    Ok(runtime.attachment)
}

fn remove_stale_socket(path: &std::path::Path) -> eyre::Result<()> {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err).context(format!("remove stale socket {}", path.display()));
        }
    }

    Ok(())
}
