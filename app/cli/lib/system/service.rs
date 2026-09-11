use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use eyre::{bail, Context as _};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};

use crate::config::GlobalConfig;
use crate::system::config::ResolvedSystemConfig;
use crate::system::provision::prepare_installation;
use crate::system::record::{load_record, write_record, SystemPaths};
use crate::system::supervisor::{read_status, DaemonPhase, DaemonStatus};

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "silo-system.service";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registration {
    pub(crate) schema: u32,
    pub(crate) executable: PathBuf,
    pub(crate) config_root: PathBuf,
    pub(crate) data_root: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) image_root: PathBuf,
    pub(crate) native_service_path: PathBuf,
    pub(crate) config: ResolvedSystemConfig,
    pub(crate) installation_id: uuid::Uuid,
}

impl Registration {
    pub(crate) fn paths(&self, run_root: PathBuf) -> SystemPaths {
        SystemPaths::new(
            self.config_root.clone(),
            self.data_root.clone(),
            self.state_root.clone(),
            run_root,
            self.image_root.clone(),
        )
    }

    pub(crate) fn global_config(&self) -> eyre::Result<GlobalConfig> {
        GlobalConfig::load_from_dir(self.config_root.clone())
    }
}

pub(crate) struct OperationLock {
    _file: Flock<File>,
}

impl OperationLock {
    pub(crate) fn acquire(path: &Path) -> eyre::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| eyre::eyre!("operation lock has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        Flock::lock(file, FlockArg::LockExclusive)
            .map(|file| Self { _file: file })
            .map_err(|(_, error)| error.into())
    }
}

fn prepare_registration(
    paths: &SystemPaths,
    config: ResolvedSystemConfig,
) -> eyre::Result<Registration> {
    reject_root()?;
    let installation = prepare_installation(paths, &config)?;
    let native_service_path = default_service_path(paths)?;
    let registration = Registration {
        schema: 1,
        executable: std::env::current_exe()?
            .canonicalize()
            .context("resolve stable Silo executable")?,
        config_root: paths.config_root.clone(),
        data_root: paths.data_root.clone(),
        state_root: paths.state_root.clone(),
        image_root: paths.image_root.clone(),
        native_service_path,
        config,
        installation_id: installation.installation_id,
    };
    if let Some(existing) = load_record::<Registration>(&paths.registration())? {
        if existing != registration && native_pid()?.is_some() {
            bail!("the running daemon registration differs; run `silo daemon down` before changing its executable or configuration");
        }
    }
    write_record(&paths.registration(), &registration)?;
    Ok(registration)
}

pub(crate) fn load_registration(path: &Path) -> eyre::Result<Registration> {
    load_optional_registration(path)?
        .ok_or_else(|| eyre::eyre!("registration does not exist: {}", path.display()))
}

pub(crate) fn load_optional_registration(path: &Path) -> eyre::Result<Option<Registration>> {
    if !path.is_absolute() {
        bail!("registration path must be absolute");
    }
    let Some(registration) = load_record::<Registration>(path)? else {
        return Ok(None);
    };
    if registration.schema != 1 {
        bail!("unsupported daemon registration schema");
    }
    Ok(Some(registration))
}

pub(crate) fn up(paths: &SystemPaths, config: ResolvedSystemConfig) -> eyre::Result<()> {
    let _lock = OperationLock::acquire(&paths.operation_lock())?;
    let registration = prepare_registration(paths, config)?;
    install_native(&registration)?;
    native_start(&registration)?;
    wait_ready(paths, Duration::from_secs(120))
}

pub(crate) fn down(registration: &Registration, paths: &SystemPaths) -> eyre::Result<()> {
    reject_root()?;
    let _lock = OperationLock::acquire(&paths.operation_lock())?;
    stop_locked(registration)
}

pub(crate) fn stop_locked(registration: &Registration) -> eyre::Result<()> {
    verify_native_owned(registration)?;
    native_stop()
}

pub(crate) fn start_locked(registration: &Registration) -> eyre::Result<()> {
    install_native(registration)?;
    native_start(registration)
}

pub(crate) fn is_enabled() -> eyre::Result<bool> {
    native_enabled()
}

pub(crate) fn status(paths: &SystemPaths) -> eyre::Result<Option<DaemonStatus>> {
    let mut observed_paths = paths.clone();
    if let Some(run_root) = crate::system::supervisor::last_run_root(paths)? {
        observed_paths.run_root = run_root;
    }
    let Some(status) = read_status(&observed_paths)? else {
        return Ok(None);
    };
    if native_pid()? == Some(status.pid)
        && crate::system::supervisor::status_owner_is_live(&observed_paths, &status)?
    {
        Ok(Some(status))
    } else {
        Ok(None)
    }
}

pub(crate) fn logs(paths: &SystemPaths, lines: usize) -> eyre::Result<String> {
    let bytes = match std::fs::read(paths.log()) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut selected: Vec<_> = text.lines().rev().take(lines.min(10_000)).collect();
    selected.reverse();
    Ok(selected.join("\n"))
}

fn wait_ready(paths: &SystemPaths, timeout: Duration) -> eyre::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = status(paths)? {
            match status.phase {
                DaemonPhase::Ready => return Ok(()),
                DaemonPhase::Failed => bail!(
                    "system daemon failed: {}",
                    status
                        .last_error
                        .unwrap_or_else(|| "unknown failure".to_string())
                ),
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("timed out waiting for readiness; the native service may still be running")
}

pub(crate) fn wait_ready_locked(paths: &SystemPaths, timeout: Duration) -> eyre::Result<()> {
    wait_ready(paths, timeout)
}

fn reject_root() -> eyre::Result<()> {
    if nix::unistd::geteuid().is_root() {
        bail!("the system daemon is a per-user service; rerun without sudo/root");
    }
    Ok(())
}

fn default_service_path(_paths: &SystemPaths) -> eyre::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let config_home = _paths
            .config_root
            .parent()
            .ok_or_else(|| eyre::eyre!("invalid Silo config root"))?;
        return Ok(config_home.join("systemd/user").join(SERVICE_NAME));
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| eyre::eyre!("HOME is required for launchd registration"))?;
        if !home.is_absolute() {
            bail!("HOME must be absolute: {}", home.display());
        }
        return Ok(home.join("Library/LaunchAgents/io.silo.system.plist"));
    }
    #[allow(unreachable_code)]
    Err(eyre::eyre!(
        "native user services are unsupported on this OS"
    ))
}

fn install_native(registration: &Registration) -> eyre::Result<()> {
    let path = &registration.native_service_path;
    let marker = format!("Silo-Installation-ID: {}", registration.installation_id);
    let bytes = render_native(registration, &marker)?;
    if let Ok(existing) = std::fs::read(path) {
        if validate_existing_service(&existing, &bytes, &marker, native_pid()?.is_some())? {
            return reload_native();
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("service path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".silo-service-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    use std::io::Write as _;
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    reload_native()
}

fn validate_existing_service(
    existing: &[u8],
    desired: &[u8],
    marker: &str,
    running: bool,
) -> eyre::Result<bool> {
    if existing == desired {
        return Ok(true);
    }
    if !String::from_utf8_lossy(existing).contains(marker) {
        bail!("refusing to overwrite a foreign native service definition");
    }
    if running {
        bail!("the native service definition changed while running; run `silo daemon down` first");
    }
    Ok(false)
}

fn verify_native_owned(registration: &Registration) -> eyre::Result<()> {
    let marker = format!("Silo-Installation-ID: {}", registration.installation_id);
    let bytes = match std::fs::read(&registration.native_service_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if native_pid()?.is_some() {
                bail!("native service is loaded but its owned definition is missing; refusing to stop an unverified service");
            }
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if !String::from_utf8_lossy(&bytes).contains(&marker) {
        bail!(
            "refusing to control foreign service file {}",
            registration.native_service_path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn render_native(registration: &Registration, marker: &str) -> eyre::Result<Vec<u8>> {
    Ok(format!(
        "# Managed by Silo\n# {marker}\n[Unit]\nDescription=Silo system VM manager\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nType=exec\nExecStart={} daemon serve --config {}\nRestart=on-failure\nRestartSec=5\nKillMode=mixed\nTimeoutStopSec=90\nUMask=0077\n\n[Install]\nWantedBy=default.target\n",
        systemd_arg(&registration.executable)?,
        systemd_arg(&registration.config_root.join("daemon/registration.json"))?
    ).into_bytes())
}

#[cfg(target_os = "linux")]
fn systemd_arg(path: &Path) -> eyre::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| eyre::eyre!("service path is not UTF-8"))?;
    if value.contains(['\n', '\r', '\0']) {
        bail!("invalid service path");
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('%', "%%")
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    ))
}

#[cfg(target_os = "macos")]
fn render_native(registration: &Registration, marker: &str) -> eyre::Result<Vec<u8>> {
    fn xml(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
    let executable = registration
        .executable
        .to_str()
        .ok_or_else(|| eyre::eyre!("service path is not UTF-8"))?;
    let config = registration.config_root.join("daemon/registration.json");
    let config = config
        .to_str()
        .ok_or_else(|| eyre::eyre!("service path is not UTF-8"))?;
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- {marker} -->\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>io.silo.system</string><key>ProgramArguments</key><array><string>{}</string><string>daemon</string><string>serve</string><string>--config</string><string>{}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer><key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer></dict></plist>\n", xml(executable), xml(config)).into_bytes())
}

#[cfg(target_os = "linux")]
fn reload_native() -> eyre::Result<()> {
    run(
        Command::new("systemctl").args(["--user", "daemon-reload"]),
        "reload systemd user manager",
    )
}
#[cfg(target_os = "linux")]
fn native_start(_registration: &Registration) -> eyre::Result<()> {
    run(
        Command::new("systemctl").args(["--user", "enable", "--now", SERVICE_NAME]),
        "enable/start systemd user service",
    )
}
#[cfg(target_os = "linux")]
fn native_stop() -> eyre::Result<()> {
    run(
        Command::new("systemctl").args(["--user", "disable", "--now", SERVICE_NAME]),
        "disable/stop systemd user service",
    )
}
#[cfg(target_os = "linux")]
fn native_pid() -> eyre::Result<Option<u32>> {
    let output = Command::new("systemctl")
        .args([
            "--user",
            "show",
            SERVICE_NAME,
            "--property=MainPID",
            "--value",
        ])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let pid = String::from_utf8(output.stdout)?.trim().parse::<u32>()?;
    Ok((pid != 0).then_some(pid))
}
#[cfg(target_os = "linux")]
fn native_enabled() -> eyre::Result<bool> {
    let output = Command::new("systemctl")
        .args(["--user", "is-enabled", SERVICE_NAME])
        .output()?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "enabled" | "enabled-runtime" | "linked" | "linked-runtime" => Ok(true),
        "disabled" | "not-found" | "masked" | "masked-runtime" | "static" => Ok(false),
        state if !output.status.success() && state.is_empty() => {
            bail!(
                "query systemd user-service enablement failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
        state => bail!("unsupported systemd enablement state {state:?}"),
    }
}

#[cfg(target_os = "macos")]
fn reload_native() -> eyre::Result<()> {
    Ok(())
}
#[cfg(target_os = "macos")]
fn native_start(registration: &Registration) -> eyre::Result<()> {
    let domain = format!("gui/{}", nix::unistd::geteuid().as_raw());
    let target = format!("{domain}/io.silo.system");
    run(
        Command::new("launchctl").args(["enable", &target]),
        "enable launchd service",
    )?;
    if Command::new("launchctl")
        .args(["print", &target])
        .status()?
        .success()
    {
        return run(
            Command::new("launchctl").args(["kickstart", &target]),
            "start launchd service",
        );
    }
    run(
        Command::new("launchctl")
            .arg("bootstrap")
            .arg(&domain)
            .arg(&registration.native_service_path),
        "load launchd service",
    )?;
    Ok(())
}
#[cfg(target_os = "macos")]
fn native_stop() -> eyre::Result<()> {
    let target = format!("gui/{}/io.silo.system", nix::unistd::geteuid().as_raw());
    run(
        Command::new("launchctl").args(["disable", &target]),
        "disable launchd service",
    )?;
    if !Command::new("launchctl")
        .args(["print", &target])
        .status()?
        .success()
    {
        return Ok(());
    }
    let output = Command::new("launchctl")
        .args(["bootout", &target])
        .output()?;
    if output.status.success()
        || String::from_utf8_lossy(&output.stderr).contains("Could not find service")
    {
        Ok(())
    } else {
        bail!(
            "stop launchd service failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}
#[cfg(target_os = "macos")]
fn native_pid() -> eyre::Result<Option<u32>> {
    let target = format!("gui/{}/io.silo.system", nix::unistd::geteuid().as_raw());
    let output = Command::new("launchctl")
        .args(["print", &target])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout)?;
    Ok(text
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = ")?.parse().ok()))
}
#[cfg(target_os = "macos")]
fn native_enabled() -> eyre::Result<bool> {
    let domain = format!("gui/{}", nix::unistd::geteuid().as_raw());
    let output = Command::new("launchctl")
        .args(["print-disabled", &domain])
        .output()?;
    if !output.status.success() {
        bail!(
            "query launchd enablement failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    for line in String::from_utf8(output.stdout)?.lines() {
        if line.contains("\"io.silo.system\"") {
            return Ok(!line.contains("=> true"));
        }
    }
    Ok(true)
}

fn run(command: &mut Command, action: &str) -> eyre::Result<()> {
    let output = command.output().with_context(|| action.to_string())?;
    if !output.status.success() {
        bail!(
            "{action} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::system::record::SystemPaths;
    #[cfg(target_os = "linux")]
    use crate::system::service::systemd_arg;
    use crate::system::service::{logs, validate_existing_service};

    #[test]
    fn logs_are_bounded_by_requested_lines() {
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().to_path_buf();
        let paths = SystemPaths::new(root.clone(), root.clone(), root.clone(), root.clone(), root);
        std::fs::create_dir_all(paths.log().parent().expect("parent")).expect("directory");
        std::fs::write(paths.log(), "one\ntwo\nthree\n").expect("log");
        assert_eq!(logs(&paths, 2).expect("logs"), "two\nthree");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_paths_escape_spaces_percent_and_quotes() {
        use std::path::Path;

        assert_eq!(
            systemd_arg(Path::new("/tmp/Silo dir/100%/a\"b")).expect("escape"),
            "\"/tmp/Silo dir/100%%/a\\\"b\""
        );
    }

    #[test]
    fn foreign_and_changed_running_services_are_rejected() {
        assert!(
            validate_existing_service(b"foreign", b"desired", "installation-id", false).is_err()
        );
        assert!(validate_existing_service(
            b"installation-id old",
            b"installation-id new",
            "installation-id",
            true
        )
        .is_err());
        assert!(!validate_existing_service(
            b"installation-id old",
            b"installation-id new",
            "installation-id",
            false
        )
        .expect("stopped owned update"));
    }
}
