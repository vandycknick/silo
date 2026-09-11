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

/// Every service definition Silo writes carries this marker followed by the
/// installation ID, so a definition from an earlier (since removed) installation is
/// still recognisably Silo-owned rather than foreign.
const MARKER_PREFIX: &str = "Silo-Installation-ID: ";

fn marker(registration: &Registration) -> String {
    format!("{MARKER_PREFIX}{}", registration.installation_id)
}

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
    let started = chrono::Utc::now();
    native_start(&registration)?;
    wait_ready(paths, started, Duration::from_secs(120))
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
    tail_lines(&paths.log(), lines)
}

fn tail_lines(path: &Path, lines: usize) -> eyre::Result<String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut selected: Vec<_> = text.lines().rev().take(lines.min(10_000)).collect();
    selected.reverse();
    Ok(selected.join("\n"))
}

fn wait_ready(
    paths: &SystemPaths,
    since: chrono::DateTime<chrono::Utc>,
    timeout: Duration,
) -> eyre::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = status(paths)? {
            match status.phase {
                DaemonPhase::Ready => return Ok(()),
                // The daemon is alive and retrying with backoff; report what blocks it
                // and leave the service running.
                DaemonPhase::Failed => return Err(retrying_failure(status.last_error)),
                _ => {}
            }
        } else if let Some(error) = recent_failure(paths, since)? {
            // The daemon process itself exited, so its PID no longer corroborates the
            // status record and the service manager is relaunching it. Report the
            // failure instead of waiting out the timeout on a crash loop.
            return Err(startup_failure(paths, Some(error)));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!(
        "timed out waiting for readiness; the native service may still be running{}",
        native_log_tail(paths)
    )
}

pub(crate) fn wait_ready_locked(
    paths: &SystemPaths,
    since: chrono::DateTime<chrono::Utc>,
    timeout: Duration,
) -> eyre::Result<()> {
    wait_ready(paths, since, timeout)
}

/// Returns the failure recorded by a daemon generation that started after `since`,
/// regardless of whether that process is still alive.
fn recent_failure(
    paths: &SystemPaths,
    since: chrono::DateTime<chrono::Utc>,
) -> eyre::Result<Option<String>> {
    let mut observed_paths = paths.clone();
    if let Some(run_root) = crate::system::supervisor::last_run_root(paths)? {
        observed_paths.run_root = run_root;
    }
    let Some(status) = read_status(&observed_paths)? else {
        return Ok(None);
    };
    if status.phase != DaemonPhase::Failed {
        return Ok(None);
    }
    let Ok(updated_at) = chrono::DateTime::parse_from_rfc3339(&status.updated_at) else {
        return Ok(None);
    };
    if updated_at.with_timezone(&chrono::Utc) < since {
        return Ok(None);
    }
    Ok(Some(
        status
            .last_error
            .unwrap_or_else(|| "unknown failure".to_string()),
    ))
}

fn retrying_failure(error: Option<String>) -> eyre::Report {
    eyre::eyre!(
        "{}\n\nhint: the daemon keeps retrying in the background; check `silo daemon status`, then rerun `silo daemon up`",
        error.unwrap_or_else(|| "system daemon is not ready".to_string())
    )
}

/// Stops the service manager from relaunching a daemon process that keeps exiting,
/// then builds the error to report. The service stays enabled so the next login
/// retries it.
fn startup_failure(paths: &SystemPaths, error: Option<String>) -> eyre::Report {
    let error = error.unwrap_or_else(|| "unknown failure".to_string());
    let halted = match native_halt() {
        Ok(()) => String::new(),
        Err(halt) => format!("\n\nstopping the failing native service also failed: {halt:#}"),
    };
    eyre::eyre!(
        "system daemon exited during startup: {error}{halted}{}\n\nhint: the service was stopped until the next `silo daemon up` or login; see `silo daemon logs`",
        native_log_tail(paths)
    )
}

fn native_log_tail(paths: &SystemPaths) -> String {
    match tail_lines(&paths.native_log(), 5) {
        Ok(tail) if !tail.trim().is_empty() => {
            format!("\n\nrecent native service output:\n{tail}")
        }
        _ => String::new(),
    }
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
    let marker = marker(registration);
    let bytes = render_native(registration, &marker)?;
    if let Ok(existing) = std::fs::read(path) {
        if validate_existing_service(path, &existing, &bytes, &marker, native_pid()?.is_some())? {
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
    refresh_native_definition()
}

/// Returns `Ok(true)` when the definition on disk is already current, `Ok(false)` when
/// it is Silo-owned and may be replaced, and an error when it is foreign or in use.
fn validate_existing_service(
    path: &Path,
    existing: &[u8],
    desired: &[u8],
    marker: &str,
    running: bool,
) -> eyre::Result<bool> {
    if existing == desired {
        return Ok(true);
    }
    let text = String::from_utf8_lossy(existing);
    if !text.contains(MARKER_PREFIX) {
        bail!(
            "refusing to overwrite a native service definition not created by Silo at {}\n\nhint: move it away, then rerun `silo daemon up`",
            path.display()
        );
    }
    if running && text.contains(marker) {
        bail!("the native service definition changed while running; run `silo daemon down` first");
    }
    if running {
        bail!("a daemon from a previous Silo installation is still running; run `silo daemon down` first");
    }
    Ok(false)
}

fn verify_native_owned(registration: &Registration) -> eyre::Result<()> {
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
    if !String::from_utf8_lossy(&bytes).contains(MARKER_PREFIX) {
        bail!(
            "refusing to control a native service definition not created by Silo at {}",
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
const LAUNCHD_LABEL: &str = "io.silo.system";

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
    fn plist_path(path: &Path) -> eyre::Result<String> {
        path.to_str()
            .map(xml)
            .ok_or_else(|| eyre::eyre!("service path is not UTF-8"))
    }
    let executable = plist_path(&registration.executable)?;
    let config = plist_path(&registration.config_root.join("daemon/registration.json"))?;
    let native_log = plist_path(&registration.state_root.join("logs/daemon/native.log"))?;
    // Mirrors the systemd unit: restart only on failure, allow 90s for a graceful VM
    // shutdown before SIGKILL, run as a background process type, and keep created
    // files private. Process output goes to a file so panics and pre-status failures
    // are diagnosable; launchd has no journal for user agents.
    Ok(format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!-- {marker} -->\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "\t<key>Label</key>\n\t<string>{label}</string>\n",
            "\t<key>ProgramArguments</key>\n\t<array>\n",
            "\t\t<string>{executable}</string>\n",
            "\t\t<string>daemon</string>\n",
            "\t\t<string>serve</string>\n",
            "\t\t<string>--config</string>\n",
            "\t\t<string>{config}</string>\n",
            "\t</array>\n",
            "\t<key>RunAtLoad</key>\n\t<true/>\n",
            "\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n",
            "\t<key>ThrottleInterval</key>\n\t<integer>5</integer>\n",
            "\t<key>ExitTimeOut</key>\n\t<integer>90</integer>\n",
            "\t<key>ProcessType</key>\n\t<string>Background</string>\n",
            "\t<key>Umask</key>\n\t<integer>63</integer>\n",
            "\t<key>StandardOutPath</key>\n\t<string>{native_log}</string>\n",
            "\t<key>StandardErrorPath</key>\n\t<string>{native_log}</string>\n",
            "</dict>\n",
            "</plist>\n",
        ),
        marker = marker,
        label = LAUNCHD_LABEL,
        executable = executable,
        config = config,
        native_log = native_log,
    )
    .into_bytes())
}

#[cfg(target_os = "linux")]
fn reload_native() -> eyre::Result<()> {
    run(
        Command::new("systemctl").args(["--user", "daemon-reload"]),
        "reload systemd user manager",
    )
}
#[cfg(target_os = "linux")]
fn refresh_native_definition() -> eyre::Result<()> {
    reload_native()
}
#[cfg(target_os = "linux")]
fn native_halt() -> eyre::Result<()> {
    run(
        Command::new("systemctl").args(["--user", "stop", SERVICE_NAME]),
        "stop systemd user service",
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
fn launchd_domain() -> String {
    format!("gui/{}", nix::unistd::geteuid().as_raw())
}
#[cfg(target_os = "macos")]
fn launchd_target() -> String {
    format!("{}/{LAUNCHD_LABEL}", launchd_domain())
}
#[cfg(target_os = "macos")]
fn reload_native() -> eyre::Result<()> {
    // launchd reads the definition at bootstrap time; an unchanged file needs nothing.
    Ok(())
}
#[cfg(target_os = "macos")]
fn refresh_native_definition() -> eyre::Result<()> {
    // launchd keeps the definition it bootstrapped, so a rewritten plist only takes
    // effect after the loaded (stopped) service is booted out and bootstrapped again.
    native_unload()
}
#[cfg(target_os = "macos")]
fn native_start(registration: &Registration) -> eyre::Result<()> {
    let target = launchd_target();
    if let Some(parent) = registration
        .state_root
        .join("logs/daemon/native.log")
        .parent()
    {
        std::fs::create_dir_all(parent).context("create native service log directory")?;
    }
    run(
        Command::new("launchctl").args(["enable", &target]),
        "enable launchd service",
    )?;
    if native_loaded()? {
        return run(
            Command::new("launchctl").args(["kickstart", &target]),
            "start launchd service",
        );
    }
    let output = Command::new("launchctl")
        .arg("bootstrap")
        .arg(launchd_domain())
        .arg(&registration.native_service_path)
        .output()
        .context("load launchd service")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    bail!(
        "load launchd service failed: {stderr}{}",
        bootstrap_hint(&stderr)
    )
}
#[cfg(target_os = "macos")]
fn bootstrap_hint(stderr: &str) -> &'static str {
    if stderr.contains("Domain does not support specified action") || stderr.contains(": 125") {
        "\n\nhint: background execution of `silo` is turned off; allow it under System Settings > General > Login Items & Extensions > Allow in the Background, then rerun `silo daemon up`"
    } else if stderr.contains("Could not find domain") || stderr.contains("Domain does not exist") {
        "\n\nhint: the per-user launchd GUI domain is unavailable (for example over SSH without a logged-in session); use a normal login session or `silo daemon up --foreground`"
    } else {
        ""
    }
}
#[cfg(target_os = "macos")]
fn native_stop() -> eyre::Result<()> {
    run(
        Command::new("launchctl").args(["disable", &launchd_target()]),
        "disable launchd service",
    )?;
    native_unload()
}
#[cfg(target_os = "macos")]
fn native_halt() -> eyre::Result<()> {
    native_unload()
}
/// Boots the service out of the GUI domain if it is loaded, terminating a running
/// daemon gracefully (SIGTERM, then SIGKILL after `ExitTimeOut`). Leaves the enabled
/// state untouched.
#[cfg(target_os = "macos")]
fn native_unload() -> eyre::Result<()> {
    if !native_loaded()? {
        return Ok(());
    }
    let output = Command::new("launchctl")
        .args(["bootout", &launchd_target()])
        .output()
        .context("unload launchd service")?;
    if output.status.success()
        || String::from_utf8_lossy(&output.stderr).contains("Could not find service")
    {
        Ok(())
    } else {
        bail!(
            "unload launchd service failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}
#[cfg(target_os = "macos")]
fn launchd_print() -> eyre::Result<Option<String>> {
    // `launchctl print` writes "Could not find service" to stderr for an unloaded
    // service; capture rather than inherit it so the CLI output stays clean.
    let output = Command::new("launchctl")
        .args(["print", &launchd_target()])
        .output()
        .context("query launchd service")?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
}
#[cfg(target_os = "macos")]
fn native_loaded() -> eyre::Result<bool> {
    Ok(launchd_print()?.is_some())
}
#[cfg(target_os = "macos")]
fn native_pid() -> eyre::Result<Option<u32>> {
    let Some(text) = launchd_print()? else {
        return Ok(None);
    };
    Ok(text
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = ")?.parse().ok()))
}
#[cfg(target_os = "macos")]
fn native_enabled() -> eyre::Result<bool> {
    let output = Command::new("launchctl")
        .args(["print-disabled", &launchd_domain()])
        .output()?;
    if !output.status.success() {
        bail!(
            "query launchd enablement failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let needle = format!("\"{LAUNCHD_LABEL}\"");
    for line in String::from_utf8(output.stdout)?.lines() {
        if line.contains(&needle) {
            return Ok(!line.contains("=> true") && !line.contains("=> disabled"));
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
    fn recent_failure_is_attributed_by_time_regardless_of_liveness() {
        use crate::system::service::recent_failure;
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().to_path_buf();
        let paths = SystemPaths::new(root.clone(), root.clone(), root.clone(), root.clone(), root);
        let before = chrono::Utc::now() - chrono::Duration::seconds(30);
        let write = |phase: &str, updated_at: &str| {
            std::fs::create_dir_all(paths.status().parent().expect("parent")).expect("dir");
            std::fs::write(
                paths.status(),
                format!(
                    r#"{{"schema":1,"generation":"d823458f-090b-48c3-87d4-33daf76c0000","pid":1,"phase":"{phase}","machine_id":null,"run_id":null,"image_digest":null,"docker_socket":"/tmp/x.sock","updated_at":"{updated_at}","last_error":"boom","restart_count":0}}"#
                ),
            )
            .expect("status");
        };
        assert!(recent_failure(&paths, before).expect("missing").is_none());
        write("failed", "2000-01-01T00:00:00+00:00");
        assert!(recent_failure(&paths, before).expect("stale").is_none());
        write("failed", &chrono::Utc::now().to_rfc3339());
        assert_eq!(
            recent_failure(&paths, before).expect("fresh").as_deref(),
            Some("boom")
        );
        write("creating", &chrono::Utc::now().to_rfc3339());
        assert!(recent_failure(&paths, before)
            .expect("progressing")
            .is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_follows_platform_conventions() {
        use std::path::PathBuf;

        use crate::system::config::ResolvedSystemConfig;
        use crate::system::service::{render_native, Registration};

        let config: ResolvedSystemConfig = serde_json::from_value(serde_json::json!({
            "schema": 1,
            "engine": "docker",
            "image": "ghcr.io/example/system:dev",
            "cpus": 1,
            "memory_bytes": 1073741824,
            "root_size_bytes": 1073741824,
            "data_size_bytes": 1073741824,
            "shares": [],
            "publish_bind": "any",
            "compatibility_socket": "auto",
            "docker_socket": "/Users/me/.docker/run/silo.sock",
            "identity": "fnv1a64:0"
        }))
        .expect("config");
        let registration = Registration {
            schema: 1,
            executable: PathBuf::from("/Applications/Silo & Co/silo"),
            config_root: PathBuf::from("/Users/me/.config/silo"),
            data_root: PathBuf::from("/Users/me/.local/share/silo"),
            state_root: PathBuf::from("/Users/me/.local/state/silo"),
            image_root: PathBuf::from("/Users/me/.local/share/silo/images"),
            native_service_path: PathBuf::from(
                "/Users/me/Library/LaunchAgents/io.silo.system.plist",
            ),
            config,
            installation_id: uuid::Uuid::nil(),
        };
        let plist = String::from_utf8(
            render_native(&registration, "Silo-Installation-ID: test").expect("render"),
        )
        .expect("utf8");
        assert!(plist.contains("<string>/Applications/Silo &amp; Co/silo</string>"));
        assert!(plist.contains("<string>/Users/me/.config/silo/daemon/registration.json</string>"));
        assert!(plist.contains(
            "<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>"
        ));
        assert!(plist.contains("<key>ExitTimeOut</key>\n\t<integer>90</integer>"));
        assert!(plist.contains("<key>StandardErrorPath</key>\n\t<string>/Users/me/.local/state/silo/logs/daemon/native.log</string>"));
        assert!(plist.contains("<key>ProcessType</key>\n\t<string>Background</string>"));
        assert!(plist.contains("<key>Umask</key>\n\t<integer>63</integer>"));
        assert!(plist.contains("<!-- Silo-Installation-ID: test -->"));
    }

    #[test]
    fn foreign_and_changed_running_services_are_rejected() {
        use std::path::Path;

        use crate::system::service::MARKER_PREFIX;

        let path = Path::new("/tmp/service");
        let current = format!("{MARKER_PREFIX}current");
        let stale = format!("{MARKER_PREFIX}previous-installation");
        assert!(validate_existing_service(path, b"foreign", b"desired", &current, false).is_err());
        assert!(validate_existing_service(
            path,
            format!("{current} old").as_bytes(),
            format!("{current} new").as_bytes(),
            &current,
            true
        )
        .is_err());
        assert!(validate_existing_service(
            path,
            stale.as_bytes(),
            format!("{current} new").as_bytes(),
            &current,
            true
        )
        .is_err());
        assert!(!validate_existing_service(
            path,
            format!("{current} old").as_bytes(),
            format!("{current} new").as_bytes(),
            &current,
            false
        )
        .expect("stopped owned update"));
        // A definition left behind by a removed installation is Silo's to replace.
        assert!(!validate_existing_service(
            path,
            stale.as_bytes(),
            format!("{current} new").as_bytes(),
            &current,
            false
        )
        .expect("stale owned update"));
        assert!(validate_existing_service(
            path,
            format!("{current} same").as_bytes(),
            format!("{current} same").as_bytes(),
            &current,
            true
        )
        .expect("unchanged"));
    }
}
