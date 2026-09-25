//! Registration of silod with the native per-user service manager (launchd or
//! systemd), and the controller's view of the daemon it starts.
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use eyre::{bail, Context as _};
use nix::fcntl::{Flock, FlockArg};
use silod_spec::paths::DaemonPaths;
use silod_spec::status::{DaemonPhase, DaemonStatus};

use crate::ui::Spinner;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "silo-system.service";

/// Identifies a Silo-created service definition. Preserve the ID when rewriting it.
const MARKER_PREFIX: &str = "Silo-Installation-ID: ";

const MAX_STATUS_BYTES: u64 = 256 * 1024;

fn service_marker(existing: Option<&[u8]>) -> eyre::Result<String> {
    let id = if let Some(existing) = existing {
        let text = std::str::from_utf8(existing)?;
        let value = text
            .split_once(MARKER_PREFIX)
            .and_then(|(_, value)| value.split_whitespace().next())
            .ok_or_else(|| eyre::eyre!("native service definition was not created by Silo"))?;
        uuid::Uuid::parse_str(value).context("invalid Silo service registration ID")?
    } else {
        uuid::Uuid::new_v4()
    };
    Ok(format!("{MARKER_PREFIX}{id}"))
}

/// How the native service manager runs silod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceConfig {
    pub(crate) executable: PathBuf,
    pub(crate) native_service_path: PathBuf,
    pub(crate) paths: DaemonPaths,
}

impl ServiceConfig {
    pub(crate) fn new(paths: &DaemonPaths, executable: PathBuf) -> eyre::Result<Self> {
        Ok(Self {
            executable,
            native_service_path: native_service_path()?,
            paths: paths.clone(),
        })
    }
}

struct OperationLock {
    _file: Flock<File>,
}

impl OperationLock {
    fn acquire(path: &Path) -> eyre::Result<Self> {
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

/// Registers silod with `arguments`, starts it, and waits for its engine,
/// narrating each daemon phase on `spinner`.
pub(crate) fn up(
    service: &ServiceConfig,
    arguments: &[OsString],
    spinner: &mut Spinner,
) -> eyre::Result<()> {
    reject_root()?;
    let _lock = OperationLock::acquire(&service.paths.operation_lock())?;
    spinner.step("Registering", "silod service");
    install_native(service, arguments)?;
    let started = chrono::Utc::now();
    spinner.step("Starting", "silod");
    native_start(service)?;
    wait_ready(&service.paths, started, Duration::from_secs(120), spinner)
}

/// Disables the service, waits for silod to stop its VM and exit, then makes sure
/// no VM of the installation is left running, even if silod died first.
pub(crate) fn down(paths: &DaemonPaths, executable: &Path) -> eyre::Result<()> {
    reject_root()?;
    let mut spinner = Spinner::start("Stopping", "system daemon");
    let _lock = OperationLock::acquire(&paths.operation_lock())?;
    verify_native_owned(&native_service_path()?)?;
    native_stop()?;
    wait_for_exit(paths, Duration::from_secs(120))?;
    spinner.step("Stopping", "system VM");
    crate::daemon::stop_installation(executable)?;
    spinner.step("Stopped", "system daemon");
    spinner.finish_success("Stopped");
    Ok(())
}

/// silod holds its lifetime lock until it has stopped the VM and exits.
fn wait_for_exit(paths: &DaemonPaths, timeout: Duration) -> eyre::Result<()> {
    let deadline = Instant::now() + timeout;
    while !lifetime_lock_is_free(&paths.lifetime_lock())? {
        if Instant::now() >= deadline {
            bail!("timed out waiting for silod to stop the system VM; see `silo daemon logs`");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

fn lifetime_lock_is_free(path: &Path) -> eyre::Result<bool> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    match Flock::lock(file, FlockArg::LockSharedNonblock) {
        Ok(_released_on_drop) => Ok(true),
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(false),
        Err((_, error)) => Err(error).context("probe the silod lifetime lock"),
    }
}

pub(crate) fn is_enabled() -> eyre::Result<bool> {
    native_enabled()
}

/// The published status, when the silod that wrote it is the one the service
/// manager is running.
pub(crate) fn status(paths: &DaemonPaths) -> eyre::Result<Option<DaemonStatus>> {
    let Some(status) = read_status(paths) else {
        return Ok(None);
    };
    if native_pid()? == Some(status.pid) && status_owner_is_live(&status)? {
        Ok(Some(status))
    } else {
        Ok(None)
    }
}

/// Reads the published status. A file this binary cannot parse is treated as
/// absent rather than fatal: it is transient runtime state, and the PID and owner
/// checks that follow decide whether anything is actually running.
fn read_status(paths: &DaemonPaths) -> Option<DaemonStatus> {
    use std::io::Read as _;
    let file = File::open(paths.status()).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_STATUS_BYTES).read_to_end(&mut bytes).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn status_owner_is_live(status: &DaemonStatus) -> eyre::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        Ok(silod_spec::process::start_time(status.pid)?.as_deref()
            == Some(status.process_start.as_str()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = status;
        Ok(true)
    }
}

pub(crate) fn logs(paths: &DaemonPaths, lines: usize) -> eyre::Result<String> {
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
    paths: &DaemonPaths,
    since: chrono::DateTime<chrono::Utc>,
    timeout: Duration,
    spinner: &mut Spinner,
) -> eyre::Result<()> {
    let mut readiness = StartupReadiness::new(timeout);
    loop {
        readiness
            .check_deadline()
            .map_err(|error| eyre::eyre!("{error}{}", native_log_tail(paths)))?;
        if let Some(status) = status(paths)? {
            let (label, target) = phase_step(&status);
            spinner.step(label, target);
            let ready = readiness.observe(status.phase, status.last_error)?;
            if let Some(error) = readiness.retry_announcement.take() {
                spinner.warn(format!("startup attempt failed, retrying: {error}"));
            }
            if ready {
                return Ok(());
            }
        } else if let Some(error) = recent_failure(paths, since)? {
            // The daemon process itself exited, so its PID no longer corroborates the
            // status record and the service manager is relaunching it. Report the
            // failure instead of waiting out the timeout on a crash loop.
            return Err(startup_failure(paths, Some(error)));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// What the spinner says while silod is in `status.phase`.
fn phase_step(status: &DaemonStatus) -> (&'static str, String) {
    match status.phase {
        DaemonPhase::PreparingStorage => ("Preparing", "installation storage".into()),
        DaemonPhase::Creating => ("Provisioning", "system VM".into()),
        DaemonPhase::StartingVm => ("Booting", "system VM".into()),
        DaemonPhase::WaitingGuest => ("Waiting", "for the guest agent".into()),
        DaemonPhase::ActivatingEngine => ("Activating", "Docker engine".into()),
        DaemonPhase::Retrying => (
            "Retrying",
            format!(
                "startup (attempt {})",
                status.restart_count.saturating_add(1)
            ),
        ),
        DaemonPhase::Degraded => ("Waiting", "for Docker to respond".into()),
        DaemonPhase::Upgrading => ("Upgrading", "system VM".into()),
        DaemonPhase::Ready => ("Ready", "system daemon".into()),
        DaemonPhase::Failed => ("Failed", "system daemon".into()),
        DaemonPhase::Stopping | DaemonPhase::Stopped => ("Stopping", "system daemon".into()),
    }
}

struct StartupReadiness {
    deadline: Instant,
    last_error: Option<String>,
    /// A retry error not reported yet; the caller takes and prints it.
    retry_announcement: Option<String>,
}

impl StartupReadiness {
    fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            last_error: None,
            retry_announcement: None,
        }
    }

    fn observe(&mut self, phase: DaemonPhase, error: Option<String>) -> eyre::Result<bool> {
        if let Some(error) = error {
            if self.last_error.as_ref() != Some(&error) && phase == DaemonPhase::Retrying {
                self.retry_announcement = Some(error.clone());
            }
            self.last_error = Some(error);
        }
        match phase {
            DaemonPhase::Ready => Ok(true),
            DaemonPhase::Failed => bail!(
                "system daemon failed: {}",
                self.last_error.as_deref().unwrap_or("unknown failure")
            ),
            DaemonPhase::Stopping | DaemonPhase::Stopped => {
                bail!("system daemon stopped before becoming ready")
            }
            _ => Ok(false),
        }
    }

    fn check_deadline(&self) -> eyre::Result<()> {
        if Instant::now() >= self.deadline {
            let detail = self
                .last_error
                .as_ref()
                .map(|error| format!("; last startup error: {error}"))
                .unwrap_or_default();
            bail!("timed out waiting for readiness{detail}\n\nhint: the native service may still be running; check `silo daemon status` and `silo daemon logs`");
        }
        Ok(())
    }
}

/// Returns the failure recorded by a daemon generation that started after `since`,
/// regardless of whether that process is still alive.
fn recent_failure(
    paths: &DaemonPaths,
    since: chrono::DateTime<chrono::Utc>,
) -> eyre::Result<Option<String>> {
    let Some(status) = read_status(paths) else {
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

/// Stops the service manager from relaunching a daemon process that keeps exiting,
/// then builds the error to report. The service stays enabled so the next login
/// retries it.
fn startup_failure(paths: &DaemonPaths, error: Option<String>) -> eyre::Report {
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

fn native_log_tail(paths: &DaemonPaths) -> String {
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

fn native_service_path() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| eyre::eyre!("HOME is required for the native user service"))?;
    if !home.is_absolute() {
        bail!("HOME must be absolute: {}", home.display());
    }
    #[cfg(target_os = "linux")]
    {
        let config_home = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
            Some(path) if !path.is_absolute() => bail!("XDG_CONFIG_HOME must be absolute"),
            Some(path) => path,
            None => home.join(".config"),
        };
        return Ok(config_home.join("systemd/user").join(SERVICE_NAME));
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(home.join("Library/LaunchAgents/io.silo.system.plist"));
    }
    #[allow(unreachable_code)]
    Err(eyre::eyre!(
        "native user services are unsupported on this OS"
    ))
}

fn install_native(service: &ServiceConfig, arguments: &[OsString]) -> eyre::Result<()> {
    let path = &service.native_service_path;
    let existing = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let marker = service_marker(existing.as_deref())?;
    let bytes = render_native(service, &marker, arguments)?;
    if let Some(existing) = existing {
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

fn verify_native_owned(native_service_path: &Path) -> eyre::Result<()> {
    let bytes = match std::fs::read(native_service_path) {
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
            native_service_path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn render_native(
    service: &ServiceConfig,
    marker: &str,
    arguments: &[OsString],
) -> eyre::Result<Vec<u8>> {
    let command = std::iter::once(service.executable.as_os_str())
        .chain(arguments.iter().map(OsString::as_os_str))
        .map(|value| systemd_arg(Path::new(value)))
        .collect::<eyre::Result<Vec<_>>>()?
        .join(" ");
    Ok(format!(
        "# Managed by Silo\n# {marker}\n[Unit]\nDescription=Silo system VM manager\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nType=exec\nExecStart={}\nRestart=on-failure\nRestartSec=5\nKillMode=mixed\nTimeoutStopSec=90\nUMask=0077\n\n[Install]\nWantedBy=default.target\n",
        command
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
            .replace('$', "$$")
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    ))
}

#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "io.silo.system";

#[cfg(target_os = "macos")]
fn render_native(
    service: &ServiceConfig,
    marker: &str,
    arguments: &[OsString],
) -> eyre::Result<Vec<u8>> {
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
    let executable = plist_path(&service.executable)?;
    let native_log = plist_path(&service.paths.native_log())?;
    let arguments = arguments
        .iter()
        .map(|value| {
            plist_path(Path::new(value)).map(|value| format!("\t\t<string>{value}</string>\n"))
        })
        .collect::<eyre::Result<Vec<_>>>()?
        .concat();
    // Mirrors the systemd unit: restart only on failure, allow 90s for a graceful VM
    // shutdown before SIGKILL, and keep created files private. Standard scheduling
    // avoids imposing background CPU/I/O restrictions on the VM's inherited policy.
    // Process output goes to a file so panics and pre-status failures are diagnosable;
    // launchd has no journal for user agents.
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
            "{arguments}",
            "\t</array>\n",
            "\t<key>RunAtLoad</key>\n\t<true/>\n",
            "\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n",
            "\t<key>ThrottleInterval</key>\n\t<integer>5</integer>\n",
            "\t<key>ExitTimeOut</key>\n\t<integer>90</integer>\n",
            "\t<key>ProcessType</key>\n\t<string>Standard</string>\n",
            "\t<key>Umask</key>\n\t<integer>63</integer>\n",
            "\t<key>StandardOutPath</key>\n\t<string>{native_log}</string>\n",
            "\t<key>StandardErrorPath</key>\n\t<string>{native_log}</string>\n",
            "</dict>\n",
            "</plist>\n",
        ),
        marker = marker,
        label = LAUNCHD_LABEL,
        executable = executable,
        arguments = arguments,
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
fn native_start(_service: &ServiceConfig) -> eyre::Result<()> {
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
fn native_start(service: &ServiceConfig) -> eyre::Result<()> {
    let target = launchd_target();
    libvm::HostPaths::ensure_log_dir(service.paths.home(), "daemon")
        .context("create native service log directory")?;
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
        .arg(&service.native_service_path)
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
    use std::path::PathBuf;

    use silod_spec::paths::DaemonPaths;
    use silod_spec::status::DaemonPhase;

    #[cfg(target_os = "linux")]
    use crate::daemon::service::systemd_arg;
    use crate::daemon::service::{
        lifetime_lock_is_free, logs, render_native, service_marker, validate_existing_service,
        ServiceConfig, StartupReadiness,
    };

    fn service(home: &std::path::Path, executable: &str) -> ServiceConfig {
        ServiceConfig {
            executable: PathBuf::from(executable),
            native_service_path: home.join("service"),
            paths: DaemonPaths::new(home.join(".silo")),
        }
    }

    #[test]
    fn service_definition_carries_only_explicit_arguments_and_a_stable_identity() {
        let temp = tempfile::tempdir().expect("temp");
        let service = service(temp.path(), "/opt/silo/bin/silod");
        let overrides = silod_spec::arguments::SystemOverrides {
            cpus: Some(10),
            additional_shares: Some(vec![silod_spec::arguments::Share {
                path: "/a & $b/100%".into(),
                read_only: false,
            }]),
            ..Default::default()
        };
        let marker = service_marker(None).expect("registration identity");
        let bytes = render_native(&service, &marker, &overrides.to_args()).expect("definition");
        assert_eq!(service_marker(Some(&bytes)).expect("preserve ID"), marker);
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("/opt/silo/bin/silod"));
        assert!(text.contains("--system-cpus"));
        assert!(text.contains("--system-share"));
        assert!(!text.contains("--system-memory"));
        assert!(!text.contains("--state"));
        assert!(!text.contains("daemon serve"));
        #[cfg(target_os = "macos")]
        assert!(text.contains("/a &amp; $b/100%"));
        #[cfg(target_os = "linux")]
        assert!(text.contains("/a & $$b/100%%"));
        assert!(!temp.path().join(".silo").exists());
        assert!(service_marker(Some(b"foreign service")).is_err());
    }

    #[test]
    fn lifetime_lock_probe_sees_a_running_daemon() {
        use nix::fcntl::{Flock, FlockArg};
        let temp = tempfile::tempdir().expect("temp");
        let path = temp.path().join("daemon.lock");
        assert!(lifetime_lock_is_free(&path).expect("absent"));
        let file = std::fs::File::create(&path).expect("lock file");
        let held = Flock::lock(file, FlockArg::LockExclusiveNonblock).expect("held");
        assert!(!lifetime_lock_is_free(&path).expect("held"));
        drop(held);
        assert!(lifetime_lock_is_free(&path).expect("released"));
    }

    #[test]
    fn every_phase_has_a_spinner_step_that_fits_the_label_column() {
        use crate::daemon::service::phase_step;
        let mut status: silod_spec::status::DaemonStatus =
            serde_json::from_value(serde_json::json!({
                "schema": 1, "generation": "d823458f-090b-48c3-87d4-33daf76c0000",
                "pid": 1, "phase": "ready", "machine_id": null, "run_id": null,
                "image_digest": null, "docker_socket": "/tmp/test.sock",
                "updated_at": "2026-01-01T00:00:00Z", "last_error": null, "restart_count": 2,
            }))
            .expect("status");
        for phase in [
            DaemonPhase::PreparingStorage,
            DaemonPhase::Creating,
            DaemonPhase::StartingVm,
            DaemonPhase::WaitingGuest,
            DaemonPhase::ActivatingEngine,
            DaemonPhase::Retrying,
            DaemonPhase::Ready,
            DaemonPhase::Degraded,
            DaemonPhase::Upgrading,
            DaemonPhase::Failed,
            DaemonPhase::Stopping,
            DaemonPhase::Stopped,
        ] {
            status.phase = phase;
            let (label, target) = phase_step(&status);
            assert!(label.len() <= 12, "{label}");
            assert!(!target.is_empty());
        }
        status.phase = DaemonPhase::Retrying;
        assert_eq!(phase_step(&status).1, "startup (attempt 3)");
    }

    #[test]
    fn startup_wait_survives_retry_and_completes_only_when_ready() {
        let mut wait = StartupReadiness::new(std::time::Duration::from_secs(120));
        for phase in [DaemonPhase::WaitingGuest, DaemonPhase::ActivatingEngine] {
            assert!(!wait.observe(phase, None).expect("starting"));
        }
        assert!(!wait
            .observe(DaemonPhase::Retrying, Some("systemd unavailable".into()))
            .expect("retry is not terminal"));
        assert_eq!(
            wait.retry_announcement.take().as_deref(),
            Some("systemd unavailable")
        );
        assert!(!wait
            .observe(DaemonPhase::Retrying, Some("systemd unavailable".into()))
            .expect("same retry"));
        assert_eq!(wait.retry_announcement, None, "announced once per error");
        wait.check_deadline().expect("retry leaves time to start");
        assert!(!wait
            .observe(DaemonPhase::Creating, None)
            .expect("next attempt"));
        assert!(!wait
            .observe(DaemonPhase::ActivatingEngine, None)
            .expect("activation"));
        assert!(wait.observe(DaemonPhase::Ready, None).expect("ready"));
    }

    #[test]
    fn startup_deadline_preserves_latest_retry_error_across_attempts() {
        let mut wait = StartupReadiness::new(std::time::Duration::ZERO);
        wait.observe(DaemonPhase::Retrying, Some("first failure".into()))
            .expect("retry");
        wait.observe(DaemonPhase::Retrying, Some("systemd unavailable".into()))
            .expect("retry");
        wait.observe(DaemonPhase::Creating, None)
            .expect("another attempt");
        let error = wait
            .check_deadline()
            .expect_err("deadline expired")
            .to_string();
        assert!(error.contains("timed out"));
        assert!(error.contains("systemd unavailable"));
        assert!(!error.contains("first failure"));
        assert!(error.contains("silo daemon status"));
    }

    #[test]
    fn startup_terminal_failure_and_shutdown_do_not_wait_for_deadline() {
        for phase in [
            DaemonPhase::Failed,
            DaemonPhase::Stopping,
            DaemonPhase::Stopped,
        ] {
            let mut wait = StartupReadiness::new(std::time::Duration::from_secs(120));
            assert!(wait
                .observe(phase, Some("terminal failure".into()))
                .is_err());
            wait.check_deadline().expect("failed before timeout");
        }
    }

    #[test]
    fn logs_are_bounded_by_requested_lines() {
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().to_path_buf();
        let paths = DaemonPaths::new(root);
        std::fs::create_dir_all(paths.log().parent().expect("parent")).expect("directory");
        std::fs::write(paths.log(), "one\ntwo\nthree\n").expect("log");
        assert_eq!(logs(&paths, 2).expect("logs"), "two\nthree");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_launches_silod_without_installation_arguments() {
        let temp = tempfile::tempdir().expect("temp");
        let service = service(temp.path(), "/opt/silo/bin/silod");
        let unit =
            String::from_utf8(render_native(&service, "test-installation", &[]).expect("render"))
                .expect("utf8");
        assert!(unit.contains(&format!(
            "ExecStart={}\n",
            systemd_arg(&service.executable).expect("escape")
        )));
        assert!(!unit.contains("--state"));
        assert!(!unit.contains("daemon serve"));
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
        use crate::daemon::service::recent_failure;
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().to_path_buf();
        let paths = DaemonPaths::new(root);
        let before = chrono::Utc::now() - chrono::Duration::seconds(30);
        let write = |phase: &str, updated_at: &str| {
            std::fs::create_dir_all(paths.status().parent().expect("parent")).expect("dir");
            std::fs::write(
                paths.status(),
                format!(
                    r#"{{"schema":1,"generation":"d823458f-090b-48c3-87d4-33daf76c0000","pid":1,"process_start":"test","phase":"{phase}","machine_id":null,"run_id":null,"image_digest":null,"docker_socket":"/tmp/x.sock","updated_at":"{updated_at}","last_error":"boom","restart_count":0}}"#
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
        write("retrying", &chrono::Utc::now().to_rfc3339());
        assert!(recent_failure(&paths, before)
            .expect("retry is not terminal")
            .is_none());
        write("creating", &chrono::Utc::now().to_rfc3339());
        assert!(recent_failure(&paths, before)
            .expect("progressing")
            .is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_follows_platform_conventions() {
        let service = ServiceConfig {
            executable: PathBuf::from("/Applications/Silo & Co/silod"),
            native_service_path: PathBuf::from(
                "/Users/me/Library/LaunchAgents/io.silo.system.plist",
            ),
            paths: DaemonPaths::for_user_home(std::path::Path::new("/Users/me")),
        };
        let plist = String::from_utf8(
            render_native(&service, "Silo-Installation-ID: test", &[]).expect("render"),
        )
        .expect("utf8");
        assert!(plist.contains("<string>/Applications/Silo &amp; Co/silod</string>"));
        assert!(!plist.contains("<string>serve</string>"));
        assert!(!plist.contains("--state"));
        assert!(!plist.contains("daemon.json"));
        assert!(plist.contains(
            "<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>"
        ));
        assert!(plist.contains("<key>ExitTimeOut</key>\n\t<integer>90</integer>"));
        assert!(plist.contains("<key>StandardErrorPath</key>\n\t<string>/Users/me/.silo/logs/daemon/native.log</string>"));
        assert!(plist.contains("<key>ProcessType</key>\n\t<string>Standard</string>"));
        assert!(plist.contains("<key>Umask</key>\n\t<integer>63</integer>"));
        assert!(plist.contains("<!-- Silo-Installation-ID: test -->"));
    }

    #[test]
    fn foreign_and_changed_running_services_are_rejected() {
        use std::path::Path;

        use crate::daemon::service::MARKER_PREFIX;

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
