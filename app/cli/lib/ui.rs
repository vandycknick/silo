use std::io::{IsTerminal, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use clap::builder::styling::{AnsiColor, Effects};
use clap::builder::Styles;
use console::{measure_text_width, style, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use libvm::{ImageProgress, ImageProgressReceiver};
use serde::Serialize;
use tokio::task::JoinHandle;

const BRAILLE_TICKS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⠋"];

/// One stderr sink and progress renderer per CLI subscriber, shared through
/// tracing's existing dispatch context rather than a second global registry.
pub(crate) struct LogWriter {
    progress: MultiProgress,
    output: std::io::Stderr,
}

impl LogWriter {
    pub(crate) fn new() -> Self {
        Self {
            progress: MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(10)),
            output: std::io::stderr(),
        }
    }
}

pub(crate) struct LogLineWriter<'a> {
    writer: &'a LogWriter,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogLineWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogLineWriter { writer: self }
    }
}

impl Write for LogLineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writer
            .progress
            .suspend(|| self.writer.output.lock().write(bytes))
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.writer
            .progress
            .suspend(|| self.writer.output.lock().write_all(bytes))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer
            .progress
            .suspend(|| self.writer.output.lock().flush())
    }
}

fn progress_renderer() -> MultiProgress {
    tracing::dispatcher::get_default(|dispatch| {
        dispatch
            .downcast_ref::<LogWriter>()
            .map(|writer| writer.progress.clone())
            .unwrap_or_else(|| {
                MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(10))
            })
    })
}

pub fn clap_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default())
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Red.on_default() | Effects::BOLD)
}

pub fn error_label() -> String {
    if should_style_stderr() {
        style("error:").red().bold().to_string()
    } else {
        "error:".to_string()
    }
}

pub fn should_style_stderr() -> bool {
    std::env::var_os("NO_COLOR").is_none() && Term::stderr().is_term()
}

pub fn stderr_is_interactive() -> bool {
    Term::stderr().is_term()
}

pub fn should_style_stdout() -> bool {
    std::env::var_os("NO_COLOR").is_none() && Term::stdout().is_term()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Plain,
    Json,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => f.write_str("plain"),
            Self::Json => f.write_str("json"),
        }
    }
}

/// Keep user-controlled names in the message, never in the spinner template.
pub(crate) fn live_operation_progress_words(
    stage: &libvm::LiveOperationProgress,
    source: &str,
) -> (&'static str, String) {
    use libvm::LiveOperationProgress;

    match stage {
        LiveOperationProgress::Admitting => ("Admitting", source.into()),
        LiveOperationProgress::PausingSource => ("Pausing", source.into()),
        LiveOperationProgress::CapturingMemory => ("Capturing memory", String::new()),
        LiveOperationProgress::CapturingDisks => ("Capturing disks", String::new()),
        LiveOperationProgress::CapturingExecution => ("Capturing execution", String::new()),
        LiveOperationProgress::VerifyingCapture => ("Verifying capture", String::new()),
        LiveOperationProgress::FinalizingCapture => ("Finalizing capture", String::new()),
        LiveOperationProgress::ResumingSource => ("Resuming", source.into()),
        LiveOperationProgress::PreservingSource => ("Leaving paused", source.into()),
        LiveOperationProgress::ComputingDiskIdentity => ("Hashing disk", String::new()),
        LiveOperationProgress::Publishing => ("Publishing snapshot", String::new()),
        LiveOperationProgress::PreparingChildStorage => ("Preparing child storage", String::new()),
        LiveOperationProgress::StartingChild { index, total, name } => {
            ("Starting child", format!("{index} of {total}: {name}"))
        }
        LiveOperationProgress::WaitingForAgent => ("Waiting for agent", String::new()),
        LiveOperationProgress::Done => ("Done", String::new()),
    }
}

pub fn print_json(value: &impl Serialize) -> eyre::Result<()> {
    write_json(&mut std::io::stdout().lock(), value)
}

pub(crate) fn write_json(out: &mut impl Write, value: &impl Serialize) -> eyre::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

#[derive(Debug)]
pub struct Spinner {
    pb: Option<ProgressBar>,
    mp: Option<MultiProgress>,
    start: Instant,
    target: String,
    quiet: bool,
    _echo_guard: Option<EchoGuard>,
}

#[cfg(unix)]
#[derive(Debug)]
struct EchoGuard {
    original: libc::termios,
    fd: i32,
}

#[cfg(not(unix))]
#[derive(Debug)]
struct EchoGuard;

pub struct PullProgressDisplay {
    mp: MultiProgress,
    header: ProgressBar,
    active_lines: Vec<ProgressBar>,
    state: PullProgressState,
    interactive: bool,
    _echo_guard: Option<EchoGuard>,
}

impl Spinner {
    pub fn start(label: &str, target: impl Into<String>) -> Self {
        let target = target.into();
        let is_tty = stderr_is_interactive();
        let (pb, mp, echo_guard) = if is_tty {
            let template = format!("   {{spinner}} {label:<12} {{msg}}");
            let style = ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template(&template)
                .unwrap_or_else(|_| ProgressStyle::default_spinner());
            let mp = progress_renderer();
            let pb = mp.add(ProgressBar::new_spinner().with_style(style));
            pb.set_message(target.clone());
            pb.enable_steady_tick(Duration::from_millis(80));
            (Some(pb), Some(mp), EchoGuard::acquire())
        } else {
            (None, None, None)
        };

        Self {
            pb,
            mp,
            start: Instant::now(),
            target,
            quiet: false,
            _echo_guard: echo_guard,
        }
    }

    pub fn quiet() -> Self {
        Self {
            pb: None,
            mp: None,
            start: Instant::now(),
            target: String::new(),
            quiet: true,
            _echo_guard: None,
        }
    }

    pub fn step(&mut self, label: &str, target: impl Into<String>) {
        let target = target.into();
        self.target = target.clone();
        if let Some(pb) = &self.pb {
            let template = format!("   {{spinner}} {label:<12} {{msg}}");
            if let Ok(style) = ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template(&template)
            {
                pb.set_style(style);
            }
            pb.set_message(target);
        }
    }

    pub fn finish_success(mut self, past_tense: &str) {
        self.clear();

        if !self.quiet {
            print_success(past_tense, &self.target, self.start.elapsed());
        }
    }

    /// Prints a warning above the spinner without tearing its line.
    pub fn warn(&self, message: impl AsRef<str>) {
        match &self.pb {
            Some(pb) => pb.suspend(|| warn(message)),
            None => warn(message),
        }
    }

    pub fn finish_clear(mut self) {
        self.clear();
    }

    fn clear(&mut self) {
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
            if let Some(mp) = &self.mp {
                mp.remove(&pb);
            }
        }
    }
}

/// Keep short operations quiet, but show progress for a slow operation without
/// cancelling or restarting it when the display delay expires. Noninteractive
/// callers receive no extra output.
pub(crate) async fn with_delayed_spinner<T, E>(
    operation: impl std::future::Future<Output = Result<T, E>>,
    delay: Duration,
    mut labels: tokio::sync::watch::Receiver<&'static str>,
    target: &str,
    past_tense: &str,
) -> Result<T, E> {
    let started = Instant::now();
    let delay = tokio::time::sleep(delay);
    tokio::pin!(operation, delay);
    let mut spinner: Option<Spinner> = None;
    let mut labels_open = true;
    loop {
        tokio::select! {
            biased;
            result = &mut operation => {
                if let Some(spinner) = spinner {
                    if result.is_ok() {
                        spinner.finish_success(past_tense);
                    } else {
                        spinner.finish_clear();
                    }
                }
                return result;
            }
            changed = labels.changed(), if labels_open => {
                if changed.is_err() {
                    labels_open = false;
                    continue;
                }
            }
            _ = &mut delay, if spinner.is_none() => {}
        }
        // A phase change (for example Ctrl+C forcing a stop) is shown
        // immediately, even if the initial quiet period has not elapsed.
        let label = *labels.borrow_and_update();
        if let Some(spinner) = &mut spinner {
            spinner.step(label, target);
        } else {
            let mut progress = if stderr_is_interactive() {
                Spinner::start(label, target)
            } else {
                Spinner::quiet()
            };
            progress.start = started;
            spinner = Some(progress);
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.clear();
    }
}

impl EchoGuard {
    #[cfg(unix)]
    fn acquire() -> Option<Self> {
        if !std::io::stdin().is_terminal() {
            return None;
        }

        let fd = std::io::stdin().as_raw_fd();
        let mut original: libc::termios = unsafe { std::mem::zeroed() };

        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }

        let mut modified = original;
        modified.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &modified) } != 0 {
            return None;
        }

        Some(Self { original, fd })
    }

    #[cfg(not(unix))]
    fn acquire() -> Option<Self> {
        None
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // `nix` termios support needs an additional feature in this crate; direct libc keeps the
        // progress UI self-contained while matching microsandbox's echo-restoration behavior.
        unsafe {
            libc::tcflush(self.fd, libc::TCIFLUSH);
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PullLayerActivity {
    #[default]
    Waiting,
    Downloading,
    Verifying,
    Unpacking,
    Done,
}

#[derive(Debug, Default)]
struct PullLayerState {
    digest: Option<String>,
    activity: PullLayerActivity,
    downloaded: u64,
    size: Option<u64>,
}

impl PullLayerState {
    fn label(&self, index: usize, total: usize) -> String {
        if let Some(hex) = self
            .digest
            .as_deref()
            .and_then(|digest| digest.strip_prefix("sha256:"))
        {
            if hex.len() >= 12 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return hex[..12].to_string();
            }
        }
        format!("layer {index}/{total}")
    }

    fn line(&self, index: usize, total: usize, width: usize) -> String {
        let label = self.label(index, total);
        let status = match self.activity {
            PullLayerActivity::Downloading => "downloading",
            PullLayerActivity::Verifying => "verifying",
            PullLayerActivity::Unpacking => "unpacking",
            PullLayerActivity::Waiting | PullLayerActivity::Done => return String::new(),
        };
        let message = if self.activity == PullLayerActivity::Unpacking {
            format!("{}", style(status).blue())
        } else {
            let bytes = match self.size {
                Some(size) => format!(
                    "{}/{}",
                    indicatif::HumanBytes(self.downloaded),
                    indicatif::HumanBytes(size)
                ),
                None => format!("{} downloaded", indicatif::HumanBytes(self.downloaded)),
            };
            format!("{bytes}  {}", style(status).magenta())
        };
        let base = format!("     {label}  {message}");
        let bar_width = width.saturating_sub(measure_text_width(&base) + 2).min(36);
        let line = if self.activity != PullLayerActivity::Unpacking && bar_width >= 4 {
            let filled = self.size.filter(|size| *size > 0).map_or(0, |size| {
                ((u128::from(self.downloaded.min(size)) * bar_width as u128) / u128::from(size))
                    as usize
            });
            format!(
                "     {label}  {}{}  {message}",
                style("━".repeat(filled)).magenta(),
                style("╌".repeat(bar_width - filled)).color256(238),
            )
        } else {
            base
        };
        console::truncate_str(&line, width, "").into_owned()
    }
}

#[derive(Debug, Clone, Copy)]
enum PullPhase {
    Resolving,
    Pulling,
    Checking,
    Cached,
    Building,
    Using,
    Writing,
    Saving,
    Pulled,
}

impl PullPhase {
    fn word(self) -> &'static str {
        match self {
            Self::Resolving => "Resolving",
            Self::Pulling => "Pulling",
            Self::Checking => "Checking",
            Self::Cached => "Cached",
            Self::Building => "Building",
            Self::Using => "Using",
            Self::Writing => "Writing",
            Self::Saving => "Saving",
            Self::Pulled => "Pulled",
        }
    }
}

struct PullProgressState {
    reference: String,
    phase: PullPhase,
    layers: Vec<PullLayerState>,
    total_download_bytes: Option<u64>,
    done: usize,
}

impl PullProgressState {
    fn new(reference: &str) -> Self {
        Self {
            reference: reference.to_string(),
            phase: PullPhase::Pulling,
            layers: Vec::new(),
            total_download_bytes: None,
            done: 0,
        }
    }

    fn layer_mut(&mut self, index: usize, total: usize) -> Option<&mut PullLayerState> {
        if total != self.layers.len() {
            return None;
        }
        index
            .checked_sub(1)
            .and_then(|index| self.layers.get_mut(index))
    }

    // A layer is done only once its unpack has ended. Ascending ApplyingLayer
    // events prove all lower indexes are done, including silent cached or repeated
    // layers. MaterializingRootfs (or Complete) proves every layer is done.
    // DownloadFinished and Skipped alone still leave unpacking work to do.
    fn finish_before(&mut self, end: usize) {
        self.done = self.done.max(end.min(self.layers.len()));
        for layer in self.layers.iter_mut().take(self.done) {
            layer.activity = PullLayerActivity::Done;
        }
    }

    fn handle_event(&mut self, event: ImageProgress) {
        match event {
            ImageProgress::ResolvingManifest { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Resolving;
            }
            ImageProgress::ResolvedManifest {
                image_ref,
                layer_count,
                total_download_bytes,
                ..
            } => {
                self.reference = image_ref;
                self.phase = PullPhase::Pulling;
                self.layers = (0..layer_count)
                    .map(|_| PullLayerState::default())
                    .collect();
                self.total_download_bytes = total_download_bytes;
                self.done = 0;
            }
            ImageProgress::CheckingCache { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Checking;
            }
            ImageProgress::CacheHit { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Cached;
            }
            ImageProgress::CacheMiss { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Building;
            }
            ImageProgress::UsingLocalDisk { image_ref } => {
                self.reference = image_ref;
                self.phase = PullPhase::Using;
            }
            ImageProgress::LayerDownloadStarted {
                index,
                total,
                digest,
                size_bytes,
            } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if layer.activity != PullLayerActivity::Done {
                        layer.digest = Some(digest);
                        layer.activity = PullLayerActivity::Downloading;
                        layer.size = size_bytes.or(layer.size);
                        layer.downloaded = layer.downloaded.min(layer.size.unwrap_or(u64::MAX));
                    }
                }
            }
            ImageProgress::LayerDownloadProgress {
                index,
                total,
                digest,
                downloaded_bytes,
                size_bytes,
            } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if layer.activity != PullLayerActivity::Done {
                        layer.digest = Some(digest);
                        layer.activity = PullLayerActivity::Downloading;
                        layer.size = size_bytes.or(layer.size);
                        layer.downloaded = layer
                            .downloaded
                            .max(downloaded_bytes)
                            .min(layer.size.unwrap_or(u64::MAX));
                    }
                }
            }
            ImageProgress::LayerDownloadVerifying {
                index,
                total,
                digest,
            } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if layer.activity != PullLayerActivity::Done {
                        layer.digest = Some(digest);
                        layer.activity = PullLayerActivity::Verifying;
                        layer.downloaded = layer.size.unwrap_or(layer.downloaded);
                    }
                }
            }
            ImageProgress::LayerDownloadFinished {
                index,
                total,
                digest,
            }
            | ImageProgress::LayerDownloadSkipped {
                index,
                total,
                digest,
            } => {
                if let Some(layer) = self.layer_mut(index, total) {
                    if layer.activity != PullLayerActivity::Done {
                        layer.digest = Some(digest);
                        layer.activity = PullLayerActivity::Waiting;
                        layer.downloaded = layer.size.unwrap_or(layer.downloaded);
                    }
                }
            }
            ImageProgress::ApplyingLayer {
                index,
                total,
                digest,
            } => {
                if total != self.layers.len() || index == 0 || index > total || index <= self.done {
                    return;
                }
                self.finish_before(index - 1);
                if let Some(layer) = self.layer_mut(index, total) {
                    layer.digest = digest.or_else(|| layer.digest.take());
                    layer.activity = PullLayerActivity::Unpacking;
                }
            }
            ImageProgress::MaterializingRootfs => {
                self.finish_before(self.layers.len());
                self.phase = PullPhase::Writing;
            }
            ImageProgress::PublishingRootfs => self.phase = PullPhase::Saving,
            ImageProgress::Complete => {
                self.finish_before(self.layers.len());
                self.phase = PullPhase::Pulled;
            }
        }
    }

    fn visible_layers(&self, cap: usize) -> impl Iterator<Item = (usize, &PullLayerState)> {
        self.layers
            .iter()
            .enumerate()
            .filter_map(|(index, layer)| {
                matches!(
                    layer.activity,
                    PullLayerActivity::Downloading
                        | PullLayerActivity::Verifying
                        | PullLayerActivity::Unpacking
                )
                .then_some((index + 1, layer))
            })
            .take(cap)
    }

    fn byte_totals(&self) -> (u64, u64) {
        let downloaded = self
            .layers
            .iter()
            .fold(0_u64, |sum, layer| sum.saturating_add(layer.downloaded));
        let total = self.total_download_bytes.unwrap_or_else(|| {
            self.layers.iter().fold(0_u64, |sum, layer| {
                sum.saturating_add(layer.size.unwrap_or(layer.downloaded))
            })
        });
        (downloaded.min(total), total)
    }

    fn header(&self, width: usize) -> String {
        let mut suffix = format!("  {}/{} layers", self.done, self.layers.len());
        let (downloaded, total) = self.byte_totals();
        if self.total_download_bytes.is_some() || total > 0 {
            suffix.push_str(&format!(
                "  {} / {}",
                indicatif::HumanBytes(downloaded),
                indicatif::HumanBytes(total)
            ));
        }
        let phase = format!("{:<12} ", self.phase.word());
        let reference_width =
            width.saturating_sub(measure_text_width(&phase) + measure_text_width(&suffix));
        let reference = console::truncate_str(&self.reference, reference_width, "");
        let message = format!("{phase}{reference}{suffix}");
        console::truncate_str(&message, width, "").into_owned()
    }
}

fn pull_layer_row_cap(rows: u16) -> usize {
    // Reserve one header row and one spare row to avoid scrolling on redraw.
    usize::from(rows.saturating_sub(2)).min(4)
}

impl PullProgressDisplay {
    pub fn new(reference: &str) -> Self {
        Self::new_inner(reference, false)
    }

    pub fn quiet(reference: &str) -> Self {
        Self::new_inner(reference, true)
    }

    fn new_inner(reference: &str, quiet: bool) -> Self {
        let interactive = !quiet && stderr_is_interactive();
        let mp = if interactive {
            progress_renderer()
        } else {
            MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
        };
        let header = mp.add(ProgressBar::new_spinner());
        header.enable_steady_tick(Duration::from_millis(80));
        let mut display = Self {
            mp,
            header,
            active_lines: Vec::new(),
            state: PullProgressState::new(reference),
            interactive,
            _echo_guard: if interactive {
                EchoGuard::acquire()
            } else {
                None
            },
        };
        display.draw();
        display
    }

    pub fn handle_event(&mut self, event: ImageProgress) {
        self.state.handle_event(event);
        self.draw();
    }

    fn draw(&mut self) {
        if !self.interactive {
            return;
        }
        let (rows, columns) = Term::stderr().size();
        // Leave the final column free so an exactly full line cannot wrap.
        let width = usize::from(columns).saturating_sub(1).max(1);
        let (template, header_prefix) = if width >= 5 {
            ("   {spinner} {msg}", 5)
        } else {
            ("{spinner}{msg}", 1)
        };
        self.header.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template(template)
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        self.header
            .set_message(self.state.header(width.saturating_sub(header_prefix)));
        let cap = pull_layer_row_cap(rows);
        let visible = self.state.visible_layers(cap);
        let mut count = 0;
        for (index, layer) in visible {
            if self.active_lines.len() == count {
                let line = self.mp.add(
                    ProgressBar::new_spinner().with_style(
                        ProgressStyle::default_spinner()
                            .template("{msg}")
                            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
                    ),
                );
                self.active_lines.push(line);
            }
            if let Some(line) = self.active_lines.get(count) {
                line.set_message(layer.line(index, self.state.layers.len(), width));
            }
            count += 1;
        }
        while self.active_lines.len() > count {
            if let Some(line) = self.active_lines.pop() {
                line.finish_and_clear();
                self.mp.remove(&line);
            }
        }
    }

    pub fn finish(self) {
        drop(self);
    }
}

impl Drop for PullProgressDisplay {
    fn drop(&mut self) {
        for line in &self.active_lines {
            line.finish_and_clear();
            self.mp.remove(line);
        }
        self.header.finish_and_clear();
        self.mp.remove(&self.header);
    }
}

pub fn watch_image_progress(
    reference: impl Into<String>,
    mut events: ImageProgressReceiver,
) -> JoinHandle<()> {
    let reference = reference.into();
    tokio::spawn(async move {
        let mut display = PullProgressDisplay::new(&reference);
        while let Some(event) = events.recv().await {
            display.handle_event(event);
        }
        display.finish();
    })
}

/// Ask a default-no question between progress phases, after consuming any spinner.
/// Noninteractive callers decline without reading input; EOF aborts the operation.
pub fn confirm(question: &str) -> std::io::Result<bool> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Ok(false);
    }
    confirm_with_io(
        question,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn confirm_with_io(
    question: &str,
    input: &mut impl std::io::BufRead,
    output: &mut impl Write,
) -> std::io::Result<bool> {
    let mut answer = String::new();
    loop {
        write!(output, "{question} [y/N]: ")?;
        output.flush()?;
        answer.clear();
        if input.read_line(&mut answer)? == 0 {
            writeln!(output)?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "confirmation cancelled: input closed",
            ));
        }
        let answer = answer.trim();
        if answer.is_empty()
            || answer.eq_ignore_ascii_case("n")
            || answer.eq_ignore_ascii_case("no")
        {
            return Ok(false);
        }
        if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
            return Ok(true);
        }
        writeln!(output, "Please answer yes or no (Enter selects no).")?;
    }
}

pub fn success(message: impl AsRef<str>) {
    let check = if should_style_stderr() {
        style("✓").green().to_string()
    } else {
        "✓".to_string()
    };
    eprintln!("   {check} {}", message.as_ref());
}

pub(crate) fn result_message(action: &str, target: &str, id: &str, elapsed: Duration) -> String {
    format!("{action:<12} {target} [{id}] {}", format_duration(elapsed))
}

pub(crate) fn secondary(message: impl AsRef<str>) {
    let message = message.as_ref();
    if should_style_stderr() {
        eprintln!("     {}", style(message).dim());
    } else {
        eprintln!("     {message}");
    }
}

pub fn hint(message: impl AsRef<str>) {
    let arrow = if should_style_stderr() {
        style("→").cyan().to_string()
    } else {
        "→".to_string()
    };
    eprintln!("   {arrow} {}", message.as_ref());
}

pub fn warn(message: impl AsRef<str>) {
    let label = if should_style_stderr() {
        style("warn:").yellow().bold().to_string()
    } else {
        "warn:".to_string()
    };
    eprintln!("{label} {}", message.as_ref());
}

fn print_success(past_tense: &str, target: &str, elapsed: Duration) {
    let check = if should_style_stderr() {
        style("✓").green().to_string()
    } else {
        "✓".to_string()
    };

    if elapsed > Duration::from_millis(500) {
        eprintln!(
            "   {check} {past_tense:<12} {target} {}",
            style(format_duration(elapsed)).dim()
        );
    } else {
        eprintln!("   {check} {past_tense:<12} {target}");
    }
}

pub(crate) fn format_duration(duration: Duration) -> String {
    if duration.as_secs() >= 60 {
        let minutes = duration.as_secs() / 60;
        let seconds = duration.as_secs() % 60;
        format!("({minutes}m {seconds}s)")
    } else {
        format!("({:.1}s)", duration.as_secs_f64())
    }
}

#[derive(Debug, Clone)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    pub fn add_row(&mut self, row: impl IntoIterator<Item = impl Into<String>>) {
        self.rows.push(row.into_iter().map(Into::into).collect());
    }

    pub fn print(&self) -> eyre::Result<()> {
        self.write_to(&mut std::io::stdout().lock(), should_style_stdout())
    }

    pub(crate) fn write_to(&self, out: &mut impl Write, styled: bool) -> eyre::Result<()> {
        let widths = self.column_widths();
        if !self.headers.is_empty() {
            let headers = if styled {
                self.headers
                    .iter()
                    .map(|header| style(header).cyan().bold().to_string())
                    .collect::<Vec<_>>()
            } else {
                self.headers.clone()
            };
            write_columns(out, &headers, &widths)?;
        }

        for row in &self.rows {
            write_columns(out, row, &widths)?;
        }
        Ok(())
    }

    fn column_widths(&self) -> Vec<usize> {
        let column_count = self
            .headers
            .len()
            .max(self.rows.iter().map(Vec::len).max().unwrap_or(0));
        let mut widths = vec![0; column_count];
        for (index, value) in self.headers.iter().enumerate() {
            widths[index] = widths[index].max(measure_text_width(value));
        }
        for row in &self.rows {
            for (index, value) in row.iter().enumerate() {
                widths[index] = widths[index].max(measure_text_width(value));
            }
        }
        widths
    }
}

pub fn print_detail_rows(rows: &[(impl AsRef<str>, impl AsRef<str>)]) -> eyre::Result<()> {
    let label_width = rows
        .iter()
        .map(|(label, _)| measure_text_width(label.as_ref()))
        .max()
        .unwrap_or(0);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for (label, value) in rows {
        let label = label.as_ref();
        let value = value.as_ref();
        write!(out, "{label}:")?;
        let padding = label_width.saturating_sub(measure_text_width(label)) + 2;
        for _ in 0..padding {
            write!(out, " ")?;
        }
        let mut lines = value.lines();
        writeln!(out, "{}", lines.next().unwrap_or_default())?;
        for line in lines {
            for _ in 0..label_width + 3 {
                write!(out, " ")?;
            }
            writeln!(out, "{line}")?;
        }
    }

    Ok(())
}

pub(crate) fn print_serialized_details(value: &impl Serialize) -> eyre::Result<()> {
    print_detail_rows(&serialized_detail_rows(value)?)
}

pub(crate) fn serialized_detail_rows(
    value: &impl Serialize,
) -> eyre::Result<Vec<(String, String)>> {
    fn append(rows: &mut Vec<(String, String)>, label: String, value: serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) if !fields.is_empty() => {
                for (key, value) in fields {
                    let key = if label.is_empty() {
                        key
                    } else {
                        format!("{label}.{key}")
                    };
                    append(rows, key, value);
                }
            }
            serde_json::Value::Array(items) if !items.is_empty() => {
                for (index, value) in items.into_iter().enumerate() {
                    append(rows, format!("{label}[{index}]"), value);
                }
            }
            serde_json::Value::String(value) => rows.push((label, value)),
            serde_json::Value::Bool(value) => rows.push((label, yes_no(value).into())),
            serde_json::Value::Number(value) => rows.push((label, value.to_string())),
            _ => rows.push((label, "-".into())),
        }
    }

    let mut rows = Vec::new();
    append(&mut rows, String::new(), serde_json::to_value(value)?);
    Ok(rows)
}

pub fn human_bytes(size: Option<u64>) -> String {
    size.map(utils::format_storage_size)
        .unwrap_or_else(|| "-".to_string())
}

pub fn human_memory_mib(memory_mib: Option<u32>) -> String {
    match memory_mib {
        Some(memory_mib) if memory_mib % 1024 == 0 => format!("{}G", memory_mib / 1024),
        Some(memory_mib) => format!("{memory_mib}M"),
        None => "-".to_string(),
    }
}

pub fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

pub fn now_unix() -> i64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// Formats whole-second timestamps using Docker's go-units HumanDuration rules.
///
/// Hour thresholds round to the nearest hour; the final year count truncates.
/// A zero timestamp is missing, and future timestamps have zero elapsed time.
pub fn relative_time(timestamp: i64, now: i64) -> String {
    if timestamp == 0 {
        return "N/A".to_string();
    }

    let seconds = now.saturating_sub(timestamp).max(0);

    if seconds < 1 {
        return "Less than a second ago".to_string();
    }
    if seconds == 1 {
        return "1 second ago".to_string();
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

    let hours = seconds / 3600 + i64::from(seconds % 3600 >= 1800);
    if hours == 1 {
        return "About an hour ago".to_string();
    }
    if hours < 48 {
        return format!("{hours} hours ago");
    }

    if hours < 24 * 7 * 2 {
        return format!("{} days ago", hours / 24);
    }
    if hours < 24 * 30 * 2 {
        return format!("{} weeks ago", hours / 24 / 7);
    }
    if hours < 24 * 365 * 2 {
        return format!("{} months ago", hours / 24 / 30);
    }

    format!("{} years ago", seconds / 3600 / 24 / 365)
}

pub fn format_unix(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}

fn write_columns(out: &mut impl Write, values: &[String], widths: &[usize]) -> eyre::Result<()> {
    for (index, width) in widths.iter().enumerate() {
        if index > 0 {
            write!(out, "  ")?;
        }
        let value = values.get(index).map(String::as_str).unwrap_or("");
        write!(out, "{value}")?;
        if index + 1 < widths.len() {
            let padding = width.saturating_sub(measure_text_width(value));
            for _ in 0..padding {
                write!(out, " ")?;
            }
        }
    }
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use libvm::ImageProgress;

    use crate::ui::{
        pull_layer_row_cap, relative_time, short_id, with_delayed_spinner, PullLayerActivity,
        PullLayerState, PullProgressDisplay, PullProgressState,
    };
    #[test]
    fn live_progress_words_describe_each_stage_without_changing_names() {
        use crate::ui::live_operation_progress_words;
        use libvm::LiveOperationProgress as Progress;

        for (stage, expected_label, expected_target) in [
            (Progress::Admitting, "Admitting", "archy"),
            (Progress::PausingSource, "Pausing", "archy"),
            (Progress::CapturingMemory, "Capturing memory", ""),
            (Progress::CapturingDisks, "Capturing disks", ""),
            (Progress::CapturingExecution, "Capturing execution", ""),
            (Progress::VerifyingCapture, "Verifying capture", ""),
            (Progress::FinalizingCapture, "Finalizing capture", ""),
            (Progress::ResumingSource, "Resuming", "archy"),
            (Progress::PreservingSource, "Leaving paused", "archy"),
            (Progress::ComputingDiskIdentity, "Hashing disk", ""),
            (Progress::Publishing, "Publishing snapshot", ""),
            (
                Progress::PreparingChildStorage,
                "Preparing child storage",
                "",
            ),
            (
                Progress::StartingChild {
                    index: 2,
                    total: 4,
                    name: "child {two}".into(),
                },
                "Starting child",
                "2 of 4: child {two}",
            ),
            (Progress::WaitingForAgent, "Waiting for agent", ""),
            (Progress::Done, "Done", ""),
        ] {
            assert_eq!(
                live_operation_progress_words(&stage, "archy"),
                (expected_label, expected_target.to_owned()),
            );
        }
        assert_eq!(
            live_operation_progress_words(&Progress::PausingSource, ""),
            ("Pausing", String::new()),
        );
    }

    #[cfg(unix)]
    #[test]
    fn tracing_writer_owns_stderr_not_stdout() {
        use std::os::fd::AsRawFd;
        use tracing_subscriber::fmt::MakeWriter;

        let writer = crate::ui::LogWriter::new();
        let event_writer = writer.make_writer();
        assert_eq!(
            event_writer.writer.output.as_raw_fd(),
            std::io::stderr().as_raw_fd()
        );
        assert_ne!(
            event_writer.writer.output.as_raw_fd(),
            std::io::stdout().as_raw_fd()
        );
    }

    #[test]
    fn progress_renderer_is_owned_by_the_current_subscriber() {
        let writer = crate::ui::LogWriter::new();
        let progress = writer.progress.clone();
        let subscriber =
            utils::logging::subscriber(utils::logging::Profile::Cli { verbosity: 0 }, writer);
        tracing::subscriber::with_default(subscriber, || {
            // Removing a bar through another renderer only works if both
            // handles point at the same actual indicatif state.
            let bar = crate::ui::progress_renderer().add(indicatif::ProgressBar::new_spinner());
            progress.remove(&bar);
            assert!(bar.is_hidden());
        });
    }

    #[test]
    fn confirmation_accepts_explicit_choices_and_defaults_to_no() {
        for (input, expected) in [
            ("\n", false),
            (" n \n", false),
            ("NO\n", false),
            ("y\n", true),
            (" YeS \n", true),
            ("perhaps\nyes\n", true),
            ("perhaps\nno\n", false),
        ] {
            assert_eq!(
                crate::ui::confirm_with_io("Continue?", &mut input.as_bytes(), &mut Vec::new())
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn confirmation_eof_aborts_instead_of_accepting_a_default() {
        for input in ["", "perhaps\n"] {
            let error =
                crate::ui::confirm_with_io("Continue?", &mut input.as_bytes(), &mut Vec::new())
                    .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn delayed_spinner_does_not_delay_fast_operations() {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            with_delayed_spinner(
                std::future::ready(Ok::<_, &str>(42)),
                std::time::Duration::from_secs(60),
                tokio::sync::watch::channel("Stopping").1,
                "vm",
                "Stopped",
            ),
        )
        .await
        .expect("fast operation should not wait for the spinner");
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn delayed_spinner_preserves_slow_results_without_restarting_work() {
        for expected in [Ok(42), Err("shutdown failed")] {
            let starts = std::cell::Cell::new(0);
            let operation = async {
                starts.set(starts.get() + 1);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                expected
            };
            let result = with_delayed_spinner(
                operation,
                std::time::Duration::ZERO,
                tokio::sync::watch::channel("Stopping").1,
                "vm",
                "Stopped",
            )
            .await;
            assert_eq!(result, expected);
            assert_eq!(starts.get(), 1);
        }
    }

    #[test]
    fn relative_time_matches_docker_boundaries() {
        let now = 2_000_000_000;
        for (seconds, expected) in [
            (-60, "Less than a second ago"),
            (0, "Less than a second ago"),
            (1, "1 second ago"),
            (2, "2 seconds ago"),
            (4, "4 seconds ago"),
            (5, "5 seconds ago"),
            (59, "59 seconds ago"),
            (60, "About a minute ago"),
            (119, "About a minute ago"),
            (120, "2 minutes ago"),
            (59 * 60, "59 minutes ago"),
            (60 * 60 - 1, "59 minutes ago"),
            (60 * 60, "About an hour ago"),
            (90 * 60 - 1, "About an hour ago"),
            (90 * 60, "2 hours ago"),
            (2 * 3600 - 1, "2 hours ago"),
            (2 * 3600, "2 hours ago"),
            (24 * 3600, "24 hours ago"),
            (47 * 3600, "47 hours ago"),
            (48 * 3600 - 1801, "47 hours ago"),
            (48 * 3600 - 1800, "2 days ago"),
            (48 * 3600 - 1, "2 days ago"),
            (48 * 3600, "2 days ago"),
            (3 * 86400 - 1801, "2 days ago"),
            (3 * 86400 - 1800, "3 days ago"),
            (7 * 86400, "7 days ago"),
            (14 * 86400 - 1801, "13 days ago"),
            (14 * 86400 - 1800, "2 weeks ago"),
            (14 * 86400 - 1, "2 weeks ago"),
            (14 * 86400, "2 weeks ago"),
            (21 * 86400 - 1801, "2 weeks ago"),
            (21 * 86400 - 1800, "3 weeks ago"),
            (56 * 86400, "8 weeks ago"),
            (60 * 86400 - 1801, "8 weeks ago"),
            (60 * 86400 - 1800, "2 months ago"),
            (60 * 86400 - 1, "2 months ago"),
            (60 * 86400, "2 months ago"),
            (90 * 86400 - 1801, "2 months ago"),
            (90 * 86400 - 1800, "3 months ago"),
            (360 * 86400, "12 months ago"),
            (365 * 86400, "12 months ago"),
            (730 * 86400 - 1801, "24 months ago"),
            (730 * 86400 - 1800, "1 years ago"),
            (730 * 86400 - 1, "1 years ago"),
            (730 * 86400, "2 years ago"),
            (3 * 365 * 86400 - 1, "2 years ago"),
            (3 * 365 * 86400, "3 years ago"),
        ] {
            assert_eq!(relative_time(now - seconds, now), expected, "{seconds}s");
        }
        assert_eq!(relative_time(0, now), "N/A");
        assert_eq!(relative_time(i64::MAX, i64::MIN), "Less than a second ago");
    }

    #[test]
    fn short_id_uses_first_eight_characters_when_available() {
        assert_eq!(short_id("1234567890abcdef"), "12345678");
        assert_eq!(short_id("1234"), "1234");
    }

    fn pull_state(total: usize, bytes: Option<u64>) -> PullProgressState {
        let mut state = PullProgressState::new("docker.io/nixos/nix:latest");
        state.handle_event(ImageProgress::ResolvedManifest {
            image_ref: state.reference.clone(),
            manifest_digest: "sha256:abcd".to_string(),
            layer_count: total,
            total_download_bytes: bytes,
        });
        state
    }

    fn download_started(index: usize, total: usize) -> ImageProgress {
        ImageProgress::LayerDownloadStarted {
            index,
            total,
            digest: format!("sha256:{index:064x}"),
            size_bytes: Some(100),
        }
    }

    #[test]
    fn pull_progress_bounds_concurrent_layers_and_finishes_silent_layers() {
        for cap in [0, 1, 2, 3, 4, 20] {
            let mut state = pull_state(69, Some(6900));
            let mut last_done = 0;
            for index in 2..=4 {
                state.handle_event(download_started(index, 69));
            }
            for index in 1..=69 {
                if index > 1 {
                    state.handle_event(ImageProgress::LayerDownloadVerifying {
                        index,
                        total: 69,
                        digest: format!("sha256:{index:064x}"),
                    });
                    state.handle_event(ImageProgress::LayerDownloadFinished {
                        index,
                        total: 69,
                        digest: format!("sha256:{index:064x}"),
                    });
                    if index + 3 <= 69 {
                        state.handle_event(download_started(index + 3, 69));
                    }
                }
                state.handle_event(ImageProgress::ApplyingLayer {
                    index,
                    total: 69,
                    digest: None,
                });
                let visible: Vec<_> = state.visible_layers(cap).map(|(index, _)| index).collect();
                assert_eq!(
                    visible,
                    (index..=(index + 3).min(69)).take(cap).collect::<Vec<_>>()
                );
                assert!(visible.len() <= cap);
                assert!(state.done >= last_done);
                assert_eq!(state.done, index - 1);
                last_done = state.done;
            }
            state.handle_event(ImageProgress::MaterializingRootfs);
            assert_eq!(state.done, 69);
            assert_eq!(state.visible_layers(cap).count(), 0);
            state.handle_event(ImageProgress::Complete);
            assert_eq!(state.done, 69);
        }
        let mut silent = pull_state(69, None);
        silent.handle_event(ImageProgress::Complete);
        assert_eq!(silent.done, 69);
        let mut empty = pull_state(0, None);
        empty.handle_event(ImageProgress::MaterializingRootfs);
        assert_eq!(empty.done, 0);
        assert_eq!(empty.byte_totals(), (0, 0));
    }

    #[test]
    fn pull_progress_interleaves_download_verification_and_unpacking() {
        let mut state = pull_state(4, Some(400));
        state.handle_event(download_started(1, 4));
        state.handle_event(download_started(2, 4));
        state.handle_event(ImageProgress::LayerDownloadProgress {
            index: 2,
            total: 4,
            digest: "sha256:bbbbbbbbbbbbbbbb".into(),
            downloaded_bytes: 75,
            size_bytes: Some(100),
        });
        state.handle_event(ImageProgress::LayerDownloadVerifying {
            index: 1,
            total: 4,
            digest: "sha256:aaaaaaaaaaaaaaaa".into(),
        });
        assert_eq!(state.layers[0].activity, PullLayerActivity::Verifying);
        assert_eq!(state.layers[0].downloaded, 100);
        assert_eq!(state.layers[1].activity, PullLayerActivity::Downloading);
        assert_eq!(state.layers[1].downloaded, 75);
        state.handle_event(ImageProgress::LayerDownloadFinished {
            index: 1,
            total: 4,
            digest: "sha256:aaaaaaaaaaaaaaaa".into(),
        });
        assert_eq!(
            state
                .visible_layers(4)
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
            [2]
        );
        assert_eq!(state.done, 0);
        state.handle_event(ImageProgress::ApplyingLayer {
            index: 1,
            total: 4,
            digest: None,
        });
        assert_eq!(state.layers[0].activity, PullLayerActivity::Unpacking);
        assert_eq!(state.layers[0].label(1, 4), "aaaaaaaaaaaa");
        assert_eq!(state.layers[1].downloaded, 75);
        // A complete partial download can go straight to verification.
        state.handle_event(ImageProgress::LayerDownloadVerifying {
            index: 3,
            total: 4,
            digest: "sha256:cccccccccccccccc".into(),
        });
        assert_eq!(state.layers[2].activity, PullLayerActivity::Verifying);
        state.handle_event(ImageProgress::LayerDownloadFinished {
            index: 3,
            total: 4,
            digest: "sha256:cccccccccccccccc".into(),
        });
        assert_eq!(state.layers[2].activity, PullLayerActivity::Waiting);
        assert_eq!(state.visible_layers(4).count(), 2);
    }

    #[test]
    fn pull_progress_counts_resumed_offsets_and_bounds_byte_totals() {
        let mut state = pull_state(2, Some(150));
        for (index, downloaded, size) in [(1, 60, Some(100)), (2, 80, None), (1, 500, Some(100))] {
            state.handle_event(ImageProgress::LayerDownloadProgress {
                index,
                total: 2,
                digest: format!("sha256:{index:064x}"),
                downloaded_bytes: downloaded,
                size_bytes: size,
            });
        }
        assert_eq!(state.layers[0].downloaded, 100);
        assert_eq!(state.layers[1].downloaded, 80);
        assert_eq!(state.byte_totals(), (150, 150));
        let mut resumed = pull_state(1, None);
        resumed.handle_event(ImageProgress::LayerDownloadProgress {
            index: 1,
            total: 1,
            digest: "sha256:aaaaaaaaaaaa".into(),
            downloaded_bytes: 60,
            size_bytes: Some(100),
        });
        assert_eq!(resumed.byte_totals(), (60, 100));
        resumed.handle_event(ImageProgress::LayerDownloadVerifying {
            index: 1,
            total: 1,
            digest: "sha256:aaaaaaaaaaaa".into(),
        });
        assert_eq!(resumed.byte_totals(), (100, 100));
        let mut unknown = pull_state(1, None);
        unknown.handle_event(ImageProgress::LayerDownloadProgress {
            index: 1,
            total: 1,
            digest: "sha256:aaaaaaaaaaaa".into(),
            downloaded_bytes: u64::MAX,
            size_bytes: None,
        });
        assert_eq!(unknown.byte_totals(), (u64::MAX, u64::MAX));
    }

    #[test]
    fn pull_progress_skipped_downloads_still_wait_for_unpacking() {
        let mut state = pull_state(3, Some(300));
        state.handle_event(ImageProgress::LayerDownloadSkipped {
            index: 1,
            total: 3,
            digest: "sha256:aaaaaaaaaaaa".into(),
        });
        assert_eq!(state.visible_layers(4).count(), 0);
        assert_eq!(state.done, 0);
        assert_eq!(state.byte_totals(), (0, 300));
        state.handle_event(ImageProgress::ApplyingLayer {
            index: 1,
            total: 3,
            digest: None,
        });
        assert_eq!(state.done, 0);
        state.handle_event(ImageProgress::ApplyingLayer {
            index: 3,
            total: 3,
            digest: None,
        });
        assert_eq!(state.done, 2);
        assert_eq!(state.layers[0].activity, PullLayerActivity::Done);
        assert_eq!(state.layers[1].activity, PullLayerActivity::Done);
        state.handle_event(ImageProgress::MaterializingRootfs);
        assert_eq!(state.done, 3);
    }

    #[test]
    fn pull_progress_ignores_unknown_indexes_without_changing_other_layers() {
        let mut state = PullProgressState::new("image");
        state.handle_event(download_started(1, 1));
        assert!(state.layers.is_empty());
        let mut state = pull_state(2, None);
        state.handle_event(download_started(1, 2));
        for (index, total) in [(0, 2), (3, 2), (usize::MAX, 2), (1, 3)] {
            let digest = "sha256:bbbbbbbbbbbb".to_string();
            for event in [
                download_started(index, total),
                ImageProgress::LayerDownloadProgress {
                    index,
                    total,
                    digest: digest.clone(),
                    downloaded_bytes: 50,
                    size_bytes: Some(100),
                },
                ImageProgress::LayerDownloadVerifying {
                    index,
                    total,
                    digest: digest.clone(),
                },
                ImageProgress::LayerDownloadFinished {
                    index,
                    total,
                    digest: digest.clone(),
                },
                ImageProgress::LayerDownloadSkipped {
                    index,
                    total,
                    digest: digest.clone(),
                },
                ImageProgress::ApplyingLayer {
                    index,
                    total,
                    digest: Some(digest),
                },
            ] {
                state.handle_event(event);
                assert_eq!(state.done, 0);
                assert_eq!(state.layers[0].activity, PullLayerActivity::Downloading);
                assert_eq!(state.layers[0].downloaded, 0);
                assert_eq!(state.layers[1].activity, PullLayerActivity::Waiting);
            }
        }
    }

    #[test]
    fn pull_progress_shortens_digests_and_falls_back_for_missing_or_invalid_digests() {
        for (digest, expected) in [
            (Some("sha256:3f2a9c1b7d04abcdef"), "3f2a9c1b7d04"),
            (None, "layer 7/69"),
            (Some("sha256:abcd"), "layer 7/69"),
            (Some("sha256:🌳🌳🌳🌳"), "layer 7/69"),
            (Some("other:3f2a9c1b7d04abcdef"), "layer 7/69"),
        ] {
            let layer = PullLayerState {
                digest: digest.map(str::to_string),
                ..Default::default()
            };
            assert_eq!(layer.label(7, 69), expected);
        }
    }

    #[test]
    fn pull_progress_fits_terminal_rows_and_columns() {
        for (rows, expected) in [(0, 0), (1, 0), (2, 0), (3, 1), (5, 3), (6, 4), (50, 4)] {
            assert_eq!(pull_layer_row_cap(rows), expected);
        }
        let mut state = pull_state(69, Some(162_400_000));
        state.handle_event(download_started(1, 69));
        state.handle_event(ImageProgress::ApplyingLayer {
            index: 2,
            total: 69,
            digest: None,
        });
        state.handle_event(download_started(3, 69));
        state.handle_event(ImageProgress::LayerDownloadVerifying {
            index: 3,
            total: 69,
            digest: "sha256:aaaaaaaaaaaa".into(),
        });
        for width in [0, 1, 5, 12, 20, 40, 79, 120] {
            assert!(console::measure_text_width(&state.header(width)) <= width);
            for (index, layer) in state.visible_layers(4) {
                assert!(console::measure_text_width(&layer.line(index, 69, width)) <= width);
            }
        }
        let header = state.header(74);
        assert!(header.contains("1/69 layers"));
        assert!(header.ends_with(&indicatif::HumanBytes(162_400_000).to_string()));
        assert!(state.layers[2].line(3, 69, 120).contains('━'));
        assert!(!state.layers[2].line(3, 69, 40).contains('━'));
    }

    #[test]
    fn pull_progress_display_handles_the_complete_image_event_sequence() {
        let mut display = PullProgressDisplay::quiet("image");
        for (event, phase) in [
            (
                ImageProgress::ResolvingManifest {
                    image_ref: "image".into(),
                },
                "Resolving",
            ),
            (
                ImageProgress::ResolvedManifest {
                    image_ref: "image".into(),
                    manifest_digest: "sha256:abcd".into(),
                    layer_count: 1,
                    total_download_bytes: Some(100),
                },
                "Pulling",
            ),
            (
                ImageProgress::CheckingCache {
                    image_ref: "image".into(),
                },
                "Checking",
            ),
            (
                ImageProgress::CacheHit {
                    image_ref: "image".into(),
                },
                "Cached",
            ),
            (
                ImageProgress::CacheMiss {
                    image_ref: "image".into(),
                },
                "Building",
            ),
            (
                ImageProgress::UsingLocalDisk {
                    image_ref: "image".into(),
                },
                "Using",
            ),
            (ImageProgress::MaterializingRootfs, "Writing"),
            (ImageProgress::PublishingRootfs, "Saving"),
            (ImageProgress::Complete, "Pulled"),
        ] {
            display.handle_event(event);
            assert_eq!(display.state.phase.word(), phase);
            assert!(display.active_lines.is_empty());
        }
        assert_eq!(display.state.done, 1);
        display.finish();
    }
}
