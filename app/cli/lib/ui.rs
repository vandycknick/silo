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

pub fn print_json(value: &impl Serialize) -> eyre::Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

#[derive(Debug)]
pub struct Spinner {
    pb: Option<ProgressBar>,
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
    layer_bars: Vec<ProgressBar>,
    reference: String,
    download_style: ProgressStyle,
    materialize_style: ProgressStyle,
    done_style: ProgressStyle,
    current_applying_layer: Option<usize>,
    _echo_guard: Option<EchoGuard>,
}

impl Spinner {
    pub fn start(label: &str, target: impl Into<String>) -> Self {
        let target = target.into();
        let is_tty = stderr_is_interactive();
        let (pb, echo_guard) = if is_tty {
            let template = format!("   {{spinner}} {label:<12} {{msg}}");
            let style = ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template(&template)
                .unwrap_or_else(|_| ProgressStyle::default_spinner());
            let pb = ProgressBar::new_spinner().with_style(style);
            pb.set_message(target.clone());
            pb.enable_steady_tick(Duration::from_millis(80));
            (Some(pb), EchoGuard::acquire())
        } else {
            (None, None)
        };

        Self {
            pb,
            start: Instant::now(),
            target,
            quiet: false,
            _echo_guard: echo_guard,
        }
    }

    pub fn quiet() -> Self {
        Self {
            pb: None,
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
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }

        if !self.quiet {
            print_success(past_tense, &self.target, self.start.elapsed());
        }
    }

    pub fn finish_clear(mut self) {
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }
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

impl PullProgressDisplay {
    pub fn new(reference: &str) -> Self {
        Self::new_inner(reference, false)
    }

    pub fn quiet(reference: &str) -> Self {
        Self::new_inner(reference, true)
    }

    fn new_inner(reference: &str, quiet: bool) -> Self {
        let is_tty = !quiet && stderr_is_interactive();
        let mp = MultiProgress::new();
        if is_tty {
            mp.set_draw_target(ProgressDrawTarget::stderr_with_hz(10));
        } else {
            mp.set_draw_target(ProgressDrawTarget::hidden());
        }

        let header = mp.add(ProgressBar::new_spinner());
        header.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template("   {spinner} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        header.set_message(format!("{:<12} {}", "Pulling", reference));
        header.enable_steady_tick(Duration::from_millis(80));

        Self {
            mp,
            header,
            layer_bars: Vec::new(),
            reference: reference.to_string(),
            download_style: ProgressStyle::default_bar()
                .template(
                    "     {prefix}  {bar:36.magenta/238}  {bytes}/{total_bytes}  {msg:.magenta}",
                )
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("━━╌"),
            materialize_style: ProgressStyle::default_bar()
                .template("     {prefix}  {bar:36.blue/238}  {msg:.blue}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("━━╌"),
            done_style: ProgressStyle::default_bar()
                .template("     {prefix}  {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
            current_applying_layer: None,
            _echo_guard: if is_tty { EchoGuard::acquire() } else { None },
        }
    }

    pub fn handle_event(&mut self, event: ImageProgress) {
        match event {
            ImageProgress::ResolvingManifest { image_ref } => {
                self.reference = image_ref;
                self.header
                    .set_message(format!("{:<12} {}...", "Resolving", self.reference));
            }
            ImageProgress::ResolvedManifest {
                image_ref,
                layer_count,
                ..
            } => {
                self.reference = image_ref;
                self.header.set_message(format!(
                    "{:<12} {} ({} layer{})",
                    "Pulling",
                    self.reference,
                    layer_count,
                    if layer_count == 1 { "" } else { "s" }
                ));
                self.ensure_layer_bars(layer_count);
            }
            ImageProgress::HashingSource { image_ref } => {
                self.reference = image_ref;
                self.header
                    .set_message(format!("{:<12} {}", "Hashing", self.reference));
            }
            ImageProgress::ReadingArchive { image_ref } => {
                self.reference = image_ref;
                self.header
                    .set_message(format!("{:<12} {}", "Reading", self.reference));
            }
            ImageProgress::CheckingCache { image_ref } => {
                self.reference = image_ref;
                self.header
                    .set_message(format!("{:<12} {}", "Checking", self.reference));
            }
            ImageProgress::CacheHit { image_ref } => {
                self.reference = image_ref;
                self.header
                    .set_message(format!("{:<12} {}", "Cached", self.reference));
            }
            ImageProgress::CacheMiss { image_ref } => {
                self.reference = image_ref;
                self.header
                    .set_message(format!("{:<12} {}", "Building", self.reference));
            }
            ImageProgress::UsingLocalDisk { image_ref } => {
                self.reference = image_ref;
                self.header
                    .set_message(format!("{:<12} {}", "Using", self.reference));
            }
            ImageProgress::LayerDownloadStarted {
                index,
                total,
                size_bytes,
                ..
            } => {
                self.ensure_layer_bars(total);
                if let Some(pb) = self.layer_bar(index) {
                    pb.set_style(self.download_style.clone());
                    pb.set_position(0);
                    if let Some(size_bytes) = size_bytes {
                        pb.set_length(size_bytes);
                    }
                    pb.set_message("downloading");
                }
            }
            ImageProgress::LayerDownloadProgress {
                index,
                total,
                downloaded_bytes,
                size_bytes,
                ..
            } => {
                self.ensure_layer_bars(total);
                if let Some(pb) = self.layer_bar(index) {
                    if let Some(size_bytes) = size_bytes {
                        pb.set_length(size_bytes);
                    }
                    pb.set_position(downloaded_bytes);
                }
            }
            ImageProgress::LayerDownloadVerifying { index, total, .. } => {
                self.ensure_layer_bars(total);
                if let Some(pb) = self.layer_bar(index) {
                    pb.set_message("verifying");
                }
            }
            ImageProgress::LayerDownloadFinished { index, total, .. } => {
                self.ensure_layer_bars(total);
                if let Some(pb) = self.layer_bar(index) {
                    pb.set_position(pb.length().unwrap_or(0));
                    pb.set_message("downloaded");
                }
            }
            ImageProgress::LayerDownloadSkipped { index, total, .. } => {
                self.ensure_layer_bars(total);
                if let Some(pb) = self.layer_bar(index) {
                    pb.set_position(pb.length().unwrap_or(1));
                    pb.set_message("cached");
                }
            }
            ImageProgress::ApplyingLayer { index, total, .. } => {
                self.finish_current_applying_layer();
                self.ensure_layer_bars(total);
                if let Some(pb) = self.layer_bar(index) {
                    pb.set_style(self.materialize_style.clone());
                    pb.set_length(1);
                    pb.set_position(0);
                    pb.set_message("unpacking");
                }
                self.current_applying_layer = Some(index);
            }
            ImageProgress::WritingExt4 => {
                self.finish_current_applying_layer();
                self.header
                    .set_message(format!("{:<12} {}", "Writing", self.reference));
            }
            ImageProgress::SavingBaseImage => {
                self.header
                    .set_message(format!("{:<12} {}", "Saving", self.reference));
            }
            ImageProgress::Complete => {
                self.finish_current_applying_layer();
                self.header
                    .set_message(format!("{:<12} {}", "Pulled", self.reference));
            }
        }
    }

    pub fn finish(mut self) {
        self.finish_current_applying_layer();
        let _ = self.mp.clear();
    }

    fn ensure_layer_bars(&mut self, layer_count: usize) {
        if self.layer_bars.len() >= layer_count {
            return;
        }
        let width = layer_count.to_string().len();
        for index in self.layer_bars.len()..layer_count {
            let pb = self.mp.add(ProgressBar::new(1));
            pb.set_style(self.download_style.clone());
            pb.set_prefix(format!("layer {:>width$}/{layer_count}", index + 1));
            pb.set_message("waiting");
            self.layer_bars.push(pb);
        }
    }

    fn layer_bar(&self, one_based_index: usize) -> Option<&ProgressBar> {
        one_based_index
            .checked_sub(1)
            .and_then(|index| self.layer_bars.get(index))
    }

    fn finish_current_applying_layer(&mut self) {
        let Some(index) = self.current_applying_layer.take() else {
            return;
        };
        if let Some(pb) = self.layer_bar(index) {
            pb.set_position(pb.length().unwrap_or(1));
            pb.set_style(self.done_style.clone());
            pb.set_message(format!("{}", style("✓").green()));
            pb.tick();
        }
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

pub fn success(message: impl AsRef<str>) {
    let check = if should_style_stderr() {
        style("✓").green().to_string()
    } else {
        "✓".to_string()
    };
    eprintln!("   {check} {}", message.as_ref());
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

fn format_duration(duration: Duration) -> String {
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
        let widths = self.column_widths();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        if !self.headers.is_empty() {
            let headers = if should_style_stdout() {
                self.headers
                    .iter()
                    .map(|header| style(header).cyan().bold().to_string())
                    .collect::<Vec<_>>()
            } else {
                self.headers.clone()
            };
            write_columns(&mut out, &headers, &widths)?;
        }

        for row in &self.rows {
            write_columns(&mut out, row, &widths)?;
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
        writeln!(out, "{value}")?;
    }

    Ok(())
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

pub fn relative_time(timestamp: i64, now: i64) -> String {
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
    use super::{relative_time, short_id};

    #[test]
    fn relative_time_formatting() {
        let now = 1000000;

        assert_eq!(relative_time(0, now), "N/A");
        assert_eq!(relative_time(now, now), "Less than a second ago");
        assert_eq!(relative_time(now - 3, now), "Less than a second ago");
        assert_eq!(relative_time(now - 30, now), "30 seconds ago");
        assert_eq!(relative_time(now - 60, now), "About a minute ago");
        assert_eq!(relative_time(now - 90, now), "About a minute ago");
        assert_eq!(relative_time(now - 300, now), "5 minutes ago");
        assert_eq!(relative_time(now - 3600, now), "About an hour ago");
        assert_eq!(relative_time(now - 7200, now), "2 hours ago");
        assert_eq!(relative_time(now - 86400, now), "24 hours ago");
        assert_eq!(relative_time(now - 172800, now), "2 days ago");
        assert_eq!(relative_time(now - 604800, now), "7 days ago");
        assert_eq!(relative_time(now - 604800 * 2, now), "2 weeks ago");
    }

    #[test]
    fn short_id_uses_first_eight_characters_when_available() {
        assert_eq!(short_id("1234567890abcdef"), "12345678");
        assert_eq!(short_id("1234"), "1234");
    }
}
