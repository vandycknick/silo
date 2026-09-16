//! Guest memory reclaim: gives idle page cache back to the kernel's free lists,
//! where the balloon's free-page reporting hands it to the host.
//!
//! Modelled on WSL2's `autoMemoryReclaim`. A background thread at `SCHED_IDLE`
//! samples `/proc/stat` every ten seconds. Once the guest has been idle for the
//! configured window it asks the kernel for cold file cache, one bounded step
//! per tick through cgroup v2 `memory.reclaim`, then compacts free memory so
//! the freed pages form blocks large enough to report. The thread only ever
//! reclaims what the kernel would reclaim under pressure anyway; it never
//! touches memory a workload is using.

use std::fs;
use std::io::{self, Write as _};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use agent_spec::{MemoryReclaimConfig, MemoryReclaimMode};
use prost_types::Timestamp;
use protocol::v1::MemoryReclaimReport;

const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Non-idle CPU share at or below which an interval counts as idle: 0.5%.
const BUSY_THRESHOLD_PER_MILLE: u64 = 5;
/// Reclaimable cache below this floor is always retained as a working set.
const FLOOR_BYTES: u64 = 128 * MIB;
/// Bounds on one reclaim step: RAM/32 clamped into this range.
const MIN_STEP_BYTES: u64 = 256 * MIB;
const MAX_STEP_BYTES: u64 = 1024 * MIB;
const MIB: u64 = 1024 * 1024;

const MEMINFO: &str = "/proc/meminfo";
const STAT: &str = "/proc/stat";
const RECLAIM: &str = "/sys/fs/cgroup/memory.reclaim";
const DROP_CACHES: &str = "/proc/sys/vm/drop_caches";
const COMPACT_MEMORY: &str = "/proc/sys/vm/compact_memory";

/// Shared view of the last reclaim run, read by the metrics collector.
#[derive(Clone, Default)]
pub(crate) struct MemoryReclaimStatus {
    last: Arc<Mutex<Option<MemoryReclaimReport>>>,
}

impl MemoryReclaimStatus {
    pub(crate) fn last(&self) -> Option<MemoryReclaimReport> {
        self.last.lock().ok().and_then(|last| last.clone())
    }

    fn record(&self, report: MemoryReclaimReport) {
        if let Ok(mut last) = self.last.lock() {
            *last = Some(report);
        }
    }
}

/// Starts the reclaim thread when the mode is not `Off`. Returns the status
/// handle either way so metrics can always ask for the last run.
pub(crate) fn start(config: &MemoryReclaimConfig) -> MemoryReclaimStatus {
    let status = MemoryReclaimStatus::default();
    if config.mode == MemoryReclaimMode::Off {
        return status;
    }
    let thread_status = status.clone();
    let mode = config.mode;
    let idle_after_secs = config.idle_after_secs;
    let thread_config = config.clone();
    let spawned = thread::Builder::new()
        .name("memory-reclaim".to_string())
        .spawn(move || {
            lower_to_idle_priority();
            run(&thread_config, &thread_status, &ProcFs);
        });
    match spawned {
        Ok(_) => tracing::info!(?mode, idle_after_secs, "memory reclaim thread started"),
        Err(error) => tracing::warn!(%error, "failed to start memory reclaim thread"),
    }
    status
}

/// Runs reclaim at idle scheduling priority so it never competes with workloads.
///
/// Uses the pthread interface: musl's `sched_setscheduler` is a stub that
/// returns `ENOSYS`, while `pthread_setschedparam` issues the real syscall.
fn lower_to_idle_priority() {
    // SAFETY: sched_param is plain old data; zeroed is a valid value for every
    // field on every libc, and SCHED_IDLE ignores the priority anyway.
    let mut parameter: libc::sched_param = unsafe { std::mem::zeroed() };
    parameter.sched_priority = 0;
    // SAFETY: applies to the calling thread with an initialized parameter block.
    let status =
        unsafe { libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_IDLE, &parameter) };
    if status != 0 {
        tracing::warn!(
            error = %io::Error::from_raw_os_error(status),
            "could not switch the memory reclaim thread to SCHED_IDLE"
        );
    }
}

/// The kernel interfaces the loop touches, abstracted so the policy is testable.
trait System {
    fn stat(&self) -> Option<String>;
    fn meminfo(&self) -> Option<String>;
    fn total_ram_bytes(&self) -> u64;
    fn reclaim_available(&self) -> bool;
    fn request_reclaim(&self, bytes: u64) -> io::Result<()>;
    fn drop_caches(&self) -> io::Result<()>;
    fn compact(&self) -> io::Result<()>;
    fn sleep(&self, duration: Duration);
    fn now(&self) -> Timestamp;
}

struct ProcFs;

impl System for ProcFs {
    fn stat(&self) -> Option<String> {
        fs::read_to_string(STAT).ok()
    }

    fn meminfo(&self) -> Option<String> {
        fs::read_to_string(MEMINFO).ok()
    }

    fn total_ram_bytes(&self) -> u64 {
        self.meminfo()
            .and_then(|text| meminfo_value(&text, "MemTotal:"))
            .unwrap_or(0)
    }

    fn reclaim_available(&self) -> bool {
        fs::OpenOptions::new().write(true).open(RECLAIM).is_ok()
    }

    fn request_reclaim(&self, bytes: u64) -> io::Result<()> {
        // EAGAIN means the kernel reclaimed some but not all of the request;
        // that is progress, not failure.
        match write_control(RECLAIM, &format!("{bytes} swappiness=0")) {
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => Ok(()),
            result => result,
        }
    }

    fn drop_caches(&self) -> io::Result<()> {
        write_control(DROP_CACHES, "3")
    }

    fn compact(&self) -> io::Result<()> {
        write_control(COMPACT_MEMORY, "1")
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }

    fn now(&self) -> Timestamp {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: duration.subsec_nanos() as i32,
        }
    }
}

fn write_control(path: &str, value: &str) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(value.as_bytes())
}

/// Cumulative CPU jiffies split into busy and idle, from the aggregate `cpu` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuSample {
    busy: u64,
    idle: u64,
}

fn parse_cpu_sample(stat: &str) -> Option<CpuSample> {
    let fields: Vec<u64> = stat
        .lines()
        .find(|line| line.starts_with("cpu "))?
        .split_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if fields.len() < 5 {
        return None;
    }
    // user nice system idle iowait irq softirq steal ...; iowait counts as idle.
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    let busy = fields
        .iter()
        .enumerate()
        .filter(|(index, _)| !matches!(index, 3 | 4))
        .map(|(_, value)| *value)
        .sum();
    Some(CpuSample { busy, idle })
}

fn meminfo_value(meminfo: &str, key: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|line| line.strip_prefix(key))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

/// File-backed page cache plus reclaimable slab: the memory the kernel can
/// return without swap. Anonymous memory and shmem are excluded.
fn reclaimable_cache_bytes(meminfo: &str) -> Option<u64> {
    Some(
        meminfo_value(meminfo, "Active(file):")?
            + meminfo_value(meminfo, "Inactive(file):")?
            + meminfo_value(meminfo, "SReclaimable:")?,
    )
}

fn reclaim_step_bytes(total_ram: u64) -> u64 {
    (total_ram / 32).clamp(MIN_STEP_BYTES, MAX_STEP_BYTES)
}

/// Rolling idle detector over `window` poll intervals.
struct IdleTracker {
    window: usize,
    samples: std::collections::VecDeque<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IdleState {
    interval_idle: bool,
    window_idle: bool,
}

impl IdleTracker {
    fn new(window: usize) -> Self {
        Self {
            window: window.max(1),
            samples: std::collections::VecDeque::new(),
        }
    }

    fn add(&mut self, busy: u64, total: u64) -> IdleState {
        if self.samples.len() == self.window {
            self.samples.pop_front();
        }
        self.samples.push_back((busy, total));
        let (window_busy, window_total) = self
            .samples
            .iter()
            .fold((0, 0), |(b, t), (busy, total)| (b + busy, t + total));
        IdleState {
            interval_idle: is_idle(busy, total),
            window_idle: self.samples.len() == self.window && is_idle(window_busy, window_total),
        }
    }

    fn reset(&mut self) {
        self.samples.clear();
    }
}

fn is_idle(busy: u64, total: u64) -> bool {
    total == 0 || busy * 1000 <= total * BUSY_THRESHOLD_PER_MILLE
}

fn run(config: &MemoryReclaimConfig, status: &MemoryReclaimStatus, system: &dyn System) {
    let window = (config.idle_after_secs / POLL_INTERVAL.as_secs()).max(1) as usize;
    let mut use_reclaim = config.mode == MemoryReclaimMode::Gradual;
    if use_reclaim && !system.reclaim_available() {
        tracing::warn!("memory.reclaim is unavailable; falling back to drop_caches");
        use_reclaim = false;
    }
    let step = reclaim_step_bytes(system.total_ram_bytes());
    let mut tracker = IdleTracker::new(window);
    let mut previous: Option<CpuSample> = None;
    let mut dropped_this_idle_period = false;
    let mut compacted_this_idle_period = false;
    let mut runs: u64 = 0;
    loop {
        system.sleep(POLL_INTERVAL);
        let Some(sample) = system.stat().and_then(|text| parse_cpu_sample(&text)) else {
            continue;
        };
        let Some(last) = previous.replace(sample) else {
            continue;
        };
        if sample.busy < last.busy || sample.idle < last.idle {
            tracker.reset();
            dropped_this_idle_period = false;
            compacted_this_idle_period = false;
            continue;
        }
        let busy = sample.busy - last.busy;
        let total = busy + (sample.idle - last.idle);
        let idle = tracker.add(busy, total);
        if !idle.window_idle {
            dropped_this_idle_period = false;
            compacted_this_idle_period = false;
            continue;
        }
        // A short burst blocks this tick but keeps the idle history.
        if !idle.interval_idle {
            continue;
        }

        let meminfo = system.meminfo().unwrap_or_default();
        let cached_before = meminfo_value(&meminfo, "Cached:").unwrap_or(0);
        let mut requested = 0;
        let mut outcome: Option<&str> = None;
        let mut mode = "gradual";
        if use_reclaim {
            let reclaimable = reclaimable_cache_bytes(&meminfo).unwrap_or(0);
            if reclaimable > FLOOR_BYTES {
                requested = (reclaimable - FLOOR_BYTES).min(step);
                outcome = Some(match system.request_reclaim(requested) {
                    Ok(()) => "reclaimed",
                    Err(error) => {
                        tracing::warn!(%error, bytes = requested, "memory.reclaim write failed");
                        "failed"
                    }
                });
            }
        } else if !dropped_this_idle_period {
            mode = "dropcache";
            outcome = Some(match system.drop_caches() {
                Ok(()) => {
                    dropped_this_idle_period = true;
                    "reclaimed"
                }
                Err(error) => {
                    tracing::warn!(%error, "drop_caches write failed");
                    "failed"
                }
            });
        }

        let reclaimed = matches!(outcome, Some("reclaimed"));
        let mut compacted = false;
        if reclaimed || !compacted_this_idle_period {
            compacted = system.compact().is_ok();
            compacted_this_idle_period |= compacted;
        }
        if outcome.is_none() && !compacted {
            continue;
        }

        let cached_after = system
            .meminfo()
            .and_then(|text| meminfo_value(&text, "Cached:"))
            .unwrap_or(cached_before);
        let outcome = outcome.unwrap_or("nothing");
        let outcome = if outcome == "reclaimed"
            && use_reclaim
            && cached_after + requested / 2 > cached_before
        {
            // The kernel accepted the request but freed less than half of it.
            "partial"
        } else {
            outcome
        };
        runs += 1;
        status.record(MemoryReclaimReport {
            finished_at: Some(system.now()),
            mode: Some(mode.to_string()),
            outcome: Some(outcome.to_string()),
            requested_bytes: Some(requested),
            cached_before_bytes: Some(cached_before),
            cached_after_bytes: Some(cached_after),
            compacted: Some(compacted),
            runs: Some(runs),
        });
        tracing::info!(
            mode,
            outcome,
            requested_bytes = requested,
            cached_before_bytes = cached_before,
            cached_after_bytes = cached_after,
            compacted,
            "memory reclaim run"
        );
        // Exclude our own work from the next interval so it does not restart
        // the idle window.
        previous = system.stat().and_then(|text| parse_cpu_sample(&text));
        if previous.is_none() {
            tracker.reset();
            dropped_this_idle_period = false;
            compacted_this_idle_period = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const MEMINFO_FIXTURE: &str = "MemTotal:        8388608 kB\nMemFree:         6291456 kB\nCached:          1048576 kB\nActive(file):     524288 kB\nInactive(file):   393216 kB\nShmem:            262144 kB\nSReclaimable:      65536 kB\n";

    #[test]
    fn cpu_sample_splits_busy_and_idle_with_iowait_as_idle() {
        let sample =
            parse_cpu_sample("cpu  100 20 30 5000 40 1 2 3 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n")
                .expect("sample");
        assert_eq!(sample.busy, 100 + 20 + 30 + 1 + 2 + 3);
        assert_eq!(sample.idle, 5000 + 40);
        assert_eq!(parse_cpu_sample("cpu 1 2 3\n"), None);
        assert_eq!(parse_cpu_sample("intr 5\n"), None);
    }

    #[test]
    fn reclaimable_cache_counts_file_pages_and_slab_only() {
        assert_eq!(
            reclaimable_cache_bytes(MEMINFO_FIXTURE),
            Some((524288 + 393216 + 65536) * 1024)
        );
        assert_eq!(meminfo_value(MEMINFO_FIXTURE, "Cached:"), Some(1024 * MIB));
        assert_eq!(reclaimable_cache_bytes("MemTotal: 1 kB\n"), None);
    }

    #[test]
    fn reclaim_step_scales_with_ram_within_bounds() {
        assert_eq!(reclaim_step_bytes(2 * 1024 * MIB), MIN_STEP_BYTES);
        assert_eq!(reclaim_step_bytes(16 * 1024 * MIB), 512 * MIB);
        assert_eq!(reclaim_step_bytes(128 * 1024 * MIB), MAX_STEP_BYTES);
    }

    #[test]
    fn idle_tracker_needs_a_full_quiet_window() {
        let mut tracker = IdleTracker::new(3);
        assert_eq!(
            tracker.add(1, 1000),
            IdleState {
                interval_idle: true,
                window_idle: false
            }
        );
        assert!(!tracker.add(2, 1000).window_idle);
        assert!(tracker.add(3, 1000).window_idle);
        // 5 busy of 1000 is the 0.5% threshold, still idle.
        assert!(tracker.add(5, 1000).window_idle);
        // A busy interval keeps the window busy for three more samples.
        let state = tracker.add(400, 1000);
        assert!(!state.interval_idle);
        assert!(!state.window_idle);
        assert!(!tracker.add(0, 1000).window_idle);
        assert!(!tracker.add(0, 1000).window_idle);
        assert!(tracker.add(0, 1000).window_idle);
        tracker.reset();
        assert!(!tracker.add(0, 1000).window_idle);
    }

    /// Fake kernel: scripted CPU samples, a fixed meminfo, and a log of writes.
    struct Fake {
        stats: RefCell<Vec<&'static str>>,
        cached_after: RefCell<Vec<u64>>,
        reclaim_available: bool,
        reclaims: RefCell<Vec<u64>>,
        drops: AtomicUsize,
        compacts: AtomicUsize,
        sleeps: AtomicUsize,
        stop_after_sleeps: usize,
    }

    impl Fake {
        fn new(stats: Vec<&'static str>, reclaim_available: bool) -> Self {
            let stop_after_sleeps = stats.len();
            Self {
                stats: RefCell::new(stats),
                cached_after: RefCell::new(Vec::new()),
                reclaim_available,
                reclaims: RefCell::new(Vec::new()),
                drops: AtomicUsize::new(0),
                compacts: AtomicUsize::new(0),
                sleeps: AtomicUsize::new(0),
                stop_after_sleeps,
            }
        }
    }

    struct StopLoop;

    impl System for Fake {
        fn stat(&self) -> Option<String> {
            let mut stats = self.stats.borrow_mut();
            if stats.is_empty() {
                return None;
            }
            Some(stats.remove(0).to_string())
        }
        fn meminfo(&self) -> Option<String> {
            let mut after = self.cached_after.borrow_mut();
            if after.is_empty() {
                return Some(MEMINFO_FIXTURE.to_string());
            }
            let cached = after.remove(0) / 1024;
            Some(MEMINFO_FIXTURE.replace(
                "Cached:          1048576 kB",
                &format!("Cached: {cached} kB"),
            ))
        }
        fn total_ram_bytes(&self) -> u64 {
            8 * 1024 * MIB
        }
        fn reclaim_available(&self) -> bool {
            self.reclaim_available
        }
        fn request_reclaim(&self, bytes: u64) -> io::Result<()> {
            self.reclaims.borrow_mut().push(bytes);
            Ok(())
        }
        fn drop_caches(&self) -> io::Result<()> {
            self.drops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn compact(&self) -> io::Result<()> {
            self.compacts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn sleep(&self, _: Duration) {
            if self.sleeps.fetch_add(1, Ordering::SeqCst) >= self.stop_after_sleeps {
                std::panic::panic_any(StopLoop);
            }
        }
        fn now(&self) -> Timestamp {
            Timestamp::default()
        }
    }

    fn run_until_exhausted(config: &MemoryReclaimConfig, fake: &Fake) -> MemoryReclaimStatus {
        let status = MemoryReclaimStatus::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(config, &status, fake);
        }));
        assert!(
            result
                .err()
                .is_some_and(|payload| payload.downcast_ref::<StopLoop>().is_some()),
            "loop must end only through the scripted stop"
        );
        status
    }

    fn config(mode: MemoryReclaimMode, idle_after_secs: u64) -> MemoryReclaimConfig {
        MemoryReclaimConfig {
            mode,
            idle_after_secs,
        }
    }

    #[test]
    fn gradual_reclaims_one_bounded_step_after_the_idle_window() {
        // Baseline, then two idle intervals (window of 2 at 20 s), then the run.
        let fake = Fake::new(
            vec![
                "cpu 1000 0 0 100000 0 0 0 0 0 0\n",
                "cpu 1001 0 0 101000 0 0 0 0 0 0\n",
                "cpu 1002 0 0 102000 0 0 0 0 0 0\n",
                "cpu 1002 0 0 102000 0 0 0 0 0 0\n", // re-sample after the run
            ],
            true,
        );
        *fake.cached_after.borrow_mut() = vec![1024 * MIB, 700 * MIB];
        let status = run_until_exhausted(&config(MemoryReclaimMode::Gradual, 20), &fake);
        // 983,040 KiB reclaimable minus the 128 MiB floor exceeds the 256 MiB step.
        assert_eq!(*fake.reclaims.borrow(), vec![256 * MIB]);
        assert_eq!(fake.compacts.load(Ordering::SeqCst), 1);
        assert_eq!(fake.drops.load(Ordering::SeqCst), 0);
        let report = status.last().expect("report");
        assert_eq!(report.mode.as_deref(), Some("gradual"));
        assert_eq!(report.outcome.as_deref(), Some("reclaimed"));
        assert_eq!(report.requested_bytes, Some(256 * MIB));
        assert_eq!(report.cached_before_bytes, Some(1024 * MIB));
        assert_eq!(report.cached_after_bytes, Some(700 * MIB));
        assert_eq!(report.compacted, Some(true));
        assert_eq!(report.runs, Some(1));
    }

    #[test]
    fn busy_intervals_postpone_reclaim() {
        let fake = Fake::new(
            vec![
                "cpu 1000 0 0 100000 0 0 0 0 0 0\n",
                "cpu 1500 0 0 100500 0 0 0 0 0 0\n", // 50% busy
                "cpu 1501 0 0 101500 0 0 0 0 0 0\n", // idle, but window still busy
            ],
            true,
        );
        let status = run_until_exhausted(&config(MemoryReclaimMode::Gradual, 20), &fake);
        assert!(fake.reclaims.borrow().is_empty());
        assert!(status.last().is_none());
    }

    #[test]
    fn dropcache_runs_once_per_idle_period_and_is_the_fallback() {
        let fake = Fake::new(
            vec![
                "cpu 1000 0 0 100000 0 0 0 0 0 0\n",
                "cpu 1000 0 0 101000 0 0 0 0 0 0\n",
                "cpu 1000 0 0 101000 0 0 0 0 0 0\n", // re-sample after first run
                "cpu 1000 0 0 102000 0 0 0 0 0 0\n", // still idle: no second drop
            ],
            false,
        );
        let status = run_until_exhausted(&config(MemoryReclaimMode::Gradual, 10), &fake);
        assert_eq!(fake.drops.load(Ordering::SeqCst), 1);
        assert_eq!(fake.compacts.load(Ordering::SeqCst), 1);
        let report = status.last().expect("report");
        assert_eq!(report.mode.as_deref(), Some("dropcache"));
        assert_eq!(report.runs, Some(1));
    }

    #[test]
    fn partial_outcome_when_the_kernel_frees_less_than_half() {
        let fake = Fake::new(
            vec![
                "cpu 1000 0 0 100000 0 0 0 0 0 0\n",
                "cpu 1000 0 0 101000 0 0 0 0 0 0\n",
                "cpu 1000 0 0 101000 0 0 0 0 0 0\n",
            ],
            true,
        );
        *fake.cached_after.borrow_mut() = vec![1024 * MIB, 1000 * MIB];
        let status = run_until_exhausted(&config(MemoryReclaimMode::Gradual, 10), &fake);
        assert_eq!(
            status.last().and_then(|report| report.outcome),
            Some("partial".to_string())
        );
    }

    #[test]
    fn off_mode_starts_no_thread() {
        let status = start(&config(MemoryReclaimMode::Off, 120));
        assert!(status.last().is_none());
    }
}
