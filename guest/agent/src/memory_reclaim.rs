//! GuestCacheReclaimer automatically reclaims cold file cache when a negotiated
//! FreePageReporter and writable cgroup v2 reclaim interfaces are available.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost_types::Timestamp;
use protocol::v1::MemoryReclaimReport;

const POLL_INTERVAL: Duration = Duration::from_secs(10);
const IDLE_WINDOW: usize = 12;
const BUSY_THRESHOLD_PER_MILLE: u64 = 5;
const MIB: u64 = 1024 * 1024;
const FLOOR_BYTES: u64 = 128 * MIB;
const MIN_STEP_BYTES: u64 = 256 * MIB;
const MAX_STEP_BYTES: u64 = 1024 * MIB;
const COMPACT_MEMORY: &str = "/proc/sys/vm/compact_memory";

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

pub(crate) fn start() -> MemoryReclaimStatus {
    let status = MemoryReclaimStatus::default();
    let thread_status = status.clone();
    if let Err(error) = thread::Builder::new()
        .name("guest-cache-reclaimer".to_string())
        .spawn(move || {
            lower_to_idle_priority();
            GuestCacheReclaimer::new().run(&thread_status);
        })
    {
        tracing::warn!(%error, "failed to start GuestCacheReclaimer");
    }
    status
}

fn lower_to_idle_priority() {
    // SAFETY: sched_param contains only integer fields (including nested timespecs).
    // Zero initializes musl's extra fields and sets the priority required by SCHED_IDLE.
    let parameter: libc::sched_param = unsafe { std::mem::zeroed() };
    // nix has no pthread scheduling wrapper. musl's sched_setscheduler is a stub;
    // pthread_setschedparam issues the syscall for this thread instead.
    // SAFETY: applies SCHED_IDLE to the calling thread with a valid parameter.
    let result =
        unsafe { libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_IDLE, &parameter) };
    if result != 0 {
        tracing::warn!(error = %io::Error::from_raw_os_error(result), "could not lower GuestCacheReclaimer priority");
    }
}

fn write_control(path: &Path, value: &str) -> io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .write_all(value.as_bytes())
}

fn parse_hex(value: &str) -> Option<u32> {
    u32::from_str_radix(value.trim().strip_prefix("0x")?, 16).ok()
}

fn reporting_ready(device: &str, status: &str, features: &str) -> bool {
    // Linux virtio sysfs prints negotiated bits in ascending bit-number order.
    let bits = features.trim().as_bytes();
    parse_hex(device) == Some(5)
        && parse_hex(status).is_some_and(|status| status & 0xf == 0xf && status & 0xc0 == 0)
        && bits.len() >= 64
        && bits.iter().all(|bit| matches!(bit, b'0' | b'1'))
        && bits.get(5) == Some(&b'1')
}

fn free_page_reporter_available(devices: &Path) -> bool {
    let Ok(devices) = fs::read_dir(devices) else {
        return false;
    };
    devices.flatten().any(|entry| {
        let path = entry.path();
        let driver = fs::read_link(path.join("driver")).ok();
        if driver.as_deref().and_then(Path::file_name)
            != Some(std::ffi::OsStr::new("virtio_balloon"))
        {
            return false;
        }
        match (
            fs::read_to_string(path.join("device")),
            fs::read_to_string(path.join("status")),
            fs::read_to_string(path.join("features")),
        ) {
            (Ok(device), Ok(status), Ok(features)) => reporting_ready(&device, &status, &features),
            _ => false,
        }
    })
}

fn reclaim_targets(root: &Path) -> Vec<PathBuf> {
    if !root.join("cgroup.controllers").exists() {
        return Vec::new();
    }
    let writable = |path: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .open(path.join("memory.reclaim"))
            .is_ok()
    };
    if writable(root) {
        return vec![root.to_path_buf()];
    }
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut targets: Vec<_> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .filter(|path| writable(path))
        .collect();
    // Top-level memory.stat/reclaim include descendants, so never reclaim both
    // a parent and its children in one policy pass.
    targets.sort();
    targets
}

fn cgroup_cache_bytes(stat: &str) -> Option<u64> {
    let value = |key| {
        stat.lines().find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == key).then(|| value.parse::<u64>().ok()).flatten()
        })
    };
    value("file")?
        .checked_sub(value("shmem")?)?
        .checked_add(value("slab_reclaimable")?)
}

fn reclaim_budget(cache: u64, total_ram: u64) -> u64 {
    cache
        .saturating_sub(FLOOR_BYTES)
        .min(reclaim_step_bytes(total_ram))
}

fn cpu_sample() -> Option<CpuSample> {
    parse_cpu_sample(&fs::read_to_string("/proc/stat").ok()?)
}

struct GuestCacheReclaimer {
    tracker: IdleTracker,
    previous: Option<CpuSample>,
    next_target: usize,
    runs: u64,
}

impl GuestCacheReclaimer {
    fn new() -> Self {
        Self {
            tracker: IdleTracker::new(IDLE_WINDOW),
            previous: None,
            next_target: 0,
            runs: 0,
        }
    }

    fn run(mut self, status: &MemoryReclaimStatus) {
        let mut last_availability = None;
        loop {
            thread::sleep(POLL_INTERVAL);
            let reporter = free_page_reporter_available(Path::new("/sys/bus/virtio/devices"));
            let targets = if reporter {
                reclaim_targets(Path::new("/sys/fs/cgroup"))
            } else {
                Vec::new()
            };
            let availability = (reporter, !targets.is_empty());
            if last_availability != Some(availability) {
                tracing::info!(
                    reporter,
                    reclaim_interface = availability.1,
                    "GuestCacheReclaimer capability detection"
                );
                last_availability = Some(availability);
            }
            if !availability.1 {
                self.previous = None;
                self.tracker.reset();
                continue;
            }
            let Some(sample) = cpu_sample() else {
                self.previous = None;
                self.tracker.reset();
                continue;
            };
            let Some(previous) = self.previous.replace(sample) else {
                continue;
            };
            let (Some(busy), Some(idle)) = (
                sample.busy.checked_sub(previous.busy),
                sample.idle.checked_sub(previous.idle),
            ) else {
                self.tracker.reset();
                continue;
            };
            let idle = self.tracker.add(busy, busy.saturating_add(idle));
            if !idle.window_idle || !idle.interval_idle {
                continue;
            }
            let index = self.next_target % targets.len();
            self.next_target = index + 1;
            if let Some(target) = targets.get(index) {
                self.reclaim(target, status);
            }
            // Do not count this worker's CPU time as workload activity.
            self.previous = cpu_sample();
            if self.previous.is_none() {
                self.tracker.reset()
            }
        }
    }

    fn reclaim(&mut self, target: &Path, status: &MemoryReclaimStatus) {
        let Ok(meminfo) = fs::read_to_string("/proc/meminfo") else {
            return;
        };
        let Some(total) = meminfo_value(&meminfo, "MemTotal:") else {
            return;
        };
        let Some(cached_before) = meminfo_value(&meminfo, "Cached:") else {
            return;
        };
        let Some(cache) = fs::read_to_string(target.join("memory.stat"))
            .ok()
            .and_then(|text| cgroup_cache_bytes(&text))
        else {
            return;
        };
        let requested = reclaim_budget(cache, total);
        if requested == 0 {
            return;
        }
        let result = write_control(
            &target.join("memory.reclaim"),
            &format!("{requested} swappiness=0"),
        );
        let outcome = match result {
            Ok(()) => "reclaimed",
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => "partial",
            Err(error) => {
                tracing::warn!(%error, cgroup = %target.display(), "GuestCacheReclaimer unavailable or failed; no global cache-drop fallback");
                self.tracker.reset();
                "failed"
            }
        };
        let compacted =
            outcome != "failed" && write_control(Path::new(COMPACT_MEMORY), "1").is_ok();
        let cached_after = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| meminfo_value(&text, "Cached:"))
            .unwrap_or(cached_before);
        self.runs = self.runs.saturating_add(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        status.record(MemoryReclaimReport {
            finished_at: Some(Timestamp {
                seconds: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
                nanos: i32::try_from(now.subsec_nanos()).unwrap_or(0),
            }),
            mode: Some("gradual".to_string()),
            outcome: Some(outcome.to_string()),
            requested_bytes: Some(requested),
            cached_before_bytes: Some(cached_before),
            cached_after_bytes: Some(cached_after),
            compacted: Some(compacted),
            runs: Some(self.runs),
        });
        tracing::info!(
            outcome,
            requested_bytes = requested,
            cached_before_bytes = cached_before,
            cached_after_bytes = cached_after,
            compacted,
            "GuestCacheReclaimer run"
        );
    }
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
    let idle = fields[3].checked_add(fields[4])?;
    // guest/guest_nice are already included in user/nice.
    let busy = fields
        .iter()
        .take(8)
        .enumerate()
        .filter(|(index, _)| !matches!(index, 3 | 4))
        .try_fold(0_u64, |sum, (_, value)| sum.checked_add(*value))?;
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
    total > 0 && u128::from(busy) * 1000 <= u128::from(total) * u128::from(BUSY_THRESHOLD_PER_MILLE)
}

#[cfg(test)]
mod tests {
    use crate::memory_reclaim::*;
    const MEMINFO_FIXTURE: &str = "MemTotal:        8388608 kB\nMemFree:         6291456 kB\nCached:          1048576 kB\nActive(file):     524288 kB\nInactive(file):   393216 kB\nShmem:            262144 kB\nSReclaimable:      65536 kB\n";

    #[test]
    fn reporter_requires_negotiation_and_ready_driver_status() {
        let bits = format!("000001{}\n", "0".repeat(58));
        assert!(reporting_ready("0x0005\n", "0x0000000f\n", &bits));
        for status in ["0x0", "0x03", "0x0b", "0x8f", "0x4f", "invalid"] {
            assert!(!reporting_ready("0x0005", status, &bits));
        }
        assert!(!reporting_ready("0x0003", "0x0f", &bits));
        assert!(!reporting_ready("0x0005", "0x0f", &"0".repeat(64)));
        assert!(!reporting_ready("0x0005", "0x0f", "000001"));
        assert!(!reporting_ready(
            "0x0005",
            "0x0f",
            &format!("{bits}garbage")
        ));
    }

    #[test]
    fn cache_budget_excludes_shared_and_anonymous_memory_and_retains_floor() {
        let stat = "anon 999999999\nfile 1073741824\nshmem 268435456\nslab_reclaimable 67108864\n";
        assert_eq!(cgroup_cache_bytes(stat), Some(832 * MIB));
        assert_eq!(reclaim_budget(832 * MIB, 8 * 1024 * MIB), 256 * MIB);
        assert_eq!(reclaim_budget(FLOOR_BYTES, 8 * 1024 * MIB), 0);
        assert_eq!(reclaim_budget(1, 8 * 1024 * MIB), 0);
        assert_eq!(reclaim_budget(FLOOR_BYTES + 10, 8 * 1024 * MIB), 10);
        assert_eq!(
            cgroup_cache_bytes("file 1\nshmem 2\nslab_reclaimable 0\n"),
            None
        );
        assert_eq!(cgroup_cache_bytes("file 1\n"), None);
        assert_eq!(
            meminfo_value(MEMINFO_FIXTURE, "MemTotal:"),
            Some(8 * 1024 * MIB)
        );
    }

    #[test]
    fn cpu_sample_splits_busy_and_idle_with_iowait_as_idle() {
        let sample =
            parse_cpu_sample("cpu  100 20 30 5000 40 1 2 3 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n")
                .expect("sample");
        assert_eq!(sample.busy, 100 + 20 + 30 + 1 + 2 + 3);
        assert_eq!(sample.idle, 5000 + 40);
        assert_eq!(parse_cpu_sample("cpu 1 2 3\n"), None);
        assert_eq!(parse_cpu_sample("intr 5\n"), None);
        assert_eq!(
            parse_cpu_sample("cpu 10 20 30 40 50 60 70 80 999 999\n")
                .expect("sample")
                .busy,
            270
        );
        assert_eq!(parse_cpu_sample("cpu 18446744073709551615 1 0 0 0\n"), None);
        assert!(!is_idle(0, 0));
        assert!(is_idle(1, u64::MAX));
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
}
