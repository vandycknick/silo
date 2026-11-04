use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use prost_types::Timestamp;
use protocol::v1::{
    AgentMetricReport, AgentMetrics, BlockDeviceMetrics, CpuMetrics, FilesystemMetrics,
    LoadAverageMetrics, MemoryMetrics, MemoryReclaimReport, MetricSnapshot,
    NetworkInterfaceMetrics, RootStorageKind, RootStorageMetrics, TemporaryDirectoryKind,
    TemporaryDirectoryMetrics,
};

pub(crate) fn collect(
    instance_id: String,
    memory_reclaim: Option<MemoryReclaimReport>,
) -> Result<AgentMetrics, String> {
    let root_storage = root_storage()?;
    Ok(AgentMetrics {
        agent_instance_id: Some(instance_id),
        report: Some(AgentMetricReport {
            observed_at: Some(now()),
            snapshot: Some(MetricSnapshot {
                memory: fs::read_to_string("/proc/meminfo")
                    .ok()
                    .and_then(|text| parse_memory(&text)),
                cpu: fs::read_to_string("/proc/stat")
                    .ok()
                    .and_then(|text| parse_cpu(&text)),
                load_average: fs::read_to_string("/proc/loadavg")
                    .ok()
                    .and_then(|text| parse_load(&text)),
                uptime_seconds: fs::read_to_string("/proc/uptime")
                    .ok()
                    .and_then(|text| parse_uptime(&text)),
                filesystems: filesystems(),
                network_interfaces: network(),
                block_devices: block_devices(),
                memory_reclaim,
                root_storage,
            }),
        }),
    })
}

fn now() -> Timestamp {
    let duration = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration,
        Err(_) => std::time::Duration::ZERO,
    };
    Timestamp {
        seconds: i64::try_from(duration.as_secs()).map_or(i64::MAX, |seconds| seconds),
        nanos: duration.subsec_nanos() as i32,
    }
}

fn parse_memory(text: &str) -> Option<MemoryMetrics> {
    let value = |key| {
        text.lines()
            .find_map(|line| {
                line.strip_prefix(key)?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .and_then(|value| value.checked_mul(1024))
    };
    Some(MemoryMetrics {
        total_bytes: Some(value("MemTotal:")?),
        available_bytes: Some(value("MemAvailable:")?),
        free_bytes: value("MemFree:"),
        cached_bytes: value("Cached:"),
    })
}

fn parse_cpu(text: &str) -> Option<CpuMetrics> {
    let fields: Vec<u64> = text
        .lines()
        .find(|line| line.starts_with("cpu "))?
        .split_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let ticks = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .ok()
        .flatten()
        .filter(|ticks| *ticks > 0)? as f64;
    let seconds = |index| {
        let value = *fields.get(index)? as f64 / ticks;
        (value.is_finite() && value >= 0.0).then_some(value)
    };
    Some(CpuMetrics {
        logical_cpu_count: std::thread::available_parallelism()
            .ok()
            .and_then(|count| u32::try_from(count.get()).ok()),
        user_seconds: Some(seconds(0)?),
        nice_seconds: Some(seconds(1)?),
        system_seconds: Some(seconds(2)?),
        idle_seconds: Some(seconds(3)?),
        iowait_seconds: Some(seconds(4)?),
        irq_seconds: Some(seconds(5)?),
        softirq_seconds: Some(seconds(6)?),
        steal_seconds: Some(seconds(7)?),
    })
}

fn parse_load(text: &str) -> Option<LoadAverageMetrics> {
    let values: Vec<f64> = text
        .split_whitespace()
        .take(3)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let value = |index| {
        values
            .get(index)
            .copied()
            .filter(|value: &f64| value.is_finite() && *value >= 0.0)
    };
    Some(LoadAverageMetrics {
        one_minute: Some(value(0)?),
        five_minutes: Some(value(1)?),
        fifteen_minutes: Some(value(2)?),
    })
}

fn parse_uptime(text: &str) -> Option<f64> {
    text.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn filesystems() -> Vec<FilesystemMetrics> {
    match fs::read_to_string("/proc/self/mounts") {
        Ok(text) => parse_filesystems(&text),
        Err(_) => Vec::new(),
    }
}

fn parse_filesystems(text: &str) -> Vec<FilesystemMetrics> {
    let mut filesystems = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let _source = fields.next();
        let Some(mount) = fields.next().and_then(decode_mount_field) else {
            continue;
        };
        // `/` already reports the upper-backed overlay. Maintenance mounts are
        // accounted for explicitly in root_storage, never as additional disks.
        if is_root_maintenance_mount(&mount) {
            continue;
        }
        let Some(filesystem_type) = fields.next().and_then(decode_mount_field) else {
            continue;
        };
        let Ok(stat) = rustix::fs::statvfs(&mount) else {
            continue;
        };
        let Some(capacity) =
            Capacity::from_counts(stat.f_frsize, stat.f_blocks, stat.f_bfree, stat.f_bavail)
        else {
            continue;
        };
        filesystems
            .entry(mount.clone())
            .or_insert(FilesystemMetrics {
                mount_point: Some(mount),
                filesystem_type: Some(filesystem_type),
                total_bytes: Some(capacity.usable),
                used_bytes: Some(capacity.used),
                available_bytes: Some(capacity.available),
            });
    }
    filesystems
        .into_values()
        .take(protocol::MAX_METRIC_ARRAY_ENTRIES)
        .collect()
}

fn is_root_maintenance_mount(mount: &str) -> bool {
    Path::new(mount).starts_with("/run/silo/rootfs")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Capacity {
    usable: u64,
    used: u64,
    free: u64,
    available: u64,
}

impl Capacity {
    fn from_counts(fragment: u64, blocks: u64, free: u64, available: u64) -> Option<Self> {
        if fragment == 0 || available > free {
            return None;
        }
        Some(Self {
            usable: blocks.checked_mul(fragment)?,
            used: blocks.checked_sub(free)?.checked_mul(fragment)?,
            free: free.checked_mul(fragment)?,
            available: available.checked_mul(fragment)?,
        })
    }
}

fn root_storage() -> Result<Option<RootStorageMetrics>, String> {
    let Some(observation) =
        crate::root_storage::retained_root().map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    use std::os::unix::fs::MetadataExt;
    let upper_device = fs::metadata(rootfs_spec::UPPER_MOUNT)
        .map_err(|error| format!("inspect managed upper mount: {error}"))?
        .dev();
    if nix::sys::stat::major(upper_device) != u64::from(observation.upper_device.major)
        || nix::sys::stat::minor(upper_device) != u64::from(observation.upper_device.minor)
    {
        return Err(
            "managed upper maintenance mount device differs from retained observation".to_string(),
        );
    }
    let stat = rustix::fs::statvfs(rootfs_spec::UPPER_MOUNT)
        .map_err(|error| format!("inspect managed upper capacity: {error}"))?;
    let capacity = Capacity::from_counts(stat.f_frsize, stat.f_blocks, stat.f_bfree, stat.f_bavail)
        .ok_or_else(|| "managed upper capacity arithmetic is inconsistent".to_string())?;
    let temporary_directory = temporary_directory()?;
    root_storage_from_observation(
        &observation,
        capacity,
        stat.f_files,
        stat.f_ffree,
        stat.f_favail,
        temporary_directory,
    )
    .map(Some)
}

fn root_storage_from_observation(
    observation: &rootfs_spec::Observation,
    capacity: Capacity,
    total_inodes: u64,
    free_inodes: u64,
    available_inodes: u64,
    temporary_directory: TemporaryDirectoryMetrics,
) -> Result<RootStorageMetrics, String> {
    observation.validate().map_err(|error| error.to_string())?;
    let overhead = observation
        .upper_filesystem_bytes
        .checked_sub(capacity.usable)
        .ok_or_else(|| "managed upper usable bytes exceed its filesystem span".to_string())?;
    let metrics = RootStorageMetrics {
        kind: Some(RootStorageKind::LinuxFlatOverlayV1 as i32),
        upper_profile: Some(observation.root.upper_profile.as_str().to_string()),
        upper_uuid: Some(observation.root.upper.filesystem_uuid.to_string()),
        upper_backing_bytes: Some(observation.root.upper.length_bytes),
        upper_filesystem_bytes: Some(observation.upper_filesystem_bytes),
        unusable_tail_bytes: Some(observation.unusable_tail_bytes),
        filesystem_overhead_bytes: Some(overhead),
        upper_usable_bytes: Some(capacity.usable),
        upper_used_bytes: Some(capacity.used),
        upper_free_bytes: Some(capacity.free),
        upper_available_bytes: Some(capacity.available),
        upper_total_inodes: Some(total_inodes),
        upper_free_inodes: Some(free_inodes),
        upper_available_inodes: Some(available_inodes),
        shared_lower_logical_bytes: Some(observation.root.lower.length_bytes),
        temporary_directory: Some(temporary_directory),
    };
    protocol::validate_root_storage_metrics(&metrics)?;
    Ok(metrics)
}

fn temporary_directory() -> Result<TemporaryDirectoryMetrics, String> {
    use std::os::unix::fs::MetadataExt;

    let stat =
        rustix::fs::statvfs("/tmp").map_err(|error| format!("inspect /tmp capacity: {error}"))?;
    let capacity = Capacity::from_counts(stat.f_frsize, stat.f_blocks, stat.f_bfree, stat.f_bavail)
        .ok_or_else(|| "/tmp capacity arithmetic is inconsistent".to_string())?;
    let filesystem = nix::sys::statfs::statfs("/tmp")
        .map_err(|error| format!("inspect /tmp filesystem: {error}"))?;
    let tmp_device = fs::metadata("/tmp")
        .map_err(|error| format!("inspect /tmp device: {error}"))?
        .dev();
    let root_device = fs::metadata("/")
        .map_err(|error| format!("inspect root device: {error}"))?
        .dev();
    let upper_device = fs::metadata(rootfs_spec::UPPER_MOUNT)
        .map_err(|error| format!("inspect upper device: {error}"))?
        .dev();
    let kind = temporary_directory_kind(
        filesystem.filesystem_type() == nix::sys::statfs::TMPFS_MAGIC,
        tmp_device == root_device || tmp_device == upper_device,
    );
    Ok(temporary_directory_metrics(kind, capacity))
}

fn temporary_directory_kind(tmpfs: bool, shares_upper: bool) -> TemporaryDirectoryKind {
    if tmpfs {
        TemporaryDirectoryKind::Tmpfs
    } else if shares_upper {
        TemporaryDirectoryKind::Upper
    } else {
        TemporaryDirectoryKind::Other
    }
}

fn temporary_directory_metrics(
    kind: TemporaryDirectoryKind,
    capacity: Capacity,
) -> TemporaryDirectoryMetrics {
    let (persistent, memory_charged) = match kind {
        TemporaryDirectoryKind::Upper => (Some(true), Some(false)),
        TemporaryDirectoryKind::Tmpfs => (Some(false), Some(true)),
        _ => (None, None),
    };
    TemporaryDirectoryMetrics {
        kind: Some(kind as i32),
        capacity_bytes: Some(capacity.usable),
        used_bytes: Some(capacity.used),
        free_bytes: Some(capacity.free),
        available_bytes: Some(capacity.available),
        persistent,
        memory_charged,
    }
}

fn decode_mount_field(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let escape = std::str::from_utf8(&bytes[index + 1..index + 4]).ok()?;
            if let Ok(value) = u8::from_str_radix(escape, 8) {
                decoded.push(char::from(value));
                index += 4;
                continue;
            }
        }
        decoded.push(char::from(bytes[index]));
        index += 1;
    }
    (!decoded.is_empty()).then_some(decoded)
}

fn network() -> Vec<NetworkInterfaceMetrics> {
    match fs::read_to_string("/proc/net/dev") {
        Ok(text) => parse_network(&text),
        Err(_) => Vec::new(),
    }
}

fn parse_network(text: &str) -> Vec<NetworkInterfaceMetrics> {
    let mut interfaces = BTreeMap::new();
    for line in text.lines().skip(2) {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        let values: Vec<u64> = match values
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<u64>, _>>()
        {
            Ok(values) if values.len() >= 9 => values,
            _ => continue,
        };
        let mac = fs::read_to_string(format!("/sys/class/net/{name}/address"))
            .ok()
            .and_then(|value| canonical_mac(value.trim()));
        interfaces
            .entry(name.to_string())
            .or_insert(NetworkInterfaceMetrics {
                name: Some(name.to_string()),
                mac,
                receive_bytes: values.first().copied(),
                transmit_bytes: values.get(8).copied(),
            });
    }
    interfaces
        .into_values()
        .take(protocol::MAX_METRIC_ARRAY_ENTRIES)
        .collect()
}

fn canonical_mac(value: &str) -> Option<String> {
    let bytes: Vec<_> = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    (bytes.len() == 6).then(|| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

fn block_devices() -> Vec<BlockDeviceMetrics> {
    match fs::read_to_string("/proc/diskstats") {
        Ok(text) => parse_block_devices(&text),
        Err(_) => Vec::new(),
    }
}

fn parse_block_devices(text: &str) -> Vec<BlockDeviceMetrics> {
    let mut devices = BTreeMap::new();
    for line in text.lines() {
        let values: Vec<_> = line.split_whitespace().collect();
        let Some(name) = values.get(2) else { continue };
        if Path::new(&format!("/sys/class/block/{name}/partition")).exists() {
            continue;
        }
        let number = |index: usize| {
            values
                .get(index)
                .and_then(|value| value.parse::<u64>().ok())
        };
        let (
            Some(read_operations),
            Some(read_sectors),
            Some(write_operations),
            Some(write_sectors),
            Some(in_flight_operations),
        ) = (number(3), number(5), number(7), number(9), number(11))
        else {
            continue;
        };
        let (Some(read_bytes), Some(write_bytes)) = (
            read_sectors.checked_mul(512),
            write_sectors.checked_mul(512),
        ) else {
            continue;
        };
        devices
            .entry((*name).to_string())
            .or_insert(BlockDeviceMetrics {
                name: Some((*name).to_string()),
                read_operations: Some(read_operations),
                read_bytes: Some(read_bytes),
                write_operations: Some(write_operations),
                write_bytes: Some(write_bytes),
                in_flight_operations: Some(in_flight_operations),
            });
    }
    devices
        .into_values()
        .take(protocol::MAX_METRIC_ARRAY_ENTRIES)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_complete_proc_fixtures() {
        let memory = crate::metrics::parse_memory(
            "MemTotal: 2 kB\nMemFree: 1 kB\nMemAvailable: 1 kB\nCached: 1 kB\n",
        )
        .expect("memory");
        assert_eq!(memory.total_bytes, Some(2048));
        assert_eq!(memory.available_bytes, Some(1024));
        assert_eq!(memory.free_bytes, Some(1024));
        assert_eq!(memory.cached_bytes, Some(1024));
        let sparse =
            crate::metrics::parse_memory("MemTotal: 2 kB\nMemAvailable: 1 kB\n").expect("memory");
        assert_eq!(sparse.free_bytes, None);
        let load = crate::metrics::parse_load("1.0 2.0 3.0 1/1 1").expect("load");
        assert_eq!(load.fifteen_minutes, Some(3.0));
        assert_eq!(crate::metrics::parse_uptime("12.5 0.0"), Some(12.5));
    }

    #[test]
    fn rejects_incomplete_or_nonfinite_metrics() {
        assert!(crate::metrics::parse_memory("MemTotal: 2 kB\n").is_none());
        assert!(crate::metrics::parse_load("NaN 1 2").is_none());
        assert!(crate::metrics::parse_uptime("-1 0").is_none());
    }

    #[test]
    fn decodes_mount_fields_and_canonicalizes_mac() {
        assert_eq!(
            crate::metrics::decode_mount_field("/a\\040b"),
            Some("/a b".to_string())
        );
        assert_eq!(
            crate::metrics::canonical_mac("A:b:0c:00:00:ff"),
            Some("0a:0b:0c:00:00:ff".to_string())
        );
        assert!(crate::metrics::canonical_mac("not-a-mac").is_none());
    }

    #[test]
    fn parses_network_fixture_in_name_order() {
        let metrics = crate::metrics::parse_network(
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n z: 2 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0\n a: 4 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0\n",
        );
        assert_eq!(
            metrics
                .iter()
                .map(|metric| metric.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("a"), Some("z")]
        );
    }

    #[test]
    fn parses_sorted_block_devices_and_skips_overflow() {
        let metrics = crate::metrics::parse_block_devices(
            "8 0 z 1 0 2 0 3 4 0 5 6 0\n8 1 a 1 0 2 0 3 4 0 5 6 0\n8 2 overflow 1 0 18446744073709551615 0 3 4 0 5 6 0\n",
        );
        assert_eq!(
            metrics
                .iter()
                .map(|metric| metric.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("a"), Some("z")]
        );
        assert_eq!(metrics[0].read_bytes, Some(1024));
    }
    #[test]
    fn capacity_checks_reserved_blocks_exhaustion_and_overflow() {
        use crate::metrics::Capacity;
        assert_eq!(
            Capacity::from_counts(4096, 10, 3, 2),
            Some(Capacity {
                usable: 40960,
                used: 28672,
                free: 12288,
                available: 8192,
            })
        );
        assert_eq!(Capacity::from_counts(4096, 10, 0, 0).unwrap().used, 40960);
        assert!(Capacity::from_counts(0, 10, 3, 2).is_none());
        assert!(Capacity::from_counts(4096, 10, 11, 0).is_none());
        assert!(Capacity::from_counts(4096, 10, 3, 4).is_none());
        assert!(Capacity::from_counts(4096, u64::MAX, 0, 0).is_none());
        assert!(Capacity::from_counts(1, u64::MAX, 0, 0).is_some());
    }

    #[test]
    fn actual_temporary_backing_overrides_boot_policy_and_unknown_is_not_persistent() {
        use crate::metrics::{temporary_directory_kind, temporary_directory_metrics, Capacity};
        use protocol::v1::TemporaryDirectoryKind;
        let capacity = Capacity::from_counts(4096, 256, 255, 254).unwrap();
        let disk = temporary_directory_metrics(temporary_directory_kind(false, true), capacity);
        assert_eq!(disk.kind, Some(TemporaryDirectoryKind::Upper as i32));
        assert_eq!(
            (disk.persistent, disk.memory_charged),
            (Some(true), Some(false))
        );
        let tmpfs = temporary_directory_metrics(temporary_directory_kind(true, true), capacity);
        assert_eq!(tmpfs.kind, Some(TemporaryDirectoryKind::Tmpfs as i32));
        assert_eq!(
            (tmpfs.persistent, tmpfs.memory_charged),
            (Some(false), Some(true))
        );
        let other = temporary_directory_metrics(temporary_directory_kind(false, false), capacity);
        assert_eq!(other.kind, Some(TemporaryDirectoryKind::Other as i32));
        assert_eq!((other.persistent, other.memory_charged), (None, None));
        protocol::validate_temporary_directory_metrics(&disk).unwrap();
        protocol::validate_temporary_directory_metrics(&tmpfs).unwrap();
        protocol::validate_temporary_directory_metrics(&other).unwrap();
    }

    #[test]
    fn maintenance_mounts_do_not_duplicate_overlay_capacity() {
        assert!(crate::metrics::is_root_maintenance_mount(
            "/run/silo/rootfs/upperfs"
        ));
        assert!(crate::metrics::is_root_maintenance_mount(
            "/run/silo/rootfs/lower"
        ));
        assert!(!crate::metrics::is_root_maintenance_mount("/"));
        assert!(!crate::metrics::is_root_maintenance_mount(
            "/run/silo/rootfs-other"
        ));
    }
    #[test]
    fn retained_observation_reports_upper_not_lower_or_overlay_and_preserves_tail() {
        use crate::metrics::{
            root_storage_from_observation, temporary_directory_metrics, Capacity,
        };
        use protocol::v1::TemporaryDirectoryKind;
        let mut observation = rootfs_spec::decode_observation(include_bytes!(
            "../../../specs/rootfs-spec/fixtures/observation.json"
        ))
        .unwrap();
        observation.root.upper.length_bytes += 4096;
        observation.unusable_tail_bytes = 4096;
        let capacity = Capacity::from_counts(4096, 15_000, 2_000, 1_000).unwrap();
        let temporary = temporary_directory_metrics(TemporaryDirectoryKind::Upper, capacity);
        let report =
            root_storage_from_observation(&observation, capacity, 8192, 0, 0, temporary).unwrap();
        assert_eq!(report.upper_backing_bytes, Some(67_112_960));
        assert_eq!(report.upper_filesystem_bytes, Some(67_108_864));
        assert_eq!(report.unusable_tail_bytes, Some(4096));
        assert_eq!(report.filesystem_overhead_bytes, Some(5_668_864));
        assert_eq!(report.upper_usable_bytes, Some(61_440_000));
        assert_eq!(report.upper_used_bytes, Some(53_248_000));
        assert_eq!(report.upper_free_bytes, Some(8_192_000));
        assert_eq!(report.upper_available_bytes, Some(4_096_000));
        assert_eq!(report.upper_free_inodes, Some(0));
        assert_eq!(report.shared_lower_logical_bytes, Some(268_435_456));
        assert_eq!(
            report.upper_uuid.as_deref(),
            Some("87654321-4321-4321-8321-cba987654321")
        );
        let too_large = Capacity::from_counts(4096, 20_000, 0, 0).unwrap();
        let temporary = temporary_directory_metrics(TemporaryDirectoryKind::Upper, too_large);
        assert!(
            root_storage_from_observation(&observation, too_large, 8192, 0, 0, temporary,).is_err()
        );
    }
}
