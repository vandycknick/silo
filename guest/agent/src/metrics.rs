use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use prost_types::Timestamp;
use protocol::v1::{
    AgentMetricReport, AgentMetrics, BlockDeviceMetrics, CpuMetrics, FilesystemMetrics,
    LoadAverageMetrics, MemoryMetrics, MetricSnapshot, NetworkInterfaceMetrics,
};

pub(crate) fn collect(instance_id: String) -> AgentMetrics {
    AgentMetrics {
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
            }),
        }),
    }
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
        let Some(filesystem_type) = fields.next().and_then(decode_mount_field) else {
            continue;
        };
        let Ok(stat) = rustix::fs::statvfs(&mount) else {
            continue;
        };
        let block_size = u64::try_from(stat.f_frsize).ok();
        let blocks = u64::try_from(stat.f_blocks).ok();
        let free_blocks = u64::try_from(stat.f_bfree).ok();
        let available_blocks = u64::try_from(stat.f_bavail).ok();
        let (Some(block_size), Some(blocks), Some(free_blocks), Some(available_blocks)) =
            (block_size, blocks, free_blocks, available_blocks)
        else {
            continue;
        };
        let (Some(total_bytes), Some(free_bytes), Some(available_bytes)) = (
            blocks.checked_mul(block_size),
            free_blocks.checked_mul(block_size),
            available_blocks.checked_mul(block_size),
        ) else {
            continue;
        };
        filesystems
            .entry(mount.clone())
            .or_insert(FilesystemMetrics {
                mount_point: Some(mount),
                filesystem_type: Some(filesystem_type),
                total_bytes: Some(total_bytes),
                used_bytes: Some(total_bytes.saturating_sub(free_bytes)),
                available_bytes: Some(available_bytes),
            });
    }
    filesystems
        .into_values()
        .take(protocol::MAX_METRIC_ARRAY_ENTRIES)
        .collect()
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
        let memory =
            crate::metrics::parse_memory("MemTotal: 2 kB\nMemAvailable: 1 kB\n").expect("memory");
        assert_eq!(memory.total_bytes, Some(2048));
        assert_eq!(memory.available_bytes, Some(1024));
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
}
