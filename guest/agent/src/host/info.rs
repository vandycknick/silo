use std::collections::BTreeSet;
use std::fs;

use nix::ifaddrs::getifaddrs;
use protocol::v1::SystemInfo;

/// Reads host information for the running guest instance.
///
/// This aggregates kernel, OS, memory, uptime, hostname, CPU, and non-loopback
/// IP address data from the local Linux system and returns it in Bento's
/// `SystemInfo` wire format.
///
/// Field collection is best-effort. If one source is unavailable, the function
/// still returns the remaining data it can gather.
pub fn get_system_info() -> eyre::Result<SystemInfo> {
    let uname = nix::sys::utsname::uname().map_err(|err| eyre::eyre!("uname failed: {err}"))?;
    let (os_name, os_version) = read_os_release();
    let (total_memory, available_memory) = read_memory_info();
    let load_average = read_load_average();
    let uptime = read_uptime();

    Ok(SystemInfo {
        kernel_version: uname.release().to_string_lossy().into_owned(),
        os_name,
        os_version,
        arch: uname.machine().to_string_lossy().into_owned(),
        total_memory,
        available_memory,
        cpu_count: std::thread::available_parallelism()
            .map(|count| count.get() as u32)
            .unwrap_or(0),
        load_average,
        hostname: read_hostname(),
        uptime,
        ip_addresses: read_ip_addresses(),
    })
}

fn read_os_release() -> (String, String) {
    let mut name = String::from("Linux");
    let mut version = String::new();

    if let Ok(contents) = fs::read_to_string("/etc/os-release") {
        for line in contents.lines() {
            if let Some(value) = parse_key_value(line, "NAME") {
                name = value;
            }
            if let Some(value) = parse_key_value(line, "VERSION") {
                version = value;
            }
        }
    }

    (name, version)
}

fn parse_key_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    line.strip_prefix(&prefix)
        .map(|value| value.trim_matches('"').to_string())
}

fn read_memory_info() -> (u64, u64) {
    let mut total_memory = 0;
    let mut available_memory = 0;

    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if let Some(value) = parse_meminfo_kib(line, "MemTotal:") {
                total_memory = value;
            }
            if let Some(value) = parse_meminfo_kib(line, "MemAvailable:") {
                available_memory = value;
            }
        }
    }

    (total_memory, available_memory)
}

fn parse_meminfo_kib(line: &str, key: &str) -> Option<u64> {
    let value = line.strip_prefix(key)?.split_whitespace().next()?;
    value.parse::<u64>().ok().map(|kib| kib * 1024)
}

fn read_load_average() -> Vec<f64> {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|contents| {
            contents
                .split_whitespace()
                .take(3)
                .filter_map(|value| value.parse::<f64>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn read_uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|contents| contents.split_whitespace().next().map(str::to_string))
        .and_then(|value| value.split('.').next().map(str::to_string))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn read_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn read_ip_addresses() -> Vec<String> {
    let mut ip_addresses = BTreeSet::new();

    let Ok(addresses) = getifaddrs() else {
        return Vec::new();
    };

    for address in addresses {
        let Some(sockaddr) = address.address else {
            continue;
        };

        if let Some(addr) = sockaddr.as_sockaddr_in() {
            let ip = addr.ip();
            if !ip.is_loopback() {
                ip_addresses.insert(ip.to_string());
            }
        }

        if let Some(addr) = sockaddr.as_sockaddr_in6() {
            let ip = addr.ip();
            if !ip.is_loopback() {
                ip_addresses.insert(ip.to_string());
            }
        }
    }

    ip_addresses.into_iter().collect()
}
