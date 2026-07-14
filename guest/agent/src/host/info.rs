use std::collections::BTreeSet;
use std::fs;

use nix::ifaddrs::getifaddrs;
use protocol::v1::SystemInfo;

/// Reads host information for the running guest instance.
///
/// This aggregates kernel, OS, hostname, and non-loopback IP address data from
/// the local Linux system and returns it in Silo's `SystemInfo` wire format.
///
/// Field collection is best-effort. If one source is unavailable, the function
/// still returns the remaining data it can gather.
pub fn get_system_info() -> eyre::Result<SystemInfo> {
    let uname = nix::sys::utsname::uname().map_err(|err| eyre::eyre!("uname failed: {err}"))?;
    let (os_name, os_version) = read_os_release();
    Ok(SystemInfo {
        kernel_version: Some(uname.release().to_string_lossy().into_owned()),
        os_name: Some(os_name),
        os_version: Some(os_version),
        architecture: Some(uname.machine().to_string_lossy().into_owned()),
        hostname: Some(read_hostname()),
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
