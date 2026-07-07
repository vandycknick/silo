use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use agent_spec::{NetworkConfig, NetworkInterfaceConfig};
use eyre::Context;

use crate::provision::{
    command_exists, run_command, sanitize_unit_name, write_file, ProvisionContext,
};

pub(crate) fn apply(context: &ProvisionContext, config: &NetworkConfig) -> eyre::Result<()> {
    let network_dir = context.guest_path("/etc/systemd/network");
    let mut desired_paths = BTreeSet::new();
    let mut changed = false;

    for interface in &config.interfaces {
        let path = network_dir.join(format!(
            "10-silo-{}.network",
            sanitize_unit_name(&interface.name)
        ));
        desired_paths.insert(path.clone());
        let rendered = render_network_file(interface);
        if file_contents(&path)?.as_deref() != Some(rendered.as_str()) {
            write_file(&path, rendered, 0o644)?;
            changed = true;
        }
    }

    for stale_path in stale_silo_network_files(&network_dir, &desired_paths)? {
        fs::remove_file(&stale_path)
            .with_context(|| format!("remove stale networkd config {}", stale_path.display()))?;
        tracing::info!(path = %stale_path.display(), "removed stale Silo networkd config");
        changed = true;
    }

    if command_exists("systemctl") && (changed || !config.interfaces.is_empty()) {
        if !config.interfaces.is_empty() {
            run_command(
                context.process_supervisor(),
                "systemctl",
                ["enable", "systemd-networkd.service"],
            )?;
        }
        if changed {
            run_command(
                context.process_supervisor(),
                "systemctl",
                ["restart", "systemd-networkd.service"],
            )?;
        } else {
            run_command(
                context.process_supervisor(),
                "systemctl",
                ["start", "systemd-networkd.service"],
            )?;
        }
    }

    tracing::info!(
        interfaces = config.interfaces.len(),
        changed,
        "reconciled systemd-networkd config"
    );
    Ok(())
}

fn file_contents(path: &std::path::Path) -> eyre::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

fn stale_silo_network_files(
    network_dir: &std::path::Path,
    desired_paths: &BTreeSet<PathBuf>,
) -> eyre::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(network_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("read {}", network_dir.display())),
    };

    let mut stale = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", network_dir.display()))?;
        let path = entry.path();
        if desired_paths.contains(&path) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("10-silo-") && name.ends_with(".network") {
            stale.push(path);
        }
    }
    Ok(stale)
}

fn render_network_file(interface: &NetworkInterfaceConfig) -> String {
    let mut rendered = String::from("[Match]\n");
    if let Some(driver) = interface.matches.driver.as_deref() {
        rendered.push_str("Driver=");
        rendered.push_str(driver);
        rendered.push('\n');
    }
    if let Some(mac_address) = interface.matches.mac_address.as_deref() {
        rendered.push_str("MACAddress=");
        rendered.push_str(mac_address);
        rendered.push('\n');
    }
    if interface.matches.driver.is_none() && interface.matches.mac_address.is_none() {
        rendered.push_str("Name=");
        rendered.push_str(&interface.name);
        rendered.push('\n');
    }

    rendered.push_str("\n[Network]\nDHCP=");
    rendered.push_str(match (interface.dhcp4, interface.dhcp6) {
        (true, true) => "yes",
        (true, false) => "ipv4",
        (false, true) => "ipv6",
        (false, false) => "no",
    });
    rendered.push('\n');
    rendered
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use agent_spec::{NetworkInterfaceConfig, NetworkMatchConfig};

    #[test]
    fn renders_networkd_mac_match() {
        let rendered = super::render_network_file(&NetworkInterfaceConfig {
            name: "silo".to_string(),
            matches: NetworkMatchConfig {
                driver: None,
                mac_address: Some("02:00:00:00:00:01".to_string()),
            },
            dhcp4: true,
            dhcp6: false,
        });

        assert!(rendered.contains("MACAddress=02:00:00:00:00:01"));
        assert!(rendered.contains("DHCP=ipv4"));
    }

    #[test]
    fn finds_stale_silo_network_files() {
        let temp =
            std::env::temp_dir().join(format!("silo-agent-networkd-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).expect("create temp dir");
        let desired = temp.join("10-silo-current.network");
        let stale = temp.join("10-silo-old.network");
        let unrelated = temp.join("20-other.network");
        fs::write(&desired, "current").expect("write desired");
        fs::write(&stale, "old").expect("write stale");
        fs::write(&unrelated, "other").expect("write unrelated");

        let mut desired_paths = BTreeSet::new();
        desired_paths.insert(desired);
        let stale_paths =
            super::stale_silo_network_files(&temp, &desired_paths).expect("find stale files");

        assert_eq!(stale_paths, [stale]);
        fs::remove_dir_all(&temp).expect("clean temp dir");
    }
}
