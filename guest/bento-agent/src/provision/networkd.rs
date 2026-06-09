use bento_core::agent::{NetworkConfig, NetworkInterfaceConfig};

use crate::provision::{
    command_exists, run_command, sanitize_unit_name, write_file, ProvisionContext,
};

pub(crate) fn apply(context: &ProvisionContext, config: &NetworkConfig) -> eyre::Result<()> {
    if config.interfaces.is_empty() {
        return Ok(());
    }

    for interface in &config.interfaces {
        let path = context.guest_path(&format!(
            "/etc/systemd/network/10-bento-{}.network",
            sanitize_unit_name(&interface.name)
        ));
        write_file(&path, render_network_file(interface), 0o644)?;
    }

    if command_exists("systemctl") {
        run_command("systemctl", ["enable", "systemd-networkd.service"])?;
        run_command("systemctl", ["restart", "systemd-networkd.service"])?;
    }

    tracing::info!(
        interfaces = config.interfaces.len(),
        "provisioned systemd-networkd config"
    );
    Ok(())
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
    use bento_core::agent::{NetworkInterfaceConfig, NetworkMatchConfig};

    #[test]
    fn renders_networkd_mac_match() {
        let rendered = super::render_network_file(&NetworkInterfaceConfig {
            name: "bento".to_string(),
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
}
