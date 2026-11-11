use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EnrollmentMode {
    OauthApp,
    Interactive,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct TailscaleConfig {
    enabled: Option<bool>,
    hostname: String,
    tag: String,
    control_url: String,
    enrollment: Enrollment,
    vm: VmSettings,
    sessions: SessionLimits,
    #[serde(deserialize_with = "size")]
    disk_reserve: u64,
    #[serde(deserialize_with = "size")]
    file_transfer_limit: u64,
}
impl Default for TailscaleConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            hostname: "silo".into(),
            tag: "tag:silo".into(),
            control_url: String::new(),
            enrollment: Enrollment::default(),
            vm: VmSettings::default(),
            sessions: SessionLimits::default(),
            disk_reserve: 1 << 30,
            file_transfer_limit: 256 << 20,
        }
    }
}
impl TailscaleConfig {
    pub(crate) fn effective_settings(&self) -> impl std::fmt::Debug + '_ {
        (
            &self.hostname,
            &self.tag,
            &self.control_url,
            &self.enrollment,
            &self.vm,
            &self.sessions,
            self.disk_reserve,
            self.file_transfer_limit,
        )
    }
    pub(crate) fn enabled(&self) -> Option<bool> {
        self.enabled
    }
    #[cfg(test)]
    pub(crate) fn hostname(&self) -> &str {
        &self.hostname
    }
    pub(crate) fn control_url(&self) -> &str {
        &self.control_url
    }
    pub(crate) fn enrollment_mode(&self) -> EnrollmentMode {
        self.enrollment.mode
    }
    pub(crate) fn disable_key_expiry(&self) -> bool {
        self.enrollment.disable_key_expiry
    }
    /// `(cpus, memory, disk)` applied when a create request omits them.
    pub(crate) fn vm_defaults(&self) -> (u64, u64, u64) {
        let d = &self.vm.defaults;
        (d.cpus, d.memory, d.disk)
    }
    /// `(vms_per_principal, cpus, memory, disk)` bounding every principal.
    pub(crate) fn vm_ceilings(&self) -> (u64, u64, u64, u64) {
        let c = &self.vm.ceilings;
        (c.vms_per_principal, c.cpus, c.memory, c.disk)
    }
    /// `(global, per_peer)` concurrent SSH session caps.
    pub(crate) fn session_limits(&self) -> (u64, u64) {
        (self.sessions.global, self.sessions.per_peer)
    }
    pub(crate) fn disk_reserve(&self) -> u64 {
        self.disk_reserve
    }
    pub(crate) fn file_transfer_limit(&self) -> u64 {
        self.file_transfer_limit
    }
    pub(super) fn validate(&self) -> eyre::Result<()> {
        let name = self.hostname.as_bytes();
        if name.is_empty()
            || name.len() > 63
            || name.last() == Some(&b'-')
            || !name
                .iter()
                .enumerate()
                .all(|(i, b)| b.is_ascii_lowercase() || b.is_ascii_digit() || (*b == b'-' && i > 0))
        {
            eyre::bail!("invalid tailscale hostname");
        }
        let tag = self.tag.strip_prefix("tag:").unwrap_or("").as_bytes();
        if tag.first().is_none_or(|b| !b.is_ascii_alphabetic())
            || !tag.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            eyre::bail!("invalid tailscale tag");
        }
        let d = &self.vm.defaults;
        let c = &self.vm.ceilings;
        if c.vms_per_principal == 0
            || c.cpus == 0
            || c.cpus > 255
            || c.memory == 0
            || c.disk == 0
            || d.cpus == 0
            || d.cpus > c.cpus
            || d.memory == 0
            || d.memory > c.memory
            || d.disk == 0
            || d.disk > c.disk
        {
            eyre::bail!("invalid resource defaults or ceilings");
        }
        if self.sessions.global == 0
            || self.sessions.per_peer == 0
            || self.sessions.per_peer > self.sessions.global
            || self.sessions.global > i64::MAX as u64
        {
            eyre::bail!("invalid session limits");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct Enrollment {
    mode: EnrollmentMode,
    disable_key_expiry: bool,
}
impl Default for Enrollment {
    fn default() -> Self {
        Self {
            mode: EnrollmentMode::OauthApp,
            disable_key_expiry: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct ResourceLimits {
    cpus: u64,
    #[serde(deserialize_with = "size")]
    memory: u64,
    #[serde(deserialize_with = "size")]
    disk: u64,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory: 4 << 30,
            disk: 20 << 30,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Ceilings {
    cpus: u64,
    #[serde(deserialize_with = "size")]
    memory: u64,
    #[serde(deserialize_with = "size")]
    disk: u64,
    vms_per_principal: u64,
}
impl Default for Ceilings {
    fn default() -> Self {
        Self {
            cpus: 8,
            memory: 32 << 30,
            disk: 200 << 30,
            vms_per_principal: 5,
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct VmSettings {
    defaults: ResourceLimits,
    ceilings: Ceilings,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct SessionLimits {
    global: u64,
    per_peer: u64,
}
impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            global: 64,
            per_peer: 8,
        }
    }
}

fn size<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Input {
        Text(String),
        Number(u64),
    }
    let input = match Input::deserialize(d)? {
        Input::Text(s) => s,
        Input::Number(n) => return Ok(n),
    };
    parse_size(&input).map_err(serde::de::Error::custom)
}
fn parse_size(input: &str) -> Result<u64, &'static str> {
    let mut digits = input;
    let mut scale = 1;
    for (suffix, value) in [
        ("TiB", 1u64 << 40),
        ("TB", 1_000_000_000_000),
        ("GiB", 1 << 30),
        ("GB", 1_000_000_000),
        ("MiB", 1 << 20),
        ("MB", 1_000_000),
        ("KiB", 1 << 10),
        ("KB", 1000),
        ("B", 1),
    ] {
        if let Some(n) = input.strip_suffix(suffix) {
            digits = n;
            scale = value;
            break;
        }
    }
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid integer byte size");
    }
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .ok_or("byte size overflow")
}
#[cfg(test)]
mod tests {
    use crate::config::tailscale::TailscaleConfig;

    #[test]
    fn defaults_are_valid_and_keep_lobby_configuration() {
        let config = TailscaleConfig::default();
        config.validate().unwrap();
        assert_eq!(config.enabled(), None);
        assert_eq!(config.hostname, "silo");
        assert_eq!(config.tag, "tag:silo");
        assert_eq!(config.control_url, "");
        assert_eq!(
            config.enrollment.mode,
            crate::config::tailscale::EnrollmentMode::OauthApp
        );
        assert!(!config.enrollment.disable_key_expiry);
        assert_eq!(config.vm.defaults.cpus, 2);
        assert_eq!(config.vm.defaults.memory, 4 << 30);
        assert_eq!(config.vm.defaults.disk, 20 << 30);
        assert_eq!(config.vm.ceilings.cpus, 8);
        assert_eq!(config.vm.ceilings.memory, 32 << 30);
        assert_eq!(config.vm.ceilings.disk, 200 << 30);
        assert_eq!(config.vm.ceilings.vms_per_principal, 5);
        assert_eq!(config.sessions.global, 64);
        assert_eq!(config.sessions.per_peer, 8);
        assert_eq!(config.disk_reserve, 1 << 30);
    }

    #[test]
    fn file_transfer_limit_defaults_and_accepts_sizes() {
        let defaults: TailscaleConfig = serde_yaml_ng::from_str("{}").unwrap();
        assert_eq!(defaults.file_transfer_limit, 256 << 20);
        let sized: TailscaleConfig = serde_yaml_ng::from_str("file-transfer-limit: 8MiB").unwrap();
        assert_eq!(sized.file_transfer_limit, 8 << 20);
        let bytes: TailscaleConfig = serde_yaml_ng::from_str("file-transfer-limit: 123").unwrap();
        assert_eq!(bytes.file_transfer_limit, 123);
        assert!(serde_yaml_ng::from_str::<TailscaleConfig>("file-transfer-limit: 8oops").is_err());
    }
}
