use serde::{Deserialize, Deserializer};
use std::time::Duration;

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
    shutdown: ShutdownSettings,
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
            shutdown: ShutdownSettings::default(),
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
            &self.shutdown,
        )
    }
    pub(crate) fn enabled(&self) -> Option<bool> {
        self.enabled
    }
    pub(crate) fn hostname(&self) -> &str {
        &self.hostname
    }
    pub(crate) fn tag(&self) -> &str {
        &self.tag
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
    pub(crate) fn vm(&self) -> &VmSettings {
        &self.vm
    }
    pub(crate) fn sessions(&self) -> &SessionLimits {
        &self.sessions
    }
    pub(crate) fn disk_reserve(&self) -> u64 {
        self.disk_reserve
    }
    pub(crate) fn file_transfer_limit(&self) -> u64 {
        self.file_transfer_limit
    }
    pub(crate) fn shutdown(&self) -> &ShutdownSettings {
        &self.shutdown
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
        if self.shutdown.stop_budget.is_zero()
            || self.shutdown.stop_budget > Duration::from_secs(60)
            || self.shutdown.margin.is_zero()
            || self.shutdown.margin > Duration::from_secs(1)
        {
            eyre::bail!("invalid shutdown stop-budget or margin");
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
impl ResourceLimits {
    pub(crate) fn cpus(&self) -> u64 {
        self.cpus
    }
    pub(crate) fn memory(&self) -> u64 {
        self.memory
    }
    pub(crate) fn disk(&self) -> u64 {
        self.disk
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
impl Ceilings {
    pub(crate) fn cpus(&self) -> u64 {
        self.cpus
    }
    pub(crate) fn memory(&self) -> u64 {
        self.memory
    }
    pub(crate) fn disk(&self) -> u64 {
        self.disk
    }
    pub(crate) fn vms_per_principal(&self) -> u64 {
        self.vms_per_principal
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct VmSettings {
    defaults: ResourceLimits,
    ceilings: Ceilings,
}
impl VmSettings {
    pub(crate) fn defaults(&self) -> &ResourceLimits {
        &self.defaults
    }
    pub(crate) fn ceilings(&self) -> &Ceilings {
        &self.ceilings
    }
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
impl SessionLimits {
    pub(crate) fn global(&self) -> u64 {
        self.global
    }
    pub(crate) fn per_peer(&self) -> u64 {
        self.per_peer
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct ShutdownSettings {
    #[serde(deserialize_with = "duration")]
    stop_budget: Duration,
    #[serde(deserialize_with = "duration")]
    margin: Duration,
}
impl Default for ShutdownSettings {
    fn default() -> Self {
        Self {
            stop_budget: Duration::from_secs(4),
            margin: Duration::from_millis(250),
        }
    }
}
impl ShutdownSettings {
    pub(crate) fn stop_budget(&self) -> Duration {
        self.stop_budget
    }
    pub(crate) fn margin(&self) -> Duration {
        self.margin
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
fn duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let input = String::deserialize(d)?;
    parse_duration(&input).map_err(serde::de::Error::custom)
}
// Go-style compound durations, with exact integer arithmetic and sub-nanosecond truncation.
fn parse_duration(mut input: &str) -> Result<Duration, &'static str> {
    if input == "0" {
        return Ok(Duration::ZERO);
    }
    input = input.strip_prefix('+').unwrap_or(input);
    let mut total = 0u128;
    let mut count = 0;
    while !input.is_empty() {
        let end = input
            .bytes()
            .take_while(|b| b.is_ascii_digit() || *b == b'.')
            .count();
        if end == 0 {
            return Err("invalid duration");
        }
        let number = &input[..end];
        input = &input[end..];
        let (unit, scale) = [
            ("ns", 1u128),
            ("us", 1000),
            ("µs", 1000),
            ("μs", 1000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ]
        .into_iter()
        .find(|(u, _)| input.starts_with(u))
        .ok_or("invalid duration unit")?;
        input = &input[unit.len()..];
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() && fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("invalid duration");
        }
        let whole: u128 = if whole.is_empty() {
            0
        } else {
            whole.parse().map_err(|_| "invalid duration")?
        };
        let fraction = &fraction[..fraction.len().min(18)];
        let fractional: u128 = if fraction.is_empty() {
            0
        } else {
            fraction.parse().map_err(|_| "invalid duration")?
        };
        let nanos = whole
            .checked_mul(scale)
            .and_then(|n| n.checked_add(fractional * scale / 10u128.pow(fraction.len() as u32)))
            .ok_or("duration overflow")?;
        total = total
            .checked_add(nanos)
            .filter(|n| *n <= i64::MAX as u128)
            .ok_or("duration overflow")?;
        count += 1;
    }
    if count == 0 {
        return Err("invalid duration");
    }
    Ok(Duration::from_nanos(total as u64))
}

#[cfg(test)]
mod tests {
    use crate::config::tailscale::TailscaleConfig;

    #[test]
    fn file_transfer_limit_defaults_and_accepts_sizes() {
        let defaults: TailscaleConfig = serde_yaml_ng::from_str("{}").unwrap();
        assert_eq!(defaults.file_transfer_limit(), 256 << 20);
        let sized: TailscaleConfig = serde_yaml_ng::from_str("file-transfer-limit: 8MiB").unwrap();
        assert_eq!(sized.file_transfer_limit(), 8 << 20);
        let bytes: TailscaleConfig = serde_yaml_ng::from_str("file-transfer-limit: 123").unwrap();
        assert_eq!(bytes.file_transfer_limit(), 123);
        assert!(serde_yaml_ng::from_str::<TailscaleConfig>("file-transfer-limit: 8oops").is_err());
    }
}
