use std::collections::HashSet;
use std::fmt;
use std::path::{Component, Path};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{Address, Endpoint, FORWARD_VSOCK_PORT, GUEST_CONTROL_VSOCK_PORT};

pub const RESERVED_RUNTIME_FILENAMES: &[&str] = &["vm.sock", "vm.pid", "vm.lock", "krun.vsock"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnixMode(u32);

impl UnixMode {
    pub const fn new(value: u32) -> Result<Self, UnixModeError> {
        if value <= 0o777 {
            Ok(Self(value))
        } else {
            Err(UnixModeError::OutOfRange(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for UnixMode {
    type Error = UnixModeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnixMode> for u32 {
    fn from(value: UnixMode) -> Self {
        value.get()
    }
}

impl fmt::Display for UnixMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:04o}", self.0)
    }
}

impl FromStr for UnixMode {
    type Err = UnixModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 4
            || !value.starts_with('0')
            || !value
                .bytes()
                .skip(1)
                .all(|byte| matches!(byte, b'0'..=b'7'))
        {
            return Err(UnixModeError::InvalidOctal(value.to_owned()));
        }
        let parsed = u32::from_str_radix(value, 8)
            .map_err(|_| UnixModeError::InvalidOctal(value.to_owned()))?;
        Self::new(parsed)
    }
}

impl Serialize for UnixMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UnixMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnixModeError {
    #[error("Unix mode {0:?} must be a four-digit octal string from 0000 through 0777")]
    InvalidOctal(String),
    #[error("Unix mode {0:o} exceeds 0777")]
    OutOfRange(u32),
}

/// One machine- or session-scoped forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Forward {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub listen: Endpoint,
    pub connect: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<UnixMode>,
}

impl Forward {
    pub fn new(listen: Endpoint, connect: Endpoint) -> Self {
        Self {
            name: None,
            listen,
            connect,
            mode: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_mode(mut self, mode: UnixMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn validate(&self) -> Result<ForwardShape, ForwardError> {
        for endpoint in [&self.listen, &self.connect] {
            if let Some(address) = endpoint.address() {
                address.validate()?;
            }
        }
        let shape = match (&self.listen, &self.connect) {
            (Endpoint::Host(_), Endpoint::Guest(_)) => ForwardShape::InboundAgent,
            (Endpoint::Host(_), Endpoint::Vsock(_)) => ForwardShape::InboundVsock,
            (Endpoint::Guest(_), Endpoint::Host(_)) => ForwardShape::OutboundAgent,
            (Endpoint::Vsock(_), Endpoint::Host(_)) => ForwardShape::OutboundVsock,
            _ => {
                return Err(ForwardError::InvalidSides {
                    listen: self.listen.to_string(),
                    connect: self.connect.to_string(),
                });
            }
        };

        if let Endpoint::Vsock(port) = self.listen {
            if matches!(port, GUEST_CONTROL_VSOCK_PORT | FORWARD_VSOCK_PORT) {
                return Err(ForwardError::ReservedVsockListenPort(port));
            }
        }
        validate_tcp_connect_port(&self.connect)?;
        validate_unix_paths(&self.listen, &self.connect)?;
        if self.mode.is_some()
            && !matches!(
                &self.listen,
                Endpoint::Host(Address::Unix(_)) | Endpoint::Guest(Address::Unix(_))
            )
        {
            return Err(ForwardError::ModeRequiresUnixListen(
                self.listen.to_string(),
            ));
        }
        Ok(shape)
    }

    pub fn shape(&self) -> Result<ForwardShape, ForwardError> {
        self.validate()
    }

    pub fn direction(&self) -> Result<Direction, ForwardError> {
        self.validate().map(ForwardShape::direction)
    }

    pub fn host_endpoint(&self) -> Result<&Address, ForwardError> {
        self.validate()?;
        match (&self.listen, &self.connect) {
            (Endpoint::Host(address), _) | (_, Endpoint::Host(address)) => Ok(address),
            _ => Err(ForwardError::InvalidSides {
                listen: self.listen.to_string(),
                connect: self.connect.to_string(),
            }),
        }
    }

    pub fn guest_half(&self) -> Result<GuestHalf, ForwardError> {
        self.validate()?;
        match (&self.listen, &self.connect) {
            (Endpoint::Guest(address), _) | (_, Endpoint::Guest(address)) => {
                Ok(GuestHalf::Agent(address.clone()))
            }
            (Endpoint::Vsock(port), _) | (_, Endpoint::Vsock(port)) => Ok(GuestHalf::Vsock(*port)),
            _ => Err(ForwardError::InvalidSides {
                listen: self.listen.to_string(),
                connect: self.connect.to_string(),
            }),
        }
    }

    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{} -> {}", self.listen, self.connect))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Host,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardShape {
    InboundAgent,
    InboundVsock,
    OutboundAgent,
    OutboundVsock,
}

impl ForwardShape {
    pub const fn direction(self) -> Direction {
        match self {
            Self::InboundAgent | Self::InboundVsock => Direction::Inbound,
            Self::OutboundAgent | Self::OutboundVsock => Direction::Outbound,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestHalf {
    Agent(Address),
    Vsock(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ForwardError {
    #[error(transparent)]
    Address(#[from] crate::AddressError),
    #[error("invalid forward sides: listen {listen}, connect {connect}")]
    InvalidSides { listen: String, connect: String },
    #[error("vsock listen port {0} is reserved")]
    ReservedVsockListenPort(u32),
    #[error("vsock listen port {0} is repeated")]
    DuplicateVsockListenPort(u32),
    #[error("TCP connect endpoint {0} must use a non-zero port")]
    ZeroTcpConnectPort(String),
    #[error("guest Unix path {0:?} must be absolute")]
    GuestUnixPathNotAbsolute(String),
    #[error("host Unix path {0:?} must be absolute or one normal path component")]
    InvalidHostUnixPath(String),
    #[error("host Unix path {0:?} is reserved by the machine runtime")]
    ReservedRuntimePath(String),
    #[error("host Unix path {path:?} conflicts with vsock mux {mux:?}")]
    VsockMuxPathConflict { path: String, mux: String },
    #[error("mode is only valid for a Unix listen endpoint, not {0}")]
    ModeRequiresUnixListen(String),
    #[error("forward name {0:?} is repeated")]
    DuplicateName(String),
}

pub fn validate_forwards(
    forwards: &[Forward],
    mux_filename: Option<&str>,
) -> Result<(), ForwardError> {
    let mut names = HashSet::new();
    let mut listen_ports = HashSet::new();
    for forward in forwards {
        forward.validate()?;
        if let Some(name) = &forward.name {
            if !names.insert(name.as_str()) {
                return Err(ForwardError::DuplicateName(name.clone()));
            }
        }
        if let Endpoint::Vsock(port) = forward.listen {
            if !listen_ports.insert(port) {
                return Err(ForwardError::DuplicateVsockListenPort(port));
            }
        }
        validate_runtime_path(&forward.listen, mux_filename)?;
        validate_runtime_path(&forward.connect, mux_filename)?;
    }
    Ok(())
}

fn validate_tcp_connect_port(connect: &Endpoint) -> Result<(), ForwardError> {
    let address = match connect {
        Endpoint::Host(address) | Endpoint::Guest(address) => address,
        Endpoint::Vsock(_) => return Ok(()),
    };
    if matches!(address, Address::Tcp(address) if address.port() == 0) {
        return Err(ForwardError::ZeroTcpConnectPort(connect.to_string()));
    }
    Ok(())
}

fn validate_unix_paths(listen: &Endpoint, connect: &Endpoint) -> Result<(), ForwardError> {
    for endpoint in [listen, connect] {
        if let Endpoint::Guest(Address::Unix(path)) = endpoint {
            if !path.is_absolute() {
                return Err(ForwardError::GuestUnixPathNotAbsolute(
                    path.to_string_lossy().into_owned(),
                ));
            }
        }
        if let Endpoint::Host(Address::Unix(path)) = endpoint {
            validate_host_unix_path(path)?;
        }
    }
    Ok(())
}

fn validate_host_unix_path(path: &Path) -> Result<(), ForwardError> {
    if path.is_absolute() {
        return Ok(());
    }
    let text = path.to_string_lossy();
    let mut components = path.components();
    let one_normal = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !text.contains(['/', '\\', '\0']);
    if !one_normal {
        return Err(ForwardError::InvalidHostUnixPath(text.into_owned()));
    }
    Ok(())
}

fn validate_runtime_path(
    endpoint: &Endpoint,
    mux_filename: Option<&str>,
) -> Result<(), ForwardError> {
    let Endpoint::Host(Address::Unix(path)) = endpoint else {
        return Ok(());
    };
    if path.is_absolute() {
        return Ok(());
    }
    let text = path.to_string_lossy();
    if RESERVED_RUNTIME_FILENAMES.contains(&text.as_ref()) {
        return Err(ForwardError::ReservedRuntimePath(text.into_owned()));
    }
    if let Some(mux) = mux_filename {
        if text == mux || is_mux_listener_name(&text, mux) {
            return Err(ForwardError::VsockMuxPathConflict {
                path: text.into_owned(),
                mux: mux.to_owned(),
            });
        }
    }
    Ok(())
}

fn is_mux_listener_name(path: &str, mux: &str) -> bool {
    path.strip_prefix(mux)
        .and_then(|suffix| suffix.strip_prefix('_'))
        .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use crate::{
        validate_forwards, Direction, Endpoint, Forward, ForwardError, ForwardShape, UnixMode,
        RESERVED_RUNTIME_FILENAMES,
    };

    fn forward(listen: &str, connect: &str) -> Forward {
        Forward::new(listen.parse().unwrap(), connect.parse().unwrap())
    }

    #[test]
    fn only_the_four_adr_shapes_validate() {
        let cases = [
            ("host:tcp:80", "host:tcp:80", None),
            (
                "host:tcp:80",
                "guest:tcp:80",
                Some((ForwardShape::InboundAgent, Direction::Inbound)),
            ),
            (
                "host:tcp:80",
                "vsock:80",
                Some((ForwardShape::InboundVsock, Direction::Inbound)),
            ),
            (
                "guest:tcp:80",
                "host:tcp:80",
                Some((ForwardShape::OutboundAgent, Direction::Outbound)),
            ),
            ("guest:tcp:80", "guest:tcp:80", None),
            ("guest:tcp:80", "vsock:80", None),
            (
                "vsock:80",
                "host:tcp:80",
                Some((ForwardShape::OutboundVsock, Direction::Outbound)),
            ),
            ("vsock:80", "guest:tcp:80", None),
            ("vsock:80", "vsock:81", None),
        ];
        for (listen, connect, expected) in cases {
            let forward = forward(listen, connect);
            match expected {
                Some((shape, direction)) => {
                    assert_eq!(forward.validate().unwrap(), shape);
                    assert_eq!(forward.direction().unwrap(), direction);
                }
                None => assert!(matches!(
                    forward.validate(),
                    Err(ForwardError::InvalidSides { .. })
                )),
            }
        }
    }

    #[test]
    fn forward_yaml_examples_round_trip() {
        let yaml = r#"
- name: docker
  listen: host:unix:docker.sock
  connect: guest:unix:/var/run/docker.sock
- listen: host:tcp:127.0.0.1:8080
  connect: guest:tcp:80
- name: postgres
  listen: guest:tcp:127.0.0.1:5432
  connect: host:tcp:127.0.0.1:5432
- listen: guest:unix:/run/host-docker.sock
  connect: host:unix:/var/run/docker.sock
  mode: "0666"
"#;
        let forwards: Vec<Forward> = serde_yaml_ng::from_str(yaml).unwrap();
        validate_forwards(&forwards, Some("vsock.sock")).unwrap();
        let json = serde_json::to_string(&forwards).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<Forward>>(&json).unwrap(),
            forwards
        );
        assert!(serde_yaml_ng::from_str::<Vec<Forward>>(
            &serde_yaml_ng::to_string(&forwards).unwrap()
        )
        .is_ok());
    }

    #[test]
    fn list_values_are_unique() {
        let named = forward("host:tcp:80", "guest:tcp:80").with_name("web");
        assert!(matches!(
            validate_forwards(&[named.clone(), named], None),
            Err(ForwardError::DuplicateName(name)) if name == "web"
        ));
        assert!(matches!(
            validate_forwards(
                &[
                    forward("vsock:5000", "host:tcp:80"),
                    forward("vsock:5000", "host:tcp:81"),
                ],
                None
            ),
            Err(ForwardError::DuplicateVsockListenPort(5000))
        ));
        validate_forwards(
            &[
                forward("vsock:5000", "host:tcp:80"),
                forward("vsock:5001", "host:tcp:81"),
            ],
            None,
        )
        .unwrap();
    }

    #[test]
    fn reserved_ports_and_invalid_address_roles_are_rejected() {
        for port in [1027, 1028] {
            assert!(matches!(
                forward(&format!("vsock:{port}"), "host:tcp:80").validate(),
                Err(ForwardError::ReservedVsockListenPort(value)) if value == port
            ));
        }
        assert!(matches!(
            forward("host:tcp:80", "guest:tcp:0").validate(),
            Err(ForwardError::ZeroTcpConnectPort(_))
        ));
        assert!(matches!(
            forward("host:tcp:80", "guest:unix:relative.sock").validate(),
            Err(ForwardError::GuestUnixPathNotAbsolute(_))
        ));
    }

    #[test]
    fn host_runtime_paths_are_safe() {
        for reserved in RESERVED_RUNTIME_FILENAMES {
            assert!(matches!(
                validate_forwards(
                    &[forward(&format!("host:unix:{reserved}"), "guest:tcp:80")],
                    Some("vsock.sock")
                ),
                Err(ForwardError::ReservedRuntimePath(_))
            ));
        }
        for path in ["vsock.sock", "vsock.sock_5000"] {
            assert!(matches!(
                validate_forwards(
                    &[forward(&format!("host:unix:{path}"), "guest:tcp:80")],
                    Some("vsock.sock")
                ),
                Err(ForwardError::VsockMuxPathConflict { .. })
            ));
        }
        for path in ["dir/x.sock", "..", ".", "dir\\x.sock"] {
            assert!(matches!(
                forward(&format!("host:unix:{path}"), "guest:tcp:80").validate(),
                Err(ForwardError::InvalidHostUnixPath(_))
            ));
        }
        validate_forwards(
            &[
                forward("host:unix:docker.sock", "guest:tcp:80"),
                forward("host:unix:/abs/path.sock", "guest:tcp:81"),
            ],
            Some("vsock.sock"),
        )
        .unwrap();
    }

    #[test]
    fn unix_mode_is_a_string_and_only_applies_to_unix_listeners() {
        let mode: UnixMode = "0666".parse().unwrap();
        assert_eq!(mode.get(), 0o666);
        assert_eq!(mode.to_string(), "0666");
        assert_eq!(serde_json::to_string(&mode).unwrap(), "\"0666\"");
        assert!(serde_json::from_str::<UnixMode>("438").is_err());
        for invalid in ["666", "0888", "777777", "-001"] {
            assert!(invalid.parse::<UnixMode>().is_err());
        }
        assert!(forward("host:unix:s.sock", "guest:tcp:80")
            .with_mode(mode)
            .validate()
            .is_ok());
        assert!(matches!(
            forward("host:tcp:80", "guest:unix:/run/s.sock")
                .with_mode(mode)
                .validate(),
            Err(ForwardError::ModeRequiresUnixListen(_))
        ));
    }

    #[test]
    fn forward_rejects_unknown_fields() {
        let yaml = "listen: host:tcp:80\nconnect: guest:tcp:80\nnam: typo\n";
        let error = serde_yaml_ng::from_str::<Forward>(yaml)
            .unwrap_err()
            .to_string();
        assert!(error.contains("nam"));
    }

    #[test]
    fn constructors_and_helpers_expose_derived_values() {
        let forward = forward("host:tcp:80", "vsock:22").with_name("ssh");
        assert_eq!(forward.display_name(), "ssh");
        assert!(matches!(
            forward.host_endpoint(),
            Ok(crate::Address::Tcp(_))
        ));
        assert!(matches!(
            forward.guest_half(),
            Ok(crate::GuestHalf::Vsock(22))
        ));
        assert_eq!(Endpoint::vsock(22), "vsock:22".parse().unwrap());
    }
}
