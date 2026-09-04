use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// A TCP or Unix socket address, without an endpoint side.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Address {
    /// Checks that this address can be represented losslessly by the target-line protocol.
    pub fn validate(&self) -> Result<(), AddressError> {
        if let Self::Unix(path) = self {
            let text = path.to_str().ok_or(AddressError::UnixPathNotUtf8)?;
            if text.is_empty() {
                return Err(AddressError::EmptyUnixPath);
            }
            if text.contains('\0') {
                return Err(AddressError::UnixPathContainsNul);
            }
            if text.contains(['\r', '\n']) {
                return Err(AddressError::UnixPathContainsLineBreak);
            }
        }
        let bytes = "CONNECT ".len() + self.to_string().len() + 1;
        if bytes > crate::MAX_TARGET_LINE_BYTES {
            return Err(AddressError::TargetTooLong(bytes));
        }
        Ok(())
    }

    pub fn tcp(address: SocketAddr) -> Self {
        Self::Tcp(address)
    }

    pub fn unix(path: impl Into<PathBuf>) -> Self {
        Self::Unix(path.into())
    }

    pub fn as_tcp(&self) -> Option<&SocketAddr> {
        match self {
            Self::Tcp(address) => Some(address),
            Self::Unix(_) => None,
        }
    }

    pub fn as_unix(&self) -> Option<&std::path::Path> {
        match self {
            Self::Tcp(_) => None,
            Self::Unix(path) => Some(path),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(value: SocketAddr) -> Self {
        Self::Tcp(value)
    }
}

impl From<PathBuf> for Address {
    fn from(value: PathBuf) -> Self {
        Self::Unix(value)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(address) => write!(formatter, "tcp:{address}"),
            Self::Unix(path) => write!(formatter, "unix:{}", path.to_string_lossy()),
        }
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(value) = value.strip_prefix("tcp:") {
            return parse_tcp(value).map(Self::Tcp);
        }
        if let Some(value) = value.strip_prefix("unix:") {
            let address = Self::Unix(PathBuf::from(value));
            address.validate()?;
            return Ok(address);
        }
        Err(AddressError::InvalidAddress(value.to_owned()))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Tcp(address) => serializer.serialize_str(&format!("tcp:{address}")),
            Self::Unix(path) => path
                .to_str()
                .map(|path| serializer.serialize_str(&format!("unix:{path}")))
                .unwrap_or_else(|| Err(serde::ser::Error::custom("Unix path is not UTF-8"))),
        }
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddressError {
    #[error("invalid address {0:?}; expected tcp:PORT, tcp:IP:PORT, or unix:PATH")]
    InvalidAddress(String),
    #[error("TCP address {0:?} has an invalid IP literal")]
    InvalidIp(String),
    #[error("TCP port {0:?} is not canonical decimal in the range 0..=65535")]
    InvalidTcpPort(String),
    #[error("Unix socket path must not be empty")]
    EmptyUnixPath,
    #[error("Unix socket path must not contain NUL")]
    UnixPathContainsNul,
    #[error("Unix socket path must not contain CR or LF")]
    UnixPathContainsLineBreak,
    #[error("Unix socket path must be UTF-8")]
    UnixPathNotUtf8,
    #[error(
        "address requires a {0}-byte target line; maximum is {limit}",
        limit = crate::MAX_TARGET_LINE_BYTES
    )]
    TargetTooLong(usize),
}

fn parse_tcp(value: &str) -> Result<SocketAddr, AddressError> {
    if value.starts_with('[') {
        let Some(close) = value.find(']') else {
            return Err(AddressError::InvalidIp(value.to_owned()));
        };
        let ip_text = &value[1..close];
        let port_text = value
            .get(close + 1..)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .ok_or_else(|| AddressError::InvalidAddress(value.to_owned()))?;
        let ip = ip_text
            .parse::<Ipv6Addr>()
            .map_err(|_| AddressError::InvalidIp(ip_text.to_owned()))?;
        return Ok(SocketAddr::new(IpAddr::V6(ip), parse_tcp_port(port_text)?));
    }

    if let Some((ip_text, port_text)) = value.rsplit_once(':') {
        let ip = ip_text
            .parse::<IpAddr>()
            .map_err(|_| AddressError::InvalidIp(ip_text.to_owned()))?;
        if ip.is_ipv6() {
            return Err(AddressError::InvalidIp(ip_text.to_owned()));
        }
        return Ok(SocketAddr::new(ip, parse_tcp_port(port_text)?));
    }

    Ok(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        parse_tcp_port(value)?,
    ))
}

fn parse_tcp_port(value: &str) -> Result<u16, AddressError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(AddressError::InvalidTcpPort(value.to_owned()));
    }
    value
        .parse()
        .map_err(|_| AddressError::InvalidTcpPort(value.to_owned()))
}

/// A socket address assigned to the host or guest, or a raw vsock port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Host(Address),
    Guest(Address),
    Vsock(u32),
}

impl Endpoint {
    pub fn host(address: impl Into<Address>) -> Self {
        Self::Host(address.into())
    }

    pub fn guest(address: impl Into<Address>) -> Self {
        Self::Guest(address.into())
    }

    pub fn vsock(port: u32) -> Self {
        Self::Vsock(port)
    }

    pub fn side(&self) -> Option<crate::Side> {
        match self {
            Self::Host(_) => Some(crate::Side::Host),
            Self::Guest(_) => Some(crate::Side::Guest),
            Self::Vsock(_) => None,
        }
    }

    pub fn address(&self) -> Option<&Address> {
        match self {
            Self::Host(address) | Self::Guest(address) => Some(address),
            Self::Vsock(_) => None,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(address) => write!(formatter, "host:{address}"),
            Self::Guest(address) => write!(formatter, "guest:{address}"),
            Self::Vsock(port) => write!(formatter, "vsock:{port}"),
        }
    }
}

impl FromStr for Endpoint {
    type Err = EndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(address) = value.strip_prefix("host:") {
            return address
                .parse()
                .map(Self::Host)
                .map_err(EndpointError::Address);
        }
        if let Some(address) = value.strip_prefix("guest:") {
            return address
                .parse()
                .map(Self::Guest)
                .map_err(EndpointError::Address);
        }
        if let Some(port) = value.strip_prefix("vsock:") {
            return parse_vsock_port(port).map(Self::Vsock);
        }
        Err(EndpointError::InvalidEndpoint(value.to_owned()))
    }
}

impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Host(Address::Tcp(address)) => {
                serializer.serialize_str(&format!("host:tcp:{address}"))
            }
            Self::Guest(Address::Tcp(address)) => {
                serializer.serialize_str(&format!("guest:tcp:{address}"))
            }
            Self::Host(Address::Unix(path)) => path
                .to_str()
                .map(|path| serializer.serialize_str(&format!("host:unix:{path}")))
                .unwrap_or_else(|| Err(serde::ser::Error::custom("Unix path is not UTF-8"))),
            Self::Guest(Address::Unix(path)) => path
                .to_str()
                .map(|path| serializer.serialize_str(&format!("guest:unix:{path}")))
                .unwrap_or_else(|| Err(serde::ser::Error::custom("Unix path is not UTF-8"))),
            Self::Vsock(port) => serializer.serialize_str(&format!("vsock:{port}")),
        }
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EndpointError {
    #[error("invalid endpoint {0:?}; expected host:ADDRESS, guest:ADDRESS, or vsock:PORT")]
    InvalidEndpoint(String),
    #[error(transparent)]
    Address(#[from] AddressError),
    #[error("vsock port {0:?} is not canonical decimal u32")]
    InvalidVsockPort(String),
}

fn parse_vsock_port(value: &str) -> Result<u32, EndpointError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(EndpointError::InvalidVsockPort(value.to_owned()));
    }
    value
        .parse()
        .map_err(|_| EndpointError::InvalidVsockPort(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use crate::{Address, Endpoint};

    #[test]
    fn address_grammar_is_canonical() {
        let cases = [
            ("tcp:80", "tcp:127.0.0.1:80"),
            ("tcp:127.0.0.1:8080", "tcp:127.0.0.1:8080"),
            ("tcp:[::1]:443", "tcp:[::1]:443"),
            ("unix:/var/run/docker.sock", "unix:/var/run/docker.sock"),
            ("unix:docker.sock", "unix:docker.sock"),
        ];
        for (input, canonical) in cases {
            let address = input.parse::<Address>().unwrap();
            assert_eq!(address.to_string(), canonical);
            assert_eq!(canonical.parse::<Address>().unwrap(), address);
            assert_eq!(
                serde_json::to_string(&address).unwrap(),
                format!("\"{canonical}\"")
            );
            assert_eq!(
                serde_yaml_ng::from_str::<Address>(canonical).unwrap(),
                address
            );
        }
    }

    #[test]
    fn endpoint_grammar_and_serde_round_trip() {
        let cases = [
            ("host:tcp:80", "host:tcp:127.0.0.1:80"),
            ("guest:tcp:[::1]:80", "guest:tcp:[::1]:80"),
            ("host:unix:docker.sock", "host:unix:docker.sock"),
            (
                "guest:unix:/run/service.sock",
                "guest:unix:/run/service.sock",
            ),
            ("vsock:5000", "vsock:5000"),
        ];
        for (input, canonical) in cases {
            let endpoint = input.parse::<Endpoint>().unwrap();
            assert_eq!(endpoint.to_string(), canonical);
            assert_eq!(
                serde_json::from_str::<Endpoint>(&format!("\"{input}\"")).unwrap(),
                endpoint
            );
            assert_eq!(
                serde_yaml_ng::from_str::<Endpoint>(input).unwrap(),
                endpoint
            );
        }
    }

    #[test]
    fn malformed_addresses_and_endpoints_are_rejected() {
        for input in [
            "tcp:08080",
            "tcp:localhost:80",
            "tcp:::1:80",
            "tcp:70000",
            "tcp:+80",
            "unix:",
            "unix:a\0b",
            "host:",
            "guest:vsock:5",
            "vsock:",
            "vsock:00",
            "hostt:tcp:80",
            "host:tcp:80 ",
            "host:TCP:80",
            "tcp:80",
        ] {
            assert!(input.parse::<Endpoint>().is_err(), "accepted {input:?}");
        }
    }
}
