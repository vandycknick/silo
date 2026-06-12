use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MachineId(Uuid);

impl MachineId {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub(crate) fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for MachineId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for MachineId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.simple())
    }
}

impl From<Uuid> for MachineId {
    fn from(value: Uuid) -> Self {
        Self::from_uuid(value)
    }
}

impl From<MachineId> for Uuid {
    fn from(value: MachineId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MachineIdParseError {
    InvalidFormat(String),
}

impl std::fmt::Display for MachineIdParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(input) => write!(f, "invalid machine id: {input:?}"),
        }
    }
}

impl std::error::Error for MachineIdParseError {}

impl FromStr for MachineId {
    type Err = MachineIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| MachineIdParseError::InvalidFormat(s.to_string()))
    }
}

impl Serialize for MachineId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MachineId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Returns true if the input looks like a hex string that could be a machine
/// ID prefix (3-32 hex characters). Requires at least 3 chars to avoid
/// treating short names as ID prefixes.
pub(crate) fn looks_like_id_prefix(input: &str) -> bool {
    input.len() >= 3 && input.len() <= 32 && input.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{looks_like_id_prefix, MachineId};
    use uuid::Uuid;

    #[test]
    fn machine_id_round_trips_through_string() {
        let id = MachineId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 32, "should be 32 hex chars, got {s:?}");
        let parsed: MachineId = s.parse().expect("parse machine id");
        assert_eq!(parsed, id);
    }

    #[test]
    fn machine_id_display_is_lowercase_hex_no_dashes() {
        let id = MachineId::new();
        let s = id.to_string();
        assert!(!s.contains('-'), "should not contain dashes: {s:?}");
        assert_eq!(s, s.to_lowercase(), "should be lowercase: {s:?}");
    }

    #[test]
    fn machine_id_parses_dashed_uuid() {
        let id = MachineId::new();
        let dashed = Uuid::from(id).to_string();
        let parsed: MachineId = dashed.parse().expect("parse dashed uuid");
        assert_eq!(parsed, id);
    }

    #[test]
    fn machine_id_serde_round_trip() {
        let id = MachineId::new();
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: MachineId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
        assert!(
            !json.contains('-'),
            "json should not contain dashes: {json}"
        );
    }

    #[test]
    fn looks_like_id_prefix_accepts_hex() {
        assert!(looks_like_id_prefix("a1b2c3"));
        assert!(looks_like_id_prefix("deadbeef"));
        assert!(looks_like_id_prefix("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn looks_like_id_prefix_rejects_non_hex() {
        assert!(!looks_like_id_prefix(""));
        assert!(!looks_like_id_prefix("ab"));
        assert!(!looks_like_id_prefix("devbox"));
        assert!(!looks_like_id_prefix("test-vm"));
        assert!(!looks_like_id_prefix("0123456789abcdef0123456789abcdef0"));
    }
}
