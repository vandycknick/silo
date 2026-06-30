use std::str::FromStr;

use crate::store::models::{looks_like_id_prefix, MachineId};
use crate::utils::{validate_identifier, IdentifierPolicy};
use crate::LibVmError;

/// Reference used to resolve a machine.
///
/// A reference can be a machine name, full machine ID, or unambiguous ID prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MachineRef {
    kind: MachineRefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum MachineRefKind {
    Id(MachineId),
    IdPrefix(String),
    Name(String),
}

impl MachineRef {
    /// Parses a name, full ID, or ID prefix into a machine reference.
    pub fn parse(input: impl Into<String>) -> Result<Self, LibVmError> {
        let input = input.into();
        if let Ok(id) = MachineId::from_str(&input) {
            return Ok(Self::id(id));
        }

        if looks_like_id_prefix(&input) {
            return Ok(Self {
                kind: MachineRefKind::IdPrefix(input.to_lowercase()),
            });
        }

        validate_machine_name(&input)?;
        Ok(Self {
            kind: MachineRefKind::Name(input),
        })
    }

    pub(crate) fn id(id: MachineId) -> Self {
        Self {
            kind: MachineRefKind::Id(id),
        }
    }

    pub(crate) fn kind(&self) -> &MachineRefKind {
        &self.kind
    }
}

pub(crate) fn validate_machine_name(name: &str) -> Result<(), LibVmError> {
    validate_identifier(name, IdentifierPolicy { reserved: &[] }).map_err(|reason| {
        LibVmError::InvalidMachineName {
            name: name.to_string(),
            reason,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{MachineRef, MachineRefKind};
    use crate::store::models::MachineId;

    #[test]
    fn parse_treats_full_uuid_as_machine_id() {
        let id = MachineId::new();
        let machine_ref = MachineRef::parse(id.to_string()).expect("parse machine ref");

        assert_eq!(machine_ref.kind(), &MachineRefKind::Id(id));
    }

    #[test]
    fn parse_treats_hex_prefix_as_id_prefix() {
        let machine_ref = MachineRef::parse("a1b2c3d4").expect("parse machine ref");

        assert_eq!(
            machine_ref.kind(),
            &MachineRefKind::IdPrefix("a1b2c3d4".to_string())
        );
    }

    #[test]
    fn parse_treats_non_hex_as_name() {
        let machine_ref = MachineRef::parse("devbox").expect("parse machine ref");

        assert_eq!(
            machine_ref.kind(),
            &MachineRefKind::Name("devbox".to_string())
        );
    }

    #[test]
    fn parse_rejects_invalid_name() {
        let err = MachineRef::parse("bad/name").expect_err("invalid name should fail");

        assert!(err.to_string().contains("unsupported character"));
    }

    #[test]
    fn parse_short_hex_is_name_not_prefix() {
        let machine_ref = MachineRef::parse("ab").expect("parse machine ref");
        assert_eq!(machine_ref.kind(), &MachineRefKind::Name("ab".to_string()));
    }
}
