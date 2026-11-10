use std::str::FromStr;

use crate::store::models::{looks_like_id_prefix, MachineId};
use crate::utils::{validate_identifier, IdentifierPolicy};
use crate::LibVmError;

/// Reference used to resolve a machine.
///
/// Full IDs select an immutable identity. Other hex-looking inputs first select
/// an exact name, preserving its case, then an unambiguous lowercase ID prefix.
/// Other inputs select an exact name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MachineRef {
    kind: MachineRefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum MachineRefKind {
    Id(MachineId),
    IdPrefix { name: String, prefix: String },
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
                kind: MachineRefKind::IdPrefix {
                    prefix: input.to_ascii_lowercase(),
                    name: input,
                },
            });
        }

        validate_machine_name(&input)?;
        Ok(Self {
            kind: MachineRefKind::Name(input),
        })
    }

    /// Parses a full ID or exact name without falling back to an ID prefix.
    ///
    /// Availability checks should use [`crate::Runtime::ensure_name_available`]
    /// to check both the exact name and full ID.
    pub fn parse_exact(input: impl Into<String>) -> Result<Self, LibVmError> {
        let input = input.into();
        if let Ok(id) = MachineId::from_str(&input) {
            return Ok(Self::id(id));
        }
        validate_machine_name(&input)?;
        Ok(Self {
            kind: MachineRefKind::Name(input),
        })
    }

    /// Exact immutable UUID, when this reference selects one machine ID.
    pub fn id_uuid(&self) -> Option<uuid::Uuid> {
        match &self.kind {
            MachineRefKind::Id(id) => Some((*id).into()),
            _ => None,
        }
    }

    /// Human-readable name selected by the native parser.
    pub fn name(&self) -> Option<&str> {
        match &self.kind {
            MachineRefKind::Name(name) => Some(name),
            _ => None,
        }
    }

    /// Normalized ID prefix selected by the native parser.
    pub fn id_prefix(&self) -> Option<&str> {
        match &self.kind {
            MachineRefKind::IdPrefix { prefix, .. } => Some(prefix),
            _ => None,
        }
    }

    /// Case-preserving exact name tried before an ID prefix.
    pub fn id_prefix_name(&self) -> Option<&str> {
        match &self.kind {
            MachineRefKind::IdPrefix { name, .. } => Some(name),
            _ => None,
        }
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

pub fn validate_new_machine_name(name: &str) -> Result<(), LibVmError> {
    let bytes = name.as_bytes();
    if bytes.len() <= 63
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes.last() != Some(&b'-')
    {
        Ok(())
    } else {
        Err(LibVmError::InvalidMachineName { name: name.into(), reason: "new names must use 1-63 lowercase letters, digits or hyphens, start with a letter or digit, and not end with a hyphen".into() })
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::reference::{MachineRef, MachineRefKind};
    use crate::store::models::MachineId;

    #[test]
    fn new_names_are_exact_dns_labels_while_legacy_references_remain_readable() {
        for name in ["dev", "def", "cafe", "abc1", "0", "a-b", &"a".repeat(63)] {
            crate::machine::reference::validate_new_machine_name(name).unwrap();
        }
        for name in [
            "",
            "-dev",
            "dev-",
            "Dev",
            "dev_box",
            "dev.box",
            &"a".repeat(64),
        ] {
            assert!(
                crate::machine::reference::validate_new_machine_name(name).is_err(),
                "{name}"
            );
        }
        assert!(MachineRef::parse("Legacy_name").is_ok());
    }

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
            &MachineRefKind::IdPrefix {
                name: "a1b2c3d4".to_string(),
                prefix: "a1b2c3d4".to_string(),
            }
        );
    }

    #[test]
    fn parse_preserves_hex_name_case_and_normalizes_prefix() {
        let reference = MachineRef::parse("DeF").unwrap();
        assert_eq!(reference.id_prefix_name(), Some("DeF"));
        assert_eq!(reference.id_prefix(), Some("def"));
    }

    #[test]
    fn parse_exact_never_selects_a_prefix() {
        let reference = MachineRef::parse_exact("def").unwrap();
        assert_eq!(reference.name(), Some("def"));
        assert_eq!(reference.id_prefix(), None);
        let id = MachineId::new();
        assert_eq!(
            MachineRef::parse_exact(id.to_string()).unwrap().kind(),
            &MachineRefKind::Id(id)
        );
        assert!(MachineRef::parse_exact("bad/name").is_err());
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
