//! Local names and record references shared by images and snapshots.
//!
//! ```text
//!   spelling            meaning
//!   ───────────────     ─────────────────────────────────────────────
//!   sha256:<64 hex>     record id
//!   hello               local name, or a hex id prefix (>= 3 chars)
//!   hello:v2, a/b, …    registry reference (names a pulled record)
//! ```
//!
//! A local name never contains `:` or `/`, so it can never collide with a
//! canonical registry reference stored as the name of a pulled record.
use crate::storage::identity::ObjectDigest;
use crate::LibVmError;

/// Longest admitted local name, in bytes.
pub(crate) const MAX_NAME_BYTES: usize = 128;
/// Longest admitted reference spelling, in bytes.
const MAX_REFERENCE_BYTES: usize = 512;
/// Shortest admitted id prefix, in hex characters.
pub(crate) const MIN_ID_PREFIX: usize = 3;

/// Validate a user-chosen local name: `[a-z0-9][a-z0-9._-]*`, at most
/// 128 bytes. Registry references are never local names.
pub(crate) fn validate_name(name: &str) -> Result<(), LibVmError> {
    let reason = if name.is_empty() {
        Some("a name cannot be empty")
    } else if name.len() > MAX_NAME_BYTES {
        Some("a name is at most 128 bytes")
    } else if !name
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        Some("a name begins with a lowercase letter or digit")
    } else if !name.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        Some("a name contains only lowercase letters, digits, '.', '_' and '-'; ':' and '/' mark registry references")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(LibVmError::InvalidName {
            name: name.to_owned(),
            reason,
        }),
        None => Ok(()),
    }
}

/// Whether `value` has local-name grammar, as opposed to a registry reference.
pub(crate) fn is_local_name(value: &str) -> bool {
    validate_name(value).is_ok()
}

/// The hex characters of an id prefix, when `value` can abbreviate an id.
pub(crate) fn id_prefix(value: &str) -> Option<&str> {
    (MIN_ID_PREFIX..=64)
        .contains(&value.len())
        .then_some(value)
        .filter(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Validate a persisted name: a local name or a pulled registry reference.
pub(crate) fn validate_stored_name(name: &str) -> Result<(), LibVmError> {
    match parse_reference(name)? {
        Spelling::Name(_) => Ok(()),
        Spelling::Id(_) => Err(LibVmError::InvalidName {
            name: name.to_owned(),
            reason: "an id is never a name",
        }),
    }
}

/// One parsed record reference: a full id, or a name to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Spelling {
    Id(ObjectDigest),
    Name(String),
}

/// Parse a reference spelling. `sha256:` requires a full id; any other
/// spelling is a local name, an id prefix or a registry reference, which
/// only the catalog (and registry policy) can tell apart.
pub(crate) fn parse_reference(value: &str) -> Result<Spelling, LibVmError> {
    let rejected = |reason: &'static str| LibVmError::InvalidName {
        name: value.to_owned(),
        reason,
    };
    if value.starts_with("sha256:") {
        return value
            .parse()
            .map(Spelling::Id)
            .map_err(|_| rejected("an id is sha256: followed by 64 lowercase hex digits"));
    }
    if value.is_empty() || value.len() > MAX_REFERENCE_BYTES {
        return Err(rejected("a reference is 1..512 bytes"));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(rejected(
            "a reference is printable ASCII without whitespace",
        ));
    }
    if !value.contains([':', '/']) {
        validate_name(value)?;
    }
    Ok(Spelling::Name(value.to_owned()))
}

/// The digest-pinned form of a canonical registry name and manifest digest:
/// `registry/repository[:tag][@digest]` becomes `registry/repository@digest`.
pub(crate) fn pinned_reference(name: &str, digest: &str) -> String {
    let repository = name
        .split_once('@')
        .map_or(name, |(repository, _)| repository);
    let repository = match (repository.rfind(':'), repository.rfind('/')) {
        (Some(colon), slash) if slash.is_none_or(|slash| colon > slash) => &repository[..colon],
        _ => repository,
    };
    format!("{repository}@{digest}")
}

#[cfg(test)]
mod tests {
    use crate::store::names::{
        id_prefix, is_local_name, parse_reference, pinned_reference, validate_name,
        validate_stored_name, Spelling,
    };
    use crate::LibVmError;

    #[test]
    fn local_names_are_lowercase_without_registry_syntax() {
        for name in ["hello", "a", "0day", "py3.13-slim_x", &"a".repeat(128)] {
            validate_name(name).unwrap();
            assert!(is_local_name(name));
        }
        for name in [
            "",
            "Hello",
            "-x",
            ".x",
            "_x",
            "hello:v2",
            "nixos/nix",
            "a b",
            &"a".repeat(129),
        ] {
            assert!(
                matches!(validate_name(name), Err(LibVmError::InvalidName { .. })),
                "{name:?}"
            );
            assert!(!is_local_name(name));
        }
    }

    #[test]
    fn references_parse_ids_names_and_registry_spellings() {
        let id = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            parse_reference(&id).unwrap(),
            Spelling::Id(id.parse().unwrap())
        );
        for value in ["hello", "abc", "hello:v2", "nixos/nix", "ghcr.io/a/b:1"] {
            assert_eq!(
                parse_reference(value).unwrap(),
                Spelling::Name(value.into())
            );
        }
        for value in ["sha256:abc", "sha256:", "", "Hello", "a b", "x\u{7f}"] {
            assert!(parse_reference(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn id_prefixes_are_three_to_sixty_four_lowercase_hex() {
        assert_eq!(id_prefix("abc"), Some("abc"));
        assert_eq!(id_prefix(&"f".repeat(64)), Some("f".repeat(64).as_str()));
        for value in ["ab", "abg", "ABC", &"f".repeat(65), "hello"] {
            assert_eq!(id_prefix(value), None, "{value:?}");
        }
    }

    #[test]
    fn stored_names_are_local_names_or_registry_references_never_ids() {
        for name in [
            "hello",
            "docker.io/library/alpine:3.21",
            "localhost:5000/a/b",
        ] {
            validate_stored_name(name).unwrap();
        }
        let id = format!("sha256:{}", "ab".repeat(32));
        for name in [id.as_str(), "sha256:abc", "", "Hello", "a b"] {
            assert!(
                matches!(
                    validate_stored_name(name),
                    Err(LibVmError::InvalidName { .. })
                ),
                "{name:?}"
            );
        }
    }

    #[test]
    fn pinned_references_replace_tag_and_digest_but_keep_registry_ports() {
        let digest = "sha256:1111";
        assert_eq!(
            pinned_reference("docker.io/library/alpine:3.21", digest),
            "docker.io/library/alpine@sha256:1111"
        );
        assert_eq!(
            pinned_reference("localhost:5000/team/app", digest),
            "localhost:5000/team/app@sha256:1111"
        );
        assert_eq!(
            pinned_reference("localhost:5000/team/app:1@sha256:2222", digest),
            "localhost:5000/team/app@sha256:1111"
        );
    }
}
