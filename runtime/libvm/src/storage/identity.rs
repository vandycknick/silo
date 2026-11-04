use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected sha256: followed by exactly 64 lowercase hexadecimal characters")]
pub struct IdentityError;

fn parse_digest(value: &str) -> Result<[u8; 32], IdentityError> {
    let hex = value.strip_prefix("sha256:").ok_or(IdentityError)?;
    parse_hex(hex.as_bytes())
}

pub(crate) fn parse_hex(hex: &[u8]) -> Result<[u8; 32], IdentityError> {
    if hex.len() != 64 {
        return Err(IdentityError);
    }
    let mut bytes = [0; 32];
    for (output, pair) in bytes.iter_mut().zip(hex.chunks_exact(2)) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(IdentityError),
        };
        *output = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(bytes)
}

macro_rules! digest_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// The validated lowercase hex filename, without the algorithm prefix.
            pub fn hex(&self) -> String {
                use std::fmt::Write as _;
                let mut hex = String::with_capacity(64);
                for byte in self.0 {
                    // Writing to a String cannot fail.
                    let _ = write!(hex, "{byte:02x}");
                }
                hex
            }
        }

        impl FromStr for $name {
            type Err = IdentityError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_digest(value).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("sha256:")?;
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Visitor;
                impl serde::de::Visitor<'_> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a lowercase SHA-256 identity")
                    }

                    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        value.parse().map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(Visitor)
            }
        }
    };
}

digest_type!(
    ObjectDigest,
    "SHA-256 of the complete, unprefixed bytes of a byte object."
);
digest_type!(
    StreamId,
    "Domain-separated SHA-256 of a canonical logical stream map."
);
digest_type!(
    ImageId,
    "Typed identity of a canonical image record, not its serialized byte digest."
);
digest_type!(
    SnapshotId,
    "Typed identity of a canonical snapshot record, not its serialized byte digest."
);
digest_type!(
    LowerResultId,
    "Typed identity of a canonical lower-result record, not its serialized byte digest."
);

impl StreamId {
    pub(crate) fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl SnapshotId {
    pub(crate) fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl ObjectDigest {
    pub(crate) fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::identity::{ImageId, LowerResultId, ObjectDigest, SnapshotId, StreamId};

    #[test]
    fn identities_reject_noncanonical_algorithms_hex_and_lengths() {
        let valid = format!("sha256:{}", "ab".repeat(32));
        for invalid in [
            "".to_owned(),
            "ab".repeat(32),
            format!("sha512:{}", "ab".repeat(32)),
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha256:{}", "gg".repeat(32)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("{valid}\n"),
            format!("sha256:{}", "é".repeat(32)),
        ] {
            assert!(invalid.parse::<ObjectDigest>().is_err(), "{invalid}");
            assert!(invalid.parse::<StreamId>().is_err(), "{invalid}");
            assert!(invalid.parse::<ImageId>().is_err(), "{invalid}");
            assert!(invalid.parse::<SnapshotId>().is_err(), "{invalid}");
            assert!(invalid.parse::<LowerResultId>().is_err(), "{invalid}");
            assert!(serde_json::from_value::<ObjectDigest>(serde_json::json!(invalid)).is_err());
        }
        let digest: ObjectDigest = valid.parse().unwrap();
        assert_eq!(digest.to_string(), valid);
        assert_eq!(digest.hex(), "ab".repeat(32));
        assert_eq!(
            serde_json::from_str::<ObjectDigest>(&serde_json::to_string(&digest).unwrap()).unwrap(),
            digest
        );
        assert_eq!(valid.parse::<ImageId>().unwrap().to_string(), valid);
        assert_eq!(valid.parse::<SnapshotId>().unwrap().to_string(), valid);
        assert_eq!(valid.parse::<LowerResultId>().unwrap().to_string(), valid);
        assert_eq!(
            ObjectDigest::of_bytes(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
