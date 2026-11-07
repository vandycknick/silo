use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::changeset::{ChangesetError, ChangesetResult};

macro_rules! identity {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);
        impl $name {
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            pub const fn from_sha256(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }
        impl FromStr for $name {
            type Err = ChangesetError;
            fn from_str(value: &str) -> ChangesetResult<Self> {
                let hex = value
                    .strip_prefix("sha256:")
                    .ok_or_else(|| ChangesetError::Invalid("expected SHA256 identity".into()))?;
                if hex.len() != 64 {
                    return Err(ChangesetError::Invalid(
                        "invalid SHA256 identity length".into(),
                    ));
                }
                let mut bytes = [0; 32];
                for (out, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
                    let digit = |b| match b {
                        b'0'..=b'9' => Ok(b - b'0'),
                        b'a'..=b'f' => Ok(b - b'a' + 10),
                        _ => Err(ChangesetError::Invalid(
                            "noncanonical SHA256 identity".into(),
                        )),
                    };
                    *out = (digit(pair[0])? << 4) | digit(pair[1])?;
                }
                Ok(Self(bytes))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("sha256:")?;
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
identity!(ContentDigest);
identity!(LayerRecipeId);
identity!(LayerResultId);
// Canonical wire spelling only; libvm authenticates the stream map.
// Deliberately no byte hasher or ContentDigest conversion.
identity!(StreamIdentity);

impl ContentDigest {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
    pub(crate) fn from_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
impl LayerRecipeId {
    pub(crate) fn of_record(bytes: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"silo:layer-recipe:v1\n");
        hash.update(bytes);
        Self(hash.finalize().into())
    }
}
impl LayerResultId {
    pub(crate) fn of_record(bytes: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"silo:layer-result:v1\n");
        hash.update(bytes);
        Self(hash.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerChangeset {
    pub diff_id: ContentDigest,
    pub pack_length: u64,
    pub entries: Vec<ChangeEntry>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEntry {
    pub ordinal: u64,
    pub path: Vec<u8>,
    pub metadata: Metadata,
    pub presence: MetadataPresence,
    pub kind: EntryKind,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    RootDirectory,
    Directory,
    Regular(PayloadRef),
    Symlink { target: Vec<u8> },
    Hardlink { target: Vec<u8> },
    CharacterDevice { major: u32, minor: u32 },
    BlockDevice { major: u32, minor: u32 },
    Fifo,
    Socket,
    Whiteout,
    Opaque,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadRef {
    pub pack_offset: u64,
    pub length: u64,
    pub sparse: Vec<SparseRange>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SparseRange {
    pub offset: u64,
    pub length: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub mtime_seconds: u64,
    pub mtime_nanos: u32,
    pub xattrs: Vec<Xattr>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetadataPresence {
    pub uid: bool,
    pub gid: bool,
    pub mode: bool,
    pub mtime: bool,
    pub xattrs: bool,
    pub acl_access: bool,
    pub acl_default: bool,
}
