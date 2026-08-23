use std::fmt::{Display, Formatter};

use sha2::{Digest, Sha256};

use crate::{OciError, OciResult};

/// A validated OCI SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub(crate) fn parse(value: &str) -> OciResult<Self> {
        let Some(encoded) = value.strip_prefix("sha256:") else {
            return Err(OciError::UnsupportedDigestAlgorithm {
                digest: value.to_string(),
            });
        };
        if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(OciError::InvalidDigest {
                digest: value.to_string(),
                message: "sha256 digests must be 64 hexadecimal characters".to_string(),
            });
        }

        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (hex_value(encoded.as_bytes()[index * 2]) << 4)
                | hex_value(encoded.as_bytes()[index * 2 + 1]);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub(crate) fn from_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn hex(self) -> String {
        hex_encode(&self.0)
    }

    pub(crate) fn cache_components(value: &str) -> OciResult<(&'static str, String)> {
        Self::parse(value)?;
        let encoded = value
            .strip_prefix("sha256:")
            .expect("validated SHA-256 digest prefix");
        Ok(("sha256", encoded.to_string()))
    }
}

impl Display for Sha256Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "sha256:{}", hex_encode(&self.0))
    }
}

fn hex_value(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use crate::digest::Sha256Digest;

    #[test]
    fn accepts_uppercase_hex_and_displays_lowercase() {
        let digest = Sha256Digest::parse(&format!("sha256:{}", "AB".repeat(32)))
            .expect("parse uppercase digest");

        assert_eq!(digest.to_string(), format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(
            Sha256Digest::cache_components(&format!("sha256:{}", "AB".repeat(32)))
                .expect("cache components"),
            ("sha256", "AB".repeat(32))
        );
    }
}
