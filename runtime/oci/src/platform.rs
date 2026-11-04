use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::{OciError, OciResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

impl Platform {
    pub fn linux_amd64() -> Self {
        Self {
            os: "linux".to_string(),
            architecture: "amd64".to_string(),
            variant: None,
        }
    }

    pub fn linux_arm64() -> Self {
        Self {
            os: "linux".to_string(),
            architecture: "arm64".to_string(),
            variant: None,
        }
    }

    pub fn host() -> OciResult<Self> {
        match std::env::consts::ARCH {
            "x86_64" | "amd64" => Ok(Self::linux_amd64()),
            "aarch64" | "arm64" => Ok(Self::linux_arm64()),
            other => Err(OciError::UnsupportedHostArchitecture {
                arch: other.to_string(),
            }),
        }
    }

    pub(crate) fn matches_config(
        &self,
        os: &str,
        architecture: &str,
        variant: Option<&str>,
    ) -> bool {
        self.os == os
            && self.architecture == architecture
            && self
                .variant
                .as_deref()
                .map(|expected| Some(expected) == variant)
                .unwrap_or(true)
    }
}

impl Display for Platform {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(variant) = &self.variant {
            write!(f, "/{variant}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Platform;

    #[test]
    fn platform_display_uses_oci_names() {
        let platform = Platform::linux_arm64();

        assert_eq!(platform.to_string(), "linux/arm64");
    }
}
