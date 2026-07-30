use std::env;

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostTarget {
    MacosArm64,
    LinuxX86_64,
    LinuxArm64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestTarget {
    X86_64Musl,
    Aarch64Musl,
}

#[derive(Debug, Error)]
#[error("unsupported host target {os}-{arch}; supported targets are darwin-arm64, linux-x86_64, and linux-arm64")]
pub struct UnsupportedHost {
    os: String,
    arch: String,
}

impl HostTarget {
    pub fn current() -> Result<Self, UnsupportedHost> {
        match (env::consts::OS, env::consts::ARCH) {
            ("macos", "aarch64") => Ok(Self::MacosArm64),
            ("linux", "x86_64") => Ok(Self::LinuxX86_64),
            ("linux", "aarch64") => Ok(Self::LinuxArm64),
            (os, arch) => Err(UnsupportedHost {
                os: os.to_string(),
                arch: arch.to_string(),
            }),
        }
    }

    pub fn guest_target(self) -> GuestTarget {
        match self {
            Self::MacosArm64 | Self::LinuxArm64 => GuestTarget::Aarch64Musl,
            Self::LinuxX86_64 => GuestTarget::X86_64Musl,
        }
    }

    pub fn runtime_target(self) -> &'static str {
        match self {
            Self::MacosArm64 => "darwin-arm64",
            Self::LinuxX86_64 => "linux-amd64-gnu",
            Self::LinuxArm64 => "linux-arm64-gnu",
        }
    }

    pub fn go_target(self) -> (&'static str, &'static str) {
        match self {
            Self::MacosArm64 => ("darwin", "arm64"),
            Self::LinuxX86_64 => ("linux", "amd64"),
            Self::LinuxArm64 => ("linux", "arm64"),
        }
    }

    pub fn oci_architecture(self) -> &'static str {
        match self {
            Self::MacosArm64 | Self::LinuxArm64 => "arm64",
            Self::LinuxX86_64 => "amd64",
        }
    }

    pub fn kernel_architecture(self) -> &'static str {
        match self {
            Self::MacosArm64 | Self::LinuxArm64 => "arm64",
            Self::LinuxX86_64 => "x86_64",
        }
    }

    pub fn workspace_excludes(self) -> &'static [&'static str] {
        match self {
            Self::MacosArm64 => &["agent", "init"],
            Self::LinuxX86_64 | Self::LinuxArm64 => &["init", "vz"],
        }
    }
}

impl GuestTarget {
    pub fn triple(self) -> &'static str {
        match self {
            Self::X86_64Musl => "x86_64-unknown-linux-musl",
            Self::Aarch64Musl => "aarch64-unknown-linux-musl",
        }
    }
}
