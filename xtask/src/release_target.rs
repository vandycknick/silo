use std::path::{Path, PathBuf};

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReleaseTarget {
    DarwinArm64,
    LinuxAmd64Gnu,
    LinuxArm64Gnu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum BuildProfile {
    Debug,
    Release,
}

impl BuildProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

impl std::fmt::Display for BuildProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReleaseTargetDescriptor {
    pub(crate) name: &'static str,
    pub(crate) rust_target: &'static str,
    pub(crate) zig_target: Option<&'static str>,
    pub(crate) glibc_baseline: Option<&'static str>,
    pub(crate) macos_minimum_version: Option<&'static str>,
    pub(crate) guest_target: &'static str,
    pub(crate) goos: &'static str,
    pub(crate) goarch: &'static str,
    pub(crate) oci_platform: &'static str,
    pub(crate) npm_os: &'static str,
    pub(crate) npm_cpu: &'static str,
    pub(crate) npm_libc: Option<&'static str>,
    pub(crate) deb_arch: &'static str,
    pub(crate) rpm_arch: &'static str,
    pub(crate) archlinux_arch: &'static str,
}

impl ReleaseTarget {
    pub(crate) fn descriptor(self) -> ReleaseTargetDescriptor {
        match self {
            Self::DarwinArm64 => ReleaseTargetDescriptor {
                name: "darwin-arm64",
                rust_target: "aarch64-apple-darwin",
                zig_target: None,
                glibc_baseline: None,
                macos_minimum_version: Some("26.0"),
                guest_target: "aarch64-unknown-linux-musl",
                goos: "darwin",
                goarch: "arm64",
                oci_platform: "linux/arm64",
                npm_os: "darwin",
                npm_cpu: "arm64",
                npm_libc: None,
                deb_arch: "arm64",
                rpm_arch: "aarch64",
                archlinux_arch: "aarch64",
            },
            Self::LinuxAmd64Gnu => ReleaseTargetDescriptor {
                name: "linux-amd64-gnu",
                rust_target: "x86_64-unknown-linux-gnu",
                zig_target: Some("x86_64-unknown-linux-gnu.2.39"),
                glibc_baseline: Some("2.39"),
                macos_minimum_version: None,
                guest_target: "x86_64-unknown-linux-musl",
                goos: "linux",
                goarch: "amd64",
                oci_platform: "linux/amd64",
                npm_os: "linux",
                npm_cpu: "x64",
                npm_libc: Some("glibc"),
                deb_arch: "amd64",
                rpm_arch: "x86_64",
                archlinux_arch: "x86_64",
            },
            Self::LinuxArm64Gnu => ReleaseTargetDescriptor {
                name: "linux-arm64-gnu",
                rust_target: "aarch64-unknown-linux-gnu",
                zig_target: Some("aarch64-unknown-linux-gnu.2.39"),
                glibc_baseline: Some("2.39"),
                macos_minimum_version: None,
                guest_target: "aarch64-unknown-linux-musl",
                goos: "linux",
                goarch: "arm64",
                oci_platform: "linux/arm64",
                npm_os: "linux",
                npm_cpu: "arm64",
                npm_libc: Some("glibc"),
                deb_arch: "arm64",
                rpm_arch: "aarch64",
                archlinux_arch: "aarch64",
            },
        }
    }
}

impl ReleaseTargetDescriptor {
    #[cfg(test)]
    pub(crate) fn stage_dir(self, profile: BuildProfile) -> PathBuf {
        self.stage_dir_in(Path::new("target"), profile)
    }

    pub(crate) fn stage_dir_in(self, target_dir: &Path, profile: BuildProfile) -> PathBuf {
        target_dir
            .join("silo-runtime")
            .join(self.name)
            .join(profile.as_str())
    }
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum;

    use crate::release_target::{BuildProfile, ReleaseTarget};

    #[test]
    fn descriptors_match_release_contract() {
        let darwin = ReleaseTarget::DarwinArm64.descriptor();
        assert_eq!(darwin.name, "darwin-arm64");
        assert_eq!(darwin.rust_target, "aarch64-apple-darwin");
        assert_eq!(darwin.zig_target, None);
        assert_eq!(darwin.guest_target, "aarch64-unknown-linux-musl");
        assert_eq!((darwin.goos, darwin.goarch), ("darwin", "arm64"));
        assert_eq!(darwin.oci_platform, "linux/arm64");
        assert_eq!((darwin.npm_os, darwin.npm_cpu), ("darwin", "arm64"));
        assert_eq!(darwin.npm_libc, None);
        assert_eq!(darwin.macos_minimum_version, Some("26.0"));
        assert_eq!(darwin.deb_arch, "arm64");
        assert_eq!(darwin.rpm_arch, "aarch64");
        assert_eq!(darwin.archlinux_arch, "aarch64");
        assert_eq!(darwin.glibc_baseline, None);

        let amd64 = ReleaseTarget::LinuxAmd64Gnu.descriptor();
        assert_eq!(amd64.name, "linux-amd64-gnu");
        assert_eq!(amd64.rust_target, "x86_64-unknown-linux-gnu");
        assert_eq!(amd64.zig_target, Some("x86_64-unknown-linux-gnu.2.39"));
        assert_eq!(amd64.guest_target, "x86_64-unknown-linux-musl");
        assert_eq!((amd64.goos, amd64.goarch), ("linux", "amd64"));
        assert_eq!(amd64.oci_platform, "linux/amd64");
        assert_eq!((amd64.npm_os, amd64.npm_cpu), ("linux", "x64"));
        assert_eq!(amd64.npm_libc, Some("glibc"));
        assert_eq!(amd64.macos_minimum_version, None);
        assert_eq!(amd64.deb_arch, "amd64");
        assert_eq!(amd64.rpm_arch, "x86_64");
        assert_eq!(amd64.archlinux_arch, "x86_64");
        assert_eq!(amd64.glibc_baseline, Some("2.39"));

        let arm64 = ReleaseTarget::LinuxArm64Gnu.descriptor();
        assert_eq!(arm64.name, "linux-arm64-gnu");
        assert_eq!(arm64.rust_target, "aarch64-unknown-linux-gnu");
        assert_eq!(arm64.zig_target, Some("aarch64-unknown-linux-gnu.2.39"));
        assert_eq!(arm64.guest_target, "aarch64-unknown-linux-musl");
        assert_eq!((arm64.goos, arm64.goarch), ("linux", "arm64"));
        assert_eq!(arm64.oci_platform, "linux/arm64");
        assert_eq!((arm64.npm_os, arm64.npm_cpu), ("linux", "arm64"));
        assert_eq!(arm64.npm_libc, Some("glibc"));
        assert_eq!(arm64.macos_minimum_version, None);
        assert_eq!(arm64.deb_arch, "arm64");
        assert_eq!(arm64.rpm_arch, "aarch64");
        assert_eq!(arm64.archlinux_arch, "aarch64");
        assert_eq!(arm64.glibc_baseline, Some("2.39"));
    }

    #[test]
    fn stage_directories_match_adr_layout() {
        assert_eq!(
            ReleaseTarget::DarwinArm64
                .descriptor()
                .stage_dir(BuildProfile::Debug),
            std::path::PathBuf::from("target/silo-runtime/darwin-arm64/debug")
        );
        assert_eq!(
            ReleaseTarget::LinuxAmd64Gnu
                .descriptor()
                .stage_dir(BuildProfile::Release),
            std::path::PathBuf::from("target/silo-runtime/linux-amd64-gnu/release")
        );
        assert_eq!(
            ReleaseTarget::LinuxArm64Gnu
                .descriptor()
                .stage_dir(BuildProfile::Release),
            std::path::PathBuf::from("target/silo-runtime/linux-arm64-gnu/release")
        );
    }

    #[test]
    fn clap_names_are_stable() {
        assert_eq!(
            ReleaseTarget::from_str("darwin-arm64", false),
            Ok(ReleaseTarget::DarwinArm64)
        );
        assert_eq!(
            ReleaseTarget::from_str("linux-amd64-gnu", false),
            Ok(ReleaseTarget::LinuxAmd64Gnu)
        );
        assert_eq!(
            ReleaseTarget::from_str("linux-arm64-gnu", false),
            Ok(ReleaseTarget::LinuxArm64Gnu)
        );
        assert!(ReleaseTarget::from_str("windows-amd64", false).is_err());
    }
}
