//! Explicit system-appliance overrides, encoded as individual argv entries.
//!
//! There are no parser defaults: an omitted option means "use silod's default",
//! which silod resolves against the installation it owns.
use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Krun,
    Vz,
}

impl Backend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Krun => "krun",
            Self::Vz => "vz",
        }
    }
}

/// Host bind policy for ports the system guest publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum PublishBind {
    Loopback,
    Any,
}

impl PublishBind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Any => "any",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub path: PathBuf,
    pub read_only: bool,
}

/// What the controller asks of the system appliance. `None` means unspecified.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemOverrides {
    pub backend: Option<Backend>,
    pub image: Option<String>,
    pub cpus: Option<u8>,
    pub memory: Option<String>,
    pub root_size: Option<String>,
    pub data_size: Option<String>,
    pub rosetta: Option<bool>,
    pub home_share: Option<bool>,
    /// `Some(vec![])` explicitly clears additional shares.
    pub additional_shares: Option<Vec<Share>>,
    pub publish_bind: Option<PublishBind>,
}

impl SystemOverrides {
    /// Encode as argv entries, never a shell string. Read-write shares precede
    /// read-only ones, which is also the order [`SystemArgs`] decodes them in.
    pub fn to_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();
        let mut push = |name: &str, value: OsString| {
            args.push(name.into());
            args.push(value);
        };
        if let Some(backend) = self.backend {
            push("--system-backend", backend.as_str().into());
        }
        if let Some(image) = &self.image {
            push("--system-image", image.into());
        }
        if let Some(cpus) = self.cpus {
            push("--system-cpus", cpus.to_string().into());
        }
        for (name, value) in [
            ("--system-memory", &self.memory),
            ("--system-root-size", &self.root_size),
            ("--system-data-size", &self.data_size),
        ] {
            if let Some(value) = value {
                push(name, value.into());
            }
        }
        if let Some(value) = self.rosetta {
            push("--system-rosetta", value.to_string().into());
        }
        if let Some(value) = self.home_share {
            push("--system-home-share", value.to_string().into());
        }
        if let Some(value) = self.publish_bind {
            push("--system-publish-bind", value.as_str().into());
        }
        if let Some(shares) = &self.additional_shares {
            for read_only in [false, true] {
                for share in shares.iter().filter(|share| share.read_only == read_only) {
                    push(
                        if read_only {
                            "--system-share-read-only"
                        } else {
                            "--system-share"
                        },
                        share.path.as_os_str().to_owned(),
                    );
                }
            }
            if shares.is_empty() {
                args.push("--system-clear-shares".into());
            }
        }
        args
    }
}

/// The argv grammar silod accepts; flatten it into a clap parser.
#[derive(Debug, Default, Args)]
pub struct SystemArgs {
    /// Virtualization backend. Fixed once the system VM exists.
    #[arg(long = "system-backend")]
    backend: Option<Backend>,
    /// System image reference. silod follows it and upgrades when it changes.
    #[arg(long = "system-image", value_name = "REFERENCE")]
    image: Option<String>,
    #[arg(long = "system-cpus", value_name = "COUNT")]
    cpus: Option<u8>,
    #[arg(long = "system-memory", value_name = "SIZE")]
    memory: Option<String>,
    /// Root disk size. Omitted keeps the installation's size.
    #[arg(long = "system-root-size", value_name = "SIZE")]
    root_size: Option<String>,
    /// Data disk size. Fixed once the data disk exists.
    #[arg(long = "system-data-size", value_name = "SIZE")]
    data_size: Option<String>,
    #[arg(long = "system-rosetta", value_name = "BOOL")]
    rosetta: Option<bool>,
    #[arg(long = "system-home-share", value_name = "BOOL")]
    home_share: Option<bool>,
    #[arg(long = "system-share", value_name = "PATH")]
    shares: Vec<PathBuf>,
    #[arg(long = "system-share-read-only", value_name = "PATH")]
    read_only_shares: Vec<PathBuf>,
    /// Explicitly request no additional shares.
    #[arg(long = "system-clear-shares", conflicts_with_all = ["shares", "read_only_shares"])]
    clear_shares: bool,
    #[arg(long = "system-publish-bind")]
    publish_bind: Option<PublishBind>,
}

impl SystemArgs {
    pub fn into_overrides(self) -> SystemOverrides {
        let additional_shares =
            (self.clear_shares || !self.shares.is_empty() || !self.read_only_shares.is_empty())
                .then(|| {
                    let read_write = self.shares.into_iter().map(|path| Share {
                        path,
                        read_only: false,
                    });
                    let read_only = self.read_only_shares.into_iter().map(|path| Share {
                        path,
                        read_only: true,
                    });
                    read_write.chain(read_only).collect()
                });
        SystemOverrides {
            backend: self.backend,
            image: self.image,
            cpus: self.cpus,
            memory: self.memory,
            root_size: self.root_size,
            data_size: self.data_size,
            rosetta: self.rosetta,
            home_share: self.home_share,
            additional_shares,
            publish_bind: self.publish_bind,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use clap::Parser as _;

    use crate::arguments::{Backend, PublishBind, Share, SystemArgs, SystemOverrides};

    #[derive(clap::Parser)]
    struct Command {
        #[command(flatten)]
        system: SystemArgs,
    }

    fn decode(args: Vec<OsString>) -> SystemOverrides {
        let argv = std::iter::once(OsString::from("silod")).chain(args);
        Command::try_parse_from(argv)
            .expect("decode")
            .system
            .into_overrides()
    }

    #[test]
    fn omitted_options_encode_to_nothing() {
        assert!(SystemOverrides::default().to_args().is_empty());
        assert_eq!(decode(Vec::new()), SystemOverrides::default());
    }

    #[test]
    fn every_override_round_trips_without_shell_interpretation() {
        let overrides = SystemOverrides {
            backend: Some(Backend::Vz),
            image: Some("registry/image:test".into()),
            cpus: Some(7),
            memory: Some("9GiB".into()),
            root_size: Some("21GiB".into()),
            data_size: Some("501GiB".into()),
            rosetta: Some(false),
            home_share: Some(false),
            additional_shares: Some(vec![
                Share {
                    path: PathBuf::from("/a directory/$(not-a-command)"),
                    read_only: false,
                },
                Share {
                    path: PathBuf::from("/read-only & 100%"),
                    read_only: true,
                },
            ]),
            publish_bind: Some(PublishBind::Loopback),
        };
        let args = overrides.to_args();
        assert!(args.contains(&OsString::from("/a directory/$(not-a-command)")));
        assert_eq!(decode(args), overrides);
    }

    #[test]
    fn shares_decode_read_write_before_read_only() {
        let share = |path: &str, read_only| Share {
            path: path.into(),
            read_only,
        };
        let overrides = SystemOverrides {
            additional_shares: Some(vec![share("/ro", true), share("/rw", false)]),
            ..SystemOverrides::default()
        };
        assert_eq!(
            decode(overrides.to_args()).additional_shares,
            Some(vec![share("/rw", false), share("/ro", true)])
        );
    }

    #[test]
    fn explicitly_empty_shares_are_not_omission() {
        let overrides = SystemOverrides {
            additional_shares: Some(Vec::new()),
            ..SystemOverrides::default()
        };
        assert_eq!(overrides.to_args(), ["--system-clear-shares"]);
        assert_eq!(decode(overrides.to_args()), overrides);
        assert!(Command::try_parse_from([
            "silod",
            "--system-clear-shares",
            "--system-share",
            "/a"
        ])
        .is_err());
    }

    #[test]
    fn enums_use_the_same_spelling_in_argv_and_serde() {
        for backend in [Backend::Krun, Backend::Vz] {
            assert_eq!(
                serde_json::to_value(backend).expect("serialize"),
                backend.as_str()
            );
        }
        for bind in [PublishBind::Loopback, PublishBind::Any] {
            assert_eq!(
                serde_json::to_value(bind).expect("serialize"),
                bind.as_str()
            );
        }
    }
}
