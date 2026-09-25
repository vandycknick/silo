//! The `daemon` section of the CLI's `config.yaml`. The CLI owns this schema and
//! translates only the explicit values into silod's `--system-*` arguments; silod
//! never reads the file.
use std::path::PathBuf;

use serde::Deserialize;
use silod_spec::arguments::{Backend, PublishBind, Share, SystemOverrides};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonConfig {
    version: String,
    /// Backend for the system appliance only. Fixed once the system VM exists.
    #[serde(default)]
    backend: Option<Backend>,
    #[serde(default)]
    system: SystemSection,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemSection {
    /// Only Docker exists today; accepted so the key keeps its documented meaning.
    #[serde(default)]
    engine: Option<Engine>,
    image: Option<String>,
    #[serde(default)]
    resources: Resources,
    #[serde(default)]
    storage: Storage,
    #[serde(default)]
    mounts: Mounts,
    #[serde(default)]
    networking: Networking,
    rosetta: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Engine {
    Docker,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resources {
    cpus: Option<u8>,
    memory: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Storage {
    #[serde(rename = "root-size")]
    root_size: Option<String>,
    #[serde(rename = "data-size")]
    data_size: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mounts {
    home: Option<bool>,
    additional: Option<Vec<AdditionalShare>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdditionalShare {
    path: PathBuf,
    #[serde(default, rename = "read-only")]
    read_only: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Networking {
    #[serde(rename = "publish-bind")]
    publish_bind: Option<PublishBind>,
}

impl DaemonConfig {
    pub(crate) fn overrides(&self) -> eyre::Result<SystemOverrides> {
        if self.version != "1" {
            eyre::bail!(
                "unsupported daemon config version {:?}; expected \"1\"",
                self.version
            );
        }
        let system = &self.system;
        // silod has no engine argument yet; this stops compiling once a second
        // engine exists and needs one.
        match system.engine {
            Some(Engine::Docker) | None => {}
        }
        Ok(SystemOverrides {
            backend: self.backend,
            image: system.image.clone(),
            cpus: system.resources.cpus,
            memory: system.resources.memory.clone(),
            root_size: system.storage.root_size.clone(),
            data_size: system.storage.data_size.clone(),
            rosetta: system.rosetta,
            home_share: system.mounts.home,
            additional_shares: system.mounts.additional.as_ref().map(|shares| {
                shares
                    .iter()
                    .map(|share| Share {
                        path: share.path.clone(),
                        read_only: share.read_only,
                    })
                    .collect()
            }),
            publish_bind: system.networking.publish_bind,
        })
    }
}

#[cfg(test)]
mod tests {
    use silod_spec::arguments::{Backend, PublishBind, Share, SystemOverrides};

    use crate::daemon::config::DaemonConfig;

    fn parse(yaml: &str) -> Result<DaemonConfig, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(yaml)
    }

    #[test]
    fn minimal_section_passes_no_overrides() {
        let config = parse("version: '1'\nsystem: {}\n").expect("minimal");
        assert_eq!(
            config.overrides().expect("overrides"),
            SystemOverrides::default()
        );
        assert!(SystemOverrides::default().to_args().is_empty());
    }

    #[test]
    fn every_documented_key_maps_to_one_override() {
        let config = parse(concat!(
            "version: '1'\n",
            "backend: vz\n",
            "system:\n",
            "  engine: docker\n",
            "  image: registry.example/system@sha256:test\n",
            "  resources:\n    cpus: 2\n    memory: 4GiB\n",
            "  storage:\n    root-size: 30GiB\n    data-size: 100GiB\n",
            "  mounts:\n    home: false\n    additional:\n      - path: /work\n      - path: /cache\n        read-only: true\n",
            "  networking:\n    publish-bind: loopback\n",
            "  rosetta: true\n",
        ))
        .expect("full section");
        assert_eq!(
            config.overrides().expect("overrides"),
            SystemOverrides {
                backend: Some(Backend::Vz),
                image: Some("registry.example/system@sha256:test".into()),
                cpus: Some(2),
                memory: Some("4GiB".into()),
                root_size: Some("30GiB".into()),
                data_size: Some("100GiB".into()),
                rosetta: Some(true),
                home_share: Some(false),
                additional_shares: Some(vec![
                    Share {
                        path: "/work".into(),
                        read_only: false
                    },
                    Share {
                        path: "/cache".into(),
                        read_only: true
                    },
                ]),
                publish_bind: Some(PublishBind::Loopback),
            }
        );
    }

    #[test]
    fn explicit_empty_shares_are_kept_distinct_from_omission() {
        let config = parse("version: '1'\nsystem:\n  mounts:\n    additional: []\n").expect("yaml");
        assert_eq!(
            config.overrides().expect("overrides").additional_shares,
            Some(Vec::new())
        );
    }

    #[test]
    fn rejects_unknown_retired_and_unsupported_settings() {
        assert!(parse("version: '1'\nunknown: true\n").is_err());
        assert!(parse("system: {}\n").is_err());
        assert!(parse("version: '1'\nsystem:\n  engine: podman\n").is_err());
        assert!(parse("version: '1'\nbackend: mock\n").is_err());
        for key in [
            "memory-reclaim",
            "memory-reclaim-after",
            "host-memory-reclaim",
            "balloon",
        ] {
            assert!(parse(&format!(
                "version: '1'\nsystem:\n  resources:\n    {key}: off\n"
            ))
            .is_err());
        }
        assert!(parse("version: '2'\n").expect("parse").overrides().is_err());
    }
}
