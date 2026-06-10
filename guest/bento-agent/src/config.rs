use std::ffi::OsString;
use std::path::{Path, PathBuf};

use bento_core::agent::AgentConfig;
use eyre::Context;

const DEFAULT_CONFIG_PATH: &str = "/etc/bento/agent.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentArgs {
    pub(crate) config_path: PathBuf,
}

impl AgentArgs {
    pub(crate) fn parse<I>(args: I) -> eyre::Result<Self>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
        let mut args = args.into_iter();
        let _program = args.next();

        while let Some(arg) = args.next() {
            if arg.as_os_str() == "--config" || arg.as_os_str() == "-c" {
                let Some(path) = args.next() else {
                    eyre::bail!("--config requires a path");
                };
                config_path = PathBuf::from(path);
            } else {
                let rendered = arg.to_string_lossy();
                if let Some(path) = rendered.strip_prefix("--config=") {
                    config_path = PathBuf::from(path);
                } else {
                    eyre::bail!("unknown argument {:?}", arg);
                }
            }
        }

        Ok(Self { config_path })
    }
}

pub fn load_agent_config(path: &Path) -> eyre::Result<AgentConfig> {
    let config = if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read agent config {}", path.display()))?;
        serde_yaml_ng::from_str(&raw)
            .with_context(|| format!("parse agent config {}", path.display()))?
    } else if path == Path::new(DEFAULT_CONFIG_PATH) {
        tracing::debug!(path = %path.display(), "agent config not found; using defaults");
        AgentConfig::default()
    } else {
        eyre::bail!("agent config not found: {}", path.display());
    };

    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use crate::config::{AgentArgs, DEFAULT_CONFIG_PATH};

    #[test]
    fn args_default_to_etc_config() {
        let args = AgentArgs::parse([OsString::from("bento-agent")]).expect("parse args");

        assert_eq!(args.config_path, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn args_accept_config_path() {
        let args = AgentArgs::parse([
            OsString::from("bento-agent"),
            OsString::from("--config"),
            OsString::from("/run/agent/bento-agent.yaml"),
        ])
        .expect("parse args");

        assert_eq!(
            args.config_path,
            PathBuf::from("/run/agent/bento-agent.yaml")
        );
    }
}
