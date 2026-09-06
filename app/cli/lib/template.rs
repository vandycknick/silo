use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{bail, Context as _};
use serde::{Deserialize, Serialize};

use crate::config::resolve_default_config_dir;
use crate::machine_defaults::{
    validate_machine_defaults, MachineMount, MachineNetwork, MachineResources,
};

const TEMPLATE_DIRECTORY_NAME: &str = "templates";
const TEMPLATE_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NamedTemplate {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) template: Template,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Template {
    pub(crate) version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resources: Option<MachineResources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) disk_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) userdata: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mounts: Vec<MachineMount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) forwards: Vec<TemplateForward>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vsock: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<MachineNetwork>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TemplateForward {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    pub(crate) listen: String,
    pub(crate) connect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
}

pub(crate) struct TemplateStore {
    root: PathBuf,
}

impl TemplateStore {
    pub(crate) fn from_env() -> eyre::Result<Self> {
        Ok(Self::from_config_root(resolve_default_config_dir()?))
    }

    pub(crate) fn from_config_root(config_root: impl Into<PathBuf>) -> Self {
        Self {
            root: config_root.into().join(TEMPLATE_DIRECTORY_NAME),
        }
    }

    pub(crate) fn ensure_dir(&self) -> eyre::Result<()> {
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("create template directory {}", self.root.display()))
    }

    pub(crate) fn path_for_new_template(&self, name: &str) -> eyre::Result<PathBuf> {
        validate_template_name(name)?;
        Ok(self.root.join(format!("{name}.yaml")))
    }

    pub(crate) fn resolve(&self, name: &str) -> eyre::Result<NamedTemplate> {
        let Some(path) = self.find_template_path(name)? else {
            bail!(
                "template `{name}` not found in {}",
                display_template_dir(&self.root)
            );
        };
        self.load_path(name.to_string(), path)
    }

    pub(crate) fn list(&self) -> eyre::Result<Vec<NamedTemplate>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read template directory {}", self.root.display()))
            }
        };

        let mut seen = BTreeMap::<String, PathBuf>::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !is_template_file(&path) {
                continue;
            }
            let name = template_name_from_path(&path)?;
            validate_template_name(&name)
                .with_context(|| format!("invalid template file name: {}", path.display()))?;
            if let Some(existing) = seen.insert(name.clone(), path.clone()) {
                bail!(
                    "duplicate template `{name}`: found both {} and {}",
                    existing
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("<unknown>"),
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("<unknown>")
                );
            }
        }

        seen.into_iter()
            .map(|(name, path)| self.load_path(name, path))
            .collect()
    }

    pub(crate) fn write(&self, name: &str, template: &Template) -> eyre::Result<PathBuf> {
        validate_template_name(name)?;
        validate_template(template)?;
        self.ensure_dir()?;

        if let Some(existing) = self.find_template_path(name)? {
            if existing
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("yml")
            {
                bail!(
                    "template `{name}` exists as {}; template writes use .yaml",
                    existing.display()
                );
            }
            bail!("template `{name}` already exists at {}", existing.display());
        }

        let path = self.path_for_new_template(name)?;
        let rendered = serde_yaml_ng::to_string(template).context("serialize template yaml")?;
        std::fs::write(&path, rendered)
            .with_context(|| format!("write template {}", path.display()))?;
        Ok(path)
    }

    fn find_template_path(&self, name: &str) -> eyre::Result<Option<PathBuf>> {
        validate_template_name(name)?;
        let yaml = self.root.join(format!("{name}.yaml"));
        let yml = self.root.join(format!("{name}.yml"));
        match (yaml.is_file(), yml.is_file()) {
            (true, true) => {
                bail!("duplicate template `{name}`: found both {name}.yaml and {name}.yml")
            }
            (true, false) => Ok(Some(yaml)),
            (false, true) => Ok(Some(yml)),
            (false, false) => Ok(None),
        }
    }

    fn load_path(&self, name: String, path: PathBuf) -> eyre::Result<NamedTemplate> {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read template {}", path.display()))?;
        let template =
            parse_template(&raw).with_context(|| format!("parse template {}", path.display()))?;
        Ok(NamedTemplate {
            name,
            path,
            template,
        })
    }
}

pub(crate) fn parse_template(raw: &str) -> eyre::Result<Template> {
    let template: Template = serde_yaml_ng::from_str(raw).context("deserialize template yaml")?;
    validate_template(&template)?;
    Ok(template)
}

pub(crate) fn validate_template(template: &Template) -> eyre::Result<()> {
    if template.version != TEMPLATE_VERSION {
        bail!(
            "unsupported template version `{}`, supported versions: {TEMPLATE_VERSION}",
            template.version
        );
    }
    if template
        .image
        .as_deref()
        .is_some_and(|image| image.trim().is_empty())
    {
        bail!("template image cannot be empty");
    }
    validate_machine_defaults(
        template.resources.as_ref(),
        template.disk_size.as_deref(),
        template.userdata.as_deref(),
        &template.mounts,
        template.network.as_ref(),
    )
    .map_err(|error| eyre::eyre!("template {error}"))
}

fn validate_template_name(name: &str) -> eyre::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!(
            "invalid template name `{name}`: use ASCII letters, digits, hyphens, and underscores"
        );
    }
    Ok(())
}

fn is_template_file(path: &Path) -> bool {
    path.is_file()
        && matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("yaml" | "yml")
        )
}

fn template_name_from_path(path: &Path) -> eyre::Result<String> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(str::to_string)
        .ok_or_else(|| eyre::eyre!("invalid template file name: {}", path.display()))
}

fn display_template_dir(path: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        if let Ok(stripped) = path.strip_prefix(home) {
            return format!("~/{}", stripped.display());
        }
    }
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::machine_defaults::{MachineMount, MachineNetwork, MachineResources, MountMode};
    use crate::template::{parse_template, Template, TemplateStore};

    fn valid_template() -> Template {
        Template {
            version: "1".to_string(),
            description: Some("Development machine defaults".to_string()),
            image: Some("ubuntu:24.04".to_string()),
            resources: Some(MachineResources {
                cpus: Some(4),
                memory: Some("4gb".to_string()),
            }),
            disk_size: Some("40gb".to_string()),
            userdata: Some("#!/bin/sh\nset -eu\n".to_string()),
            mounts: vec![MachineMount {
                source: "/tmp/workspace".into(),
                target: "/workspace".to_string(),
                mode: MountMode::Ro,
            }],
            forwards: Vec::new(),
            vsock: None,
            network: Some(MachineNetwork::None),
            labels: BTreeMap::from([("team".to_string(), "runtime".to_string())]),
        }
    }

    #[test]
    fn parses_schema_version_one_template_with_optional_image() {
        let template = parse_template(
            r#"
version: "1"
description: image is supplied later
resources:
  cpus: 2
  memory: 2gb
disk_size: 20gb
userdata: |
  #!/bin/sh
  set -eu
mounts:
  - source: ./workspace
    target: /workspace
    mode: rw
forwards:
  - name: web
    listen: host:tcp:8080
    connect: guest:tcp:80
    mode: null
vsock: true
network:
  kind: private
  publish: any
labels:
  environment: development
"#,
        )
        .expect("parse template");

        assert_eq!(template.image, None);
        assert_eq!(template.resources.expect("resources").cpus, Some(2));
        assert_eq!(template.mounts.len(), 1);
        assert_eq!(template.forwards.len(), 1);
        assert_eq!(template.forwards[0].name.as_deref(), Some("web"));
        assert_eq!(template.vsock, Some(true));
        let Some(MachineNetwork::Private { publish, .. }) = template.network else {
            panic!("expected private network");
        };
        assert_eq!(publish, Some(libvm::PublishBind::Any));
    }

    #[test]
    fn rejects_unknown_fields_at_every_structured_level() {
        for document in [
            "version: \"1\"\nunknown: true\n",
            "version: \"1\"\nresources:\n  unknown: true\n",
            "version: \"1\"\nmounts:\n  - source: /tmp\n    target: /tmp\n    unknown: true\n",
            "version: \"1\"\nnetwork:\n  kind: private\n  unknown: true\n",
        ] {
            let error = parse_template(document).expect_err("unknown field must fail");
            assert!(
                error
                    .chain()
                    .any(|cause| cause.to_string().contains("unknown field")),
                "unexpected error: {error:?}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let error = parse_template("version: \"2\"\n").expect_err("unsupported version");

        assert!(error
            .to_string()
            .contains("unsupported template version `2`"));
    }

    #[test]
    fn reads_and_lists_do_not_create_the_template_directory() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let store = TemplateStore::from_config_root(config_root.path());
        let template_dir = config_root.path().join("templates");

        assert!(store.list().expect("list missing directory").is_empty());
        assert!(store.resolve("missing").is_err());
        assert!(!template_dir.exists());
    }

    #[test]
    fn writes_yaml_and_round_trips_through_the_store() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let store = TemplateStore::from_config_root(config_root.path());
        let path = store
            .write("development", &valid_template())
            .expect("write template");

        assert_eq!(path, config_root.path().join("templates/development.yaml"));
        assert!(path.is_file());

        let template = store.resolve("development").expect("read template");
        assert_eq!(template.name, "development");
        assert_eq!(template.path, path);
        assert_eq!(template.template.image.as_deref(), Some("ubuntu:24.04"));
    }

    #[test]
    fn rejects_duplicate_yaml_and_yml_stems() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let template_dir = config_root.path().join("templates");
        std::fs::create_dir_all(&template_dir).expect("create templates directory");
        let contents = "version: \"1\"\n";
        std::fs::write(template_dir.join("dev.yaml"), contents).expect("write yaml");
        std::fs::write(template_dir.join("dev.yml"), contents).expect("write yml");
        let store = TemplateStore::from_config_root(config_root.path());

        let error = store.list().expect_err("duplicate stem must fail");
        assert!(error.to_string().contains("duplicate template `dev`"));
        let error = store.resolve("dev").expect_err("duplicate stem must fail");
        assert!(error.to_string().contains("duplicate template `dev`"));
    }

    #[test]
    fn rejects_unsafe_template_names_before_accessing_the_store() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let store = TemplateStore::from_config_root(config_root.path());

        for name in [
            "",
            ".",
            "..",
            "../outside",
            "nested/name",
            "name.yml",
            "hello world",
        ] {
            assert!(store.resolve(name).is_err(), "resolve accepted {name:?}");
            assert!(
                store.path_for_new_template(name).is_err(),
                "path accepted {name:?}"
            );
            assert!(
                store.write(name, &valid_template()).is_err(),
                "write accepted {name:?}"
            );
        }
        assert!(!config_root.path().join("templates").exists());
    }

    #[test]
    fn refuses_to_replace_a_yml_template_with_a_yaml_write() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let template_dir = config_root.path().join("templates");
        std::fs::create_dir_all(&template_dir).expect("create templates directory");
        std::fs::write(template_dir.join("dev.yml"), "version: \"1\"\n").expect("write yml");
        let store = TemplateStore::from_config_root(config_root.path());

        let error = store
            .write("dev", &valid_template())
            .expect_err("yml write must fail");
        assert!(error.to_string().contains("writes use .yaml"));
        assert!(!template_dir.join("dev.yaml").exists());
    }

    #[test]
    fn refuses_to_replace_a_yaml_template() {
        let config_root = tempfile::tempdir().expect("tempdir");
        let store = TemplateStore::from_config_root(config_root.path());
        store
            .write("dev", &valid_template())
            .expect("write template");

        let error = store
            .write("dev", &valid_template())
            .expect_err("existing yaml must not be replaced");

        assert!(error.to_string().contains("template `dev` already exists"));
    }
}
