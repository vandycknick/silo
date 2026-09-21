use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt as _;

use eyre::{bail, Context as _};

use crate::system::config::ResolvedSystemConfig;

const CONTEXT_NAME: &str = "silo";

pub(crate) fn preflight(config: &ResolvedSystemConfig, daemon_live: bool) -> eyre::Result<()> {
    validate_socket_length(&config.docker_socket)?;
    ensure_owned_socket_parent(&config.docker_socket)?;
    let metadata = match std::fs::symlink_metadata(&config.docker_socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() {
        bail!(
            "refusing to replace non-socket Docker endpoint {}",
            config.docker_socket.display()
        );
    }
    validate_owner(&config.docker_socket, &metadata)?;
    if !daemon_live {
        bail!(
            "Docker endpoint {} already exists without a live owned daemon; remove it manually only after verifying its owner",
            config.docker_socket.display()
        );
    }
    Ok(())
}

pub(crate) fn integrate(config: &ResolvedSystemConfig, switch_context: bool) -> eyre::Result<()> {
    if let Some(value) = std::env::var_os("DOCKER_CONFIG") {
        let path = Path::new(&value);
        if !path.is_absolute() {
            bail!("DOCKER_CONFIG must be absolute: {}", path.display());
        }
        eprintln!(
            "Docker context metadata will use DOCKER_CONFIG={}",
            path.display()
        );
    }
    let host_override = std::env::var_os("DOCKER_HOST").is_some();
    let context_override = std::env::var_os("DOCKER_CONTEXT").is_some();
    if host_override {
        eprintln!(
            "warning: DOCKER_HOST overrides Docker contexts; unset it or use --host unix://{}",
            config.docker_socket.display()
        );
    }
    if context_override {
        eprintln!("warning: DOCKER_CONTEXT overrides the active Docker context; unset it or pass --context {CONTEXT_NAME}");
    }

    let version = docker(&["--version"]);
    match version {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("warning: Docker is ready at unix://{}, but the host Docker CLI is not installed; install Docker CLI and run `docker context create {CONTEXT_NAME} --docker host=unix://{}`", config.docker_socket.display(), config.docker_socket.display());
            return Ok(());
        }
        Err(error) => return Err(error).context("run host Docker CLI"),
        Ok(output) if !output.status.success() => {
            bail!("host Docker CLI failed: {}", stderr(&output));
        }
        Ok(_) => {}
    }

    let contexts = docker_success(
        &["context", "ls", "--format", "{{.Name}}"],
        "list Docker contexts",
    )?;
    let exists = contexts.lines().any(|name| name.trim() == CONTEXT_NAME);
    let endpoint = format!("unix://{}", config.docker_socket.display());
    if exists {
        let host = docker_success(
            &[
                "context",
                "inspect",
                CONTEXT_NAME,
                "--format",
                "{{.Endpoints.docker.Host}}",
            ],
            "inspect Docker context `silo`",
        )?;
        if host.trim() != endpoint {
            bail!(
                "Docker context `silo` is foreign or points to {}; refusing to overwrite it (expected {})",
                host.trim(), endpoint
            );
        }
    } else {
        docker_success(
            &[
                "context",
                "create",
                CONTEXT_NAME,
                "--description",
                "Silo system Docker engine",
                "--docker",
                &format!("host={endpoint}"),
            ],
            "create Docker context `silo`",
        )?;
    }

    if switch_context && !host_override && !context_override {
        docker_success(
            &["context", "use", CONTEXT_NAME],
            "activate Docker context `silo`",
        )?;
    }
    Ok(())
}

fn ensure_owned_socket_parent(socket: &Path) -> eyre::Result<()> {
    let run = socket
        .parent()
        .ok_or_else(|| eyre::eyre!("Docker socket has no parent"))?;
    let docker = run
        .parent()
        .ok_or_else(|| eyre::eyre!("Docker run directory has no parent"))?;
    ensure_owned_directory(docker)?;
    ensure_owned_directory(run)
}

fn ensure_owned_directory(path: &Path) -> eyre::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!(
                    "Docker integration path is not a real directory: {}",
                    path.display()
                );
            }
            validate_owner(path, &metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| eyre::eyre!("directory has no parent"))?;
            if !parent.is_dir() {
                bail!(
                    "Docker integration parent does not exist: {}",
                    parent.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new().mode(0o700).create(path)?;
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn validate_owner(path: &Path, metadata: &std::fs::Metadata) -> eyre::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let expected = nix::unistd::geteuid().as_raw();
    if metadata.uid() != expected {
        bail!(
            "{} is owned by UID {}, expected {}",
            path.display(),
            metadata.uid(),
            expected
        );
    }
    Ok(())
}

fn validate_socket_length(path: &Path) -> eyre::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        #[cfg(target_os = "linux")]
        const MAX: usize = 107;
        #[cfg(target_os = "macos")]
        const MAX: usize = 103;
        if path.as_os_str().as_bytes().len() > MAX {
            bail!(
                "Docker socket path exceeds the platform Unix-socket limit: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn docker(arguments: &[&str]) -> std::io::Result<Output> {
    Command::new("docker").args(arguments).output()
}

fn docker_success(arguments: &[&str], action: &str) -> eyre::Result<String> {
    let output = docker(arguments).with_context(|| action.to_string())?;
    if !output.status.success() {
        bail!("{action} failed: {}", stderr(&output));
    }
    String::from_utf8(output.stdout).context("Docker CLI returned non-UTF-8 output")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

#[cfg(test)]
mod tests {
    use crate::system::docker::{preflight, validate_socket_length};

    fn config(home: &std::path::Path) -> crate::system::config::ResolvedSystemConfig {
        let config: crate::system::config::SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nsystem:\n  image: registry.example/system@sha256:test\n",
        )
        .expect("config");
        config.resolve(home, None).expect("resolve")
    }

    #[test]
    fn preflight_creates_socket_directories_without_a_compatibility_alias() {
        let temp = tempfile::tempdir().expect("temp");
        let mut config = config(temp.path());
        config.docker_socket = temp.path().join("docker/run/silo.sock");
        preflight(&config, false).expect("preflight");
        preflight(&config, false).expect("repeat preflight");
        assert!(temp.path().join("docker/run").is_dir());
        assert!(std::fs::symlink_metadata(temp.path().join("docker/run/docker.sock")).is_err());
    }

    #[test]
    fn preflight_leaves_existing_docker_socket_entries_untouched() {
        for symlink in [false, true] {
            let temp = tempfile::tempdir().expect("temp");
            let mut config = config(temp.path());
            let run = temp.path().join("docker/run");
            std::fs::create_dir_all(&run).expect("directories");
            let alias = run.join("docker.sock");
            if symlink {
                std::os::unix::fs::symlink("silo.sock", &alias).expect("existing symlink");
            } else {
                std::fs::write(&alias, "foreign").expect("existing file");
            }
            config.docker_socket = run.join("silo.sock");
            preflight(&config, false).expect("preflight");
            if symlink {
                assert_eq!(
                    std::fs::read_link(&alias).expect("symlink"),
                    std::path::Path::new("silo.sock")
                );
            } else {
                assert_eq!(std::fs::read_to_string(&alias).expect("file"), "foreign");
            }
        }
    }

    #[test]
    fn long_socket_paths_are_rejected() {
        assert!(
            validate_socket_length(std::path::Path::new(&format!("/{}", "x".repeat(200)))).is_err()
        );
    }
}
