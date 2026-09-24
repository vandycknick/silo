//! The Docker engine inside the system VM: activation, reachability, and shutdown.
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::ExecutionResult;
use uuid::Uuid;

use crate::config::ResolvedSystemConfig;
use crate::runtime::SystemMachine;

pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const ENGINE_REACHABLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Stops Docker in the guest so containers exit cleanly before the VM stops. Best
/// effort: the VM stop that follows is authoritative.
pub(crate) async fn stop_engine(machine: &SystemMachine) {
    let _ = machine
        .exec_with_input(
            "/usr/bin/systemctl",
            &["stop", "silo-system-docker.target"],
            "root",
            Vec::new(),
            Duration::from_secs(30),
        )
        .await;
}

pub(crate) async fn activate(
    machine: &SystemMachine,
    config: &ResolvedSystemConfig,
    machine_spec: &vm_spec::VmSpec,
    data_uuid: Uuid,
) -> eyre::Result<()> {
    let request = activation_request(config, machine_spec, data_uuid)?;
    let output = machine
        .exec_with_input(
            "/usr/sbin/silo-system-activate",
            &["activate"],
            "root",
            serde_json::to_vec(&request)?,
            Duration::from_secs(60),
        )
        .await?;
    if !matches!(output.result(), ExecutionResult::Exited { code: Some(0) }) {
        bail!(
            "guest Docker activation failed: {}",
            guest_error(&String::from_utf8_lossy(output.stderr_bytes()))
        );
    }
    Ok(())
}

fn activation_request(
    config: &ResolvedSystemConfig,
    machine_spec: &vm_spec::VmSpec,
    data_uuid: Uuid,
) -> eyre::Result<serde_json::Value> {
    let projected = vm_spec::project_mounts(&machine_spec.mounts)
        .map_err(eyre::Report::msg)
        .context("project actual system machine shares for activation")?;
    if projected.len() != config.shares.len() {
        bail!(
            "system activation configuration/spec mismatch: actual machine has {} shares, configuration requires {}",
            projected.len(),
            config.shares.len()
        );
    }

    let required_shares = config
        .shares
        .iter()
        .map(|share| {
            let mut matching = projected
                .iter()
                .filter(|mount| mount.host_source == share.path);
            let mount = matching.next().ok_or_else(|| {
                eyre::eyre!(
                    "system activation configuration/spec mismatch: required host share {} is missing from the actual machine",
                    share.path.display()
                )
            })?;
            if matching.next().is_some() {
                bail!(
                    "system activation configuration/spec mismatch: required host share {} is ambiguous in the actual machine",
                    share.path.display()
                );
            }
            if mount.guest_path != share.path {
                bail!(
                    "system activation configuration/spec mismatch: host share {} has guest path {}, expected {}",
                    share.path.display(),
                    mount.guest_path.display(),
                    share.path.display()
                );
            }
            if mount.read_only != share.read_only {
                bail!(
                    "system activation configuration/spec mismatch: share {} is {} in the actual machine, expected {}",
                    share.path.display(),
                    if mount.read_only { "read-only" } else { "read-write" },
                    if share.read_only { "read-only" } else { "read-write" }
                );
            }
            Ok(serde_json::json!({
                "path": mount.guest_path,
                "tag": mount.backend_tag,
                "writable": !mount.read_only,
            }))
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    Ok(serde_json::json!({
        "schema": 1,
        "data_uuid": data_uuid,
        "data_layout": 1,
        "required_shares": required_shares,
    }))
}

/// One line from a guest command's stderr: distinct lines in order, so a message
/// systemctl repeats for every call it makes reads once.
fn guest_error(stderr: &str) -> String {
    let mut lines: Vec<&str> = Vec::new();
    for line in stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    if lines.is_empty() {
        "no error output".to_string()
    } else {
        lines.join("; ")
    }
}

pub(crate) async fn wait_docker_socket(path: &Path, timeout: Duration) -> eyre::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = None;
    while tokio::time::Instant::now() < deadline {
        match probe_docker_socket(path) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(last_error
        .unwrap_or_else(|| eyre::eyre!("no probe attempted"))
        .wrap_err(format!(
            "Docker engine did not become reachable at {} within {}s",
            path.display(),
            timeout.as_secs()
        )))
}

pub(crate) fn probe_docker_socket(path: &Path) -> eyre::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(path)
            .with_context(|| format!("connect Docker socket {}", path.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(b"GET /_ping HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")?;
        let mut response = Vec::new();
        stream.take(8192).read_to_end(&mut response)?;
        if !response.starts_with(b"HTTP/1.1 200")
            || !response.windows(2).any(|window| window == b"OK")
        {
            bail!("Docker /_ping returned an unhealthy response");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("Docker Unix sockets are unsupported on this host")
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{ResolvedShare, ResolvedSystemConfig};
    use crate::engine::{activation_request, guest_error};

    #[test]
    fn guest_errors_collapse_to_distinct_lines() {
        let bus =
            "Failed to connect to system scope bus via local transport: No such file or directory";
        assert_eq!(guest_error(&format!("{bus}\n{bus}\n")), bus);
        assert_eq!(
            guest_error("silo-system-activate: invalid request\n\nsecond\n"),
            "silo-system-activate: invalid request; second"
        );
        assert_eq!(guest_error(" \n"), "no error output");
    }
    use vm_spec::Mount;

    fn activation_config(shares: Vec<ResolvedShare>) -> ResolvedSystemConfig {
        let temp = tempfile::tempdir().expect("temp");
        let (_paths, record) = crate::record::tests::fixture(temp.path());
        ResolvedSystemConfig {
            shares,
            ..record.config
        }
    }

    #[test]
    fn activation_uses_full_machine_mount_projection() {
        let long_one = "/guest/a/very/long/workspace/destination/that/exceeds/the/tag/field";
        let long_two = "/guest/another/long/read-only/destination/that/exceeds/the/tag/field";
        let shares = vec![
            ResolvedShare {
                path: long_one.into(),
                read_only: false,
            },
            ResolvedShare {
                path: "/literal".into(),
                read_only: false,
            },
            ResolvedShare {
                path: long_two.into(),
                read_only: true,
            },
            ResolvedShare {
                path: "/cache".into(),
                read_only: true,
            },
        ];
        let config = activation_config(shares.clone());
        let mut spec = vm_spec::VmSpec::current();
        spec.mounts = vec![
            Mount {
                source: long_one.into(),
                tag: long_one.to_string(),
                read_only: false,
            },
            Mount {
                source: "/literal".into(),
                tag: "silo-mount-0".to_string(),
                read_only: false,
            },
            Mount {
                source: long_two.into(),
                tag: long_two.to_string(),
                read_only: true,
            },
            Mount {
                source: "/cache".into(),
                tag: "/cache".to_string(),
                read_only: true,
            },
        ];

        let request = activation_request(&config, &spec, uuid::Uuid::nil())
            .expect("build activation request");

        assert_eq!(
            request["required_shares"],
            serde_json::json!([
                { "path": long_one, "tag": "silo-mount-1", "writable": true },
                { "path": "/literal", "tag": "silo-mount-0", "writable": true },
                { "path": long_two, "tag": "silo-mount-2", "writable": false },
                { "path": "/cache", "tag": "/cache", "writable": false }
            ])
        );
        assert_eq!(spec.mounts[0].source, shares[0].path);
        assert_eq!(spec.mounts[0].tag, long_one);
    }

    #[test]
    fn activation_rejects_required_share_configuration_spec_mismatches() {
        let config = activation_config(vec![ResolvedShare {
            path: "/required".into(),
            read_only: true,
        }]);
        let spec_with = |source: &str, tag: &str, read_only| {
            let mut spec = vm_spec::VmSpec::current();
            spec.mounts.push(Mount {
                source: source.into(),
                tag: tag.to_string(),
                read_only,
            });
            spec
        };

        for (spec, expected) in [
            (
                spec_with("/other", "/required", true),
                "required host share /required is missing",
            ),
            (
                spec_with("/required", "/other", true),
                "has guest path /other, expected /required",
            ),
            (
                spec_with("/required", "/required", false),
                "is read-write in the actual machine, expected read-only",
            ),
        ] {
            let error = activation_request(&config, &spec, uuid::Uuid::nil())
                .expect_err("mismatched activation share must fail");
            assert!(error.to_string().contains(expected), "{error:#}");
        }

        let empty = vm_spec::VmSpec::current();
        let error = activation_request(&config, &empty, uuid::Uuid::nil())
            .expect_err("missing machine share must fail");
        assert!(error
            .to_string()
            .contains("actual machine has 0 shares, configuration requires 1"));
    }
}
