//! Bounded, nonsecret netd observations. Historical metadata is never live readiness.
use crate::machine::{Machine, MachineRef};
use crate::LibVmError;
use chrono::{DateTime, TimeDelta, Utc};
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineNetworkObservation {
    pub live: Option<MachineNodeStatus>,
    pub historical: Option<MachineNodeObservation>,
    pub issues: Vec<MachineNetworkObservationIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineNetworkObservationIssue {
    Missing,
    Unsafe,
    Invalid,
    Stale,
    WrongGeneration,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineNodeState {
    Connecting,
    ApprovalRequired,
    Ready,
    Disconnected,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineNodeStatus {
    pub version: u32,
    pub machine_id: String,
    pub run_id: String,
    pub observed_at: DateTime<Utc>,
    pub state: MachineNodeState,
    pub approval_url: Option<String>,
    pub node_id: Option<String>,
    pub dns_name: Option<String>,
    pub error_code: Option<String>,
    pub tags: Vec<String>,
    pub addresses: Vec<IpAddr>,
    pub key_expiry: Option<DateTime<Utc>>,
    pub key_expiry_known: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MachineNodeObservation {
    #[serde(skip)]
    pub machine_id: String,
    #[serde(default = "zero_time", deserialize_with = "deserialize_time")]
    pub observed_at: DateTime<Utc>,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub tailnet: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub dns_name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub key_expiry: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct Snapshot {
    version: u32,
    vm_id: String,
    #[serde(default)]
    run_id: String,
    observed_at: Option<DateTime<Utc>>,
    state: MachineNodeState,
    #[serde(default)]
    approval_url: String,
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    dns_name: String,
    #[serde(default)]
    error_code: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    addresses: Vec<IpAddr>,
    key_expiry: Option<DateTime<Utc>>,
    #[serde(default)]
    key_expiry_known: bool,
    last_known: Option<MachineNodeObservation>,
}

impl Machine {
    /// Reads the observation adjacent to this machine's authoritative netd state.
    /// Unsafe, missing or stale observations return typed issues, not live data.
    pub async fn network_observation(&self) -> Result<MachineNetworkObservation, LibVmError> {
        let config = self
            .runtime()
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        self.runtime().validate_machine_data_dir(&config)?;
        let data = self.runtime().machine_inspect_data(config).await?;
        let Some(tailscale) = data.tailscale else {
            return Ok(MachineNetworkObservation::default());
        };
        Ok(read_observation(
            &tailscale.state_dir,
            &data.id,
            data.run_id.as_ref().map(|run| run.as_str()),
            Utc::now(),
        ))
    }
}

fn file_issue(error: std::io::Error) -> MachineNetworkObservationIssue {
    use MachineNetworkObservationIssue as I;
    match error.raw_os_error() {
        Some(code) if code == nix::errno::Errno::ENOENT as i32 => I::Missing,
        Some(code)
            if matches!(
                nix::errno::Errno::from_raw(code),
                nix::errno::Errno::ELOOP
                    | nix::errno::Errno::ENOTDIR
                    | nix::errno::Errno::EACCES
                    | nix::errno::Errno::EPERM
            ) =>
        {
            I::Unsafe
        }
        _ => I::Unavailable,
    }
}

fn read_snapshot(
    state_dir: &Path,
    machine: &str,
) -> Result<Snapshot, MachineNetworkObservationIssue> {
    use MachineNetworkObservationIssue as I;
    let parent = state_dir
        .parent()
        .filter(|path| path.is_absolute())
        .ok_or(I::Unsafe)?;
    let mut filename = state_dir.file_name().ok_or(I::Unsafe)?.to_os_string();
    filename.push(".status.json");
    // Anchor the open to an owned directory descriptor; never follow the leaf or
    // block on a FIFO. The observation is a sibling of the tailscale state dir.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
        .open(parent)
        .map_err(file_issue)?;
    let metadata = directory.metadata().map_err(|_| I::Unavailable)?;
    if metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(I::Unsafe);
    }
    let fd = openat(
        &directory,
        Path::new(&filename),
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| file_issue(error.into()))?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| I::Unavailable)?;
    validate_snapshot_metadata(&metadata, nix::unistd::geteuid().as_raw())?;
    if metadata.len() > 4096 {
        return Err(I::Invalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| I::Unavailable)?;
    if bytes.len() > 4096 {
        return Err(I::Invalid);
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| I::Invalid)?;
    if snapshot.version != 1 || snapshot.vm_id != machine {
        return Err(I::Invalid);
    }
    if !snapshot.approval_url.is_empty() {
        let value = &snapshot.approval_url;
        let url = url::Url::parse(value).map_err(|_| I::Invalid)?;
        let authority = value
            .split_once("://")
            .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
            .ok_or(I::Invalid)?;
        if value.len() > 1000
            || value.contains(['\r', '\n', '\u{1b}'])
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || authority.is_empty()
            || authority.contains(['@', '\\'])
            || snapshot.state != MachineNodeState::ApprovalRequired
        {
            return Err(I::Invalid);
        }
    }
    Ok(snapshot)
}

fn validate_snapshot_metadata(
    metadata: &std::fs::Metadata,
    owner: u32,
) -> Result<(), MachineNetworkObservationIssue> {
    if !metadata.is_file() || metadata.mode() & 0o777 != 0o600 || metadata.uid() != owner {
        return Err(MachineNetworkObservationIssue::Unsafe);
    }
    Ok(())
}

fn zero_time() -> DateTime<Utc> {
    DateTime::<Utc>::MIN_UTC
}

fn deserialize_time<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<DateTime<Utc>>::deserialize(deserializer)?.unwrap_or_else(zero_time))
}

fn nonzero(time: DateTime<Utc>) -> bool {
    // Missing historical timestamps use MIN_UTC; Go's zero time is year 1.
    time != DateTime::<Utc>::MIN_UTC
        && (time.timestamp() != -62_135_596_800 || time.timestamp_subsec_nanos() != 0)
}
fn present(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn read_observation(
    state_dir: &Path,
    machine: &str,
    run: Option<&str>,
    now: DateTime<Utc>,
) -> MachineNetworkObservation {
    use MachineNetworkObservationIssue as I;
    let snapshot = match read_snapshot(state_dir, machine) {
        Ok(value) => value,
        Err(issue) => {
            return MachineNetworkObservation {
                issues: vec![issue],
                ..Default::default()
            }
        }
    };
    let mut result = MachineNetworkObservation::default();
    let future = now + TimeDelta::seconds(5);
    if let Some(mut history) = snapshot.last_known {
        if nonzero(history.observed_at)
            && history.observed_at <= future
            && snapshot
                .observed_at
                .is_some_and(|time| history.observed_at <= time)
            && !history.node_id.is_empty()
            && !history.dns_name.is_empty()
        {
            history.machine_id = machine.to_owned();
            result.historical = Some(history);
        } else {
            result.issues.push(I::Invalid);
        }
    }
    if run.is_none_or(|run| run.is_empty() || snapshot.run_id != run) {
        result.issues.push(I::WrongGeneration);
        return result;
    }
    let Some(observed_at) = snapshot.observed_at.filter(|time| nonzero(*time)) else {
        result.issues.push(I::Invalid);
        return result;
    };
    if observed_at > future || now - observed_at > TimeDelta::minutes(1) {
        result.issues.push(I::Stale);
        return result;
    }
    result.live = Some(MachineNodeStatus {
        version: snapshot.version,
        machine_id: snapshot.vm_id,
        run_id: snapshot.run_id,
        observed_at,
        state: snapshot.state,
        approval_url: present(snapshot.approval_url),
        node_id: present(snapshot.node_id),
        dns_name: present(snapshot.dns_name),
        error_code: present(snapshot.error_code),
        tags: snapshot.tags,
        addresses: snapshot.addresses,
        key_expiry: snapshot.key_expiry,
        key_expiry_known: snapshot.key_expiry_known,
    });
    result
}

#[cfg(test)]
mod tests {
    use crate::machine::node_status::*;
    use serde_json::{json, Value};
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, Value, DateTime<Utc>) {
        let dir = tempfile::tempdir().unwrap();
        let now = DateTime::parse_from_rfc3339("2026-10-07T12:00:00.123456789Z")
            .unwrap()
            .with_timezone(&Utc);
        let value = json!({
            "version": 1, "vm_id": "machine", "run_id": "run", "observed_at": now,
            "state": "approval_required", "approval_url": "https://login.tailscale.com/a/approve",
            "addresses": ["100.64.0.1", "fd7a:115c:a1e0::1"], "key_expiry_known": true,
            "last_known": {"observed_at": now - TimeDelta::days(30), "owner": "owner",
                "tailnet": "tailnet", "node_id": "node", "dns_name": "vm.example.ts.net",
                "tags": ["tag:silo"], "key_expiry": now + TimeDelta::days(1)}
        });
        (dir, value, now)
    }
    fn write(dir: &Path, value: &Value) {
        let path = dir.join("tailscale.status.json");
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn observe(dir: &Path, now: DateTime<Utc>) -> MachineNetworkObservation {
        read_observation(&dir.join("tailscale"), "machine", Some("run"), now)
    }
    #[test]
    fn node_status_live_and_historical_are_separate() {
        let (dir, mut value, now) = fixture();
        write(dir.path(), &value);
        let observation = observe(dir.path(), now);
        let live = observation.live.unwrap();
        assert_eq!(live.observed_at, now);
        assert_eq!(live.addresses.len(), 2);
        assert!(live.key_expiry_known);
        assert_eq!(observation.historical.unwrap().machine_id, "machine");
        value["run_id"] = json!("old-run");
        write(dir.path(), &value);
        let observation = observe(dir.path(), now);
        assert!(observation.live.is_none());
        assert!(observation.historical.is_some());
        assert_eq!(
            observation.issues,
            vec![MachineNetworkObservationIssue::WrongGeneration]
        );
        assert!(
            read_observation(&dir.path().join("tailscale"), "machine", None, now)
                .live
                .is_none()
        );
    }
    #[test]
    fn node_status_derives_filename_from_authoritative_state_directory() {
        let (dir, value, now) = fixture();
        // A valid observation at the old hardcoded location must be ignored.
        write(dir.path(), &value);
        let state_dir = dir.path().join("custom-node-state");
        assert_eq!(
            read_observation(&state_dir, "machine", Some("run"), now).issues,
            vec![MachineNetworkObservationIssue::Missing],
        );
        let path = dir.path().join("custom-node-state.status.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_observation(&state_dir, "machine", Some("run"), now)
            .live
            .is_some());
        let alias = dir.path().join("parent-alias");
        symlink(dir.path(), &alias).unwrap();
        assert_eq!(
            read_observation(
                &alias.join("custom-node-state"),
                "machine",
                Some("run"),
                now
            )
            .issues,
            vec![MachineNetworkObservationIssue::Unsafe],
        );
    }

    #[test]
    fn node_status_missing_timestamps_never_expose_live_or_historical_data() {
        let (dir, original, now) = fixture();
        for timestamp in [None, Some(Value::Null), Some(json!("0001-01-01T00:00:00Z"))] {
            let mut value = original.clone();
            match timestamp.clone() {
                Some(timestamp) => {
                    value["observed_at"] = timestamp;
                }
                None => {
                    value.as_object_mut().unwrap().remove("observed_at");
                }
            }
            write(dir.path(), &value);
            let result = observe(dir.path(), now);
            assert!(result.live.is_none());
            assert!(result.historical.is_none());
            assert!(result
                .issues
                .contains(&MachineNetworkObservationIssue::Invalid));

            let mut value = original.clone();
            match timestamp {
                Some(timestamp) => {
                    value["last_known"]["observed_at"] = timestamp;
                }
                None => {
                    value["last_known"]
                        .as_object_mut()
                        .unwrap()
                        .remove("observed_at");
                }
            }
            write(dir.path(), &value);
            let result = observe(dir.path(), now);
            assert!(result.live.is_some());
            assert!(result.historical.is_none());
            assert_eq!(result.issues, vec![MachineNetworkObservationIssue::Invalid]);
        }
    }
    #[test]
    fn node_status_freshness_and_historical_boundaries() {
        let (dir, original, now) = fixture();
        for offset in [-61, 6] {
            let mut value = original.clone();
            value["observed_at"] = json!(now + TimeDelta::seconds(offset));
            write(dir.path(), &value);
            let result = observe(dir.path(), now);
            assert!(result.live.is_none());
            assert!(result.historical.is_some());
            assert!(result
                .issues
                .contains(&MachineNetworkObservationIssue::Stale));
        }
        for offset in [-60, 5] {
            let mut value = original.clone();
            value["observed_at"] = json!(now + TimeDelta::seconds(offset));
            write(dir.path(), &value);
            assert!(observe(dir.path(), now).live.is_some());
        }
        for field in ["observed_at", "node_id", "dns_name"] {
            let mut value = original.clone();
            value["last_known"][field] = if field == "observed_at" {
                json!(now + TimeDelta::seconds(1))
            } else {
                json!("")
            };
            write(dir.path(), &value);
            let result = observe(dir.path(), now);
            assert!(result.historical.is_none());
            assert!(result.live.is_some());
        }
        let mut value = original;
        value["observed_at"] = json!("0001-01-01T00:00:00Z");
        write(dir.path(), &value);
        assert!(observe(dir.path(), now).live.is_none());
    }
    #[test]
    fn node_status_rejects_invalid_schema_and_approval_urls() {
        let (dir, original, now) = fixture();
        for url in [
            "http://login.example/a",
            "https://user@login.example/a",
            "https://@login.example/a",
            "https:///",
            "https:///login.example/a",
            "https://login.example\\other/a",
            "https://login.example/a\n",
            "https://login.example/\u{1b}",
        ] {
            let mut value = original.clone();
            value["approval_url"] = json!(url);
            write(dir.path(), &value);
            assert_eq!(
                observe(dir.path(), now).issues,
                vec![MachineNetworkObservationIssue::Invalid],
                "{url:?}"
            );
        }
        for (field, replacement) in [
            ("version", json!(2)),
            ("vm_id", json!("other")),
            ("state", json!("unknown")),
            ("state", json!("ready")),
            ("addresses", json!(["invalid"])),
        ] {
            let mut value = original.clone();
            value[field] = replacement;
            write(dir.path(), &value);
            assert!(observe(dir.path(), now).live.is_none());
        }
        let mut value = original;
        value["approval_url"] = json!(format!("https://login.example/{}", "a".repeat(1000)));
        write(dir.path(), &value);
        assert!(observe(dir.path(), now).live.is_none());
    }
    #[test]
    fn node_status_file_boundaries() {
        let (dir, value, now) = fixture();
        let path = dir.path().join("tailscale.status.json");
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Missing]
        );
        write(dir.path(), &value);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Unsafe]
        );
        std::fs::remove_file(&path).unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, serde_json::to_vec(&value).unwrap()).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Unsafe]
        );
        std::fs::remove_file(&path).unwrap();
        nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Unsafe]
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Unsafe]
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, vec![b' '; 4097]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Invalid]
        );
        std::fs::write(&path, b"{malformed").unwrap();
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Invalid]
        );
    }
    #[test]
    fn node_status_metadata_rejects_foreign_owner_without_privileges() {
        let (dir, value, _) = fixture();
        write(dir.path(), &value);
        let metadata = std::fs::metadata(dir.path().join("tailscale.status.json")).unwrap();
        assert!(validate_snapshot_metadata(&metadata, metadata.uid()).is_ok());
        assert_eq!(
            validate_snapshot_metadata(&metadata, metadata.uid().wrapping_add(1)),
            Err(MachineNetworkObservationIssue::Unsafe),
        );
    }
    #[test]
    fn node_status_rejects_foreign_owner_when_privileged() {
        // Changing file ownership requires root; unprivileged runs cover all
        // other boundaries without pretending to have exercised chown.
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let (dir, value, now) = fixture();
        write(dir.path(), &value);
        nix::unistd::chown(
            &dir.path().join("tailscale.status.json"),
            Some(nix::unistd::Uid::from_raw(1)),
            None,
        )
        .unwrap();
        assert_eq!(
            observe(dir.path(), now).issues,
            vec![MachineNetworkObservationIssue::Unsafe]
        );
    }
}
