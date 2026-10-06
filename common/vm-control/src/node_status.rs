//! Nonsecret netd observations; historical fields never imply live readiness.
use crate::{invalid, ConversionError};
use silod_spec::daemon::v1 as w;

fn timestamp(seconds: i64, nanos: u32) -> Result<prost_types::Timestamp, ConversionError> {
    if !(-62_135_596_800..=253_402_300_799).contains(&seconds) {
        return Err(invalid("network_observation.timestamp", "out of range"));
    }
    Ok(prost_types::Timestamp {
        seconds,
        nanos: nanos as i32,
    })
}

pub fn observation_to_wire(
    value: &libvm::MachineNetworkObservation,
) -> Result<w::NetworkObservation, ConversionError> {
    use libvm::{MachineNetworkObservationIssue as I, MachineNodeState as S};
    let live = value
        .live
        .as_ref()
        .map(|v| -> Result<_, ConversionError> {
            Ok(w::NodeStatus {
                machine_id: v.machine_id.clone(),
                run_id: v.run_id.clone(),
                version: v.version,
                updated_at: Some(timestamp(
                    v.observed_at.timestamp(),
                    v.observed_at.timestamp_subsec_nanos(),
                )?),
                state: match v.state {
                    S::Connecting => w::NodeState::Connecting,
                    S::ApprovalRequired => w::NodeState::ApprovalRequired,
                    S::Ready => w::NodeState::Ready,
                    S::Disconnected => w::NodeState::Disconnected,
                    S::Failed => w::NodeState::Failed,
                    S::Stopped => w::NodeState::Stopped,
                } as i32,
                approval_url: v.approval_url.clone(),
                dns_name: v.dns_name.clone(),
                node_id: v.node_id.clone(),
                tags: v.tags.clone(),
                addresses: v.addresses.iter().map(ToString::to_string).collect(),
                key_expiry: v
                    .key_expiry
                    .map(|t| timestamp(t.timestamp(), t.timestamp_subsec_nanos()))
                    .transpose()?,
                error_code: v.error_code.clone(),
                key_expiry_known: v.key_expiry_known,
            })
        })
        .transpose()?;
    let historical = value
        .historical
        .as_ref()
        .map(|v| -> Result<_, ConversionError> {
            Ok(w::NodeObservation {
                machine_id: v.machine_id.clone(),
                observed_at: Some(timestamp(
                    v.observed_at.timestamp(),
                    v.observed_at.timestamp_subsec_nanos(),
                )?),
                node_id: v.node_id.clone(),
                dns_name: v.dns_name.clone(),
                tags: v.tags.clone(),
                // The netd historical schema has no addresses: do not copy a previous run's live fields.
                addresses: Vec::new(),
                key_expiry: v
                    .key_expiry
                    .map(|t| timestamp(t.timestamp(), t.timestamp_subsec_nanos()))
                    .transpose()?,
                owner: v.owner.clone(),
                tailnet: v.tailnet.clone(),
            })
        })
        .transpose()?;
    Ok(w::NetworkObservation {
        live,
        historical,
        issues: value
            .issues
            .iter()
            .map(|issue| match issue {
                I::Missing => w::NetworkObservationIssue::Missing,
                I::Unsafe => w::NetworkObservationIssue::Unsafe,
                I::Invalid => w::NetworkObservationIssue::Invalid,
                I::Stale => w::NetworkObservationIssue::Stale,
                I::WrongGeneration => w::NetworkObservationIssue::WrongGeneration,
                I::Unavailable => w::NetworkObservationIssue::Unavailable,
            } as i32)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use crate::node_status::observation_to_wire;
    use silod_spec::daemon::v1 as w;
    #[test]
    fn observation_to_wire_preserves_absence_and_issues() {
        let value = libvm::MachineNetworkObservation {
            live: None,
            historical: None,
            issues: vec![
                libvm::MachineNetworkObservationIssue::WrongGeneration,
                libvm::MachineNetworkObservationIssue::Unsafe,
            ],
        };
        let wire = observation_to_wire(&value).unwrap();
        assert!(wire.live.is_none());
        assert!(wire.historical.is_none());
        assert_eq!(
            wire.issues,
            vec![
                w::NetworkObservationIssue::WrongGeneration as i32,
                w::NetworkObservationIssue::Unsafe as i32
            ]
        );
    }
}

#[cfg(test)]
mod value_tests {
    use crate::node_status::observation_to_wire;
    use silod_spec::daemon::v1 as w;
    #[test]
    fn observation_to_wire_preserves_live_and_historical_metadata() {
        let observed_at = "2026-10-07T12:00:00.123456789Z".parse().unwrap();
        let key_expiry = Some("2026-11-07T12:00:00Z".parse().unwrap());
        for (state, wire_state) in [
            (
                libvm::MachineNodeState::Connecting,
                w::NodeState::Connecting,
            ),
            (
                libvm::MachineNodeState::ApprovalRequired,
                w::NodeState::ApprovalRequired,
            ),
            (libvm::MachineNodeState::Ready, w::NodeState::Ready),
            (
                libvm::MachineNodeState::Disconnected,
                w::NodeState::Disconnected,
            ),
            (libvm::MachineNodeState::Failed, w::NodeState::Failed),
            (libvm::MachineNodeState::Stopped, w::NodeState::Stopped),
        ] {
            let value = libvm::MachineNetworkObservation {
                live: Some(libvm::MachineNodeStatus {
                    version: 1,
                    machine_id: "machine".into(),
                    run_id: "run".into(),
                    observed_at,
                    state,
                    approval_url: Some("https://login.example/approve".into()),
                    node_id: Some("node".into()),
                    dns_name: Some("dns".into()),
                    error_code: Some("safe_code".into()),
                    tags: vec!["tag:silo".into()],
                    addresses: vec!["100.64.0.1".parse().unwrap()],
                    key_expiry,
                    key_expiry_known: true,
                }),
                historical: Some(libvm::MachineNodeObservation {
                    machine_id: "machine".into(),
                    observed_at,
                    owner: "owner".into(),
                    tailnet: "tailnet".into(),
                    node_id: "old-node".into(),
                    dns_name: "old-dns".into(),
                    tags: vec!["tag:old".into()],
                    key_expiry,
                }),
                issues: Vec::new(),
            };
            let wire = observation_to_wire(&value).unwrap();
            let live = wire.live.unwrap();
            assert_eq!(live.state, wire_state as i32);
            assert_eq!(live.updated_at.unwrap().nanos, 123456789);
            assert_eq!(live.run_id, "run");
            assert_eq!(live.addresses, vec!["100.64.0.1"]);
            assert!(live.key_expiry_known);
            assert!(live.key_expiry.is_some());
            assert_eq!(live.error_code.as_deref(), Some("safe_code"));
            let historical = wire.historical.unwrap();
            assert_eq!(historical.machine_id, "machine");
            assert_eq!(historical.owner, "owner");
            assert_eq!(historical.tailnet, "tailnet");
            assert_eq!(historical.node_id, "old-node");
            assert!(historical.addresses.is_empty());
        }
    }
}
