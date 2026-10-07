use crate::errors::{native_error_to_status, status_to_native_error};
use crate::snapshots::{snapshot_from_wire, snapshot_to_wire};
use crate::*;
use silod_spec::daemon::v1 as w;
use std::collections::BTreeMap;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[test]
fn updates_distinguish_absent_empty_and_clear() {
    let absent = updates::update_from_wire(w::MachineUpdate::default()).unwrap();
    assert!(absent.is_empty());
    let update = updates::update_from_wire(w::MachineUpdate {
        labels: Some(w::StringMap {
            values: BTreeMap::new(),
        }),
        forwards: Some(w::ForwardList { values: vec![] }),
        policy: Some(w::PolicyUpdate {
            update: Some(w::policy_update::Update::Clear(())),
        }),
        publication: Some(w::PublicationUpdate {
            update: Some(w::publication_update::Update::Clear(())),
        }),
        user: Some(w::UserUpdate {
            update: Some(w::user_update::Update::Clear(())),
        }),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(update.labels, Some(BTreeMap::new()));
    assert_eq!(update.forwards, Some(vec![]));
    assert!(matches!(
        update.network_policy,
        Some(libvm::NetworkPolicyUpdate::Clear)
    ));
    assert!(matches!(
        update.guest_publish,
        Some(libvm::GuestPublishUpdate::Clear)
    ));
    assert!(matches!(update.user, Some(libvm::MachineUserUpdate::Clear)));
    assert!(!update.is_empty());
    assert!(updates::update_from_wire(w::MachineUpdate {
        policy: Some(w::PolicyUpdate::default()),
        ..Default::default()
    })
    .is_err());
}
#[test]
fn non_utf8_host_paths_and_exact_argv_are_preserved() {
    let bytes = b"/tmp/host-\xff".to_vec();
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes.clone()));
    let mount = values::mount_from_wire(w::Mount {
        source: bytes.clone(),
        tag: "guest".into(),
        read_only: true,
    })
    .unwrap();
    assert_eq!(mount.source.as_os_str().as_bytes(), bytes);
    assert!(mount.read_only);
    let agent = values::agent_from_wire(w::Agent {
        mode: Some(w::agent::Mode::CustomPath(path_to_wire(&path))),
    })
    .unwrap();
    assert!(matches!(agent,libvm::MachineAgent::Custom{path:p} if p==path));
    let entry = lifecycle::entrypoint_from_wire(w::Entrypoint {
        program: "/bin/program".into(),
        args: vec!["".into(), "a b".into(), "$literal;not-shell".into()],
        cwd: Some("/workspace".into()),
        environment: vec![
            w::EnvironmentPair {
                name: "K".into(),
                value: "first".into(),
            },
            w::EnvironmentPair {
                name: "K".into(),
                value: "second".into(),
            },
        ],
        user: Some("123:456".into()),
    })
    .unwrap();
    assert_eq!(entry.arguments(), ["", "a b", "$literal;not-shell"]);
    assert_eq!(entry.environment().len(), 2);
    assert_eq!(entry.user_selector(), Some("123:456"));
    assert_eq!(entry.working_directory(), Some("/workspace"));
    assert!(path_from_wire(b"/tmp/\0bad".to_vec()).is_err());
}
#[test]
fn invalid_required_values_fail_without_echoing_inputs() {
    assert!(values::retention_from_wire(0).is_err());
    assert!(values::retention_from_wire(99).is_err());
    assert!(values::agent_from_wire(w::Agent::default()).is_err());
    assert!(values::network_from_wire(w::ResolvedNetwork::default()).is_err());
    assert!(updates::cpu_from_wire(256).is_err());
    assert!(updates::memory_from_wire(u64::MAX).is_err());
    assert!(updates::memory_from_wire(0).is_err());
    assert!(validate_uuid("secret-invalid-id", "id")
        .unwrap_err()
        .to_string()
        .find("secret-invalid-id")
        .is_none());
    assert!(duration_from_wire(prost_types::Duration {
        seconds: 1,
        nanos: -1
    })
    .is_err());
    let err = lifecycle::start_options_from_wire(w::StartOptions {
        egress_secrets: vec![w::EgressSecret {
            slot: "slot".into(),
            value: vec![b'S'; 16 * 1024 + 1],
        }],
        ..Default::default()
    })
    .err()
    .unwrap();
    assert!(!err.to_string().contains("SSSS"));
}
fn snapshot() -> libvm::MachineData {
    let spec = spec::spec_from_wire(w::VmSpec {
        spec_version: "1.0.0".into(),
        ..Default::default()
    })
    .unwrap();
    let mut data = libvm::MachineData::new(
        "12345678-1234-4234-8234-123456789abc".into(),
        "test".into(),
        spec,
    );
    data.process.entrypoint = Some(vec![]);
    data.process.command = Some(vec!["one".into(), "two words".into()]);
    data.retention = libvm::MachineRetention::Ephemeral;
    data.labels.insert("owner".into(), "alice".into());
    data.observation = libvm::MachineObservation::LastKnown;
    data.machine_dir =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/machine-\xff".to_vec()));
    data
}

#[test]
fn start_acknowledgement_is_independent_of_later_observation() {
    let acknowledged: libvm::MachineRunId = "12345678-1234-4234-8234-123456789abc".parse().unwrap();
    let replacement: libvm::MachineRunId = "22345678-1234-4234-8234-123456789abc".parse().unwrap();
    for observed_run in [None, Some(replacement)] {
        let mut data = snapshot();
        data.run_id = observed_run.clone();
        let start = libvm::MachineStart::new(data, acknowledged.clone());
        let decoded =
            lifecycle::start_from_wire(lifecycle::start_to_wire(&start).unwrap()).unwrap();
        assert_eq!(decoded.run_id, acknowledged);
        assert_eq!(decoded.machine.run_id, observed_run);
    }
}

#[test]
fn deferred_network_failure_cannot_become_a_valid_partial_update() {
    let update = libvm::MachineUpdate::new()
        .name("renamed")
        .network(|network| network.named("bad/name"));
    let error = updates::update_to_wire(&update).unwrap_err();
    assert_eq!(error.field, "update.network");
    assert!(!error.to_string().contains("bad/name"));
}
#[test]
fn inventory_retains_unreadable_identity_and_all_lifecycle_states() {
    let id = "12345678-1234-4234-8234-123456789abc";
    let unreadable = snapshots::inventory_from_wire(w::MachineInventoryEntry {
        id: id.into(),
        name: "broken".into(),
        data: None,
        issues: vec![w::MachineIssue {
            component: 5,
            message: "configuration unavailable".into(),
        }],
    })
    .unwrap();
    assert!(unreadable.data.is_none());
    assert_eq!(
        unreadable.issues[0].component,
        libvm::MachineIssueComponent::Configuration
    );
    for status in [
        libvm::MachineStatus::Stopped,
        libvm::MachineStatus::Starting {
            message: Some("starting".into()),
        },
        libvm::MachineStatus::Running {
            ready: false,
            guest_ready: true,
            message: None,
        },
        libvm::MachineStatus::Stopping { message: None },
        libvm::MachineStatus::Error {
            message: Some("failed".into()),
        },
    ] {
        let mut native = snapshot();
        native.status = status.clone();
        let decoded = snapshot_from_wire(snapshot_to_wire(&native).unwrap()).unwrap();
        assert_eq!(decoded.status, status);
        assert_eq!(decoded.process.entrypoint, Some(vec![]));
        assert_eq!(
            decoded.process.command,
            Some(vec!["one".into(), "two words".into()])
        );
        assert_eq!(decoded.machine_dir, native.machine_dir);
        assert_eq!(decoded.retention, libvm::MachineRetention::Ephemeral);
        assert_eq!(decoded.labels["owner"], "alice");
        assert_eq!(decoded.observation, libvm::MachineObservation::LastKnown);
    }
}
#[test]
fn typed_errors_preserve_generation_and_guest_exit_classification() {
    let requested = "12345678-1234-4234-8234-123456789abc".parse().unwrap();
    let original = libvm::LibVmError::MachineStaleGeneration {
        reference: "vm".into(),
        requested,
        current: None,
    };
    let received = status_to_native_error(&native_error_to_status(&original)).unwrap();
    assert!(matches!(
        received,
        libvm::LibVmError::MachineStaleGeneration { current: None, .. }
    ));
    for reason in [
        libvm::ExecutionLaunchFailureReason::CommandNotFound,
        libvm::ExecutionLaunchFailureReason::PermissionDenied,
        libvm::ExecutionLaunchFailureReason::SpawnFailed,
    ] {
        let error = libvm::LibVmError::EntrypointLaunchFailed {
            failure: libvm::ExecutionLaunchFailure {
                reason,
                message: Some("SECRET-DIAGNOSTIC".into()),
            },
        };
        let status = native_error_to_status(&error);
        assert!(!status.message().contains("SECRET-DIAGNOSTIC"));
        assert!(!String::from_utf8_lossy(status.details()).contains("SECRET-DIAGNOSTIC"));
        assert!(
            matches!(status_to_native_error(&status).unwrap(),libvm::LibVmError::EntrypointLaunchFailed{failure} if failure.reason==reason)
        );
    }
}
#[test]
fn image_progress_preserves_layer_accounting_and_absence() {
    let events = [
        libvm::ImageProgress::ResolvedManifest {
            image_ref: "image".into(),
            manifest_digest: "sha256:abc".into(),
            layer_count: 3,
            total_download_bytes: None,
        },
        libvm::ImageProgress::LayerDownloadProgress {
            index: 2,
            total: 3,
            digest: "sha256:def".into(),
            downloaded_bytes: 123,
            size_bytes: Some(456),
        },
        libvm::ImageProgress::ApplyingLayer {
            index: 3,
            total: 3,
            digest: None,
        },
        libvm::ImageProgress::Complete,
    ];
    for event in events {
        assert_eq!(
            images::progress_from_wire(images::progress_to_wire(&event).unwrap()).unwrap(),
            event
        );
    }
    assert!(images::progress_from_wire(w::ImageProgress::default()).is_err());
}
#[test]
fn canonical_policy_retains_explicit_deny_and_secret_metadata() {
    let doc = policy::normalize_policy(w::NormalizePolicyRequest {
        input: Some(w::normalize_policy_request::Input::Hcl(
            r#"
settings { default_action = "deny" }
endpoint "https" "api" { hosts = ["example.com"] }
credential "bearer_token" "key" { endpoint = https.api }
rule "deny-api" {
  endpoints = [https.api]
  verdict = "deny"
}
"#
            .into(),
        )),
    })
    .unwrap();
    let native = values::policy_from_wire(&doc.canonical_json).unwrap();
    assert!(!native.secret_slots().is_empty());
    assert_eq!(doc.secret_slots.len(), native.secret_slots().len());
    let canonical: serde_json::Value = serde_json::from_str(&doc.canonical_json).unwrap();
    assert_eq!(canonical["settings"]["default_action"], "deny");
    assert_eq!(canonical["rules"][0]["verdict"], "deny");
    assert!(!doc.secret_requirements.is_empty());
    let rendered = libvm::NetworkPolicy::from_hcl_str(&doc.hcl).unwrap();
    assert_eq!(rendered.settings(), native.settings());
    assert_eq!(rendered.rules(), native.rules());
    assert_eq!(
        rendered
            .secret_slots()
            .iter()
            .map(policy::slot_to_wire)
            .collect::<Vec<_>>(),
        native
            .secret_slots()
            .iter()
            .map(policy::slot_to_wire)
            .collect::<Vec<_>>(),
    );
    for slot in doc.secret_slots {
        let decoded = policy::slot_from_wire(slot).unwrap();
        assert!(!decoded.source.key.as_str().is_empty());
    }
}

#[test]
fn readiness_preserves_each_outcome_and_reason() {
    let now = std::time::UNIX_EPOCH + std::time::Duration::new(123, 456_789_123);
    let reasons = [
        libvm::MachineReadinessReason::VmStarting,
        libvm::MachineReadinessReason::VmStopping,
        libvm::MachineReadinessReason::VmStopped,
        libvm::MachineReadinessReason::VmFailed,
        libvm::MachineReadinessReason::AgentNotRequired,
        libvm::MachineReadinessReason::AgentUnavailable,
        libvm::MachineReadinessReason::AgentStatusStale,
        libvm::MachineReadinessReason::GuestStarting,
        libvm::MachineReadinessReason::GuestFailed,
        libvm::MachineReadinessReason::GuestReportedReady,
    ];
    for outcome in [
        libvm::MachineReadinessOutcome::Ready,
        libvm::MachineReadinessOutcome::Terminal,
        libvm::MachineReadinessOutcome::TimedOut,
    ] {
        for reason in reasons {
            let native = libvm::MachineReadiness {
                outcome,
                status: libvm::MachineMonitorStatus {
                    machine_id: "12345678-1234-4234-8234-123456789abc".into(),
                    run_id: None,
                    name: "test".into(),
                    monitor: libvm::MachineMonitorSnapshot {
                        instance_id: "monitor".into(),
                        observed_at: now,
                    },
                    vm: libvm::MachineVmSnapshot {
                        state: libvm::MachineVmState::Running,
                        state_changed_at: now,
                        running_since: Some(now),
                        code: Some("status".into()),
                        message: None,
                    },
                    readiness: libvm::MachineReadinessState {
                        ready: outcome == libvm::MachineReadinessOutcome::Ready,
                        reason,
                    },
                    agent: libvm::MachineAgentStatus::Disabled,
                },
            };
            let decoded =
                readiness::readiness_from_wire(readiness::readiness_to_wire(&native).unwrap())
                    .unwrap();
            assert_eq!(decoded, native);
            assert_eq!(decoded.status.monitor.observed_at, now);
            assert_eq!(decoded.status.readiness.reason, reason);
        }
    }
    assert!(readiness::readiness_from_wire(w::MachineReadiness {
        outcome: 99,
        ..Default::default()
    })
    .is_err());
}

#[test]
fn immutable_image_verification_ignores_cache_warming_but_not_identity() {
    let identity = w::OciIdentity {
        requested_reference: "registry/repo:latest".into(),
        selected_reference: "registry/repo@sha256:manifest".into(),
        platform: "linux/arm64/v8".into(),
        manifest_digest: "sha256:manifest".into(),
        config_digest: "sha256:config".into(),
        pull_policy: 3,
    };
    let selection = images::identity_from_wire(identity.clone()).unwrap();
    assert_eq!(selection.pull_policy, libvm::ImagePullPolicy::Never);
    assert_eq!(selection.platform.variant.as_deref(), Some("v8"));
    let metadata = libvm::OciImageConfigMetadata::default();
    for cache_state in [1, 2] {
        let image = images::resolved_image_from_wire(w::ResolvedImage {
            identity: Some(identity.clone()),
            cache_state,
            oci_config_json: serde_json::to_string(&metadata).unwrap(),
        })
        .unwrap();
        assert_eq!(
            image.identity.selected_reference,
            selection.selected_reference
        );
    }
    let mut mutable = identity;
    mutable.selected_reference = "registry/repo:latest".into();
    assert!(images::identity_from_wire(mutable).is_err());
    assert_eq!(
        requests::parse_resource(w::ParseResourceRequest {
            kind: 1,
            value: "4GiB".into()
        })
        .unwrap()
        .bytes,
        4 << 30
    );
    assert!(requests::parse_resource(w::ParseResourceRequest {
        kind: 0,
        value: "4GiB".into()
    })
    .is_err());
}

#[test]
fn bootstrap_and_secret_debug_never_include_values() {
    let bootstrap = w::HelperBootstrap {
        client_secret: Some(b"never-show-this".to_vec()),
        oauth_app_secret: Some(b"never-show-this".to_vec()),
        api_token: Some(b"never-show-this".to_vec()),
        ..Default::default()
    };
    assert!(!format!("{bootstrap:?}").contains("never-show-this"));
    assert!(format!("{bootstrap:?}").contains("<redacted>"));
    assert!(!format!("{bootstrap:?}").contains(&format!("{:?}", b"never-show-this".to_vec())));
    let request = w::SetMachineSecretRequest {
        id: "12345678-1234-4234-8234-123456789abc".into(),
        name: "tailscale.vm.auth_key".into(),
        value: b"never-show-this".to_vec(),
    };
    requests::validate_machine_secret(&request).unwrap();
    assert!(!format!("{request:?}").contains("never-show-this"));
    assert!(format!("{request:?}").contains("<redacted>"));
    assert!(!format!("{request:?}").contains(&format!("{:?}", request.value)));
    assert!(!format!(
        "{:?}",
        w::EgressSecret {
            slot: "slot".into(),
            value: b"never-show-this".to_vec()
        }
    )
    .contains("never-show-this"));
}

#[test]
fn exit_outcomes_keep_optional_run_and_timestamp() {
    let at = std::time::UNIX_EPOCH - std::time::Duration::new(1, 123);
    for outcome in [
        libvm::MachineExitOutcome::Clean,
        libvm::MachineExitOutcome::Error {
            message: Some("worker failed".into()),
        },
        libvm::MachineExitOutcome::AlreadyStopped,
        libvm::MachineExitOutcome::Forced,
        libvm::MachineExitOutcome::Unknown,
    ] {
        let native = libvm::MachineExit::new(snapshot(), None, Some(at), outcome.clone());
        let decoded = lifecycle::exit_from_wire(lifecycle::exit_to_wire(&native).unwrap()).unwrap();
        assert_eq!(decoded.outcome, outcome);
        assert_eq!(decoded.run_id, None);
        assert_eq!(decoded.exited_at, Some(at));
    }
}

#[test]
fn references_use_native_id_name_and_prefix_semantics() {
    for (text, kind) in [
        ("ab", 2),
        ("a1b2c3", 3),
        ("12345678-1234-4234-8234-123456789abc", 1),
        ("Legacy_name", 2),
    ] {
        let native = libvm::MachineRef::parse(text).unwrap();
        let wire = lifecycle::reference_to_wire(&native).unwrap();
        assert!(matches!(
            (&wire.reference, kind),
            (Some(w::machine_ref::Reference::Id(_)), 1)
                | (Some(w::machine_ref::Reference::Name(_)), 2)
                | (Some(w::machine_ref::Reference::IdPrefix(_)), 3)
        ));
        assert_eq!(lifecycle::reference_from_wire(wire).unwrap(), native);
    }
    assert!(lifecycle::reference_from_wire(w::MachineRef {
        reference: Some(w::machine_ref::Reference::Name("a1b2c3".into()))
    })
    .is_err());
    assert!(lifecycle::reference_from_wire(w::MachineRef {
        reference: Some(w::machine_ref::Reference::IdPrefix("ab".into()))
    })
    .is_err());
}

#[test]
fn conflicting_rich_status_code_does_not_reconstruct_a_native_error() {
    let native = libvm::LibVmError::MachineNotFound {
        reference: "missing".into(),
    };
    let status = native_error_to_status(&native);
    let contradictory = tonic::Status::with_details(
        tonic::Code::AlreadyExists,
        status.message(),
        status.details().to_vec().into(),
    );
    assert!(status_to_native_error(&contradictory).is_err());
}
