//! The contract between the `silo` controller and the `silod` daemon.
//!
//! ```text
//!  silo ── --system-* argv (arguments) ──────────────► silod
//!  silo ◄─ status.json, daemon.log (paths, status) ─── silod
//!  both ── io.silo.system.* machine labels (labels) ── libvm
//! ```
//!
//! Only data and its encoding live here. Neither side's behavior does: silod owns
//! resolution, provisioning, and upgrades; silo owns service registration.
pub mod arguments;
pub mod labels;
pub mod paths;
pub mod process;
pub mod status;

/// Typed local management API. Guest execution remains a native session API.
pub mod daemon {
    pub mod v1 {
        tonic::include_proto!("silo.daemon.v1");
    }
}

impl std::fmt::Debug for daemon::v1::EgressSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressSecret")
            .field("slot", &self.slot)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for daemon::v1::SetMachineSecretRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetMachineSecretRequest")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::daemon::v1::{
        machine_status, LifecycleDetail, MachineStatus, ReadinessReason, VmState,
    };
    use prost::Message;

    #[test]
    fn hibernation_states_append_wire_values_and_roundtrip() {
        for (state, value, reason, reason_value, status) in [
            (
                VmState::Hibernating,
                13,
                ReadinessReason::VmHibernating,
                18,
                machine_status::Status::Hibernating(LifecycleDetail {
                    message: Some("saving".into()),
                }),
            ),
            (
                VmState::Hibernated,
                14,
                ReadinessReason::VmHibernated,
                19,
                machine_status::Status::Hibernated(LifecycleDetail {
                    message: Some("saved".into()),
                }),
            ),
        ] {
            assert_eq!(state as i32, value);
            assert_eq!(VmState::try_from(value).unwrap(), state);
            assert_eq!(reason as i32, reason_value);
            assert_eq!(ReadinessReason::try_from(reason_value).unwrap(), reason);
            let message = MachineStatus {
                status: Some(status),
            };
            assert_eq!(
                MachineStatus::decode(message.encode_to_vec().as_slice()).unwrap(),
                message
            );
        }
        assert_eq!(VmState::Error as i32, 12);
        assert_eq!(ReadinessReason::VmError as i32, 17);
    }
    #[test]
    fn hibernate_request_and_additive_stop_warning_roundtrip() {
        use crate::daemon::v1 as w;
        let request = w::LiveMachineRequest {
            machine: Some(w::MachineRef {
                reference: Some(w::machine_ref::Reference::Name("saved".into())),
            }),
        };
        assert_eq!(
            w::LiveMachineRequest::decode(request.encode_to_vec().as_slice()).unwrap(),
            request
        );
        for warning in [
            w::machine_stop_warning::Warning::SavedStateUnusable(
                w::HibernateUnusableReason::FilesMissing as i32,
            ),
            w::machine_stop_warning::Warning::WakeFailed(()),
        ] {
            let response = w::MachineSnapshot {
                stop_warning: Some(w::MachineStopWarning {
                    warning: Some(warning),
                }),
                ..Default::default()
            };
            assert_eq!(
                w::MachineSnapshot::decode(response.encode_to_vec().as_slice()).unwrap(),
                response
            );
        }
        let old = w::MachineSnapshot::decode(&[][..]).unwrap();
        assert!(old.stop_warning.is_none());
        assert!(old.hibernation.is_none());
    }
}
