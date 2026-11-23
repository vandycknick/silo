//! Strict activation purpose and pre-execution consume wire contracts.
use crate::v1 as wire;
use vm_spec::hibernate::{ConsumeAuthorization, RestorePrepared};
use vm_spec::lifecycle::LiveId;
use vm_spec::restore::{ActivationPurpose, RestoreRequest};

impl From<ActivationPurpose> for wire::ActivationPurpose {
    fn from(value: ActivationPurpose) -> Self {
        match value {
            ActivationPurpose::Clone => Self::Clone,
            ActivationPurpose::SameMachine => Self::SameMachine,
        }
    }
}

impl TryFrom<wire::ActivationPurpose> for ActivationPurpose {
    type Error = String;
    fn try_from(value: wire::ActivationPurpose) -> Result<Self, Self::Error> {
        match value {
            wire::ActivationPurpose::Clone => Ok(Self::Clone),
            wire::ActivationPurpose::SameMachine => Ok(Self::SameMachine),
            wire::ActivationPurpose::Unspecified => Err("activation purpose is required".into()),
        }
    }
}

pub fn activation_purpose_from_wire(value: Option<i32>) -> Result<ActivationPurpose, String> {
    let value = value.ok_or_else(|| "activation purpose is required".to_string())?;
    wire::ActivationPurpose::try_from(value)
        .map_err(|_| "unknown activation purpose".to_string())?
        .try_into()
}

/// Checks identity policy only, not guest activation behavior or other fields.
pub fn validate_activate_request(
    request: &wire::ActivateRequest,
) -> Result<ActivationPurpose, String> {
    let purpose = activation_purpose_from_wire(request.purpose)?;
    let source = request
        .expected
        .as_ref()
        .ok_or_else(|| "activation source identity is required".to_string())?;
    purpose.validate(
        &LiveId::parse(&source.machine_id)?,
        &LiveId::parse(&source.run_id)?,
        &LiveId::parse(&request.destination_machine_id)?,
        &LiveId::parse(&request.destination_run_id)?,
    )?;
    if purpose == ActivationPurpose::SameMachine && request.hook.is_some() {
        return Err("same-machine activation must not run a restore hook".into());
    }
    Ok(purpose)
}

impl TryFrom<RestoreRequest> for wire::RestoreRequest {
    type Error = String;
    fn try_from(value: RestoreRequest) -> Result<Self, Self::Error> {
        value.validate_for_inspection()?;
        Ok(Self {
            purpose: Some(wire::ActivationPurpose::from(value.purpose) as i32),
            request: Some(serde_json::to_vec(&value).map_err(|error| error.to_string())?),
        })
    }
}

impl TryFrom<wire::RestoreRequest> for RestoreRequest {
    type Error = String;
    fn try_from(value: wire::RestoreRequest) -> Result<Self, Self::Error> {
        let purpose = activation_purpose_from_wire(value.purpose)?;
        let bytes = value
            .request
            .ok_or_else(|| "restore request is required".to_string())?;
        if bytes.len() > vm_spec::restore::MAX_RESTORE_INSPECTION_BYTES {
            return Err("restore request exceeds the size limit".into());
        }
        let request: Self = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if purpose != request.purpose {
            return Err("restore activation purposes do not match".into());
        }
        request.validate_for_inspection()?;
        Ok(request)
    }
}

fn id(value: Option<String>, field: &str) -> Result<LiveId, String> {
    LiveId::try_from(value.ok_or_else(|| format!("missing {field}"))?)
}

impl From<RestorePrepared> for wire::RestorePrepared {
    fn from(value: RestorePrepared) -> Self {
        Self {
            machine_id: Some(value.machine_id.to_string()),
            save_id: Some(value.save_id.to_string()),
            new_run_id: Some(value.new_run_id.to_string()),
        }
    }
}
impl TryFrom<wire::RestorePrepared> for RestorePrepared {
    type Error = String;
    fn try_from(value: wire::RestorePrepared) -> Result<Self, Self::Error> {
        Ok(Self {
            machine_id: id(value.machine_id, "machine_id")?,
            save_id: id(value.save_id, "save_id")?,
            new_run_id: id(value.new_run_id, "new_run_id")?,
        })
    }
}
impl From<ConsumeAuthorization> for wire::ConsumeAuthorization {
    fn from(value: ConsumeAuthorization) -> Self {
        Self {
            machine_id: Some(value.machine_id.to_string()),
            save_id: Some(value.save_id.to_string()),
            new_run_id: Some(value.new_run_id.to_string()),
        }
    }
}
impl TryFrom<wire::ConsumeAuthorization> for ConsumeAuthorization {
    type Error = String;
    fn try_from(value: wire::ConsumeAuthorization) -> Result<Self, Self::Error> {
        Ok(Self {
            machine_id: id(value.machine_id, "machine_id")?,
            save_id: id(value.save_id, "save_id")?,
            new_run_id: id(value.new_run_id, "new_run_id")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::restore::{activation_purpose_from_wire, validate_activate_request};
    use crate::v1 as wire;
    use prost::Message;
    use vm_spec::hibernate::{ConsumeAuthorization, RestorePrepared};
    use vm_spec::lifecycle::LiveId;
    use vm_spec::restore::ActivationPurpose;

    fn id(value: u8) -> LiveId {
        LiveId::parse(&format!("00000000-0000-4000-8000-{value:012x}")).unwrap()
    }

    #[test]
    fn activation_purpose_rejects_missing_unspecified_unknown_and_wrong_identity() {
        for value in [None, Some(0), Some(-1), Some(3), Some(i32::MAX)] {
            assert!(activation_purpose_from_wire(value).is_err());
        }
        for purpose in [ActivationPurpose::Clone, ActivationPurpose::SameMachine] {
            assert_eq!(
                activation_purpose_from_wire(Some(wire::ActivationPurpose::from(purpose) as i32))
                    .unwrap(),
                purpose
            );
        }
        let request = wire::ActivateRequest {
            purpose: Some(wire::ActivationPurpose::SameMachine as i32),
            expected: Some(wire::ExpectedGuestIdentity {
                machine_id: id(1).to_string(),
                run_id: id(2).to_string(),
                ..Default::default()
            }),
            destination_machine_id: id(1).to_string(),
            destination_run_id: id(3).to_string(),
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let decoded = wire::ActivateRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(
            validate_activate_request(&decoded).unwrap(),
            ActivationPurpose::SameMachine
        );
        for mutation in 0..9 {
            let mut bad = request.clone();
            match mutation {
                0 => bad.purpose = None,
                1 => bad.purpose = Some(0),
                2 => bad.purpose = Some(99),
                3 => bad.destination_machine_id = id(4).to_string(),
                4 => bad.destination_run_id = id(2).to_string(),
                5 => bad.expected = None,
                6 => bad.destination_run_id.clear(),
                7 => bad.hook = Some(wire::ActivationHook::default()),
                _ => bad.purpose = Some(wire::ActivationPurpose::Clone as i32),
            }
            assert!(
                validate_activate_request(&bad).is_err(),
                "mutation {mutation}"
            );
        }
        let mut clone = request;
        clone.purpose = Some(wire::ActivationPurpose::Clone as i32);
        clone.destination_machine_id = id(4).to_string();
        assert_eq!(
            validate_activate_request(&clone).unwrap(),
            ActivationPurpose::Clone
        );
        clone.destination_run_id = id(2).to_string();
        assert!(validate_activate_request(&clone).is_err());
    }

    #[test]
    fn consume_handshake_roundtrips_and_rejects_missing_or_mismatched_authority() {
        let prepared = RestorePrepared {
            machine_id: id(1),
            save_id: id(2),
            new_run_id: id(3),
        };
        let authorization = ConsumeAuthorization {
            machine_id: id(1),
            save_id: id(2),
            new_run_id: id(3),
        };
        let bytes = wire::RestorePrepared::from(prepared.clone()).encode_to_vec();
        let wire = wire::RestorePrepared::decode(bytes.as_slice()).unwrap();
        assert_eq!(RestorePrepared::try_from(wire.clone()).unwrap(), prepared);
        let bytes = wire::ConsumeAuthorization::from(authorization.clone()).encode_to_vec();
        let consume = wire::ConsumeAuthorization::decode(bytes.as_slice()).unwrap();
        assert_eq!(
            ConsumeAuthorization::try_from(consume.clone()).unwrap(),
            authorization
        );
        prepared.validate_authorization(&authorization).unwrap();
        for mutation in 0..3 {
            let mut bad = authorization.clone();
            let mut missing = consume.clone();
            let mut missing_prepared = wire.clone();
            match mutation {
                0 => {
                    bad.machine_id = id(9);
                    missing.machine_id = None;
                    missing_prepared.machine_id = None;
                }
                1 => {
                    bad.save_id = id(9);
                    missing.save_id = None;
                    missing_prepared.save_id = None;
                }
                _ => {
                    bad.new_run_id = id(9);
                    missing.new_run_id = None;
                    missing_prepared.new_run_id = None;
                }
            }
            assert!(prepared.validate_authorization(&bad).is_err());
            assert!(ConsumeAuthorization::try_from(missing).is_err());
            assert!(RestorePrepared::try_from(missing_prepared).is_err());
        }
        assert!(RestorePrepared::try_from(wire::RestorePrepared::default()).is_err());
        assert!(ConsumeAuthorization::try_from(wire::ConsumeAuthorization::default()).is_err());
    }
}
