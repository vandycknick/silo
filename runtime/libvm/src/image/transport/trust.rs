//! Local digest approval. Integrity of a VM artifact is established by its
//! exact index digest; publisher authentication is a separate property that
//! v1 never claims. A resolved tag is never an approval by itself.
use serde::{Deserialize, Serialize};

use crate::image::transport::blobs::invalid;
use crate::image::transport::ArtifactTrust;
use crate::storage::identity::ObjectDigest;
use crate::LibVmError;

/// Stable identity of the only admitted v1 trust policy.
pub(crate) const DIGEST_APPROVAL_POLICY: &str = "explicit-digest-approval-v1";

/// Local authorization to import exactly one immutable index from exactly one
/// repository. Only [`approve`] constructs it, and only after policy approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovedArtifactDigest {
    repository: String,
    index_digest: ObjectDigest,
    policy_id: &'static str,
}

impl ApprovedArtifactDigest {
    pub(crate) fn index_digest(&self) -> ObjectDigest {
        self.index_digest
    }

    /// The persisted local receipt. It never travels with the artifact and
    /// never participates in ImageId/SnapshotId.
    pub(crate) fn receipt(&self, approved_at_unix_ms: u64) -> AcquisitionReceipt {
        AcquisitionReceipt {
            schema: 1,
            kind: AcquisitionReceiptKind::ApprovedDigest,
            repository: self.repository.clone(),
            index_digest: self.index_digest,
            policy_id: self.policy_id.to_owned(),
            approved_at_unix_ms,
        }
    }
}

/// Apply the caller's explicit trust request to the index resolved from
/// `repository`. Must run before any payload is fetched or published.
pub(crate) fn approve(
    repository: &str,
    resolved: ObjectDigest,
    trust: &ArtifactTrust,
) -> Result<ApprovedArtifactDigest, LibVmError> {
    validate_repository(repository)?;
    match trust {
        ArtifactTrust::ApproveDigest { digest } if *digest == resolved => {
            Ok(ApprovedArtifactDigest {
                repository: repository.to_owned(),
                index_digest: resolved,
                policy_id: DIGEST_APPROVAL_POLICY,
            })
        }
        ArtifactTrust::ApproveDigest { digest } => Err(LibVmError::ArtifactTrustMismatch {
            expected: digest.to_string(),
            actual: resolved.to_string(),
        }),
        // No signature verifier is integrated. A stricter policy is never
        // downgraded to digest-only approval.
        ArtifactTrust::RequireSignature => Err(LibVmError::ArtifactSignatureProviderUnavailable),
    }
}

/// Repository identity only: registry host and path, never credentials,
/// tags, digests or URL syntax.
fn validate_repository(repository: &str) -> Result<(), LibVmError> {
    if repository.is_empty()
        || repository.len() > 512
        || repository.contains(['@', '?', '#', ' '])
        || repository.contains("://")
        || !repository.contains('/')
        || !repository.is_ascii()
    {
        return Err(invalid(
            "trust",
            format!("{repository:?} is not a bare repository identity"),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AcquisitionReceiptKind {
    ApprovedDigest,
}

/// Immutable local record of the approval under which an import was admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AcquisitionReceipt {
    pub(crate) schema: u32,
    pub(crate) kind: AcquisitionReceiptKind,
    pub(crate) repository: String,
    pub(crate) index_digest: ObjectDigest,
    pub(crate) policy_id: String,
    pub(crate) approved_at_unix_ms: u64,
}

impl AcquisitionReceipt {
    pub(crate) fn validate(&self) -> Result<(), LibVmError> {
        validate_repository(&self.repository)?;
        if self.schema != 1 || self.policy_id != DIGEST_APPROVAL_POLICY {
            return Err(invalid(
                "receipt",
                "unsupported acquisition receipt schema or policy",
            ));
        }
        Ok(())
    }

    /// Canonical JSON: lexicographic keys, no whitespace.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, LibVmError> {
        self.validate()?;
        Ok(oci::vm_artifact::wire::canonical_bytes(self)?)
    }

    /// Strict closed decoding of exactly canonical bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LibVmError> {
        let receipt: Self = oci::vm_artifact::wire::decode_record(bytes)?;
        if receipt.canonical_bytes()? != bytes {
            return Err(invalid("receipt", "acquisition receipt is not canonical"));
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use crate::image::transport::trust::{approve, AcquisitionReceipt, DIGEST_APPROVAL_POLICY};
    use crate::image::transport::ArtifactTrust;
    use crate::storage::identity::ObjectDigest;
    use crate::LibVmError;

    #[test]
    fn only_the_exact_approved_digest_is_admitted() {
        let resolved = ObjectDigest::of_bytes(b"index");
        let approved = approve(
            "registry.example/team/vm",
            resolved,
            &ArtifactTrust::ApproveDigest { digest: resolved },
        )
        .unwrap();
        assert_eq!(approved.index_digest(), resolved);
        assert_eq!(approved.receipt(0).repository, "registry.example/team/vm");
        let other = ObjectDigest::of_bytes(b"moved tag");
        assert!(matches!(
            approve(
                "registry.example/team/vm",
                other,
                &ArtifactTrust::ApproveDigest { digest: resolved }
            ),
            Err(LibVmError::ArtifactTrustMismatch { .. })
        ));
        assert!(matches!(
            approve(
                "registry.example/team/vm",
                resolved,
                &ArtifactTrust::RequireSignature
            ),
            Err(LibVmError::ArtifactSignatureProviderUnavailable)
        ));
        for repository in [
            "",
            "https://registry.example/team/vm",
            "user:pass@registry.example/vm",
            "registry.example/vm@sha256:00",
            "plain",
        ] {
            assert!(approve(
                repository,
                resolved,
                &ArtifactTrust::ApproveDigest { digest: resolved }
            )
            .is_err());
        }
    }

    #[test]
    fn receipt_is_canonical_closed_and_bound_to_its_index() {
        let resolved = ObjectDigest::of_bytes(b"index");
        let approved = approve(
            "registry.example/team/vm",
            resolved,
            &ArtifactTrust::ApproveDigest { digest: resolved },
        )
        .unwrap();
        let receipt = approved.receipt(1_700_000_000_000);
        let bytes = receipt.canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!(
                "{{\"approvedAtUnixMs\":1700000000000,\"indexDigest\":\"{resolved}\",\"kind\":\"approved-digest\",\"policyId\":\"{DIGEST_APPROVAL_POLICY}\",\"repository\":\"registry.example/team/vm\",\"schema\":1}}"
            )
        );
        assert_eq!(AcquisitionReceipt::decode(&bytes).unwrap(), receipt);
        assert_ne!(
            approved.receipt(1).canonical_bytes().unwrap(),
            receipt.canonical_bytes().unwrap()
        );
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(AcquisitionReceipt::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        let spaced = String::from_utf8(bytes).unwrap().replace(':', ": ");
        assert!(AcquisitionReceipt::decode(spaced.as_bytes()).is_err());
        let mut wrong = receipt.clone();
        wrong.policy_id = "signature".into();
        assert!(wrong.canonical_bytes().is_err());
    }
}
