//! Local acquisition receipts. A VM artifact's integrity is established by its
//! exact index digest and the verified digest chain below it (index, config,
//! records, chunks). The receipt records which repository and index a record
//! was acquired from; it never travels with the artifact and never
//! participates in ImageId/SnapshotId.
use serde::{Deserialize, Serialize};

use crate::image::transport::blobs::invalid;
use crate::storage::identity::ObjectDigest;
use crate::LibVmError;

/// Stable identity of the only receipt policy.
pub(crate) const RESOLVED_INDEX_POLICY: &str = "resolved-index-v1";

/// One immutable index resolved from exactly one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedIndex {
    repository: String,
    index_digest: ObjectDigest,
}

impl ResolvedIndex {
    pub(crate) fn new(repository: &str, index_digest: ObjectDigest) -> Result<Self, LibVmError> {
        validate_repository(repository)?;
        Ok(Self {
            repository: repository.to_owned(),
            index_digest,
        })
    }

    pub(crate) fn index_digest(&self) -> ObjectDigest {
        self.index_digest
    }

    /// The persisted local receipt.
    pub(crate) fn receipt(&self, acquired_at_unix_ms: u64) -> AcquisitionReceipt {
        AcquisitionReceipt {
            schema: 1,
            kind: AcquisitionReceiptKind::ResolvedIndex,
            repository: self.repository.clone(),
            index_digest: self.index_digest,
            policy_id: RESOLVED_INDEX_POLICY.to_owned(),
            acquired_at_unix_ms,
        }
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
            "receipt",
            format!("{repository:?} is not a bare repository identity"),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AcquisitionReceiptKind {
    ResolvedIndex,
}

/// Immutable local record of the index an import was acquired from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AcquisitionReceipt {
    pub(crate) schema: u32,
    pub(crate) kind: AcquisitionReceiptKind,
    pub(crate) repository: String,
    pub(crate) index_digest: ObjectDigest,
    pub(crate) policy_id: String,
    pub(crate) acquired_at_unix_ms: u64,
}

impl AcquisitionReceipt {
    pub(crate) fn validate(&self) -> Result<(), LibVmError> {
        validate_repository(&self.repository)?;
        if self.schema != 1 || self.policy_id != RESOLVED_INDEX_POLICY {
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
    use crate::image::transport::receipt::{
        AcquisitionReceipt, ResolvedIndex, RESOLVED_INDEX_POLICY,
    };
    use crate::storage::identity::ObjectDigest;

    #[test]
    fn only_bare_repository_identities_are_admitted() {
        let resolved = ObjectDigest::of_bytes(b"index");
        let index = ResolvedIndex::new("registry.example/team/vm", resolved).unwrap();
        assert_eq!(index.index_digest(), resolved);
        assert_eq!(index.receipt(0).repository, "registry.example/team/vm");
        for repository in [
            "",
            "https://registry.example/team/vm",
            "user:pass@registry.example/vm",
            "registry.example/vm@sha256:00",
            "plain",
        ] {
            assert!(ResolvedIndex::new(repository, resolved).is_err());
        }
    }

    #[test]
    fn receipt_is_canonical_closed_and_bound_to_its_index() {
        let resolved = ObjectDigest::of_bytes(b"index");
        let index = ResolvedIndex::new("registry.example/team/vm", resolved).unwrap();
        let receipt = index.receipt(1_700_000_000_000);
        let bytes = receipt.canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!(
                "{{\"acquiredAtUnixMs\":1700000000000,\"indexDigest\":\"{resolved}\",\"kind\":\"resolved-index\",\"policyId\":\"{RESOLVED_INDEX_POLICY}\",\"repository\":\"registry.example/team/vm\",\"schema\":1}}"
            )
        );
        assert_eq!(AcquisitionReceipt::decode(&bytes).unwrap(), receipt);
        assert_ne!(
            index.receipt(1).canonical_bytes().unwrap(),
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
