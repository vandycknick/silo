//! Backend-neutral snapshots of native host memory reclamation.

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HostMemoryReclaimBacking {
    #[serde(rename = "boot")]
    Boot,
    #[serde(rename = "restored-private")]
    RestoredPrivate,
}

impl HostMemoryReclaimBacking {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::RestoredPrivate => "restored-private",
        }
    }
}

/// Structural inhibition, independent of ordinary policy or qualification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HostMemoryReclaimReason {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "tracked-capture")]
    TrackedCapture,
    #[serde(rename = "restored-private-mapping")]
    RestoredPrivateMapping,
}

impl HostMemoryReclaimReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TrackedCapture => "tracked-capture",
            Self::RestoredPrivateMapping => "restored-private-mapping",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMemoryReclaimQualification {
    NotRun,
    Passed,
    Failed,
    Inconclusive,
}

impl HostMemoryReclaimQualification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not-run",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// Process-local lifetime operations, not resident or compressed memory savings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostMemoryReclaimStatus {
    pub backing: HostMemoryReclaimBacking,
    pub reason: HostMemoryReclaimReason,
    pub requested: bool,
    /// Host-specific qualification; Linux advice does not require a probe.
    pub qualification: HostMemoryReclaimQualification,
    pub effective: bool,
    /// Successfully advised bytes/ranges, including repeats, not physical savings.
    pub released_bytes: u64,
    pub released_extents: u64,
    pub retried_faults: u64,
    /// Skipped operations, not a universal count of queue heads or pages.
    pub skipped_reports: u64,
    pub failed_operations: u64,
}
