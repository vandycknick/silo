//! Backend-neutral snapshots of native host memory reclamation.

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

/// Cumulative operations, not measured reductions in resident or compressed memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostMemoryReclaimStatus {
    pub requested: bool,
    pub qualification: HostMemoryReclaimQualification,
    pub effective: bool,
    pub released_bytes: u64,
    pub released_extents: u64,
    pub retried_faults: u64,
    pub skipped_reports: u64,
    pub failed_operations: u64,
}
