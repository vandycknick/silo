use std::time::{Duration, Instant};

use crate::store::models::MachineId;

/// Opening costs belong to the runtime, not to guest boot or readiness.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RuntimeOpenTiming {
    pub(crate) discovery: Duration,
    pub(crate) catalog_recovery: Duration,
}

/// One cold-start attempt, emitted once immediately after monitor exec succeeds.
/// Durations use the host monotonic clock; no guest clocks or input paths escape.
pub(crate) struct StartTimeline {
    opened: RuntimeOpenTiming,
    began: Instant,
    pub(crate) lifecycle_admission: Duration,
    pub(crate) lower_resolve_authentication: Duration,
    pub(crate) secrets_netd: Duration,
    pub(crate) launch_publication: Duration,
    pub(crate) durability_barrier: Duration,
    pub(crate) admit_spawn: Duration,
}

impl StartTimeline {
    pub(crate) fn new(opened: RuntimeOpenTiming) -> Self {
        Self {
            opened,
            began: Instant::now(),
            lifecycle_admission: Duration::ZERO,
            lower_resolve_authentication: Duration::ZERO,
            secrets_netd: Duration::ZERO,
            launch_publication: Duration::ZERO,
            durability_barrier: Duration::ZERO,
            admit_spawn: Duration::ZERO,
        }
    }

    pub(crate) fn elapsed(&self) -> Duration {
        self.began.elapsed()
    }

    pub(crate) fn emit(&self, machine_id: MachineId, run_id: &str) {
        let milliseconds = |duration: Duration| duration.as_secs_f64() * 1000.0;
        tracing::info!(
            parent: None,
            machine_id = %uuid::Uuid::from(machine_id),
            run_id,
            runtime_discovery_ms = milliseconds(self.opened.discovery),
            catalog_open_recovery_ms = milliseconds(self.opened.catalog_recovery),
            lifecycle_admission_ms = milliseconds(self.lifecycle_admission),
            lower_resolve_authentication_ms = milliseconds(self.lower_resolve_authentication),
            secrets_netd_ms = milliseconds(self.secrets_netd),
            launch_publication_ms = milliseconds(self.launch_publication),
            durability_barrier_ms = milliseconds(self.durability_barrier),
            admit_spawn_ms = milliseconds(self.admit_spawn),
            total_ms = milliseconds(self.opened.discovery + self.opened.catalog_recovery + self.elapsed()),
            "machine start timeline"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use crate::runtime::start_timeline::{RuntimeOpenTiming, StartTimeline};
    use crate::store::models::MachineId;

    #[test]
    fn emitted_start_timeline_is_one_parseable_structured_line() {
        let captured = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_target(false)
            .with_writer(captured.reopen().unwrap())
            .finish();
        let machine_id = MachineId::new();
        let timeline = StartTimeline::new(RuntimeOpenTiming {
            discovery: Duration::from_millis(10),
            catalog_recovery: Duration::from_millis(20),
        });
        tracing::subscriber::with_default(subscriber, || timeline.emit(machine_id, "test-run"));
        let line = std::fs::read_to_string(captured.path()).unwrap();
        assert_eq!(line.lines().count(), 1, "{line}");
        let (_, fields) = line.split_once("machine start timeline ").expect(&line);
        let fields: BTreeMap<_, _> = fields
            .split_whitespace()
            .map(|field| field.split_once('=').expect(field))
            .collect();
        assert_eq!(
            fields["machine_id"],
            uuid::Uuid::from(machine_id).to_string()
        );
        assert_eq!(fields["run_id"].trim_matches('"'), "test-run");
        assert_eq!(fields.len(), 11);
        for stage in [
            "runtime_discovery",
            "catalog_open_recovery",
            "lifecycle_admission",
            "lower_resolve_authentication",
            "secrets_netd",
            "launch_publication",
            "durability_barrier",
            "admit_spawn",
            "total",
        ] {
            let value: f64 = fields[format!("{stage}_ms").as_str()].parse().expect(stage);
            assert!(value.is_finite() && value >= 0.0, "{stage}: {line}");
        }
        assert_eq!(fields["runtime_discovery_ms"].parse::<f64>().unwrap(), 10.0);
        assert_eq!(
            fields["catalog_open_recovery_ms"].parse::<f64>().unwrap(),
            20.0
        );
        assert!(fields["total_ms"].parse::<f64>().unwrap() >= 30.0);
    }
}
