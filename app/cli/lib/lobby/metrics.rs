//! Prometheus counters, cumulative duration histograms and resource gauges.
//! Only fixed operational labels are admitted; principals and VM names are not.

use std::{
    collections::BTreeMap,
    fmt::Write,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use parking_lot::Mutex;

const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0];

#[derive(Default)]
struct Observation {
    count: u64,
    seconds: f64,
    buckets: [u64; BUCKETS.len()],
}

impl Observation {
    fn observe(&mut self, duration: Duration) {
        let seconds = duration.as_secs_f64();
        self.count += 1;
        self.seconds += seconds;
        for (bound, count) in BUCKETS.iter().zip(&mut self.buckets) {
            if seconds <= *bound {
                *count += 1;
            }
        }
    }
}

#[derive(Default)]
struct State {
    sessions: i64,
    jobs: i64,
    handles: BTreeMap<&'static str, i64>,
    operations: BTreeMap<(&'static str, &'static str), Observation>,
    latency: BTreeMap<(&'static str, &'static str), Observation>,
}

/// Shared via Arc. Dimensions are restricted to operational constants, never identities.
#[derive(Default)]
pub(crate) struct Metrics {
    state: Mutex<State>,
}

/// Counts only lobby-owned references, not the daemon's underlying resources.
pub(crate) struct Handle<T> {
    value: T,
    metrics: Arc<Metrics>,
    kind: &'static str,
}

impl<T> Deref for Handle<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for Handle<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T> Drop for Handle<T> {
    fn drop(&mut self) {
        self.metrics.handle(self.kind, -1);
    }
}

impl Metrics {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn session(&self, delta: i64) {
        self.state.lock().sessions += delta;
    }
    pub(crate) fn job(&self, delta: i64) {
        self.state.lock().jobs += delta;
    }

    pub(crate) fn track<T>(self: &Arc<Self>, kind: &'static str, value: T) -> Handle<T> {
        self.handle(kind, 1);
        Handle {
            value,
            metrics: self.clone(),
            kind,
        }
    }

    pub(crate) fn handle(&self, kind: &str, delta: i64) {
        let kind = match kind {
            "runtime" => "runtime",
            "machine" => "machine",
            "exec" => "exec",
            "logs" => "logs",
            _ => return,
        };
        *self.state.lock().handles.entry(kind).or_default() += delta;
    }

    pub(crate) fn operation(&self, kind: &str, outcome: &str, duration: Duration) {
        let kind = match kind {
            "create" => "create",
            "start" => "start",
            "stop" => "stop",
            "restart" => "restart",
            "remove" => "remove",
            "set" => "set",
            _ => "other",
        };
        let outcome = if outcome == "succeeded" {
            "succeeded"
        } else {
            "failed"
        };
        self.state
            .lock()
            .operations
            .entry((kind, outcome))
            .or_default()
            .observe(duration);
    }

    pub(crate) fn latency(&self, name: &str, duration: Duration, ok: bool) {
        let name = match name {
            "whois" => "whois",
            "enrollment" => "enrollment",
            _ => return,
        };
        let outcome = if ok { "succeeded" } else { "failed" };
        self.state
            .lock()
            .latency
            .entry((name, outcome))
            .or_default()
            .observe(duration);
    }

    pub(crate) fn render(&self) -> String {
        let state = self.state.lock();
        let mut text = String::new();
        text.push_str(concat!(
            "# TYPE lobby_active_sessions gauge\n",
            "# TYPE lobby_active_operations gauge\n",
            "# TYPE lobby_native_handles gauge\n",
            "# TYPE lobby_operations_total counter\n",
            "# TYPE lobby_operation_duration_seconds histogram\n",
            "# TYPE lobby_whois_duration_seconds histogram\n",
            "# TYPE lobby_enrollment_duration_seconds histogram\n",
        ));
        let _ = writeln!(
            text,
            "lobby_active_sessions {}\nlobby_active_operations {}",
            state.sessions, state.jobs
        );
        for ((kind, outcome), observation) in &state.operations {
            let labels = format!("kind=\"{kind}\",outcome=\"{outcome}\"");
            let _ = writeln!(
                text,
                "lobby_operations_total{{{labels}}} {}",
                observation.count
            );
            histogram(&mut text, "operation", &labels, observation);
        }
        for name in ["whois", "enrollment"] {
            for outcome in ["succeeded", "failed"] {
                let empty = Observation::default();
                let observation = state.latency.get(&(name, outcome)).unwrap_or(&empty);
                histogram(
                    &mut text,
                    name,
                    &format!("outcome=\"{outcome}\""),
                    observation,
                );
            }
        }
        for kind in ["runtime", "machine", "exec", "logs"] {
            let count = state.handles.get(kind).copied().unwrap_or_default();
            let _ = writeln!(
                text,
                "lobby_native_handles{{kind=\"{kind}\",scope=\"daemon_owned\"}} {count}"
            );
        }
        text
    }
}

fn histogram(text: &mut String, name: &str, labels: &str, observation: &Observation) {
    for (bound, count) in BUCKETS.iter().zip(observation.buckets) {
        let _ = writeln!(
            text,
            "lobby_{name}_duration_seconds_bucket{{{labels},le=\"{bound}\"}} {count}"
        );
    }
    let _ = writeln!(
        text,
        "lobby_{name}_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}",
        observation.count
    );
    let _ = writeln!(
        text,
        "lobby_{name}_duration_seconds_sum{{{labels}}} {}",
        observation.seconds
    );
    let _ = writeln!(
        text,
        "lobby_{name}_duration_seconds_count{{{labels}}} {}",
        observation.count
    );
}

#[cfg(test)]
mod tests {
    use crate::lobby::metrics::Metrics;
    use std::{sync::Arc, time::Duration};

    #[test]
    fn metrics_are_shared_bounded_and_cumulative() {
        let metrics = Arc::new(Metrics::new());
        let shared = metrics.clone();
        let runtime = shared.track("runtime", ());
        assert!(metrics
            .render()
            .contains("lobby_native_handles{kind=\"runtime\",scope=\"daemon_owned\"} 1\n"));
        drop(runtime);
        assert!(metrics
            .render()
            .contains("lobby_native_handles{kind=\"runtime\",scope=\"daemon_owned\"} 0\n"));
        shared.session(1);
        shared.job(1);
        shared.handle("machine", 2);
        shared.handle("secret identity", 1);
        shared.operation("create", "succeeded", Duration::from_millis(20));
        shared.operation("secret identity", "secret result", Duration::from_secs(40));
        shared.latency("whois", Duration::from_millis(10), true);
        shared.latency("enrollment", Duration::from_secs(2), false);
        shared.latency("secret identity", Duration::ZERO, true);
        shared.session(-1);
        let output = metrics.render();
        assert!(output.contains("# TYPE lobby_whois_duration_seconds histogram\n"));
        assert!(output.contains("lobby_active_sessions 0\nlobby_active_operations 1\n"));
        assert!(
            output.contains("lobby_operations_total{kind=\"create\",outcome=\"succeeded\"} 1\n")
        );
        assert!(output.contains(
            "lobby_whois_duration_seconds_bucket{outcome=\"succeeded\",le=\"0.005\"} 0\n"
        ));
        assert!(output.contains(
            "lobby_whois_duration_seconds_bucket{outcome=\"succeeded\",le=\"0.01\"} 1\n"
        ));
        assert!(output.contains("lobby_operation_duration_seconds_bucket{kind=\"other\",outcome=\"failed\",le=\"+Inf\"} 1\n"));
        assert!(output.contains("lobby_enrollment_duration_seconds_sum{outcome=\"failed\"} 2\n"));
        assert!(!output.contains("secret"));
        assert!(!output.contains("taild_"));
    }
}
