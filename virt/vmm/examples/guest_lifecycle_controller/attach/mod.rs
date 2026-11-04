//! `guest-lifecycle-controller --attach REQUEST_JSON`: real guest RPCs over one
//! inherited native mux stream for the restored-Silo smoke orchestrator.
//!
//! Ownership: this mode owns only the supplied connection(s). It never starts,
//! stops, waits for, reaps or releases fences of any VM; the native owner does.
//! stdout carries exactly one `{"record":"result"}` JSON line (`hold` first
//! prints one `{"record":"ready"}` line). Exit 0 iff every check passed.

mod connection;
mod dto;
mod lifecycle;
mod observe;
mod profile;
mod session;

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::attach::dto::{monotonic_ns, Checks, FreezeRef, Identity, LifecycleState};
use crate::attach::lifecycle::{ActivateOperation, FreezeOperation, ThawOperation};
use crate::attach::observe::{Guest, Observation, Observe};
use crate::attach::profile::ProfileOperation;
use crate::attach::session::{
    ExecOperation, HoldOperation, ListDirectoryOperation, ListenOperation,
};

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_DEADLINE_MS: u32 = 600_000;
/// A held session releases itself this long before the attach deadline so its
/// result line is still printed.
const HOLD_RELEASE_MARGIN: Duration = Duration::from_secs(1);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    fd: i32,
    deadline_ms: u32,
    operation: Operation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Operation {
    Observe(ObserveOperation),
    Profile(ProfileOperation),
    Freeze(FreezeOperation),
    Activate(Box<ActivateOperation>),
    Thaw(ThawOperation),
    Exec(ExecOperation),
    ListDirectory(ListDirectoryOperation),
    Listen(ListenOperation),
    Hold(HoldOperation),
}

impl Operation {
    fn kind(&self) -> &'static str {
        match self {
            Self::Observe(_) => "observe",
            Self::Profile(_) => "profile",
            Self::Freeze(_) => "freeze",
            Self::Activate(_) => "activate",
            Self::Thaw(_) => "thaw",
            Self::Exec(_) => "exec",
            Self::ListDirectory(_) => "list_directory",
            Self::Listen(_) => "listen",
            Self::Hold(_) => "hold",
        }
    }

    fn validate(&self, fd: i32) -> eyre::Result<()> {
        match self {
            Self::Observe(operation) => operation.observe.validate(),
            Self::Freeze(operation) => operation.observe.validate(),
            Self::Activate(operation) => operation.observe.validate(),
            Self::Thaw(operation) => operation.observe.validate(),
            Self::Exec(operation) => operation.validate(),
            Self::Hold(operation) => operation.validate(fd),
            Self::Profile(_) | Self::ListDirectory(_) | Self::Listen(_) => Ok(()),
        }
    }
}

/// Status predicates for a restored guest: responsive, exact identity and
/// FreezeRef, deliberately not Ready while frozen. No Ready wait exists here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusExpect {
    #[serde(default)]
    identity: Option<Identity>,
    #[serde(default)]
    lifecycle_state: Option<LifecycleState>,
    #[serde(default)]
    freeze_ref: Option<FreezeRef>,
    #[serde(default)]
    activation_id: Option<String>,
    #[serde(default)]
    ready: Option<bool>,
    #[serde(default)]
    agent_pid1: Option<bool>,
}

impl StatusExpect {
    fn evaluate(&self, observation: &Observation, checks: &mut Checks) {
        let status = observation.status();
        let lifecycle = status.and_then(|status| status.lifecycle.as_ref());
        if let Some(identity) = &self.identity {
            let actual = status.and_then(|status| status.expected_identity.as_ref());
            checks.check(
                "expected_identity",
                actual == Some(identity),
                format!("expected {identity:?}, got {actual:?}"),
            );
        }
        if let Some(state) = self.lifecycle_state {
            let actual = lifecycle.and_then(|lifecycle| lifecycle.state);
            checks.check(
                "lifecycle_state",
                actual == Some(state),
                format!("expected {state:?}, got {actual:?}"),
            );
        }
        if let Some(reference) = &self.freeze_ref {
            let actual = lifecycle.and_then(|lifecycle| lifecycle.freeze_ref.as_ref());
            checks.check(
                "freeze_ref",
                actual == Some(reference),
                format!("expected {reference:?}, got {actual:?}"),
            );
        }
        if let Some(activation) = &self.activation_id {
            let actual = lifecycle.and_then(|lifecycle| lifecycle.activation_id.as_ref());
            checks.check(
                "activation_id",
                actual == Some(activation),
                format!("expected {activation}, got {actual:?}"),
            );
        }
        if let Some(ready) = self.ready {
            let actual = status.map(|status| status.ready());
            checks.check(
                "ready",
                actual == Some(ready),
                format!(
                    "expected {ready}, got {actual:?} ({:?})",
                    status.map(|status| &status.report_state)
                ),
            );
        }
        if let Some(pid1) = self.agent_pid1 {
            let actual = status
                .and_then(|status| status.boot.as_ref())
                .and_then(|boot| boot.agent_is_pid1);
            checks.check(
                "agent_pid1",
                actual == Some(pid1),
                format!("expected {pid1}, got {actual:?}"),
            );
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserveOperation {
    #[serde(default)]
    expect: Option<StatusExpect>,
    #[serde(default)]
    observe: Observe,
}

#[derive(Debug, Serialize)]
struct ObserveOutput {
    observation: Observation,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct Connection {
    fd: i32,
    source_port: u32,
}

#[derive(Debug, Serialize)]
struct ResultLine<'a> {
    record: &'static str,
    operation: Option<&'static str>,
    request_sha256: Option<String>,
    connection: Option<Connection>,
    started_monotonic_ns: Option<u64>,
    finished_monotonic_ns: Option<u64>,
    input: Option<&'a Operation>,
    output: Option<serde_json::Value>,
    checks: Checks,
    passed: bool,
    harness_error: Option<String>,
}

#[derive(Debug, Default)]
struct Outcome {
    connection: Option<Connection>,
    output: Option<serde_json::Value>,
    checks: Checks,
    harness_error: Option<String>,
}

fn emit(value: &impl Serialize) -> eyre::Result<()> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&line)?;
    stdout.flush()?;
    Ok(())
}

fn load(path: &Path) -> eyre::Result<(Request, String)> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    eyre::ensure!(
        metadata.is_file() && metadata.len() <= MAX_REQUEST_BYTES,
        "attach request must be a regular file of at most {MAX_REQUEST_BYTES} bytes"
    );
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAX_REQUEST_BYTES + 1),
        &mut bytes,
    )?;
    eyre::ensure!(
        bytes.len() as u64 <= MAX_REQUEST_BYTES,
        "attach request grew beyond its bound while read"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    Ok((request, crate::capabilities::scenario_digest(&bytes)))
}

/// Runs one attach request; returns the process exit code. The result line is
/// always printed, including for invalid requests and harness failures.
pub(crate) fn main(path: &Path) -> std::process::ExitCode {
    let started = monotonic_ns().ok();
    let mut outcome = Outcome::default();
    let loaded = load(path);
    let request = match &loaded {
        Ok((request, _)) => Some(request),
        Err(error) => {
            outcome.harness_error = Some(format!("invalid attach request: {error:#}"));
            None
        }
    };
    if let Some(request) = request {
        match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => {
                runtime.block_on(execute(request, &mut outcome));
                // A held session's blocked stdin reader must never delay exit.
                runtime.shutdown_background();
            }
            Err(error) => outcome.harness_error = Some(format!("tokio runtime: {error}")),
        }
    }
    let passed = outcome.harness_error.is_none() && outcome.checks.passed();
    let line = ResultLine {
        record: "result",
        operation: request.map(|request| request.operation.kind()),
        request_sha256: loaded.as_ref().ok().map(|(_, digest)| digest.clone()),
        connection: outcome.connection,
        started_monotonic_ns: started,
        finished_monotonic_ns: monotonic_ns().ok(),
        input: request.map(|request| &request.operation),
        output: outcome.output,
        checks: outcome.checks,
        passed,
        harness_error: outcome.harness_error,
    };
    match emit(&line) {
        Ok(()) if passed => std::process::ExitCode::SUCCESS,
        Ok(()) => std::process::ExitCode::FAILURE,
        Err(error) => {
            // stdout is gone; stderr is the only remaining channel.
            let _ = writeln!(
                std::io::stderr(),
                "attach result emission failed: {error:#}"
            );
            std::process::ExitCode::FAILURE
        }
    }
}

async fn execute(request: &Request, outcome: &mut Outcome) {
    if !(1..=MAX_DEADLINE_MS).contains(&request.deadline_ms) {
        outcome.harness_error = Some(format!("deadline_ms must be 1..={MAX_DEADLINE_MS}"));
        return;
    }
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(u64::from(request.deadline_ms));
    let result = tokio::time::timeout_at(deadline, run(request, deadline, outcome)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => outcome.harness_error = Some(format!("{error:#}")),
        Err(_) => outcome.harness_error = Some("attach deadline exceeded".to_string()),
    }
}

async fn run(
    request: &Request,
    deadline: tokio::time::Instant,
    outcome: &mut Outcome,
) -> eyre::Result<()> {
    request
        .operation
        .validate(request.fd)
        .map_err(|error| eyre::eyre!("invalid attach request: {error:#}"))?;
    let (stream, source_port) = connection::open(request.fd).await?;
    outcome.connection = Some(Connection {
        fd: request.fd,
        source_port,
    });
    let guest = Guest::new(connection::channel(stream).await?);
    let checks = &mut outcome.checks;
    let output = match &request.operation {
        Operation::Observe(operation) => {
            let observation = guest.observe(&operation.observe).await?;
            if let Some(expect) = &operation.expect {
                expect.evaluate(&observation, checks);
            }
            observation.evaluate(&operation.observe, checks);
            serde_json::to_value(ObserveOutput { observation })?
        }
        Operation::Profile(operation) => {
            serde_json::to_value(profile::profile(&guest, operation).await?)?
        }
        Operation::Freeze(operation) => {
            serde_json::to_value(lifecycle::freeze(&guest, operation, checks).await?)?
        }
        Operation::Activate(operation) => {
            serde_json::to_value(lifecycle::activate(&guest, operation, checks).await?)?
        }
        Operation::Thaw(operation) => {
            serde_json::to_value(lifecycle::thaw(&guest, operation, checks).await?)?
        }
        Operation::Exec(operation) => {
            serde_json::to_value(session::exec(&guest, operation, checks).await?)?
        }
        Operation::ListDirectory(operation) => {
            serde_json::to_value(session::list_directory(&guest, operation, checks).await?)?
        }
        Operation::Listen(operation) => {
            serde_json::to_value(session::listen(&guest, operation, checks).await?)?
        }
        Operation::Hold(operation) => {
            let release = deadline
                .checked_sub(HOLD_RELEASE_MARGIN)
                .unwrap_or(deadline);
            let ready = |ready: &session::Ready<'_>| emit(ready);
            serde_json::to_value(session::hold(&guest, operation, release, ready, checks).await?)?
        }
    };
    outcome.output = Some(output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::attach::{load, Request};
    use std::io::Write;

    fn request(text: &str) -> eyre::Result<Request> {
        let mut file = tempfile_path();
        file.1.write_all(text.as_bytes()).unwrap();
        let result = load(&file.0).map(|(request, _)| request);
        std::fs::remove_file(&file.0).unwrap();
        result
    }

    fn tempfile_path() -> (std::path::PathBuf, std::fs::File) {
        let path = std::env::temp_dir().join(format!(
            "guest-lifecycle-attach-{}.json",
            uuid::Uuid::new_v4()
        ));
        let file = std::fs::File::create_new(&path).unwrap();
        (path, file)
    }

    #[test]
    fn requests_reject_unknown_fields_and_kinds() {
        assert!(request(r#"{"fd":3,"deadline_ms":1,"operation":{"kind":"reboot"}}"#).is_err());
        assert!(
            request(r#"{"fd":3,"deadline_ms":1,"operation":{"kind":"observe"},"extra":1}"#)
                .is_err()
        );
        assert!(request(
            r#"{"fd":3,"deadline_ms":1,"operation":{"kind":"observe","observe":{},"stray":1}}"#
        )
        .is_err());
        let hold = request(
            r#"{"fd":3,"deadline_ms":1,"operation":{"kind":"hold","ssh":{"fd":3,"host_public_key":"k","private_key":"/c","certificate":"/c.pub","user":"root","command":"true"}}}"#,
        )
        .unwrap();
        assert!(hold.operation.validate(hold.fd).is_err(), "shared fd");
    }
}
