use crate::store::models::{MachineRuntimeState, MachineState};

const START_TIMEOUT_ERROR: &str = "machine start did not leave a live runtime";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    StartRequested {
        run_id: String,
    },
    MonitorReady {
        run_id: String,
        pid: i32,
        started_at: i64,
    },
    MonitorObserved {
        pid: i32,
        started_at: i64,
        run_id: Option<String>,
    },
    StartFailed {
        run_id: String,
        failure: StartFailure,
        error: Option<String>,
    },
    StopRequested {
        pid: i32,
        started_at: Option<i64>,
        run_id: Option<String>,
    },
    StopCompleted {
        pid: i32,
        started_at: Option<i64>,
        run_id: Option<String>,
        last_error: Option<String>,
    },
    ExitObserved {
        clean: bool,
        error: Option<String>,
    },
    MonitorGone {
        last_error: Option<String>,
    },
    StartTimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartFailure {
    Stopped,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TransitionError {
    #[error("machine is already active")]
    AlreadyActive,
    #[error("machine is not running")]
    NotRunning,
    #[error("invalid transition from {state:?} for event {event}")]
    InvalidTransition {
        state: MachineRuntimeState,
        event: &'static str,
    },
    #[error("event belongs to a stale runtime generation")]
    StaleGeneration,
}

pub(crate) fn reduce(
    state: MachineState,
    event: Event,
    now: i64,
) -> Result<MachineState, TransitionError> {
    match event {
        Event::StartRequested { run_id } => start_requested(state, run_id, now),
        Event::MonitorReady {
            run_id,
            pid,
            started_at,
        } => monitor_ready(state, run_id, pid, started_at, now),
        Event::MonitorObserved {
            pid,
            started_at,
            run_id,
        } => monitor_observed(state, pid, started_at, run_id, now),
        Event::StartFailed {
            run_id,
            failure,
            error,
        } => start_failed(state, run_id, failure, error, now),
        Event::StopRequested {
            pid,
            started_at,
            run_id,
        } => stop_requested(state, pid, started_at, run_id, now),
        Event::StopCompleted {
            pid,
            started_at,
            run_id,
            last_error,
        } => stop_completed(state, pid, started_at, run_id, last_error, now),
        Event::ExitObserved { clean, error } => exit_observed(state, clean, error, now),
        Event::MonitorGone { last_error } => monitor_gone(state, last_error, now),
        Event::StartTimedOut => start_timed_out(state, now),
    }
}

fn start_requested(
    state: MachineState,
    run_id: String,
    now: i64,
) -> Result<MachineState, TransitionError> {
    if is_active(state.status) {
        return Err(TransitionError::AlreadyActive);
    }

    Ok(replace_runtime(
        state,
        MachineRuntimeState::Starting,
        None,
        None,
        Some(run_id),
        None,
        now,
    ))
}

fn monitor_ready(
    state: MachineState,
    run_id: String,
    pid: i32,
    started_at: i64,
    now: i64,
) -> Result<MachineState, TransitionError> {
    require_state(state.status, MachineRuntimeState::Starting, "MonitorReady")?;
    require_run_id(&state, Some(run_id.as_str()))?;

    Ok(replace_runtime(
        state,
        MachineRuntimeState::Running,
        Some(pid),
        Some(started_at),
        Some(run_id),
        None,
        now,
    ))
}

fn monitor_observed(
    state: MachineState,
    pid: i32,
    started_at: i64,
    run_id: Option<String>,
    now: i64,
) -> Result<MachineState, TransitionError> {
    let status = match state.status {
        MachineRuntimeState::Starting => MachineRuntimeState::Starting,
        MachineRuntimeState::Stopping => MachineRuntimeState::Stopping,
        _ => MachineRuntimeState::Running,
    };

    Ok(replace_runtime(
        state,
        status,
        Some(pid),
        Some(started_at),
        run_id,
        None,
        now,
    ))
}

fn start_failed(
    state: MachineState,
    run_id: String,
    failure: StartFailure,
    error: Option<String>,
    now: i64,
) -> Result<MachineState, TransitionError> {
    require_state(state.status, MachineRuntimeState::Starting, "StartFailed")?;
    require_run_id(&state, Some(run_id.as_str()))?;

    let status = match failure {
        StartFailure::Stopped => MachineRuntimeState::Stopped,
        StartFailure::Error => MachineRuntimeState::Error,
    };
    Ok(replace_runtime(state, status, None, None, None, error, now))
}

fn stop_requested(
    state: MachineState,
    pid: i32,
    started_at: Option<i64>,
    run_id: Option<String>,
    now: i64,
) -> Result<MachineState, TransitionError> {
    if matches!(
        state.status,
        MachineRuntimeState::Stopped | MachineRuntimeState::Error
    ) {
        return Err(TransitionError::NotRunning);
    }

    Ok(replace_runtime(
        state,
        MachineRuntimeState::Stopping,
        Some(pid),
        started_at,
        run_id,
        None,
        now,
    ))
}

fn stop_completed(
    state: MachineState,
    pid: i32,
    started_at: Option<i64>,
    run_id: Option<String>,
    last_error: Option<String>,
    now: i64,
) -> Result<MachineState, TransitionError> {
    require_state(state.status, MachineRuntimeState::Stopping, "StopCompleted")?;
    require_generation(&state, pid, started_at, run_id.as_deref())?;

    Ok(replace_runtime(
        state,
        MachineRuntimeState::Stopped,
        None,
        None,
        None,
        last_error,
        now,
    ))
}

fn exit_observed(
    state: MachineState,
    clean: bool,
    error: Option<String>,
    now: i64,
) -> Result<MachineState, TransitionError> {
    let (status, last_error) = if clean {
        (MachineRuntimeState::Stopped, None)
    } else {
        (
            MachineRuntimeState::Error,
            Some(error.unwrap_or_else(|| "machine runtime exited with an error".to_string())),
        )
    };

    Ok(replace_runtime(
        state, status, None, None, None, last_error, now,
    ))
}

fn monitor_gone(
    state: MachineState,
    last_error: Option<String>,
    now: i64,
) -> Result<MachineState, TransitionError> {
    let status = match state.status {
        MachineRuntimeState::Error => MachineRuntimeState::Error,
        _ => MachineRuntimeState::Stopped,
    };
    Ok(replace_runtime(
        state, status, None, None, None, last_error, now,
    ))
}

fn start_timed_out(state: MachineState, now: i64) -> Result<MachineState, TransitionError> {
    require_state(state.status, MachineRuntimeState::Starting, "StartTimedOut")?;
    Ok(replace_runtime(
        state,
        MachineRuntimeState::Error,
        None,
        None,
        None,
        Some(START_TIMEOUT_ERROR.to_string()),
        now,
    ))
}

fn require_state(
    actual: MachineRuntimeState,
    expected: MachineRuntimeState,
    event: &'static str,
) -> Result<(), TransitionError> {
    if actual == expected {
        Ok(())
    } else {
        Err(TransitionError::InvalidTransition {
            state: actual,
            event,
        })
    }
}

fn require_generation(
    state: &MachineState,
    pid: i32,
    started_at: Option<i64>,
    run_id: Option<&str>,
) -> Result<(), TransitionError> {
    require_run_id(state, run_id)?;

    if state.vmmon_pid != Some(pid) {
        return Err(TransitionError::StaleGeneration);
    }

    if started_at.is_some() && state.started_at != started_at {
        return Err(TransitionError::StaleGeneration);
    }

    Ok(())
}

fn require_run_id(state: &MachineState, run_id: Option<&str>) -> Result<(), TransitionError> {
    if let Some(run_id) = run_id {
        if state.run_id.as_deref() != Some(run_id) {
            return Err(TransitionError::StaleGeneration);
        }
    }
    Ok(())
}

fn replace_runtime(
    mut state: MachineState,
    status: MachineRuntimeState,
    vmmon_pid: Option<i32>,
    started_at: Option<i64>,
    run_id: Option<String>,
    last_error: Option<String>,
    now: i64,
) -> MachineState {
    state.status = status;
    state.vmmon_pid = vmmon_pid;
    state.started_at = started_at;
    state.run_id = run_id;
    state.last_error = last_error;
    state.updated_at = now;
    state
}

fn is_active(status: MachineRuntimeState) -> bool {
    matches!(
        status,
        MachineRuntimeState::Starting
            | MachineRuntimeState::Running
            | MachineRuntimeState::Stopping
    )
}

#[cfg(test)]
mod tests {
    use super::{reduce, Event, StartFailure, TransitionError, START_TIMEOUT_ERROR};
    use crate::store::models::{MachineId, MachineRuntimeState, MachineState};

    const NOW: i64 = 100;

    fn state(status: MachineRuntimeState) -> MachineState {
        MachineState {
            machine_id: MachineId::new(),
            status,
            vmmon_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        }
    }

    fn running() -> MachineState {
        MachineState {
            status: MachineRuntimeState::Running,
            vmmon_pid: Some(123),
            started_at: Some(42),
            run_id: Some("run-1".to_string()),
            ..state(MachineRuntimeState::Running)
        }
    }

    #[test]
    fn stopped_or_error_can_start() {
        for initial in [MachineRuntimeState::Stopped, MachineRuntimeState::Error] {
            let next = reduce(
                state(initial),
                Event::StartRequested {
                    run_id: "run-1".to_string(),
                },
                NOW,
            )
            .expect("start should be accepted");

            assert_eq!(next.status, MachineRuntimeState::Starting);
            assert_eq!(next.run_id.as_deref(), Some("run-1"));
            assert_eq!(next.vmmon_pid, None);
            assert_eq!(next.started_at, None);
            assert_eq!(next.last_error, None);
            assert_eq!(next.updated_at, NOW);
        }
    }

    #[test]
    fn active_machine_cannot_start_again() {
        for initial in [
            MachineRuntimeState::Starting,
            MachineRuntimeState::Running,
            MachineRuntimeState::Stopping,
        ] {
            let err = reduce(
                state(initial),
                Event::StartRequested {
                    run_id: "run-2".to_string(),
                },
                NOW,
            )
            .expect_err("active machine should reject start");

            assert_eq!(err, TransitionError::AlreadyActive);
        }
    }

    #[test]
    fn matching_monitor_ready_marks_running() {
        let starting = reduce(
            state(MachineRuntimeState::Stopped),
            Event::StartRequested {
                run_id: "run-1".to_string(),
            },
            NOW,
        )
        .expect("start should be accepted");

        let next = reduce(
            starting,
            Event::MonitorReady {
                run_id: "run-1".to_string(),
                pid: 123,
                started_at: 42,
            },
            NOW + 1,
        )
        .expect("monitor ready should be accepted");

        assert_eq!(next.status, MachineRuntimeState::Running);
        assert_eq!(next.vmmon_pid, Some(123));
        assert_eq!(next.started_at, Some(42));
        assert_eq!(next.run_id.as_deref(), Some("run-1"));
        assert_eq!(next.updated_at, NOW + 1);
    }

    #[test]
    fn observed_live_monitor_preserves_starting_state() {
        let mut starting = state(MachineRuntimeState::Starting);
        starting.run_id = Some("run-1".to_string());

        let next = reduce(
            starting,
            Event::MonitorObserved {
                pid: 123,
                started_at: 42,
                run_id: Some("run-1".to_string()),
            },
            NOW,
        )
        .expect("observed monitor should be accepted");

        assert_eq!(next.status, MachineRuntimeState::Starting);
        assert_eq!(next.vmmon_pid, Some(123));
        assert_eq!(next.started_at, Some(42));
        assert_eq!(next.run_id.as_deref(), Some("run-1"));
    }

    #[test]
    fn monitor_ready_rejects_stale_run_id() {
        let mut starting = state(MachineRuntimeState::Starting);
        starting.run_id = Some("run-1".to_string());

        let err = reduce(
            starting,
            Event::MonitorReady {
                run_id: "run-2".to_string(),
                pid: 123,
                started_at: 42,
            },
            NOW,
        )
        .expect_err("stale monitor ready should be rejected");

        assert_eq!(err, TransitionError::StaleGeneration);
    }

    #[test]
    fn start_failure_maps_to_requested_terminal_state() {
        for (failure, expected) in [
            (StartFailure::Stopped, MachineRuntimeState::Stopped),
            (StartFailure::Error, MachineRuntimeState::Error),
        ] {
            let mut starting = state(MachineRuntimeState::Starting);
            starting.run_id = Some("run-1".to_string());

            let next = reduce(
                starting,
                Event::StartFailed {
                    run_id: "run-1".to_string(),
                    failure,
                    error: Some("boom".to_string()),
                },
                NOW,
            )
            .expect("matching start failure should be accepted");

            assert_eq!(next.status, expected);
            assert_eq!(next.vmmon_pid, None);
            assert_eq!(next.started_at, None);
            assert_eq!(next.run_id, None);
            assert_eq!(next.last_error.as_deref(), Some("boom"));
        }
    }

    #[test]
    fn running_machine_can_stop() {
        let next = reduce(
            running(),
            Event::StopRequested {
                pid: 123,
                started_at: Some(42),
                run_id: Some("run-1".to_string()),
            },
            NOW,
        )
        .expect("stop should be accepted");

        assert_eq!(next.status, MachineRuntimeState::Stopping);
        assert_eq!(next.vmmon_pid, Some(123));
        assert_eq!(next.started_at, Some(42));
        assert_eq!(next.run_id.as_deref(), Some("run-1"));
    }

    #[test]
    fn stop_completed_requires_matching_generation() {
        let stopping = reduce(
            running(),
            Event::StopRequested {
                pid: 123,
                started_at: Some(42),
                run_id: Some("run-1".to_string()),
            },
            NOW,
        )
        .expect("stop should be accepted");

        let err = reduce(
            stopping,
            Event::StopCompleted {
                pid: 999,
                started_at: Some(42),
                run_id: Some("run-1".to_string()),
                last_error: None,
            },
            NOW + 1,
        )
        .expect_err("wrong pid should be stale");

        assert_eq!(err, TransitionError::StaleGeneration);
    }

    #[test]
    fn stop_completed_clears_active_generation() {
        let stopping = reduce(
            running(),
            Event::StopRequested {
                pid: 123,
                started_at: Some(42),
                run_id: Some("run-1".to_string()),
            },
            NOW,
        )
        .expect("stop should be accepted");

        let next = reduce(
            stopping,
            Event::StopCompleted {
                pid: 123,
                started_at: Some(42),
                run_id: Some("run-1".to_string()),
                last_error: None,
            },
            NOW + 1,
        )
        .expect("matching stop completion should be accepted");

        assert_eq!(next.status, MachineRuntimeState::Stopped);
        assert_eq!(next.vmmon_pid, None);
        assert_eq!(next.started_at, None);
        assert_eq!(next.run_id, None);
        assert_eq!(next.last_error, None);
    }

    #[test]
    fn exit_observed_maps_clean_and_error_outcomes() {
        let clean = reduce(
            running(),
            Event::ExitObserved {
                clean: true,
                error: Some("ignored".to_string()),
            },
            NOW,
        )
        .expect("clean exit should be accepted");
        assert_eq!(clean.status, MachineRuntimeState::Stopped);
        assert_eq!(clean.last_error, None);

        let error = reduce(
            running(),
            Event::ExitObserved {
                clean: false,
                error: Some("runtime exploded".to_string()),
            },
            NOW,
        )
        .expect("error exit should be accepted");
        assert_eq!(error.status, MachineRuntimeState::Error);
        assert_eq!(error.last_error.as_deref(), Some("runtime exploded"));
    }

    #[test]
    fn stale_start_timeout_marks_error() {
        let mut starting = state(MachineRuntimeState::Starting);
        starting.run_id = Some("run-1".to_string());

        let next =
            reduce(starting, Event::StartTimedOut, NOW).expect("start timeout should be accepted");

        assert_eq!(next.status, MachineRuntimeState::Error);
        assert_eq!(next.run_id, None);
        assert_eq!(next.last_error.as_deref(), Some(START_TIMEOUT_ERROR));
    }
}
