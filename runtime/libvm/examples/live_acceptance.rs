//! Standalone consumer of the durable manager lifecycle API, never a Cargo VM test.
//!
//! ```text
//! live_acceptance MACHINE REQUEST_JSON                 raw LiveCommand (replays only for Capture)
//! live_acceptance MACHINE capture REQUEST_ID POLICY    reserve + journal + submit, no wait
//! live_acceptance MACHINE complete-capture REQUEST_ID  seal -> publish -> continuation -> release
//! ```
use std::io::Read;

use libvm::{LiveObservationReader, LiveSnapshotOptions, MachineRef, Runtime, RuntimeConfig};
use vm_spec::lifecycle::{CaptureResumePolicy, LiveCommand};

const USAGE: &str = "usage: live_acceptance MACHINE (REQUEST_JSON | capture REQUEST_ID resume-if-acquired|preserve | complete-capture REQUEST_ID)";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let reference = MachineRef::parse(args.first().ok_or(USAGE)?)?;
    let config = RuntimeConfig::from_env()?;
    match args.get(1).map(String::as_str) {
        Some("capture") => {
            let [_, _, request, policy] = args.as_slice() else {
                return Err(USAGE.into());
            };
            let resume_policy = match policy.as_str() {
                "resume-if-acquired" => CaptureResumePolicy::ResumeIfAcquired,
                "preserve" => CaptureResumePolicy::Preserve,
                _ => return Err(USAGE.into()),
            };
            let observation = LiveObservationReader::open(&config)?
                .observe(&reference)
                .await?;
            let runtime = Runtime::new(config).await?;
            let machine = runtime.get_machine(&reference).await?;
            let result = machine
                .submit_capture(
                    &observation,
                    uuid::Uuid::parse_str(request)?,
                    LiveSnapshotOptions {
                        name: None,
                        resume_policy,
                        policy: vm_spec::lifecycle::CapturePolicy::Full,
                        dirty_crossover_percent: 60,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Some("complete-capture") => {
            let [_, _, request] = args.as_slice() else {
                return Err(USAGE.into());
            };
            let runtime = Runtime::new(config).await?;
            let machine = runtime.get_machine(&reference).await?;
            let snapshot = machine
                .complete_capture(uuid::Uuid::parse_str(request)?)
                .await?;
            println!("{}", serde_json::to_string(&snapshot)?);
        }
        Some(request) if args.len() == 2 => {
            let mut bytes = Vec::new();
            std::fs::File::open(request)?
                .take(16_385)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 16_384 {
                return Err("live acceptance request exceeds 16 KiB".into());
            }
            let command: LiveCommand = serde_json::from_slice(&bytes)?;
            let observation = LiveObservationReader::open(&config)?
                .observe(&reference)
                .await?;
            if matches!(command, LiveCommand::Pause(_)) {
                observation.require_pause_submission()?;
            }
            let runtime = Runtime::new(config).await?;
            let machine = runtime.get_machine(&reference).await?;
            let result = machine.live_command(&observation, command).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
