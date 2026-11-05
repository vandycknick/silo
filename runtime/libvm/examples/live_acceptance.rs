//! Standalone consumer of the durable manager lifecycle API, never a Cargo VM test.
use std::io::Read;

use libvm::{LiveObservationReader, MachineRef, Runtime, RuntimeConfig};
use vm_spec::lifecycle::LiveCommand;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let reference = args
        .next()
        .ok_or("usage: live_acceptance MACHINE REQUEST_JSON")?;
    let request = args.next().ok_or("missing request JSON path")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(request)?
        .take(16_385)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16_384 {
        return Err("live acceptance request exceeds 16 KiB".into());
    }
    let command: LiveCommand = serde_json::from_slice(&bytes)?;
    command.validate()?;
    let reference = MachineRef::parse(&reference)?;
    let config = RuntimeConfig::from_env()?;
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
    Ok(())
}
