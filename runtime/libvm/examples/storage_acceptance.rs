//! Standalone real storage/GC and cancellable stopped-operation smoke consumer.
//! Never starts a VM and never fabricates an operation result.
use std::io::Write;

use libvm::{ForkOptions, MachineRef, Runtime};
use tokio::io::AsyncBufReadExt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or(
        "usage: storage_acceptance prune | remove-image REFERENCE | fork-cancellable SOURCE CHILD",
    )?;
    let reference = args.next();
    let destination = args.next();
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let runtime = Runtime::from_env().await?;
    match (action.as_str(), reference, destination) {
        ("prune", None, None) => {
            let report = runtime.images().prune().await?;
            println!("{report:?}");
        }
        ("remove-image", Some(reference), None) => {
            runtime.images().remove(&reference).await?;
            println!("removed image reference {reference}");
        }
        ("fork-cancellable", Some(reference), Some(destination)) => {
            let machine = runtime.get_machine(&MachineRef::parse(&reference)?).await?;
            let options = ForkOptions {
                name: Some(destination),
                ..ForkOptions::default()
            };
            let operation = tokio::spawn(async move { machine.fork_stopped(options).await });
            let mut input = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            if input.next_line().await?.as_deref() != Some("cancel") {
                return Err("expected cancel after the real source syscall is held".into());
            }
            operation.abort();
            let result = operation.await;
            if !matches!(&result, Err(error) if error.is_cancelled()) {
                return Err("operation completed before its actual worker was cancelled".into());
            }
            println!("SILO_STOPPED_WAITER_CANCELLED");
            std::io::stdout().flush()?;
            // Keep Runtime/catalog alive while the detached blocking owner is
            // syscall-stopped. The controller probes the real held locks, then
            // resumes the worker before asking this process to finish.
            if input.next_line().await?.as_deref() != Some("finish") {
                return Err("expected finish after the actual worker was released".into());
            }
        }
        _ => return Err("usage: storage_acceptance prune | remove-image REFERENCE | fork-cancellable SOURCE CHILD".into()),
    }
    Ok(())
}
