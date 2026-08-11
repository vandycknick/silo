use libvm::{
    ExecutionLaunchFailureReason, ExecutionResult, ImageSource, LibVmError,
    MachineReadinessOutcome, MachineUserConfig, Runtime,
};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let image = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ubuntu:26.04".to_string());
    let executable = std::env::current_exe()?;
    let adjacent = executable
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("example executable has no adjacent runtime parent")?;
    let runtime = Runtime::builder()
        .vmmon_path(adjacent.join("vmmon"))
        .netd_path(adjacent.join("netd"))
        .krun_path(adjacent.join("krun"))
        .kernel_path(adjacent.join("assets/kernel-default"))
        .initramfs_path(adjacent.join("assets/initramfs"))
        .agent_path(adjacent.join("assets/agent"))
        .open()
        .await?;
    let machine = runtime
        .machine()
        .image_source(ImageSource::oci(image.clone()))
        .create()
        .await?;

    let start = machine
        .start_with(|options| {
            options.entrypoint("/usr/bin/printf", |entrypoint| {
                entrypoint.arg("entrypoint-output\n")
            })
        })
        .await;
    if let Err(error) = start {
        let _ = machine.remove().await;
        return Err(error.into());
    }

    let exit = machine.wait().await?;
    eprintln!("entrypoint acknowledged Started and vmmon exited: {exit:?}");
    machine.remove().await?;

    let machine = runtime
        .machine()
        .image_source(ImageSource::oci(image.clone()))
        .create()
        .await?;
    let failure = machine
        .start_with(|options| {
            options.entrypoint("/silo-missing-entrypoint", |entrypoint| entrypoint)
        })
        .await;
    match failure {
        Err(LibVmError::EntrypointLaunchFailed { failure })
            if failure.reason == ExecutionLaunchFailureReason::CommandNotFound => {}
        Err(error) => {
            let _ = machine.remove().await;
            return Err(format!("unexpected entrypoint launch failure: {error}").into());
        }
        Ok(_) => {
            let _ = machine.stop().await;
            let _ = machine.remove().await;
            return Err("missing entrypoint unexpectedly reached Started".into());
        }
    }
    if machine.inspect().await?.is_running() {
        let _ = machine.stop().await;
        let _ = machine.remove().await;
        return Err("failed entrypoint left the VM running".into());
    }
    eprintln!("entrypoint launch failure remained typed and stopped the VM");
    machine.remove().await?;

    let machine = runtime
        .machine()
        .image_source(ImageSource::oci(image))
        .guest(|guest| {
            guest.user(MachineUserConfig::new(
                "silo-stage5",
                12345,
                12345,
                "/home/silo-stage5",
            ))
        })
        .create()
        .await?;
    machine.start().await?;
    let readiness = machine.wait_ready(Duration::from_secs(5 * 60)).await?;
    if readiness.outcome != MachineReadinessOutcome::Ready {
        let _ = machine.remove().await;
        return Err(format!("ordinary execution machine was not ready: {readiness:?}").into());
    }
    let identity = machine.exec("/usr/bin/id", ["-u"]).await?;
    if identity.stdout_bytes() != b"12345\n" {
        let _ = machine.stop().await;
        let _ = machine.remove().await;
        return Err(format!(
            "ordinary execution ignored the configured guest user: {:?}",
            identity.stdout_bytes()
        )
        .into());
    }
    let output = machine
        .exec_with("/usr/bin/cat", |options| {
            options.stdin_bytes("ordinary-execution-output\n")
        })
        .await?;
    if !matches!(output.result(), ExecutionResult::Exited { code: Some(0) }) {
        let _ = machine.stop().await;
        let _ = machine.remove().await;
        return Err("ordinary execution failed".into());
    }
    if output.stdout_bytes() != b"ordinary-execution-output\n" {
        let _ = machine.stop().await;
        let _ = machine.remove().await;
        return Err("fixed stdin was not delivered after guest Started".into());
    }
    machine.stop().await?;
    eprintln!("ordinary execution preserved default user and fixed stdin");
    machine.remove().await?;
    Ok(())
}
