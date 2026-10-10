//! File transfer qualification through the actual CLI and guest filesystem service.
use std::path::Path;
use std::time::Duration;

use libvm::{MachineReadinessOutcome, Runtime, RuntimeConfig};
use sha2::{Digest, Sha256};

async fn cp(home: &Path, directory: &Path, args: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_silo"));
    command
        .env("SILO_HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .current_dir(directory)
        .arg("cp")
        .args(args);
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn cp_real_vm_round_trip() {
    if std::env::var("SILO_E2E_KVM").as_deref() != Ok("1") {
        eprintln!("SKIPPED cp VM: SILO_E2E_KVM=1 is required");
        return;
    }
    assert!(
        Path::new("/dev/kvm").exists(),
        "SILO_E2E_KVM=1 requires /dev/kvm"
    );
    let (Some(root), Ok(image)) = (
        std::env::var_os("SILO_TEST_RUNTIME_ROOT"),
        std::env::var("SILO_TEST_IMAGE"),
    ) else {
        eprintln!("SKIPPED cp VM: SILO_TEST_RUNTIME_ROOT and SILO_TEST_IMAGE are required");
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::new(RuntimeConfig::local(home.path()).with_runtime_root(root))
        .await
        .unwrap();
    let machine = runtime
        .machine()
        .name("cp-round-trip")
        .image(image)
        .vsock(true)
        .create()
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(210), async {
        machine.start().await?;
        let ready = machine.wait_ready(Duration::from_secs(90)).await?;
        eyre::ensure!(
            ready.outcome == MachineReadinessOutcome::Ready,
            "guest not ready"
        );
        let bytes: Vec<u8> = (0..300 * 1024).map(|index| (index % 251) as u8).collect();
        tokio::fs::write(directory.path().join("in.bin"), &bytes).await?;
        tokio::fs::create_dir(directory.path().join("dir")).await?;
        let destination = format!("{}:/root/in.bin", machine.id());
        for disposition in ["created", "replaced"] {
            let output = cp(
                home.path(),
                directory.path(),
                &["./in.bin", &destination, "--format", "json"],
            )
            .await;
            eyre::ensure!(
                output.status.success(),
                "upload failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let summary: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            eyre::ensure!(
                summary["direction"] == "upload"
                    && summary["vm"] == machine.id()
                    && summary["path"] == "/root/in.bin"
                    && summary["bytes"] == bytes.len()
                    && summary["sha256"]
                        == Sha256::digest(&bytes)
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    && summary["disposition"] == disposition,
                "unexpected upload summary: {summary}"
            );
        }
        let output = cp(home.path(), directory.path(), &[&destination, "./out.bin"]).await;
        eyre::ensure!(
            output.status.success(),
            "download failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        eyre::ensure!(output.stdout.is_empty(), "human summary polluted stdout");
        eyre::ensure!(
            tokio::fs::read(directory.path().join("out.bin")).await? == bytes,
            "round-trip differs"
        );
        let output = cp(home.path(), directory.path(), &["./dir", &destination]).await;
        eyre::ensure!(
            output.status.code() == Some(1),
            "directory upload must exit 1"
        );
        eyre::ensure!(
            String::from_utf8_lossy(&output.stderr).contains("is a directory; use: exec")
                && String::from_utf8_lossy(&output.stderr).contains("-- tar -xC DIR < bundle.tar"),
            "missing tar hint"
        );
        Ok::<(), eyre::Report>(())
    })
    .await;
    let stopped = machine.stop().await;
    let removed = machine.remove().await;
    result.unwrap().unwrap();
    stopped.unwrap();
    removed.unwrap();
}
