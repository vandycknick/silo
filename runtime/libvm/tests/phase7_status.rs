use std::time::Duration;

use libvm::{
    ImageSource, MachineAgentStatus, MachineFreshness, MachineStopOptions, MachineUserConfig,
    Memory, Runtime, RuntimeConfig,
};

#[tokio::test]
async fn phase7_generic_status_real_kvm() {
    if std::env::var("SILO_E2E_KVM").as_deref() != Ok("1") {
        eprintln!("SKIPPED: SILO_E2E_KVM=1 is required for actual generic status qualification");
        return;
    }
    let (Ok(root), Ok(disk)) = (
        std::env::var("SILO_TEST_RUNTIME_ROOT"),
        std::env::var("SILO_TEST_DISK_IMAGE"),
    ) else {
        eprintln!("SKIPPED: SILO_TEST_RUNTIME_ROOT and SILO_TEST_DISK_IMAGE are required");
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let runtime = Runtime::new(RuntimeConfig::local(home.path()).with_runtime_root(root))
        .await
        .unwrap();
    let machine = runtime
        .machine()
        .name("phase7-generic-status")
        .image_source(ImageSource::disk(disk))
        .cpus(1)
        .memory(Memory::gibibytes(1))
        .vsock(true)
        .network(|network| network.none())
        .guest(|guest| guest.user(MachineUserConfig::new("silo", 1000, 1000, "/home/silo")))
        .create()
        .await
        .unwrap();
    let outcome = async {
        let start = machine.start().await?;
        let ready = machine.wait_ready(Duration::from_secs(30)).await?;
        eyre::ensure!(ready.status.readiness.ready, "guest was not ready");
        eyre::ensure!(ready.status.run_id.as_ref() == Some(&start.run_id), "WaitReady lost launch run identity");
        let status = machine.monitor_status().await?;
        eyre::ensure!(status.run_id.as_ref() == Some(&start.run_id), "GetStatus lost launch run identity");
        eyre::ensure!(status.monitor.instance_id != start.run_id.as_str(), "monitor instance was substituted for run identity");
        let expected_machine = uuid::Uuid::parse_str(&machine.id())?.to_string();
        eyre::ensure!(status.machine_id == expected_machine, "GetStatus returned a different machine");
        let MachineAgentStatus::Enabled(agent) = status.agent else { eyre::bail!("agent disabled"); };
        let observation = agent.status.ok_or_else(|| eyre::eyre!("missing guest status"))?;
        eyre::ensure!(observation.freshness == MachineFreshness::Fresh, "guest report stale");
        let ssh = observation.report.ssh.ok_or_else(|| eyre::eyre!("missing actual listener descriptor"))?;
        eyre::ensure!(ssh.config_verified && ssh.kex_verified && ssh.port == 22, "SSH config/KEX not verified");
        let key = ssh_key::PublicKey::from_openssh(&ssh.host_public_key)?;
        eprintln!("PASS: actual generic gRPC status machine={} run={} monitor={} fresh=true config_verified=true kex_verified=true host_key={}", status.machine_id, start.run_id, status.monitor.instance_id, key.fingerprint(ssh_key::HashAlg::Sha256));
        Ok::<(), eyre::Report>(())
    }.await;
    let stopped = machine
        .stop_with(
            MachineStopOptions::new()
                .timeout(Duration::from_secs(10))
                .force_after_timeout(Duration::from_secs(10)),
        )
        .await;
    if outcome.is_err() || stopped.is_err() {
        eprintln!(
            "failed stopped fixture retained at {}",
            home.keep().display()
        );
    } else {
        machine.remove().await.unwrap();
    }
    stopped.expect("stop actual VM");
    outcome.expect("actual generic status contract");
}
