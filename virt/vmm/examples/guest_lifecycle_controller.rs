//! Explicit smoke executable, never a Cargo test. Uses production VM/worker/mux.
//!
//! Cold mode: `guest-lifecycle-controller FIXTURE_JSON` owns one normal VM.
//! Attach mode: `guest-lifecycle-controller --attach REQUEST_JSON` owns only an
//! inherited, already-connected native mux stream (see `attach`).
#![allow(dead_code)]
#[path = "guest_lifecycle_controller/attach/mod.rs"]
mod attach;
#[cfg(test)]
#[path = "../build_inputs.rs"]
mod build_inputs;
#[path = "../src/capabilities.rs"]
mod capabilities;
#[path = "../src/clock_sync.rs"]
mod clock_sync;
#[path = "../src/context.rs"]
mod context;
#[cfg(test)]
#[path = "../dependency_source.rs"]
mod dependency_source;
#[path = "../src/durable_file.rs"]
mod durable_file;
#[path = "../src/exec_log.rs"]
mod exec_log;
#[path = "../src/execution.rs"]
mod execution;
#[path = "../src/exit_command.rs"]
mod exit_command;
#[path = "../src/exit_status.rs"]
mod exit_status;
#[path = "../src/ext.rs"]
mod ext;
#[path = "../src/finalize.rs"]
mod finalize;
#[path = "../src/forward/mod.rs"]
mod forward;
#[path = "../src/guest.rs"]
mod guest;
#[path = "../src/krun/mod.rs"]
mod krun;
#[path = "../src/live.rs"]
mod live;
#[path = "../src/lock/mod.rs"]
mod lock;
#[path = "../src/machine.rs"]
mod machine;
#[path = "../src/restore/mod.rs"]
mod restore;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "../src/rosetta/mod.rs"]
mod rosetta;
#[path = "../src/secure_file.rs"]
mod secure_file;
#[path = "../src/services.rs"]
mod services;
#[path = "../src/shutdown.rs"]
mod shutdown;
#[path = "../src/start_request.rs"]
mod start_request;
#[path = "../src/startup.rs"]
mod startup;
#[path = "../src/state.rs"]
mod state;
#[path = "../src/virt/mod.rs"]
mod virt;
#[path = "../src/vsock/mod.rs"]
mod vsock;

use eyre::{ensure, Context};
use protocol::v1::guest_agent_service_client::GuestAgentServiceClient;
use protocol::v1::guest_filesystem_service_client::GuestFilesystemServiceClient;
use protocol::v1::{self, GuestLifecycleState as LiveState};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Channel;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    kernel: PathBuf,
    initramfs: PathBuf,
    directory: PathBuf,
    machine_id: String,
    run_id: String,
    root: vm_spec::Disk,
    expect_unsupported: bool,
}

fn main() -> eyre::Result<std::process::ExitCode> {
    if krun::worker::invoked_as_worker() {
        krun::worker::main()?;
        return Ok(std::process::ExitCode::SUCCESS);
    }
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments
        .next()
        .ok_or_else(|| eyre::eyre!("fixture JSON path or --attach REQUEST_JSON required"))?;
    if first == "--attach" {
        let request = arguments
            .next()
            .ok_or_else(|| eyre::eyre!("--attach requires a REQUEST_JSON path"))?;
        ensure!(arguments.next().is_none(), "unexpected attach argument");
        return Ok(attach::main(std::path::Path::new(&request)));
    }
    let bytes = std::fs::read(first)?;
    ensure!(bytes.len() <= 65536, "oversized fixture");
    let fixture: Fixture = serde_json::from_slice(&bytes)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(fixture))?;
    Ok(std::process::ExitCode::SUCCESS)
}

async fn run(fixture: Fixture) -> eyre::Result<()> {
    protocol::shutdown::validate_uuid(&fixture.machine_id).map_err(|error| eyre::eyre!(error))?;
    protocol::shutdown::validate_uuid(&fixture.run_id).map_err(|error| eyre::eyre!(error))?;
    let lease_path = fixture.directory.join("controller.lease");
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(lease_path)?;
    let lease = nix::fcntl::Flock::lock(lease, nix::fcntl::FlockArg::LockSharedNonblock)
        .map_err(|(_, error)| eyre::eyre!(error))?;
    let metadata = lease.metadata()?;
    let launch = virt::StorageLaunch {
        machine_id: fixture.machine_id.clone(),
        run_id: fixture.run_id.clone(),
        binding: protocol::shutdown::StorageLeaseBinding {
            operation_id: uuid::Uuid::new_v4().to_string(),
            file_device: metadata.dev(),
            file_inode: metadata.ino(),
        },
        lease: Arc::new(lease.try_clone()?.into()),
        holder_path: fixture.directory.join("vm.storage-holder.json"),
    };
    let config = virt::VmConfig::builder("guest-lifecycle-smoke")
        .vm_id(&fixture.machine_id)
        .base_directory(&fixture.directory)
        .cpus(2)
        .memory(512)
        .kernel(&fixture.kernel)
        .initramfs(&fixture.initramfs)
        // Root selection comes only from the composite initramfs's bootstrap.
        .kernel_cmdline(vec!["console=hvc0".into()])
        .no_network()
        .disk(fixture.root.clone())
        .build()
        .with_storage_launch(launch);
    let machine = virt::VirtualMachine::with_backend(virt::BackendKind::Krun, config)?;
    machine
        .serial()
        .add_sink(tokio::fs::File::create(fixture.directory.join("serial.log")).await?)
        .await;
    let result = match tokio::time::timeout(Duration::from_secs(120), async {
        machine.start().await?;
        checks(&machine, &fixture).await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(eyre::eyre!("guest lifecycle smoke deadline")),
    };
    // Cleanup always runs, including timeout and failed assertions while frozen.
    let stopped = machine.force_stop().await;
    let waited = machine.wait().await;
    let finalized = machine.finalize_storage(false).await;
    drop(lease);
    result?;
    stopped.context("stop owned smoke worker")?;
    waited.context("reap owned smoke worker")?;
    finalized.context("close owned smoke attachments")?;
    Ok(())
}

async fn ready(machine: &virt::VirtualMachine) -> eyre::Result<(Channel, v1::AgentStatus)> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(channel) = guest::connect(machine).await {
            let mut client = GuestAgentServiceClient::new(channel.clone());
            if let Ok(response) = client.get_status(v1::GetAgentStatusRequest {}).await {
                let status = response.into_inner();
                if status.report.as_ref().and_then(|report| report.state)
                    == Some(v1::AgentStatusState::Ready as i32)
                {
                    return Ok((channel, status));
                }
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "agent did not become Ready; inspect serial.log"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn expected(status: &v1::AgentStatus) -> eyre::Result<v1::ExpectedGuestIdentity> {
    let identity = status
        .identity
        .as_ref()
        .ok_or_else(|| eyre::eyre!("missing agent identity"))?;
    let live = status
        .report
        .as_ref()
        .and_then(|report| report.lifecycle.as_ref())
        .ok_or_else(|| eyre::eyre!("missing lifecycle status"))?;
    Ok(v1::ExpectedGuestIdentity {
        machine_id: live.machine_id.clone(),
        run_id: live.run_id.clone(),
        agent_instance_id: identity
            .instance_id
            .clone()
            .ok_or_else(|| eyre::eyre!("missing instance"))?,
        boot_id: identity
            .boot_id
            .clone()
            .ok_or_else(|| eyre::eyre!("missing boot"))?,
    })
}

async fn read(channel: &Channel, path: &str) -> eyre::Result<Vec<u8>> {
    let mut client = GuestFilesystemServiceClient::new(channel.clone());
    let mut stream = client
        .download_file(v1::DownloadFileRequest {
            path: Some(path.into()),
        })
        .await?
        .into_inner();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.message().await? {
        bytes.extend(
            chunk
                .data
                .ok_or_else(|| eyre::eyre!("missing byte chunk"))?,
        );
        ensure!(bytes.len() <= 65536, "oversized control observation");
    }
    Ok(bytes)
}
async fn frozen(channel: &Channel) -> eyre::Result<bool> {
    let bytes = read(channel, "/sys/fs/cgroup/silo/workloads/cgroup.events").await?;
    let text = std::str::from_utf8(&bytes)?;
    match text.lines().find_map(|line| line.strip_prefix("frozen ")) {
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        _ => eyre::bail!("missing/malformed kernel frozen event"),
    }
}
async fn counter(channel: &Channel) -> eyre::Result<u64> {
    counter_at(channel, "/lifecycle-counter").await
}
async fn counter_at(channel: &Channel, path: &str) -> eyre::Result<u64> {
    let mut client = GuestFilesystemServiceClient::new(channel.clone());
    let entry = client
        .get_entry(v1::GetEntryRequest {
            path: Some(path.into()),
        })
        .await?
        .into_inner();
    entry
        .size_bytes
        .ok_or_else(|| eyre::eyre!("counter size absent"))
}
async fn growing(channel: &Channel, previous: u64) -> eyre::Result<u64> {
    growing_at(channel, "/lifecycle-counter", previous).await
}
async fn growing_at(channel: &Channel, path: &str, previous: u64) -> eyre::Result<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let value = counter_at(channel, path).await?;
        if value > previous {
            return Ok(value);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "workload counter did not advance"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct SshKey {
    expected: russh::keys::PublicKey,
}
impl russh::client::Handler for SshKey {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(key.key_data() == self.expected.key_data())
    }
}

async fn ssh_counter(
    machine: &virt::VirtualMachine,
    fixture: &Fixture,
    status: &v1::AgentStatus,
) -> eyre::Result<(
    russh::client::Handle<SshKey>,
    russh::Channel<russh::client::Msg>,
)> {
    let descriptor = status
        .report
        .as_ref()
        .and_then(|report| report.ssh.as_ref())
        .ok_or_else(|| eyre::eyre!("missing SSH host key descriptor"))?;
    let key = russh::keys::PublicKey::from_openssh(&descriptor.host_public_key)?;
    let stream = machine.connect_vsock(agent_spec::SSH_VSOCK_PORT).await?;
    let mut client = russh::client::connect_stream(
        Arc::new(Default::default()),
        stream,
        SshKey { expected: key },
    )
    .await?;
    let private = Arc::new(russh::keys::PrivateKey::read_openssh_file(
        fixture.directory.join("client"),
    )?);
    let certificate = russh::keys::ssh_key::Certificate::from_openssh(&std::fs::read_to_string(
        fixture.directory.join("client-cert.pub"),
    )?)?;
    ensure!(
        client
            .authenticate_openssh_cert("root", private, certificate)
            .await?
            .success(),
        "SSH CA authentication failed"
    );
    let channel = client.channel_open_session().await?;
    channel.exec(true, "cat /proc/self/cgroup >/lifecycle-ssh-membership; while :; do printf x >>/lifecycle-ssh-counter; sleep 0.02; done").await?;
    Ok((client, channel))
}

async fn checks(machine: &virt::VirtualMachine, fixture: &Fixture) -> eyre::Result<()> {
    let (channel, initial) = ready(machine).await?;
    let identity = expected(&initial)?;
    ensure!(
        identity.machine_id == fixture.machine_id && identity.run_id == fixture.run_id,
        "launch identity mismatch"
    );
    let mut client = GuestAgentServiceClient::new(channel.clone());
    let reference = v1::FreezeRef {
        machine_id: identity.machine_id.clone(),
        run_id: identity.run_id.clone(),
        operation_id: uuid::Uuid::new_v4().to_string(),
        freeze_epoch: Some(1),
    };
    let freeze = v1::FreezeWorkloadsRequest {
        expected: Some(identity.clone()),
        freeze_ref: Some(reference.clone()),
        deadline_ms: Some(5000),
    };
    if fixture.expect_unsupported {
        let error = client
            .freeze_workloads(freeze)
            .await
            .err()
            .ok_or_else(|| eyre::eyre!("image-owned profile unexpectedly froze"))?;
        ensure!(
            error.code() == tonic::Code::FailedPrecondition
                && error.message().contains("InitChild"),
            "unnamed profile refusal: {error}"
        );
        ensure!(
            !frozen(&channel).await?,
            "unsupported profile changed kernel freeze"
        );
        println!(
            "{}",
            serde_json::json!({"result":"unsupported-profile-refused", "reason":error.message()})
        );
        return Ok(());
    }
    let boot = initial
        .report
        .as_ref()
        .and_then(|report| report.boot.as_ref())
        .ok_or_else(|| eyre::eyre!("missing boot report"))?;
    ensure!(
        boot.agent_is_pid1 == Some(true),
        "positive smoke requires AgentPid1"
    );
    // An empty workload subtree must still establish the real kernel barrier.
    let empty = client.freeze_workloads(freeze.clone()).await?.into_inner();
    ensure!(
        empty.status.as_ref().map(|status| status.state) == Some(LiveState::Frozen as i32)
            && frozen(&channel).await?,
        "empty freeze did not complete"
    );
    client
        .thaw(v1::ThawRequest {
            expected: Some(identity.clone()),
            freeze_ref: Some(reference.clone()),
            rollback: false,
            deadline_ms: Some(5000),
        })
        .await?;
    let userdata_membership =
        String::from_utf8(read(&channel, "/lifecycle-userdata-membership").await?)?;
    ensure!(
        userdata_membership
            .lines()
            .any(|line| line == "0::/silo/workloads"),
        "userdata escaped containment: {userdata_membership}"
    );
    let (ssh, _ssh_channel) = ssh_counter(machine, fixture, &initial).await?;

    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    let start = v1::StartGuestProcess { execution_id: uuid::Uuid::new_v4().to_string(), expected_agent_instance_id: identity.agent_instance_id.clone(), expected_agent_boot_id: identity.boot_id.clone(),
        process: Some(v1::ProcessSpec { argv: vec!["/bin/sh".into(), "-c".into(), r#"cat /proc/self/cgroup >/lifecycle-membership; ( ( /bin/sh -c 'mkdir -p /sys/fs/cgroup/silo/workloads/nested; echo 0 >/sys/fs/cgroup/silo/workloads/nested/cgroup.procs; cat /proc/self/cgroup >/lifecycle-descendant-membership; while :; do printf x >>/lifecycle-descendant-counter; sleep 0.02; done' </dev/null >/dev/null 2>&1 & ) & ); : >/lifecycle-counter; while :; do printf x >>/lifecycle-counter; sleep 0.02; done"#.into()], working_directory: Some("/".into()), user: Some("root".into()), environment: Vec::new(), stdio: Some(v1::process_spec::Stdio::Pipes(v1::PipeStdio { stdin: false })) }) };
    sender
        .send(v1::GuestProcessInput {
            message: Some(v1::guest_process_input::Message::Start(start)),
        })
        .await?;
    let mut processes =
        protocol::v1::guest_process_service_client::GuestProcessServiceClient::new(channel.clone());
    let mut process = processes
        .execute(tokio_stream::wrappers::ReceiverStream::new(receiver))
        .await?
        .into_inner();
    let first = process
        .message()
        .await?
        .ok_or_else(|| eyre::eyre!("counter launch stream ended"))?;
    ensure!(
        matches!(
            first.event,
            Some(v1::guest_process_event::Event::Started(_))
        ),
        "counter failed to start: {first:?}"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let before = loop {
        match counter(&channel).await {
            Ok(value) if value > 0 => break value,
            _ => {}
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "counter file was not created"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let advancing = growing(&channel, before).await?;
    let membership = String::from_utf8(read(&channel, "/lifecycle-membership").await?)?;
    ensure!(
        membership.lines().any(|line| line == "0::/silo/workloads"),
        "native exec escaped containment: {membership}"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if counter_at(&channel, "/lifecycle-ssh-counter")
            .await
            .is_ok_and(|value| value > 0)
            && counter_at(&channel, "/lifecycle-descendant-counter")
                .await
                .is_ok_and(|value| value > 0)
        {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "SSH/double-fork counters did not start"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let ssh_membership = String::from_utf8(read(&channel, "/lifecycle-ssh-membership").await?)?;
    let descendant_membership =
        String::from_utf8(read(&channel, "/lifecycle-descendant-membership").await?)?;
    ensure!(
        ssh_membership
            .lines()
            .any(|line| line == "0::/silo/workloads"),
        "SSH escaped containment"
    );
    ensure!(
        descendant_membership
            .lines()
            .any(|line| line == "0::/silo/workloads/nested"),
        "double-fork descendant escaped nested workload containment"
    );
    let ssh_before = counter_at(&channel, "/lifecycle-ssh-counter").await?;
    growing_at(&channel, "/lifecycle-ssh-counter", ssh_before).await?;
    let descendant_before = counter_at(&channel, "/lifecycle-descendant-counter").await?;
    growing_at(&channel, "/lifecycle-descendant-counter", descendant_before).await?;
    let mut second_ref = reference.clone();
    second_ref.freeze_epoch = Some(2);
    let second = v1::FreezeWorkloadsRequest {
        expected: Some(identity.clone()),
        freeze_ref: Some(second_ref.clone()),
        deadline_ms: Some(5000),
    };
    let mut left_client = client.clone();
    let mut right_client = client.clone();
    let (left, right) = tokio::join!(
        left_client.freeze_workloads(second.clone()),
        right_client.freeze_workloads(second.clone())
    );
    let response = left?.into_inner();
    ensure!(
        response == right?.into_inner(),
        "concurrent exact freezes returned different completions"
    );
    ensure!(
        frozen(&channel).await?,
        "freeze response preceded kernel event"
    );
    let stopped = counter(&channel).await?;
    let ssh_stopped = counter_at(&channel, "/lifecycle-ssh-counter").await?;
    let descendant_stopped = counter_at(&channel, "/lifecycle-descendant-counter").await?;
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(80)).await;
        ensure!(
            counter(&channel).await? == stopped,
            "frozen workload advanced"
        );
        ensure!(
            counter_at(&channel, "/lifecycle-ssh-counter").await? == ssh_stopped,
            "frozen SSH workload advanced"
        );
        ensure!(
            counter_at(&channel, "/lifecycle-descendant-counter").await? == descendant_stopped,
            "frozen nested descendant advanced"
        );
        let status = tokio::time::timeout(
            Duration::from_secs(1),
            client.get_status(v1::GetAgentStatusRequest {}),
        )
        .await??
        .into_inner();
        ensure!(
            status.report.as_ref().and_then(|report| report.state)
                != Some(v1::AgentStatusState::Ready as i32),
            "frozen workload advertised Ready"
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            client.get_metrics(v1::GetAgentMetricsRequest {}),
        )
        .await??;
    }
    let mut files = GuestFilesystemServiceClient::new(channel.clone());
    ensure!(
        files
            .create_directory(v1::CreateDirectoryRequest {
                path: Some("/must-not-mutate".into()),
                ..Default::default()
            })
            .await
            .is_err(),
        "filesystem mutation admitted frozen"
    );
    let thaw = v1::ThawRequest {
        expected: Some(identity.clone()),
        freeze_ref: Some(second_ref.clone()),
        rollback: false,
        deadline_ms: Some(5000),
    };
    // Intentionally discard this exact reply after independently observing thaw.
    let lost_client = client.clone();
    let lost_request = thaw.clone();
    let lost = tokio::spawn(async move {
        let mut client = lost_client;
        client.thaw(lost_request).await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while frozen(&channel).await? {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "lost-reply thaw never took effect"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    lost.abort();
    let _ = lost.await;
    let resumed = growing(&channel, stopped).await?;
    ensure!(
        client.freeze_workloads(second).await.is_err(),
        "old cached freeze certified thawed workload"
    );
    let mut third_ref = second_ref.clone();
    third_ref.freeze_epoch = Some(3);
    let recovery = client
        .freeze_workloads(v1::FreezeWorkloadsRequest {
            expected: Some(identity.clone()),
            freeze_ref: Some(third_ref.clone()),
            deadline_ms: Some(5000),
        })
        .await?
        .into_inner();
    ensure!(
        frozen(&channel).await?,
        "lost-thaw recovery did not actually refreeze"
    );
    ensure!(
        client.thaw(thaw).await.is_err(),
        "stale epoch thaw released recovery freeze"
    );
    let recovered = counter(&channel).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    ensure!(
        counter(&channel).await? == recovered && frozen(&channel).await?,
        "stale thaw allowed counter progress"
    );
    let final_thaw = v1::ThawRequest {
        expected: Some(identity.clone()),
        freeze_ref: Some(third_ref),
        rollback: false,
        deadline_ms: Some(5000),
    };
    let thawed = client.thaw(final_thaw.clone()).await?.into_inner();
    ensure!(
        client.thaw(final_thaw).await?.into_inner() == thawed,
        "duplicate thaw changed settled result"
    );
    let final_counter = growing(&channel, recovered).await?;
    growing_at(&channel, "/lifecycle-ssh-counter", ssh_stopped).await?;
    growing_at(
        &channel,
        "/lifecycle-descendant-counter",
        descendant_stopped,
    )
    .await?;
    let final_status = client
        .get_status(v1::GetAgentStatusRequest {})
        .await?
        .into_inner();
    ensure!(
        expected(&final_status)? == identity,
        "source freeze/thaw rotated identity"
    );
    sender
        .send(v1::GuestProcessInput {
            message: Some(v1::guest_process_input::Message::SignalProcess(
                v1::SignalProcess { signal: Some(9) },
            )),
        })
        .await?;
    while process.message().await?.is_some() {}
    ssh.disconnect(russh::Disconnect::ByApplication, "smoke complete", "en")
        .await?;
    match ssh.await {
        Ok(()) | Err(russh::Error::Disconnect) => {}
        Err(error) => return Err(error.into()),
    }
    println!(
        "{}",
        serde_json::json!({"result":"cold-freeze-thaw", "machineId":identity.machine_id, "runId":identity.run_id,
        "bootId":identity.boot_id, "agentInstanceId":identity.agent_instance_id, "membership":membership,
        "sshMembership":ssh_membership, "userdataMembership":userdata_membership, "descendantMembership":descendant_membership,
        "counterBefore":before, "counterAdvancing":advancing, "counterFrozen":stopped, "counterResumed":resumed,
        "counterRecoveryFrozen":recovered, "counterFinal":final_counter, "recoveryEpoch":recovery.status.and_then(|status| status.freeze_ref).and_then(|reference| reference.freeze_epoch),
        "lostThawReply":"intentionally-discarded-after-independent-kernel-observation", "restoreGenerationEvidence":"not-exercised"})
    );
    Ok(())
}
