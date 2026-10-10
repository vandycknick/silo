#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};

use eyre::{ensure, eyre, Result};
use libvm::{
    ExecutionResult, ImageSource, Machine, MachineAgentStatus, MachineFreshness,
    MachineMonitorStatus, MachineSshBackend, MachineStopOptions, MachineUserConfig, Memory,
    Runtime, RuntimeConfig,
};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug)]
enum Case {
    AgentOwned,
    SystemdOwned,
    FailureRecovery,
}

impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::AgentOwned => "ssh-verification-agent-owned",
            Self::SystemdOwned => "ssh-verification-systemd-owned",
            Self::FailureRecovery => "ssh-verification-failure-recovery",
        }
    }

    fn backend(self) -> MachineSshBackend {
        match self {
            Self::AgentOwned => MachineSshBackend::OpenSsh,
            Self::SystemdOwned | Self::FailureRecovery => MachineSshBackend::SystemdOpenSsh,
        }
    }
}

#[tokio::test]
async fn ssh_verification_agent_owned_real_kvm() {
    qualify(Case::AgentOwned).await;
}

#[tokio::test]
async fn ssh_verification_systemd_owned_real_kvm() {
    qualify(Case::SystemdOwned).await;
}

#[tokio::test]
async fn ssh_verification_failure_recovery_real_kvm() {
    qualify(Case::FailureRecovery).await;
}

async fn qualify(case: Case) {
    if std::env::var("SILO_E2E_KVM").as_deref() != Ok("1") {
        eprintln!("SKIPPED: SILO_E2E_KVM=1 is required for actual SSH lifecycle qualification");
        return;
    }
    // An explicitly enabled qualification must fail, not silently skip, missing prerequisites.
    let root = std::env::var("SILO_TEST_RUNTIME_ROOT").expect("set fresh release runtime root");
    let disk =
        std::env::var("SILO_TEST_DISK_IMAGE").expect("set disposable systemd/OpenSSH base disk");
    File::options()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .expect("accessible KVM");
    ensure_release_stage(Path::new(&root)).expect("release runtime prerequisites");
    let home = tempfile::tempdir().expect("isolated Silo home");
    let runtime = Runtime::new(RuntimeConfig::local(home.path()).with_runtime_root(root))
        .await
        .expect("isolated runtime");
    // ImageSource::disk is cloned/copied into the machine directory by MachineBuilder.
    let machine = runtime
        .machine()
        .name(case.name())
        .image_source(ImageSource::disk(disk))
        .cpus(1)
        .memory(Memory::gibibytes(1))
        .vsock(true)
        .network(|network| network.none())
        .guest(|guest| guest.user(MachineUserConfig::new("silo", 1000, 1000, "/home/silo")))
        .userdata(userdata(case))
        .create()
        .await
        .expect("create disposable fixture");
    let mut evidence =
        File::create(home.path().join("ssh-qualification.log")).expect("evidence log");
    let outcome = match tokio::time::timeout(
        Duration::from_secs(210),
        exercise(&machine, case, &mut evidence),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => Err(eyre!("qualification exceeded 210 seconds")),
    };
    // Do not propagate any exercise error before bounded teardown of this fixture.
    let stopped = tokio::time::timeout(
        Duration::from_secs(30),
        machine.stop_with(
            MachineStopOptions::new()
                .timeout(Duration::from_secs(10))
                .force_after_timeout(Duration::from_secs(10)),
        ),
    )
    .await;
    let stop_ok = matches!(&stopped, Ok(Ok(_)));
    if outcome.is_err() || !stop_ok {
        let _ = writeln!(evidence, "outcome={outcome:?} teardown={stopped:?}");
        eprintln!(
            "failed fixture artifacts retained at {}",
            home.keep().display()
        );
    } else {
        machine.remove().await.expect("remove stopped fixture");
    }
    stopped
        .expect("bounded fixture teardown")
        .expect("stop fixture VM");
    outcome.expect("actual SSH readiness lifecycle qualification");
}

fn ensure_release_stage(root: &Path) -> Result<()> {
    ensure!(
        root.file_name().is_some_and(|name| name == "release"),
        "qualification requires release runtime stage"
    );
    for entry in [
        "runtime-manifest.json",
        "bin/silo-vmm",
        "bin/netd",
        "assets/agent",
        "assets/kernel-default",
        "assets/initramfs",
    ] {
        ensure!(root.join(entry).is_file(), "missing staged {entry}");
    }
    Ok(())
}

fn userdata(case: Case) -> String {
    let ownership = match case {
        Case::AgentOwned => "timeout 5 systemctl mask --runtime sshd-vsock.socket\ntimeout 5 systemctl stop sshd-vsock.socket",
        Case::SystemdOwned | Case::FailureRecovery => "timeout 5 systemctl daemon-reload\ntimeout 5 systemctl start sshd-vsock.socket\ntimeout 5 systemctl is-active --quiet sshd-vsock.socket",
    };
    format!(
        r#"#!/bin/sh
set -eu
for binary in systemctl journalctl systemd-run ss timeout cat tee; do command -v "$binary"; done
test -x /usr/lib/systemd/system-generators/systemd-ssh-generator
test -x /usr/sbin/sshd
# The manager can be starting during root provisioning. Bound each RPC and the whole wait.
timeout 15 /bin/sh -c 'until timeout 1 systemctl show --property=Version >/dev/null 2>&1; do sleep 0.2; done'
{ownership}
cat > /run/silo-test-certificate-login <<'EOF'
#!/bin/sh
printf 'Silo certificate login qualified\n' | tee /run/silo-test-certificate-success
exit 0
EOF
chmod 755 /run/silo-test-certificate-login
"#
    )
}

async fn root_exec(machine: &Machine, script: &str) -> Result<String> {
    let output = machine
        .exec_with("/bin/sh", |options| {
            options
                .args(["-eu", "-c", script])
                .user("root")
                .env("LC_ALL", "C")
                .timeout(Duration::from_secs(10))
        })
        .await?;
    ensure!(
        matches!(output.result(), ExecutionResult::Exited { code: Some(0) }),
        "guest inspection failed: {:?}, stderr={}",
        output.result(),
        output.stderr()?
    );
    Ok(output.stdout()?)
}

fn record(evidence: &mut File, label: &str, value: impl std::fmt::Display) -> Result<()> {
    eprintln!("{label}: {value}");
    writeln!(evidence, "{label}: {value}")?;
    evidence.flush()?;
    Ok(())
}

async fn exercise(machine: &Machine, case: Case, evidence: &mut File) -> Result<()> {
    let start = machine.start().await?;
    let ready = machine.wait_ready(Duration::from_secs(35)).await?;
    ensure!(
        ready.status.run_id.as_ref() == Some(&start.run_id),
        "wrong launch identity"
    );
    assert_status(&ready.status, case, true)?;
    record(evidence, "initial readiness", format!("{:?}", ready.status))?;
    if matches!(case, Case::AgentOwned) {
        let loss = root_exec(
            machine,
            r#"
systemctl unmask --runtime sshd-vsock.socket
systemctl daemon-reload
if systemctl start sshd-vsock.socket; then echo 'losing socket unexpectedly bound' >&2; exit 1; fi
test "$(systemctl show sshd-vsock.socket -p ActiveState --value)" = failed
journalctl -b -u sshd-vsock.socket --no-pager
"#,
        )
        .await?;
        ensure!(
            loss.to_lowercase().contains("address already in use"),
            "missing EADDRINUSE evidence: {loss}"
        );
        record(evidence, "expected losing systemd bind", loss)?;
    }
    inspect_listener(machine, case, evidence).await?;
    // Exercise libvm's real pin check and certificate authentication, outside the idle window.
    // A test-only shell exits without needing interactive terminal input.
    let (_signals, receiver) = tokio::sync::mpsc::channel(1);
    let login = tokio::time::timeout(
        Duration::from_secs(15),
        machine.attach_shell_with_signals(
            |options| {
                options
                    .user("root")
                    .env("SHELL", "/run/silo-test-certificate-login")
            },
            receiver,
        ),
    )
    .await??;
    ensure!(
        login.success && login.code == 0,
        "certificate SSH failed: {login:?}"
    );
    let login_output = root_exec(machine, "cat /run/silo-test-certificate-success").await?;
    ensure!(
        login_output.trim() == "Silo certificate login qualified",
        "certificate shell did not execute"
    );
    record(
        evidence,
        "certificate login",
        format!("{login:?}, output={login_output}"),
    )?;
    record(evidence, "journal before sample", journal(machine).await?)?;
    match case {
        Case::AgentOwned | Case::SystemdOwned => healthy_sample(machine, case, evidence).await?,
        Case::FailureRecovery => failure_recovery(machine, case, evidence).await?,
    }
    record(evidence, "journal after sample", journal(machine).await?)?;
    record(evidence, "probe accounting", "healthy idle checks should be initial plus roughly one per minute, not one per five-second heartbeat; journal above is retained without matching OpenSSH prose")?;
    inspect_listener(machine, case, evidence).await?;
    Ok(())
}

fn assert_status(status: &MachineMonitorStatus, case: Case, ready: bool) -> Result<SystemTime> {
    let MachineAgentStatus::Enabled(agent) = &status.agent else {
        return Err(eyre!("agent disabled"));
    };
    let observation = agent
        .status
        .as_ref()
        .ok_or_else(|| eyre!("missing guest observation"))?;
    ensure!(
        observation.freshness == MachineFreshness::Fresh,
        "guest status stale"
    );
    let ssh = observation
        .report
        .ssh
        .as_ref()
        .ok_or_else(|| eyre!("missing SSH descriptor"))?;
    ensure!(
        ssh.backend == case.backend() && ssh.port == 22 && ssh.config_verified,
        "unexpected SSH descriptor: {ssh:?}"
    );
    ensure!(
        status.readiness.ready == ready && ssh.kex_verified == ready,
        "unexpected effective readiness: {status:?}"
    );
    if !ready {
        ensure!(
            observation.report.code.as_deref() == Some("SSH_NOT_READY"),
            "wrong unavailable code"
        );
    }
    Ok(observation.received_at)
}

async fn inspect_listener(
    machine: &Machine,
    case: Case,
    evidence: &mut File,
) -> Result<(usize, usize)> {
    let sockets = root_exec(machine, "ss --vsock -H -lpn").await?;
    let listeners = sockets
        .lines()
        .filter(|line| {
            line.split_ascii_whitespace()
                .any(|field| field.rsplit_once(':').is_some_and(|(_, port)| port == "22"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    ensure!(
        listeners
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
            == 1,
        "not exactly one vsock-22 listener: {sockets}"
    );
    match case {
        Case::AgentOwned => ensure!(
            listeners.contains("silo-agent"),
            "agent does not own listener: {listeners}"
        ),
        Case::SystemdOwned | Case::FailureRecovery => ensure!(
            listeners.contains("systemd") && listeners.contains("pid=1,"),
            "systemd does not own listener: {listeners}"
        ),
    }
    record(evidence, "listener ownership", listeners)?;
    let processes = root_exec(
        machine,
        r#"
count=0
total_fds=0
for process in /proc/[0-9]*; do
    test -r "$process/comm" || continue
    read -r name < "$process/comm" || continue
    case "$name" in sshd*)
        stat=$(cat "$process/stat" 2>/dev/null) || continue
        count=$((count + 1))
        fds=0
        for fd in "$process"/fd/*; do
            test -L "$fd" || continue
            fds=$((fds + 1))
        done
        total_fds=$((total_fds + fds))
        printf '%s %s fd_count=%s\n' "$process" "$stat" "$fds"
        ;;
    esac
done
printf 'totals %s %s\n' "$count" "$total_fds"
"#,
    )
    .await?;
    record(evidence, "guest sshd processes and descriptors", &processes)?;
    let totals: Vec<_> = processes
        .lines()
        .last()
        .ok_or_else(|| eyre!("missing process totals"))?
        .split_whitespace()
        .collect();
    ensure!(
        totals.len() == 3 && totals[0] == "totals",
        "malformed guest process totals"
    );
    Ok((totals[1].parse()?, totals[2].parse()?))
}

async fn journal(machine: &Machine) -> Result<String> {
    root_exec(machine, "journalctl -b --no-pager -o short-monotonic -t sshd -t sshd-session -t silo-agent; journalctl -b --no-pager -o short-monotonic -u sshd-vsock.socket -u 'sshd-vsock@*'").await
}

async fn fresh_sample(machine: &Machine, evidence: &mut File) -> Result<MachineMonitorStatus> {
    let status = machine.monitor_status().await?;
    let MachineAgentStatus::Enabled(agent) = &status.agent else {
        return Err(eyre!("agent disabled"));
    };
    let observation = agent
        .status
        .as_ref()
        .ok_or_else(|| eyre!("missing status"))?;
    ensure!(
        observation.freshness == MachineFreshness::Fresh,
        "status stale during probe lifecycle"
    );
    let metrics = machine.metrics().await?;
    let metrics = metrics.metrics.ok_or_else(|| eyre!("missing metrics"))?;
    ensure!(
        metrics.freshness == MachineFreshness::Fresh,
        "metrics stale during probe lifecycle"
    );
    record(
        evidence,
        "receipt cadence",
        format!(
            "status_received={:?} metrics_received={:?} readiness={:?} report={:?}",
            observation.received_at, metrics.received_at, status.readiness, observation.report
        ),
    )?;
    Ok(status)
}

async fn healthy_sample(machine: &Machine, case: Case, evidence: &mut File) -> Result<()> {
    let guest_before = inspect_listener(machine, case, evidence).await?;
    let profiler = Profiler::new(machine.id().as_str())?;
    let initial = profiler.sample(evidence)?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(135);
    let mut last_receipt = None;
    let mut advanced = 0;
    let mut sample = 0;
    loop {
        let status = fresh_sample(machine, evidence).await?;
        let receipt = assert_status(&status, case, true)?;
        if last_receipt.is_some_and(|last| receipt > last) {
            advanced += 1;
        }
        last_receipt = Some(receipt);
        profiler.sample(evidence)?;
        if sample % 3 == 0 {
            inspect_listener(machine, case, evidence).await?;
        }
        sample += 1;
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep_until((started + Duration::from_secs(sample * 5)).min(deadline)).await;
    }
    ensure!(
        advanced >= 20,
        "five-second guest status receipts did not continue: {advanced}"
    );
    let guest_after = inspect_listener(machine, case, evidence).await?;
    ensure!(guest_after.0 <= guest_before.0 && guest_after.1 <= guest_before.1,
        "guest sshd children/descriptors accumulated: before={guest_before:?}, after={guest_after:?}");
    profiler.finish(initial, started.elapsed(), evidence)?;
    Ok(())
}

async fn failure_recovery(machine: &Machine, case: Case, evidence: &mut File) -> Result<()> {
    let profiler = Profiler::new(machine.id().as_str())?;
    let initial = profiler.sample(evidence)?;
    record(evidence, "recovery timer", root_exec(machine, "systemd-run --unit=silo-test-restore-ssh --on-active=75s --timer-property=AccuracySec=1s -- /bin/sh -c 'systemctl start sshd-vsock.socket'; systemctl is-active --quiet silo-test-restore-ssh.timer").await?)?;
    let stopped = Instant::now();
    root_exec(machine, "systemctl stop sshd-vsock.socket; test \"$(systemctl show sshd-vsock.socket -p ActiveState --value)\" = inactive").await?;
    let mut failed_at = None;
    let mut prior_receipt = None;
    let mut advances = 0;
    loop {
        let status = fresh_sample(machine, evidence).await?;
        let elapsed = stopped.elapsed();
        let receipt = if status.readiness.ready {
            assert_status(&status, case, true)?
        } else {
            let receipt = assert_status(&status, case, false)?;
            if failed_at.is_none() {
                ensure!(
                    elapsed <= Duration::from_secs(65),
                    "failure detected too late: {elapsed:?}"
                );
                failed_at = Some(elapsed);
                record(evidence, "SSH-not-ready transition", format!("{elapsed:?}"))?;
            }
            receipt
        };
        if prior_receipt.is_some_and(|prior| receipt > prior) {
            advances += 1;
        }
        prior_receipt = Some(receipt);
        profiler.sample(evidence)?;
        if let Some(failed) = failed_at {
            if status.readiness.ready {
                ensure!(
                    elapsed <= Duration::from_secs(140),
                    "recovery detected too late"
                );
                let since_failure = elapsed - failed;
                ensure!(
                    (Duration::from_secs(59)..=Duration::from_secs(66)).contains(&since_failure)
                        || (Duration::from_secs(119)..=Duration::from_secs(131)).contains(&since_failure),
                    "recovery does not match completion-plus-60-second retry cadence: {since_failure:?}"
                );
                ensure!(
                    advances >= 10,
                    "guest status receipts stalled during failure"
                );
                record(
                    evidence,
                    "SSH-ready recovery",
                    format!("{elapsed:?}, failure_at={failed:?}"),
                )?;
                break;
            }
        } else {
            ensure!(
                elapsed <= Duration::from_secs(65),
                "no SSH failure within 65 seconds"
            );
        }
        ensure!(
            elapsed < Duration::from_secs(140),
            "no SSH recovery within 140 seconds"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    profiler.finish(initial, stopped.elapsed(), evidence)?;
    Ok(())
}

#[derive(Debug)]
struct ProcessSample {
    pid: u32,
    start_ticks: u64,
    cpu_ticks: u64,
    voluntary: u64,
    involuntary: u64,
    fds: usize,
    children: BTreeSet<u32>,
}

impl ProcessSample {
    fn read(pid: u32) -> Result<Self> {
        let root = std::path::PathBuf::from(format!("/proc/{pid}"));
        let stat = fs::read_to_string(root.join("stat"))?;
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .ok_or_else(|| eyre!("malformed process stat"))?
            .1
            .split_whitespace()
            .collect();
        // The first field after comm is field 3 (state).
        let cpu_ticks = fields[11].parse::<u64>()? + fields[12].parse::<u64>()?;
        let start_ticks = fields[19].parse()?;
        let status = fs::read_to_string(root.join("status"))?;
        let counter = |name: &str| -> Result<u64> {
            Ok(status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .ok_or_else(|| eyre!("missing {name}"))?
                .trim()
                .parse()?)
        };
        let mut children = BTreeSet::new();
        for thread in fs::read_dir(root.join("task"))? {
            let path = thread?.path().join("children");
            if let Ok(value) = fs::read_to_string(path) {
                for child in value.split_whitespace() {
                    children.insert(child.parse()?);
                }
            }
        }
        Ok(Self {
            pid,
            start_ticks,
            cpu_ticks,
            voluntary: counter("voluntary_ctxt_switches:")?,
            involuntary: counter("nonvoluntary_ctxt_switches:")?,
            fds: fs::read_dir(root.join("fd"))?.count(),
            children,
        })
    }
}

struct Profiler {
    supervisor: u32,
    worker: u32,
    ticks_per_second: f64,
}

impl Profiler {
    fn new(machine_id: &str) -> Result<Self> {
        let mut supervisors = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let args: Vec<_> = cmdline.split(|byte| *byte == 0).collect();
            if args
                .windows(2)
                .any(|args| args[0] == b"--id" && args[1] == machine_id.as_bytes())
            {
                supervisors.push(pid);
            }
        }
        ensure!(
            supervisors.len() == 1,
            "cannot identify fixture supervisor: {supervisors:?}"
        );
        let supervisor = supervisors[0];
        let children = ProcessSample::read(supervisor)?.children;
        let workers: Vec<_> = children
            .into_iter()
            .filter(|pid| {
                fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|args| {
                    args.split(|byte| *byte == 0).next() == Some(b"krun".as_slice())
                })
            })
            .collect();
        ensure!(
            workers.len() == 1,
            "cannot identify real krun worker: {workers:?}"
        );
        let clock = std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()?;
        ensure!(clock.status.success(), "getconf CLK_TCK failed");
        let ticks_per_second: f64 = std::str::from_utf8(&clock.stdout)?.trim().parse()?;
        ensure!(ticks_per_second > 0.0, "invalid clock tick rate");
        Ok(Self {
            supervisor,
            worker: workers[0],
            ticks_per_second,
        })
    }

    fn sample(&self, evidence: &mut File) -> Result<[ProcessSample; 2]> {
        let samples = [
            ProcessSample::read(self.supervisor)?,
            ProcessSample::read(self.worker)?,
        ];
        for (role, sample) in ["supervisor", "worker"].into_iter().zip(&samples) {
            record(evidence, role, format!("pid={} cpu_ticks={} main_thread_voluntary={} main_thread_involuntary={} fds={} children={:?}", sample.pid, sample.cpu_ticks, sample.voluntary, sample.involuntary, sample.fds, sample.children))?;
        }
        Ok(samples)
    }

    fn finish(
        &self,
        initial: [ProcessSample; 2],
        elapsed: Duration,
        evidence: &mut File,
    ) -> Result<()> {
        let final_samples = self.sample(evidence)?;
        for ((role, before), after) in ["supervisor", "worker"]
            .into_iter()
            .zip(initial)
            .zip(final_samples)
        {
            ensure!(
                before.start_ticks == after.start_ticks,
                "{role} process replaced during sample"
            );
            let cpu = 100.0 * (after.cpu_ticks - before.cpu_ticks) as f64
                / self.ticks_per_second
                / elapsed.as_secs_f64();
            record(evidence, "idle profile", format!("role={role} seconds={:.3} CLK_TCK={} one_core_cpu_percent={cpu:.4} main_thread_voluntary_delta={} main_thread_involuntary_delta={} fd_delta={} children_before={:?} children_after={:?}", elapsed.as_secs_f64(), self.ticks_per_second, after.voluntary - before.voluntary, after.involuntary - before.involuntary, after.fds as i64 - before.fds as i64, before.children, after.children))?;
            ensure!(
                after.fds <= before.fds + 2,
                "{role} descriptors accumulated during sample"
            );
            ensure!(
                after.children == before.children,
                "{role} children accumulated or replaced"
            );
            if role == "supervisor" {
                ensure!(
                    cpu <= 1.0,
                    "sustained supervisor CPU above 1% of one core, profile before qualification"
                );
            }
        }
        Ok(())
    }
}
